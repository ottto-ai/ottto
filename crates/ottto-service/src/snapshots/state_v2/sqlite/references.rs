//! Backend implementations of bounded full-value comparison and ref updates.
use super::*;

/// Daily idle check only. Saves adjust counts for changed rows; they never
/// enumerate history. The mapper supplies decoding, the store owns comparison.
pub(super) fn verify_counts(conn: &Connection, extract: ReferenceExtractor) -> Result<()> {
    let mut expected = BTreeMap::<RowKey, u64>::new();
    let mut actual = BTreeMap::new();
    for table in Table::ALL {
        let mut after = None;
        loop {
            let page = scan(conn, RowPrefix { table }, after.as_ref(), PAGE_HEADERS)?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|h| h.key.clone());
            for header in page {
                if let Fixed::RequestSet { refs, .. } | Fixed::Interned { refs } = header.fixed {
                    read_value(conn, &header, &mut io::sink())?;
                    actual.insert(header.key.clone(), refs);
                } else {
                    extract(
                        &header,
                        &StoredValue {
                            conn,
                            header: &header,
                        },
                        &mut |key| {
                            ensure!(
                                matches!(key, RowKey::RequestSet(_) | RowKey::Interned { .. }),
                                "state_v2_reference_kind"
                            );
                            let count = expected.entry(key.clone()).or_default();
                            *count = count.checked_add(1).context("state_v2_reference_count")?;
                            Ok(())
                        },
                    )?;
                }
            }
        }
    }
    ensure!(actual == expected, super::super::Hold::ReferenceDrift);
    Ok(())
}

struct Compare<'a> {
    conn: &'a Connection,
    header: &'a Header,
    key_bytes: Vec<u8>,
    part_no: Option<u64>,
    part: Vec<u8>,
    compared: u64,
    equal: bool,
}
impl Compare<'_> {
    fn part(&mut self, number: u64) -> Result<()> {
        if self.part_no == Some(number) {
            return Ok(());
        }
        let table = self.header.key.table();
        self.part = if self.header.parts == 0 {
            self.conn.query_row(
                &format!(
                    "SELECT inline FROM {} WHERE {}",
                    table.name(),
                    predicate(table)
                ),
                params_from_iter(self.header.key.values()?),
                |row| {
                    let b = row.get_ref(0)?.as_blob()?;
                    if b.len() > INLINE_BYTES {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(b.to_vec())
                },
            )?
        } else {
            self.conn.query_row(
                "SELECT bytes FROM blob_parts WHERE owner=?1 AND key=?2 AND part=?3",
                params![table_number(table), self.key_bytes, number],
                |row| {
                    let b = row.get_ref(0)?.as_blob()?;
                    if b.len() > PART_BYTES {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(b.to_vec())
                },
            )?
        };
        self.part_no = Some(number);
        Ok(())
    }
}
impl Write for Compare<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .compared
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or_else(|| io::Error::other("state_v2_value_admission"))?;
        let mut rest = bytes;
        while !rest.is_empty() && self.compared < self.header.len {
            let number = self.compared / PART_BYTES as u64;
            self.part(number)
                .map_err(|_| io::Error::other("state_v2_compare_read"))?;
            let offset = self.compared as usize % PART_BYTES;
            let available = self
                .part
                .len()
                .checked_sub(offset)
                .filter(|n| *n != 0)
                .ok_or_else(|| io::Error::other("state_v2_compare_part"))?;
            let n = rest.len().min(available);
            self.equal &= self.part[offset..offset + n] == rest[..n];
            rest = &rest[n..];
            self.compared += n as u64;
        }
        self.equal &= rest.is_empty();
        self.compared = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn matches(conn: &Connection, header: &Header, value: &dyn Value) -> Result<bool> {
    // Validate even a colliding candidate that ultimately differs. Damaged
    // evidence must not be silently skipped to allocate a new authority row.
    read_value(conn, header, &mut io::sink())?;
    if header.key.table() == Table::Census {
        bail!("state_v2_value_comparison_kind");
    }
    let mut compare = Compare {
        conn,
        header,
        key_bytes: owner_key_bytes(&header.key)?,
        part_no: None,
        part: Vec::new(),
        compared: 0,
        equal: true,
    };
    value.write(&mut compare)?;
    Ok(compare.equal && compare.compared == header.len)
}

pub(super) fn candidates(
    conn: &Connection,
    commitment: &[u8; 32],
    after: u64,
    limit: usize,
) -> Result<Vec<Header>> {
    ensure!(limit <= PAGE_HEADERS, "state_v2_header_page_admission");
    let mut stmt = conn
        .prepare_cached(&format!(
        "SELECT {} FROM request_sets WHERE commitment=?1 AND set_id>?2 ORDER BY set_id LIMIT ?3",
        projection(Table::RequestSets)))?;
    let rows = stmt.query_map(params![commitment, after, limit as u64], |row| {
        header(Table::RequestSets, row)
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub(super) fn adjust(tx: &mut Txn<'_>, key: &RowKey, delta: i64) -> Result<u64> {
    ensure!(tx.write && !tx.failed, "state_v2_transaction_refused");
    let result = (|| {
        let old = tx.get(key)?.context("state_v2_reference_missing")?;
        let mut fixed = old.fixed.clone();
        let refs = match &mut fixed {
            Fixed::RequestSet { refs, .. } | Fixed::Interned { refs } => refs,
            _ => bail!("state_v2_reference_kind"),
        };
        ensure!(*refs != 0, "state_v2_reference_count");
        let next = i128::from(*refs)
            .checked_add(i128::from(delta))
            .filter(|n| *n >= 0 && *n <= i128::from(i64::MAX))
            .context("state_v2_reference_count")? as u64;
        if next == 0 || delta == 0 {
            // Fixed columns are integrity-protected by the value digest too.
            // A corrupted refs=1 must never authorize last-owner reclamation.
            // Nonzero updates below validate while computing the new digest.
            read_value(tx.store.conn()?, &old, &mut io::sink())?;
        }
        if next == 0 {
            tx.delete(key)?;
        } else if delta != 0 {
            *refs = next;
            struct Hash(sha2::Sha256);
            impl Write for Hash {
                fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                    self.0.update(b);
                    Ok(b.len())
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            let mut hash = Hash(digest_start(key, &fixed)?);
            read_value(tx.store.conn()?, &old, &mut hash)?;
            tx.admit_change(key, 0)?;
            let digest = integrity(hash.0);
            let mut params = vec![
                SqlValue::Integer(next as i64),
                SqlValue::Blob(digest.to_vec()),
            ];
            params.extend(key.values()?);
            let sql = match key {
                RowKey::RequestSet(_) => {
                    "UPDATE request_sets SET refs=?1,digest=?2 WHERE set_id=?3"
                }
                RowKey::Interned { .. } => {
                    "UPDATE interned SET refs=?1,digest=?2 WHERE kind=?3 AND ordinal=?4"
                }
                _ => bail!("state_v2_reference_kind"),
            };
            ensure!(
                tx.store.conn()?.execute(sql, params_from_iter(params))? == 1,
                "state_v2_reference_missing"
            );
            tx.changed.insert(
                key.clone(),
                Some(Header {
                    fixed,
                    digest,
                    ..old
                }),
            );
        }
        Ok(next)
    })();
    tx.failed |= result.is_err();
    result
}

pub(super) fn interned_candidates(
    conn: &Connection,
    kind: u16,
    after: u64,
    limit: usize,
) -> Result<Vec<Header>> {
    ensure!(limit <= PAGE_HEADERS, "state_v2_header_page_admission");
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {} FROM interned WHERE kind=?1 AND ordinal>?2 ORDER BY ordinal LIMIT ?3",
        projection(Table::Interned)
    ))?;
    let rows = stmt.query_map(params![kind, after, limit as u64], |row| {
        header(Table::Interned, row)
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
