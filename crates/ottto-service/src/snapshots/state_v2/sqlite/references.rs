//! Full evidence comparison and O(changed) reference-count updates.
use super::*;

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
            for h in page {
                if let Fixed::RequestSet { refs, .. } = &h.fixed {
                    actual.insert(h.key.clone(), *refs);
                } else {
                    extract(&h, &StoredValue { conn, header: &h }, &mut |key| {
                        ensure!(
                            matches!(key, RowKey::RequestSet(_)),
                            "state_v2_reference_kind"
                        );
                        let n = expected.entry(key.clone()).or_default();
                        *n = n.checked_add(1).context("state_v2_reference_count")?;
                        Ok(())
                    })?;
                }
            }
        }
    }
    ensure!(actual == expected, super::super::Hold::ReferenceDrift);
    Ok(())
}
pub(super) fn candidates(
    conn: &Connection,
    commitment: &[u8; 32],
    after: u64,
    limit: usize,
) -> Result<Vec<Header>> {
    ensure!(limit <= PAGE_HEADERS, "state_v2_header_page_admission");
    let mut stmt=conn.prepare_cached(&format!("SELECT {} FROM shared_values WHERE class='request_hash_set' AND lookup_hash=?1 AND id>?2 ORDER BY id LIMIT ?3",projection(Table::RequestSets)))?;
    let rows = stmt.query_map(params![commitment, after, limit as u64], |r| {
        header(Table::RequestSets, r)
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
pub(super) fn adjust(tx: &mut Txn<'_>, key: &RowKey, delta: i64) -> Result<u64> {
    ensure!(tx.write && !tx.failed, "state_v2_transaction_refused");
    let result = (|| {
        let mut h = tx.get(key)?.context("state_v2_reference_missing")?;
        let Fixed::RequestSet { refs, .. } = &mut h.fixed else {
            bail!("state_v2_reference_kind")
        };
        let next = i128::from(*refs)
            .checked_add(i128::from(delta))
            .filter(|n| *n >= 0 && *n <= i128::from(i64::MAX))
            .context("state_v2_reference_count")? as u64;
        if next == 0 {
            tx.delete(key)?;
        } else if delta != 0 {
            *refs = next;
            h.row_checksum = row_checksum(&h)?;
            tx.admit_change(key, 0, 0, true)?;
            let RowKey::RequestSet(id) = key else {
                bail!("state_v2_reference_kind")
            };
            ensure!(tx.store.conn()?.execute("UPDATE shared_values SET ref_count=?1,row_checksum=?2 WHERE class='request_hash_set' AND id=?3",params![next,h.row_checksum.as_slice(),id])?==1,"state_v2_reference_missing");
        }
        Ok(next)
    })();
    if let Err(error) = &result {
        tx.store.record_save_error(error);
    }
    tx.failed |= result.is_err();
    result
}
