//! Exact released envelope decoders, test-only. No modern v3 parser is
//! relabelled as an old reader. The old envelope dispatch and pins are frozen:
//! newer-format or PL allowlist refusal precedes the shared body verifier.
use super::*;

mod v201 {
    // Released source 7997fe740064273ffc145d2168c299f5d8b9ee3d; copied decoder span SHA256
    // 30fc1c2f70cbf2729d9cd0f05459c18a665108ac368f6aa724ccb8d3bd2d6afd (before rustfmt).
    use super::*;
    const FORMAT_VERSION: u16 = 1;
    #[derive(Debug, PartialEq, Eq)]
    enum Refusal {
        AllowlistChanged,
        Corrupt,
        NewerFormat,
        OlderFormat,
    }
    struct PendingRecord {
        binding: Binding,
        certificate: DurableCertificate,
        body: Vec<u8>,
        allowlist: Digest32,
    }
    struct DurableRecord {
        record: PendingRecord,
        index_generation: u64,
    }
    struct Cursor<'a>(&'a [u8]);
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Some(head)
        }
        fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
            self.take(N)?.try_into().ok()
        }
        fn u8(&mut self) -> Option<u8> {
            Some(self.array::<1>()?[0])
        }
        fn u16(&mut self) -> Option<u16> {
            Some(u16::from_le_bytes(self.array()?))
        }
        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_le_bytes(self.array()?))
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.array()?))
        }
        fn i64(&mut self) -> Option<i64> {
            Some(i64::from_le_bytes(self.array()?))
        }
    }

    fn decode(bytes: &[u8], allowlist: &Digest32) -> Result<DurableRecord, Refusal> {
        let mut cursor = Cursor(bytes);
        if cursor.array::<8>() != Some(MAGIC) {
            return Err(Refusal::Corrupt);
        }
        let version = cursor.u16().ok_or(Refusal::Corrupt)?;
        if version > FORMAT_VERSION {
            return Err(Refusal::NewerFormat);
        }
        if version < FORMAT_VERSION {
            return Err(Refusal::OlderFormat);
        }
        let body_end = bytes
            .len()
            .checked_sub(TRAILER_BYTES)
            .filter(|end| *end >= MAGIC.len() + 2)
            .ok_or(Refusal::Corrupt)?;
        let trailer: Digest32 = Sha256::digest(&bytes[..body_end]).into();
        if bytes[body_end..] != trailer {
            return Err(Refusal::Corrupt);
        }
        let mut cursor = Cursor(&bytes[10..body_end]);
        let record_allowlist = cursor.array::<32>().ok_or(Refusal::Corrupt)?;
        let decoded = (|| {
            let source = DurableSource::from_tag(cursor.u8()?)?;
            let binding = Binding {
                source,
                key: cursor.array()?,
                context: cursor.array()?,
                scope: cursor.array()?,
                entry: cursor.array()?,
            };
            let index_generation = cursor.u64()?;
            let certificate = DurableCertificate {
                device: cursor.u64()?,
                inode: cursor.u64()?,
                length: cursor.u64()?,
                modified: (cursor.i64()?, cursor.i64()?),
                birth_nanos: cursor.u64()?,
                sealed_offset: cursor.u64()?,
                sample_len: cursor.u32()?,
                head_sha256: cursor.array()?,
                boundary_sha256: cursor.array()?,
                verified_unix_seconds: cursor.u64()?,
                audit_debt_unix_seconds: {
                    let present = cursor.u8()?;
                    let due = cursor.u64()?;
                    match present {
                        0 if due == 0 => None,
                        1 => Some(due),
                        _ => return None,
                    }
                },
            };
            let body_len = cursor.u32()? as usize;
            let body = cursor.take(body_len)?.to_vec();
            cursor.0.is_empty().then_some(DurableRecord {
                record: PendingRecord {
                    binding,
                    certificate,
                    body,
                    allowlist: record_allowlist,
                },
                index_generation,
            })
        })();
        let record = decoded.ok_or(Refusal::Corrupt)?;
        if record_allowlist != *allowlist {
            return Err(Refusal::AllowlistChanged);
        }
        Ok(record)
    }
    pub(super) fn refuses_new_record(bytes: &[u8], allowlist: &Digest32) -> bool {
        matches!(decode(bytes, allowlist), Err(Refusal::NewerFormat))
    }
    pub(super) fn assert_original_v1(
        bytes: &[u8],
        expected: &super::super::PendingRecord,
        generation: u64,
    ) {
        let record = decode(bytes, &expected.allowlist)
            .unwrap_or_else(|e| panic!("released v1 control: {e:?}"));
        assert_eq!(record.record.binding, expected.binding);
        assert_eq!(record.record.certificate, expected.certificate);
        assert_eq!(record.record.body, expected.body);
        assert_eq!(record.record.allowlist, expected.allowlist);
        assert_eq!(record.index_generation, generation);
    }
}

mod v202 {
    // Released source 79488a7297817edfe1eb5cfc34b779408d511726; copied decoder span SHA256
    // 3cb05777c260d08332565d8f0826956c6c0a28c4921325537448e9337f560caa (before rustfmt).
    use super::*;
    const FORMAT_VERSION: u16 = 1;
    #[derive(Debug, PartialEq, Eq)]
    enum Refusal {
        Corrupt,
        NewerFormat,
        Unbindable,
        Undecodable,
        Unknown,
    }
    struct PendingRecord {
        binding: Binding,
        certificate: DurableCertificate,
        body: Vec<u8>,
        allowlist: Digest32,
    }
    struct DurableRecord {
        record: PendingRecord,
        index_generation: u64,
    }
    struct Cursor<'a>(&'a [u8]);
    impl<'a> Cursor<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Some(head)
        }
        fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
            self.take(N)?.try_into().ok()
        }
        fn u8(&mut self) -> Option<u8> {
            Some(self.array::<1>()?[0])
        }
        fn u16(&mut self) -> Option<u16> {
            Some(u16::from_le_bytes(self.array()?))
        }
        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_le_bytes(self.array()?))
        }
        fn u64(&mut self) -> Option<u64> {
            Some(u64::from_le_bytes(self.array()?))
        }
        fn i64(&mut self) -> Option<i64> {
            Some(i64::from_le_bytes(self.array()?))
        }
    }

    fn decode_header(
        header: &[u8],
        key: &Digest32,
        source: DurableSource,
    ) -> Result<Binding, Refusal> {
        let mut c = Cursor(header);
        if c.array::<8>() != Some(MAGIC) {
            return Err(Refusal::Undecodable);
        }
        let version = c.u16().ok_or(Refusal::Undecodable)?;
        if version > FORMAT_VERSION {
            return Err(Refusal::NewerFormat);
        }
        if version != FORMAT_VERSION {
            return Err(Refusal::Unknown);
        }
        let allowlist = c.array::<32>().ok_or(Refusal::Undecodable)?;
        let tag = c.u8().ok_or(Refusal::Undecodable)?;
        // Both pinned v1 writers (72205c6c and 4f143c16/ffc6c846) have these same lists.
        let pin = match tag {
            1 => "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c",
            2 => "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
            _ => return Err(Refusal::Unknown),
        };
        if Some(allowlist) != parse_hex_digest(pin) {
            return Err(Refusal::Unknown);
        }
        let binding = (|| {
            Some(Binding {
                source: DurableSource::from_tag(tag)?,
                key: c.array()?,
                context: c.array()?,
                scope: c.array()?,
                entry: c.array()?,
            })
        })()
        .ok_or(Refusal::Undecodable)?;
        if binding.key != *key || binding.source != source {
            return Err(Refusal::Unbindable);
        }
        Ok(binding)
    }

    fn verify(bytes: &[u8], source: DurableSource) -> Result<(), Refusal> {
        let bad = Refusal::Corrupt;
        if bytes.len() < HEADER_BYTES + TRAILER_BYTES {
            return Err(bad);
        }
        let end = bytes.len() - TRAILER_BYTES;
        // Trailer FIRST: structural duplicate checks on unsorted maps/sets can be quadratic.
        if bytes[end..] != Sha256::digest(&bytes[..end])[..] {
            return Err(bad);
        }
        let mut c = Cursor(&bytes[HEADER_BYTES - 4..HEADER_BYTES]);
        if c.u32().map(|n| n as usize) != Some(end - HEADER_BYTES) {
            return Err(bad);
        }
        let debt = HEADER_BYTES - 4 - 9;
        if !matches!(bytes[debt], 0 | 1)
            || (bytes[debt] == 0 && bytes[debt + 1..debt + 9] != [0; 8])
        {
            return Err(bad);
        }
        crate::snapshots::verify_durable_body(&bytes[HEADER_BYTES..end], source)
            .then_some(())
            .ok_or(bad)
    }

    fn decode(bytes: &[u8], allowlist: &Digest32) -> Result<DurableRecord, Refusal> {
        let source = bytes
            .get(42)
            .and_then(|tag| DurableSource::from_tag(*tag))
            .ok_or(Refusal::Undecodable)?;
        let key: Digest32 = bytes
            .get(43..75)
            .and_then(|b| b.try_into().ok())
            .ok_or(Refusal::Undecodable)?;
        decode_header(bytes, &key, source)?;
        verify(bytes, source)?;
        let body_end = bytes.len() - TRAILER_BYTES;
        let mut cursor = Cursor(&bytes[10..body_end]);
        let record_allowlist = cursor.array::<32>().ok_or(Refusal::Corrupt)?;
        let decoded = (|| {
            let source = DurableSource::from_tag(cursor.u8()?)?;
            let binding = Binding {
                source,
                key: cursor.array()?,
                context: cursor.array()?,
                scope: cursor.array()?,
                entry: cursor.array()?,
            };
            let index_generation = cursor.u64()?;
            let certificate = DurableCertificate {
                device: cursor.u64()?,
                inode: cursor.u64()?,
                length: cursor.u64()?,
                modified: (cursor.i64()?, cursor.i64()?),
                birth_nanos: cursor.u64()?,
                sealed_offset: cursor.u64()?,
                sample_len: cursor.u32()?,
                head_sha256: cursor.array()?,
                boundary_sha256: cursor.array()?,
                verified_unix_seconds: cursor.u64()?,
                audit_debt_unix_seconds: {
                    let present = cursor.u8()?;
                    let due = cursor.u64()?;
                    match present {
                        0 if due == 0 => None,
                        1 => Some(due),
                        _ => return None,
                    }
                },
            };
            let body_len = cursor.u32()? as usize;
            let body = cursor.take(body_len)?.to_vec();
            cursor.0.is_empty().then_some(DurableRecord {
                record: PendingRecord {
                    binding,
                    certificate,
                    body,
                    allowlist: record_allowlist,
                },
                index_generation,
            })
        })();
        let record = decoded.ok_or(Refusal::Corrupt)?;
        if record_allowlist != *allowlist {
            return Err(Refusal::Unknown);
        }
        Ok(record)
    }
    pub(super) fn refuses_new_record(bytes: &[u8], allowlist: &Digest32) -> bool {
        matches!(decode(bytes, allowlist), Err(Refusal::NewerFormat))
    }
    pub(super) fn assert_repin_refused(bytes: &[u8], allowlist: &Digest32) {
        match decode(bytes, allowlist) {
            Err(Refusal::Unknown) => {}
            Ok(record) => {
                // Consume every frozen-decoder output field without exposing
                // its values; acceptance itself is the regression.
                let _ = (
                    record.record.binding,
                    record.record.certificate,
                    record.record.body,
                    record.record.allowlist,
                    record.index_generation,
                );
                panic!("released reader accepted the PL re-pin");
            }
            Err(reason) => panic!("expected PL allowlist refusal, got {reason:?}"),
        }
    }
}

pub(super) fn assert_old_readers_refuse_native_v3(
    bytes: &[u8],
    original: &PendingRecord,
    generation: u64,
) {
    let v1 = super::tests::pinned_v1_bytes(original, generation);
    v201::assert_original_v1(&v1, original, generation);
    v202::assert_repin_refused(&v1, &original.allowlist);
    assert!(v201::refuses_new_record(bytes, &original.allowlist));
    assert!(v202::refuses_new_record(bytes, &original.allowlist));
}

/// M-2 seam control. Runs both genuine released envelope decoders without
/// changing their pins or decoder spans, using the frozen old body encoder.
pub(super) fn assert_pre_m2_bytes(bytes: &[u8], expected: &PendingRecord, generation: u64) {
    v201::assert_original_v1(bytes, expected, generation);
    v202::assert_original_v1(bytes, expected, generation);
}
