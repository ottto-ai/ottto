//! The exact retired v1 cohort is rebuildable, never dual-pin decodable.
use super::*;

pub(crate) fn retired_pin(source: DurableSource, format: u16, pin: &Digest32) -> bool {
    let retired = match source {
        DurableSource::ClaudeCode => {
            "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c"
        }
        DurableSource::Codex => "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
    };
    format == FORMAT_V1 && parse_hex_digest(retired).as_ref() == Some(pin)
}

pub(super) fn retired_at(path: &Path) -> io::Result<bool> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let mut bytes = [0; DISPATCH_BYTES];
    if let Err(error) = file.read_exact(&mut bytes) {
        return if error.kind() == io::ErrorKind::UnexpectedEof {
            Ok(false)
        } else {
            Err(error)
        };
    }
    Ok(dispatch(&bytes).is_ok_and(|(format, pin, source, _)| retired_pin(source, format, &pin)))
}

impl DurableTailStore {
    /// Header-only cohort discovery has no T14/rebuild/restore side effects.
    pub(crate) fn has_retired_pin(&mut self, key: &Digest32) -> bool {
        if !self.usable(None) {
            return false;
        }
        let result = (|| -> io::Result<bool> {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(self.record_path(key))?;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.uid() != our_uid() || meta.mode() & 0o777 != 0o600 {
                return Ok(false);
            }
            let mut bytes = [0; DISPATCH_BYTES];
            file.read_exact(&mut bytes)?;
            self.counters.guard_header_bytes += DISPATCH_BYTES as u64;
            Ok(dispatch(&bytes).is_ok_and(|(format, pin, source, _)| {
                source == self.source && retired_pin(source, format, &pin)
            }))
        })();
        result.unwrap_or(false)
    }

    /// Integrity and original same-context identity, with no retired-body
    /// decode. The caller funds the bounded envelope before entering Stores.
    pub(crate) fn repin_witness(
        &mut self,
        key: &Digest32,
        context: &Digest32,
        generation: u64,
    ) -> Option<(MutationWitness, DurableCertificate)> {
        if self.receipt_pending(key) {
            return None;
        }
        let header = self.classify(key, "repin", None).ok()??;
        if !retired_pin(self.source, header.format, &header.record.allowlist)
            || header.record.binding.context != *context
            || header.generation > generation
        {
            return None;
        }
        let (Some(content), stamp, _) = *self.durable.get(key)? else {
            return None;
        };
        let proof = MutationWitness {
            key: *key,
            content,
            stamp,
            original: content,
            migration_floor: None,
        };
        self.witness_current(&proof)
            .then_some((proof, header.record.certificate))
    }

    pub(crate) fn authorize_repin(&mut self, proof: &MutationWitness) -> bool {
        let Some(header) = self.classify(&proof.key, "repin", None).ok().flatten() else {
            return false;
        };
        if !retired_pin(self.source, header.format, &header.record.allowlist)
            || !self.witness_current(proof)
            || !self
                .durable
                .get(&proof.key)
                .is_some_and(|(content, stamp, _)| {
                    *content == Some(proof.content) && *stamp == proof.stamp
                })
        {
            return false;
        }
        self.memoize(proof.key, (Some(proof.content), proof.stamp, true));
        true
    }
}
