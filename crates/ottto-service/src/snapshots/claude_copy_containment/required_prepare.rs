//! Actual required preparation: fund new context inputs before constructing
//! them. Existing source preparation strings remain borrowed baseline owners.
use super::required_budget::{error_box_layout, Unavailable};
use crate::snapshots::ScanIndex;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn digest_parts(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
    }
    // Only called beneath the prepaid fixed digest-output envelope.
    format!("{:x}", digest.finalize())
}

impl ScanIndex {
    pub(crate) fn attach_prepaid_copy_owner(
        &mut self,
        support_dir: &Path,
        sampled_scope: &str,
        destination: &str,
        source: &str,
        index_path: &Path,
    ) -> Result<(), Unavailable> {
        let owner = self.required_copy_owner()?.ok_or(Unavailable)?.clone();
        let path = index_path.to_str().ok_or(Unavailable)?;
        let name = ottto_core::CLAUDE_CONFIG_SLOT_SETTINGS_FILE_NAME;
        let path_capacity = support_dir
            .as_os_str()
            .len()
            .checked_add(name.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(Unavailable)?;
        // Exact-capacity path, three64-byte digests plus formatting growth,
        // fixed input-free error recipes/boxes. Registry decode/validation
        // later extend this SAME lease before their first allocation.
        let fixed = path_capacity
            .checked_add(3 * 4 * 64)
            .and_then(|n| n.checked_add(4 * 146))
            .and_then(|n| n.checked_add(error_box_layout()?.checked_mul(2)?))
            .ok_or(Unavailable)?;
        let mut temporary = owner.reserve_copy_bytes(fixed).ok_or(Unavailable)?;
        let mut registry_path = PathBuf::with_capacity(path_capacity);
        registry_path.push(support_dir);
        registry_path.push(name);
        let store = ottto_core::FileClaudeConfigSlotSettingsStore::new(registry_path);
        let mut funding_refused = false;
        let result = store.transcript_binding_fingerprint_prepaid(|bytes| {
            let funded = fixed
                .checked_add(bytes)
                .and_then(|n| temporary.resize(n))
                .is_some();
            funding_refused |= !funded;
            funded
        });
        if funding_refused {
            return Err(Unavailable);
        }
        // Missing/malformed/changed storage stays UNKNOWN, as before. Funding
        // refusal is different and must abort required preparation explicitly.
        let registered_slots = result.ok();
        let scope = digest_parts(&["copy_containment_owner:v1:", sampled_scope]);
        let attempt = digest_parts(&[
            "copy_attempt_destination:v1:",
            destination,
            ":",
            source,
            ":",
            path,
        ]);
        // The original helpers transfer paid temporary inputs to independently
        // paid retained index metadata before the temporary lease can retire.
        self.attach_unknown_copy_owner_with_registered_slots(scope, registered_slots)
            .map_err(|_| Unavailable)?;
        self.attach_copy_attempt_scope(attempt)
            .map_err(|_| Unavailable)?;
        // Drop store/path and any local data before temporary is retired.
        drop(store);
        drop(temporary);
        self.begin_copy_completion_provenance();
        Ok(())
    }
}
