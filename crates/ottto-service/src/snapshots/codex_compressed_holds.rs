//! Dedicated non-red custody; no acquisition or ACK authority.
use super::*;

pub(super) fn deserialize_hold<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<CodexZstCause>, D::Error> {
    let value = Option::<Value>::deserialize(de)?;
    Ok(value.map(|value| {
        serde_json::from_value(value).unwrap_or_else(|_| {
            crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::OwnerUnproven);
            CodexZstCause::OwnerUnproven
        })
    }))
}
