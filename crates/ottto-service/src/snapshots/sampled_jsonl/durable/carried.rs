//! SOURCE PL: record-owned literals, never a second content store.
use super::*;
use crate::durable_tail_codec::PrivateLocalLiteral;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const WORKSPACE_CAP: usize = 4096;
// The upload's prompt-prefix display label is the only literal prompt carrier.
// Material/template hashes do not authorize copying the original prompt. Use
// its byte bound, not the larger, character-bounded template-hashing scratch.
pub(super) const FIRST_PROMPT_CAP: usize =
    crate::session_attribution::MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES;

/// Borrow the FINAL upload-builder fields, after consent, redaction,
/// normalization and truncation. None means that field was NOT uploaded.
/// Never construct this view from accumulator values or a pre-policy body.
/// Deliberately no Debug/Serialize: even a temporary wire view is private.
pub(crate) struct UploadedLiterals<'a> {
    workspace: Option<&'a str>,
    first_prompt: Option<&'a str>,
}
impl<'a> UploadedLiterals<'a> {
    pub(crate) fn from_wire(workspace: Option<&'a str>, first_prompt: Option<&'a str>) -> Self {
        Self {
            workspace,
            first_prompt,
        }
    }
}

/// Private local literals (PL), SOURCE 2026-10-30. Single use: restore only
/// the SAME field after the enclosing record's head/identity checks. Never
/// identity, grouping or dedupe inputs; never log/export these values.
///
/// A source places this inside its OWN section (PiSection for Pi), not the
/// shared body. Erase with that record on head change, retirement, removal,
/// forget or uninstall. On consent-off, purge at the next save AND omit that
/// source's corresponding H obligations: no upload means no obligation. A
/// missing literal with an existing H obligation retains legacy refusal/read
/// behavior; it is not evidence of consent. Claude/Codex must pass None until
/// separately approved. No Serialize/Display and no literal getters.
#[derive(Default)]
pub(crate) struct CarriedUploaded {
    workspace: Option<PathBuf>,
    first_prompt: Option<String>,
}
impl std::fmt::Debug for CarriedUploaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarriedUploaded")
            .field(
                "workspace_bytes",
                &self.workspace.as_ref().map(|p| p.as_os_str().len()),
            )
            .field(
                "first_prompt_bytes",
                &self.first_prompt.as_ref().map(String::len),
            )
            .finish()
    }
}
crate::heap_layout_bound::fields!(CarriedUploaded; workspace, first_prompt);
crate::durable_tail_codec::durable_struct!(CarriedUploaded {
    PL workspace: Option<PathBuf>,
    PL first_prompt: Option<String>,
});

static PURGED: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static MISMATCH: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
fn source_slot(source: SnapshotSource) -> usize {
    match source {
        SnapshotSource::ClaudeCode => 0,
        SnapshotSource::Codex => 1,
        SnapshotSource::Pi => 2,
    }
}

impl CarriedUploaded {
    /// Own only bytes the final, consent-filtered upload actually carried AND
    /// which exactly equal the accumulator field. A truncated/redacted mismatch
    /// stays H-only. Never reconstruct missing wire values from the accumulator.
    pub(crate) fn from_upload(
        acc: &SnapshotAccumulator,
        uploaded: super::UploadedLiterals<'_>,
    ) -> Result<Self, Refuse> {
        if uploaded.workspace.is_some_and(|s| s.len() > WORKSPACE_CAP)
            || uploaded
                .first_prompt
                .is_some_and(|s| s.len() > FIRST_PROMPT_CAP)
        {
            return Err(Refuse::TooLarge);
        }
        Ok(Self {
            workspace: uploaded
                .workspace
                .filter(|wire| {
                    acc.workspace_path
                        .as_ref()
                        .is_some_and(|path| path.as_os_str().as_encoded_bytes() == wire.as_bytes())
                })
                .map(PathBuf::from),
            first_prompt: uploaded
                .first_prompt
                .filter(|wire| {
                    acc.first_prompt_material.as_deref() == Some(*wire)
                        && first_prompt_display_title(acc.source, (*wire).to_owned())
                            == acc.first_prompt_title
                })
                .map(str::to_owned),
        })
    }

    /// Revoke owned copies at the next save. Caller must save this purged
    /// section together with the consent-filtered (empty) obligations, then
    /// retire any superseded record; never keep another literal side store.
    /// Counts records purged once, regardless of how many fields they held.
    pub(crate) fn purge_carried_literals(&mut self, source: SnapshotSource) -> bool {
        let had = self.workspace.take().is_some() | self.first_prompt.take().is_some();
        if had {
            let total = PURGED[source_slot(source)].fetch_add(1, Ordering::Relaxed) + 1;
            let name = match source {
                SnapshotSource::ClaudeCode => "claude_code_uploaded_literal_purged",
                SnapshotSource::Codex => "codex_uploaded_literal_purged",
                SnapshotSource::Pi => "pi_uploaded_literal_purged",
            };
            crate::local_resource_diagnostics::durable_tail_alarm(
                source.api_slug(),
                &serde_json::json!({name: [1, total]}),
            );
        }
        had
    }

    pub(super) fn has_workspace(&self) -> bool {
        self.workspace.is_some()
    }
    pub(super) fn has_prompt(&self) -> bool {
        self.first_prompt.is_some()
    }

    // Clone/derived-title overlap is charged before allocation. This is heap
    // admission, never input bytes: carried-only restore does no file I/O.
    pub(super) fn restore_charge(&self) -> u64 {
        self.workspace
            .as_ref()
            .map_or(0, |p| p.as_os_str().len() as u64)
            + self
                .first_prompt
                .as_ref()
                .map_or(0, |s| 16 * s.len() as u64 + 1024)
    }

    pub(super) fn restore_fields(&self, decoded: &mut Decoded) -> Result<(), Refuse> {
        let acc = &mut decoded.reduction.accumulator;
        let r = &mut decoded.rederive;
        // Validate both before applying either. The shared H digest functions
        // include the Option tags and (for prompt) the derived display title.
        let title = self
            .first_prompt
            .as_ref()
            .filter(|_| r.first_prompt.is_some())
            .and_then(|s| first_prompt_display_title(acc.source, s.clone()));
        let mismatch = (r.workspace.is_some()
            && self.workspace.is_some()
            && r.workspace != Some(workspace_value_digest(&self.workspace)?))
            || (r.first_prompt.is_some()
                && self.first_prompt.is_some()
                && r.first_prompt != Some(first_prompt_parts_digest(&self.first_prompt, &title)?));
        if mismatch {
            let total = MISMATCH[source_slot(acc.source)].fetch_add(1, Ordering::Relaxed) + 1;
            crate::local_resource_diagnostics::durable_tail_alarm(
                acc.source.api_slug(),
                &serde_json::json!({"not_rederived": {"carried_digest": [1, total]}}),
            );
            return Err(Refuse::NotRederivable("carried_digest"));
        }
        if r.workspace.is_some() && self.workspace.is_some() {
            acc.workspace_path.clone_from(&self.workspace);
            r.workspace = None;
        }
        if r.first_prompt.is_some() && self.first_prompt.is_some() {
            acc.first_prompt_material.clone_from(&self.first_prompt);
            acc.first_prompt_title = title;
            r.first_prompt = None;
        }
        Ok(())
    }
}

// PL is deliberately a separate bounded codec: ordinary PathBuf::put remains
// hash-only. Borrow/validate the length and UTF-8 before allocating or charging.
fn take_text<'a>(d: &mut Dec<'a>, cap: usize) -> Result<Option<&'a str>, Corrupt> {
    match d.varint()? {
        0 => Ok(None),
        1 => {
            let bytes = d.len_prefixed()?;
            if bytes.len() > cap {
                return Err(Corrupt);
            }
            std::str::from_utf8(bytes).map(Some).map_err(|_| Corrupt)
        }
        _ => Err(Corrupt),
    }
}
fn put_text(value: Option<&str>, cap: usize, e: &mut Enc<'_>) -> Result<(), Refuse> {
    match value {
        None => e.varint(0),
        Some(s) if s.len() <= cap => {
            e.varint(1)?;
            e.len_prefixed(s.as_bytes())
        }
        Some(_) => Err(Refuse::TooLarge),
    }
}
impl PrivateLocalLiteral for Option<String> {
    fn put_pl(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_text(self.as_deref(), FIRST_PROMPT_CAP, e)
    }
    fn take_pl(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        take_text(d, FIRST_PROMPT_CAP)?
            .map(|s| {
                d.slots::<u8>(s.len())?;
                Ok(s.to_owned())
            })
            .transpose()
    }
    fn verify_pl(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        take_text(d, FIRST_PROMPT_CAP).map(|_| ())
    }
    fn shape_pl(s: &mut Shape) {
        s.push("Option<String>;utf8;max_bytes=96");
    }
}
impl PrivateLocalLiteral for Option<PathBuf> {
    fn put_pl(&self, e: &mut Enc) -> Result<(), Refuse> {
        let text = self
            .as_ref()
            .map(|p| p.to_str().ok_or(Refuse::NotRederivable("carried_encoding")))
            .transpose()?;
        put_text(text, WORKSPACE_CAP, e)
    }
    fn take_pl(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        take_text(d, WORKSPACE_CAP)?
            .map(|s| {
                d.slots::<u8>(s.len())?;
                Ok(PathBuf::from(s))
            })
            .transpose()
    }
    fn verify_pl(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        take_text(d, WORKSPACE_CAP).map(|_| ())
    }
    fn shape_pl(s: &mut Shape) {
        s.push("Option<PathBuf>;utf8;max_bytes=4096");
    }
}

#[cfg(test)]
mod tests;
