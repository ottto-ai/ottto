//! Bounded content-only extraction. Never invokes native usage/selector folds.
use super::*;
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::os::unix::fs::FileExt;

const CWD_CAP: usize = 4096;

/// The visitor checks BEFORE making an owned capture. Unknown fields use
/// serde's IgnoredAny; no Value or collection of unknown content is built.
#[derive(Default)]
struct Cwd(Option<String>);
impl<'de> Deserialize<'de> for Cwd {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Capture;
        impl<'de> serde::de::Visitor<'de> for Capture {
            type Value = Cwd;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded workspace text")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Cwd, E> {
                if s.len() > CWD_CAP {
                    return Err(E::custom("workspace capture cap"));
                }
                Ok(Cwd((!s.trim().is_empty()).then(|| s.trim().to_owned())))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Cwd, E> {
                Ok(Cwd::default())
            }
        }
        d.deserialize_str(Capture)
    }
}

#[derive(Default, Deserialize)]
struct Fields {
    #[serde(default)]
    cwd: Cwd,
}
#[derive(Default, Deserialize)]
struct Nested {
    #[serde(default)]
    payload: Fields,
}
#[derive(Deserialize)]
struct Row {
    #[serde(default)]
    cwd: Cwd,
    #[serde(default, rename = "projectPath")]
    project_path: Cwd,
    #[serde(default)]
    workspace: Cwd,
    #[serde(default)]
    payload: Fields,
    #[serde(default)]
    session_meta: Nested,
    #[serde(default)]
    turn_context: Nested,
    #[serde(default, rename = "type")]
    kind: Cwd,
}

impl Decoded {
    /// Enabled obligation class: workspace only. Other classes refuse before
    /// I/O, retaining the existing resource-growth fallback and all hash fences.
    pub(crate) fn content_charge(&self) -> Result<u64, RederiveUnfunded> {
        let r = &self.rederive;
        if r.first_prompt.is_some()
            || r.title.is_some()
            || r.agent_label.is_some()
            || r.session_start.is_some()
        {
            return Err(RederiveUnfunded);
        }
        if r.workspace.is_none() {
            return Ok(0);
        }
        let end = self.head_end().map_err(|_| RederiveUnfunded)?;
        // One exact head buffer; serde_json's string/key scratch grows by
        // reserve/push, at most the next doubling above the entire input.
        // Six cwd captures + kind (all <=4096), one temporary clone, and
        // fixed typed/deserializer/error frames. Captures are dropped before
        // the output is moved; count both anyway. No native accumulator.
        let scratch = end.checked_next_power_of_two().ok_or(RederiveUnfunded)?;
        end.checked_add(scratch.checked_mul(2).ok_or(RederiveUnfunded)?)
            .and_then(|n| {
                n.checked_add(
                    (8 * CWD_CAP
                        + size_of::<Row>()
                        + size_of::<serde_json::Deserializer<serde_json::de::SliceRead<'_>>>()
                        + size_of::<RederiveReceipt>()) as u64,
                )
            })
            .ok_or(RederiveUnfunded)
    }

    /// Caller already charged content_charge, before certificate/read/allocation.
    pub(crate) fn rederive_content(
        mut self,
        file: &File,
    ) -> Result<(CachedJsonlReduction, RederiveReceipt), Refuse> {
        let Some(want) = self.rederive.workspace else {
            return Ok((self.reduction, RederiveReceipt::default()));
        };
        let end = self.head_end()?;
        let mut head = vec![0; end as usize];
        let mut offset = 0;
        while offset < head.len() {
            let n = match file.read_at(&mut head[offset..], offset as u64) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => return Err(Refuse::NotRederivable("workspace_read")),
                Ok(n) => n,
            };
            sampled_scan::durable_tail::record_rederive_input(
                self.reduction.accumulator.source,
                n as u64,
            );
            offset += n;
        }
        if head.last() != Some(&b'\n') {
            return Err(Refuse::NotRederivable("workspace_line"));
        }
        // The native first-assignment mark names this exact row. Earlier rows
        // need no parsing or accumulation; the stored digest is mandatory.
        let start = head[..head.len() - 1]
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        let row: Row = serde_json::from_slice(&head[start..])
            .map_err(|_| Refuse::NotRederivable("workspace_capture"))?;
        let raw = match self.reduction.accumulator.source {
            SnapshotSource::ClaudeCode => row.cwd.0.or(row.project_path.0).or(row.workspace.0),
            SnapshotSource::Codex => {
                // Same precedence as apply_codex_envelope_line followed by
                // apply_codex_owned_line. Hash equality also excludes wrong
                // ownership/compaction candidates without granting authority.
                let meta = if row.kind.0.as_deref() == Some("session_meta") {
                    row.payload.cwd.0.clone()
                } else {
                    row.session_meta.payload.cwd.0
                };
                meta.or(row.turn_context.payload.cwd.0)
                    .or(row.payload.cwd.0)
                    .or(row.cwd.0)
            }
            SnapshotSource::Pi => return Err(Refuse::NotRederivable("workspace_source")),
        };
        let path = raw.map(PathBuf::from);
        let got = digest("ottto-dt-rederive:workspace:v1", |e| path.put(e))?;
        if got != want {
            return Err(Refuse::NotRederivable("workspace_digest"));
        }
        self.reduction.accumulator.workspace_path = path;
        Ok((
            self.reduction,
            RederiveReceipt {
                head_bytes: end,
                ..Default::default()
            },
        ))
    }
}
