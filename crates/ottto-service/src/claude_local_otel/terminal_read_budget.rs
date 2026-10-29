// One allowance shared by every baseline API/trace read in a terminal attempt,
// including strict rereads and prepared-evidence fallbacks. Never persisted.
use std::cell::Cell;
use std::io::{self, Read};

#[derive(Clone, Copy)]
struct State {
    left: u64,
    read: u64,
    exceeded: bool,
}
thread_local! {
    static BUDGET: Cell<Option<State>> = const { Cell::new(None) };
    #[cfg(test)]
    static LAST_READ: Cell<u64> = const { Cell::new(0) };
}

pub(crate) struct TerminalReadBudget(Option<State>);
impl TerminalReadBudget {
    pub(crate) fn begin(bytes: u64) -> Self {
        Self(BUDGET.with(|slot| {
            slot.replace(Some(State {
                left: bytes,
                read: 0,
                exceeded: false,
            }))
        }))
    }
    pub(crate) fn exceeded(&self) -> bool {
        BUDGET.with(|slot| slot.get().is_some_and(|state| state.exceeded))
    }
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> u64 {
        BUDGET.with(|slot| slot.get().map_or(0, |state| state.read))
    }
}
impl Drop for TerminalReadBudget {
    fn drop(&mut self) {
        #[cfg(test)]
        LAST_READ.with(|last| last.set(self.bytes()));
        BUDGET.with(|slot| slot.set(self.0));
    }
}

pub(super) fn refuse_oversized_input() {
    BUDGET.with(|slot| {
        if let Some(mut state) = slot.get() {
            state.exceeded = true;
            slot.set(Some(state));
        }
    });
}
#[cfg(test)]
pub(super) fn last_read_bytes_for_test() -> u64 {
    LAST_READ.with(Cell::get)
}

pub(super) struct EvidenceReader<R>(pub(super) R);
impl<R: Read> Read for EvidenceReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let allowance = BUDGET.with(|slot| slot.get().map(|state| state.left));
        let limit = allowance.map_or(output.len(), |left| output.len().min(left as usize));
        if limit == 0 {
            BUDGET.with(|slot| {
                if let Some(mut state) = slot.get() {
                    state.exceeded = true;
                    slot.set(Some(state));
                }
            });
            return Err(io::Error::other(
                "terminal evidence byte allowance exceeded",
            ));
        }
        let read = self.0.read(&mut output[..limit])?;
        BUDGET.with(|slot| {
            if let Some(mut state) = slot.get() {
                state.left -= read as u64;
                state.read += read as u64;
                slot.set(Some(state));
            }
        });
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_and_trace_share_one_physical_byte_allowance() {
        let dir = std::env::temp_dir().join(format!(
            "ottto-shared-terminal-bytes-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let (api, trace) = super::super::terminal_sidecar_paths_for_test(&dir, "shared");
        std::fs::create_dir_all(api.parent().unwrap()).unwrap();
        std::fs::create_dir_all(trace.parent().unwrap()).unwrap();
        std::fs::write(api, b"\n\n\n\n\n\n\n\n").unwrap();
        std::fs::write(trace, b"\n\n\n\n\n\n\n\n").unwrap();
        let budget = TerminalReadBudget::begin(12);
        let _api = super::super::ClaudeApiEvidenceRead::load(&dir, ["shared".to_owned()]).unwrap();
        assert_eq!(budget.bytes(), 8);
        let trace = super::super::load_claude_trace_ownership_evidence(&dir, ["shared".to_owned()]);
        assert_eq!(budget.bytes(), 12);
        assert!(budget.exceeded());
        assert!(trace.unreadable_lines > 0);
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
#[test]
fn refused_terminal_allowance_does_not_poison_ordinary_page_enrichment() {
    let dir = std::env::temp_dir().join(format!(
        "ottto-terminal-budget-drop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (api, _) = super::terminal_sidecar_paths_for_test(&dir, "live");
    std::fs::create_dir_all(api.parent().unwrap()).unwrap();
    let row = super::ClaudeLocalOtelEvidence {
        session_id: "live".into(),
        request_id: "req_live".into(),
        ..Default::default()
    };
    std::fs::write(api, serde_json::to_vec(&row).unwrap()).unwrap();
    {
        let budget = TerminalReadBudget::begin(4);
        let _ = super::ClaudeApiEvidenceRead::load(&dir, ["live".to_owned()]);
        assert!(budget.exceeded());
    }
    let ordinary = super::ClaudeApiEvidenceRead::load(&dir, ["live".to_owned()]).unwrap();
    assert_eq!(ordinary.evidence["live"].len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}
