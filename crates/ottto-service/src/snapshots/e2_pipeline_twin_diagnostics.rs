//! Opt-in, thread-local diagnostics for the synthetic forced-twin rows.
//! Paths identify roles internally and are never included in the dump.
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Trace {
    arm: String,
    round: String,
    owner: &'static str,
    roles: BTreeMap<PathBuf, &'static str>,
    events: Vec<String>,
}
thread_local! {
    static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
}

pub(crate) struct DumpOnPanic;
impl Drop for DumpOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", context());
        }
        TRACE.with(|slot| *slot.borrow_mut() = None);
    }
}

pub(crate) fn begin(arm: &str) -> DumpOnPanic {
    TRACE.with(|slot| {
        *slot.borrow_mut() = Some(Trace {
            arm: arm.to_owned(),
            round: "setup".into(),
            owner: "RAM",
            ..Trace::default()
        });
    });
    DumpOnPanic
}

pub(crate) fn register(path: &Path, role: &'static str) {
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.roles.insert(path.to_owned(), role);
        }
    });
}

pub(crate) fn round(round: impl ToString) {
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.round = round.to_string();
            trace.events.clear();
        }
    });
}

pub(crate) fn owner(owner: &'static str) {
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            trace.owner = owner;
        }
    });
}

/// Format lazily: ordinary fixtures neither allocate nor retain trace events.
pub(crate) fn event(path: &Path, detail: impl FnOnce() -> String) {
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            let role = trace.roles.get(path).copied().unwrap_or("other");
            trace
                .events
                .push(format!("{} {role}: {}", trace.owner, detail()));
        }
    });
}

pub(crate) fn folds(items: &[SnapshotItem]) {
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            let members: Vec<_> = items
                .iter()
                .filter_map(|item| {
                    let location = item.claude_money.as_deref()?.location_key()?;
                    Some(
                        trace
                            .roles
                            .iter()
                            .find_map(|(path, role)| {
                                (claude_money_birth_store::location_key(&local_index_key(path))
                                    == location)
                                    .then_some(*role)
                            })
                            .unwrap_or("other"),
                    )
                })
                .collect();
            trace
                .events
                .push(format!("{} page folds={members:?}", trace.owner));
        }
    });
}

/// Inspect the actual emitted envelopes, rather than pre-upload counters.
pub(crate) fn emitted(owner: &'static str, wire: &[Vec<u8>]) {
    fn sessions(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(session) = fields.get("source_session_id") {
                    out.push(format!(
                        "session={session} request_count={} removed_request_count={}",
                        fields
                            .get("request_count")
                            .unwrap_or(&serde_json::Value::Null),
                        fields
                            .get("removed_request_count")
                            .unwrap_or(&serde_json::Value::Null),
                    ));
                } else {
                    for value in fields.values() {
                        sessions(value, out);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    sessions(value, out);
                }
            }
            _ => {}
        }
    }
    TRACE.with(|slot| {
        if let Some(trace) = slot.borrow_mut().as_mut() {
            let mut bodies = Vec::new();
            for body in wire {
                match serde_json::from_slice(body) {
                    Ok(value) => sessions(&value, &mut bodies),
                    Err(_) => bodies.push("undecodable envelope".into()),
                }
            }
            trace.events.push(format!("{owner} emitted={bodies:?}"));
        }
    });
}

pub(crate) fn context() -> String {
    TRACE.with(|slot| {
        slot.borrow().as_ref().map_or_else(String::new, |trace| {
            format!(
                "twin arm={} round={} owner/mode={}\n{}",
                trace.arm,
                trace.round,
                trace.owner,
                trace.events.join("\n")
            )
        })
    })
}
