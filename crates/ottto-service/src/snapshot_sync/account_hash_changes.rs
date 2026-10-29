//! Diagnostic baseline in the existing destination-scoped ACK ledger.
//! Unknown/evicted predecessors establish a baseline, never a guessed change.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SESSIONS: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(super) struct AcceptedAccounts(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for AcceptedAccounts {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Diagnostic damage must not invalidate billing ACKs or trigger replay.
        let value = Value::deserialize(d)?;
        let entries = value.as_object().into_iter().flat_map(|map| map.iter());
        Ok(Self(
            entries
                .filter_map(|(key, value)| {
                    let digest = value.as_str()?;
                    (super::is_snapshot_fingerprint(key) && super::is_snapshot_fingerprint(digest))
                        .then(|| (key.clone(), digest.to_string()))
                })
                .take(MAX_SESSIONS)
                .collect(),
        ))
    }
}

impl AcceptedAccounts {
    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Called only after a stored-body ACK, including count-only legacy ACKs.
    /// Compare the set of emitted usage account hashes (including unassigned
    /// rows and identity parts), independent of usage totals and row duplication.
    pub(super) fn record(&mut self, item: &Value) {
        let Some(session) = item.get("source_session_id").and_then(Value::as_str) else {
            return;
        };
        let rows = item["model_usage"].as_array().into_iter().flatten().chain(
            item["usage_buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|bucket| bucket["model_usage"].as_array().into_iter().flatten()),
        );
        let mut accounts = BTreeSet::new();
        for row in rows {
            let parts = row["identity_parts"].as_array();
            if let Some(parts) = parts.filter(|parts| !parts.is_empty()) {
                accounts.extend(
                    parts
                        .iter()
                        .map(|part| part["account_identifier_hash"].as_str()),
                );
            } else {
                accounts.insert(row["account_identifier_hash"].as_str());
            }
        }
        if accounts.is_empty() {
            return;
        }
        let key = super::cache_session_key(session);
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&accounts).expect("account hashes serialize"))
        );
        if self.0.get(&key).is_some_and(|previous| previous != &digest) {
            crate::local_resource_diagnostics::account_hash_changed(&key);
        }
        if !self.0.contains_key(&key) && self.0.len() >= MAX_SESSIONS {
            self.0.pop_first();
        }
        self.0.insert(key, digest);
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for AcceptedAccounts {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.0, c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(account: Option<&str>) -> Value {
        serde_json::json!({
            "source_session_id":"session",
            "model_usage":[{"account_identifier_hash":account,"input_tokens":10}],
            "usage_buckets":[]
        })
    }

    fn observed(f: impl FnOnce()) -> u64 {
        let (_, lines) = crate::local_resource_diagnostics::capture(|| {
            crate::local_resource_diagnostics::source_finish("claude_code", || {
                f();
                Ok(())
            })
            .unwrap();
        });
        assert_eq!(lines.len(), 1, "use only the existing finish emitter");
        assert_eq!(lines[0]["stage"], "source_finish");
        let counts = &lines[0]["counts"];
        assert_eq!(counts.as_object().unwrap().len(), 1);
        counts["account_hash_changed"].as_u64().unwrap()
    }

    #[test]
    fn acknowledged_accounts_survive_restart_and_count_changes_without_identifiers() {
        let mut accounts = AcceptedAccounts::default();
        assert_eq!(observed(|| accounts.record(&body(Some("account-a")))), 0);
        let saved = serde_json::to_vec(&accounts).unwrap();
        assert!(!String::from_utf8_lossy(&saved).contains("account-a"));
        accounts = serde_json::from_slice(&saved).unwrap();
        let mut same = body(Some("account-a"));
        same["model_usage"][0]["input_tokens"] = 99.into();
        same["usage_buckets"] = serde_json::json!([{"model_usage":same["model_usage"]}]);
        assert_eq!(observed(|| accounts.record(&same)), 0);
        assert_eq!(
            observed(|| {
                accounts.record(&body(Some("account-b")));
                accounts.record(&body(Some("account-c")));
                accounts.record(&body(Some("account-b")));
            }),
            1,
            "count sessions rather than revisions within a finish"
        );
        assert_eq!(observed(|| accounts.record(&body(Some("account-b")))), 0);
        assert_eq!(observed(|| accounts.record(&body(None))), 1);
        assert_eq!(observed(|| accounts.record(&body(Some("account-a")))), 1);
        let mut mixed = body(None);
        mixed["model_usage"][0]["identity_parts"] = serde_json::json!([
            {"account_identifier_hash":"account-a"},
            {"account_identifier_hash":"account-b"}
        ]);
        assert_eq!(observed(|| accounts.record(&mixed)), 1);
    }

    #[test]
    fn malformed_or_evicted_diagnostic_baseline_is_unknown_not_a_change() {
        for value in [serde_json::json!({"bad":"bad"}), Value::Null] {
            let accounts: AcceptedAccounts = serde_json::from_value(value).unwrap();
            assert!(accounts.is_empty());
        }
        let mut accounts = AcceptedAccounts::default();
        observed(|| {
            for n in 0..MAX_SESSIONS + 1 {
                let mut item = body(Some("account-a"));
                item["source_session_id"] = format!("session-{n}").into();
                accounts.record(&item);
            }
        });
        assert_eq!(accounts.0.len(), MAX_SESSIONS);
        let overfull = serde_json::json!((0..MAX_SESSIONS + 1)
            .map(|n| (format!("{n:064x}"), "a".repeat(64)))
            .collect::<BTreeMap<_, _>>());
        let restored: AcceptedAccounts = serde_json::from_value(overfull).unwrap();
        assert_eq!(restored.0.len(), MAX_SESSIONS);
    }
}
