//! The existing account-proof owner projects every root-sidecar dependency.
use super::*;
use crate::claude_local_otel::ClaudeLocalOtelEvidence;

pub(super) struct Projection<'a> {
    rows: &'a [ClaudeLocalOtelEvidence],
    pub(super) account_hash: Option<&'a str>,
    pub(super) evidence_request_count: u128,
}
impl<'a> Projection<'a> {
    pub(super) fn new(rows: &'a [ClaudeLocalOtelEvidence]) -> Self {
        Self {
            rows,
            account_hash: strict_claude_account_hash(rows),
            evidence_request_count: rows.iter().map(|row| u128::from(row.request_count)).sum(),
        }
    }
    pub(super) fn invalidates(&self, witness: &ClaudeAccountFamilyWitness) -> bool {
        self.account_hash != Some(witness.account_identifier_hash.as_str())
            || self.evidence_request_count != witness.evidence_request_count
    }
    pub(super) fn covers(&self, item: &SnapshotItem) -> bool {
        claude_account_evidence_covers_request_ids(item, self.rows)
    }
    pub(super) fn child_dependencies(
        &self,
        root: &str,
        identity: &claude_request_identity::ScanEvidence<'_>,
    ) -> Dependencies {
        let rows = self.rows;
        let accounts = rows
            .iter()
            .map(|row| {
                (
                    row.account_identity_checked,
                    row.account_identifier_hash.as_deref(),
                )
            })
            .collect::<BTreeSet<_>>();
        // An API observation without an unambiguous trace owner might belong
        // to this child. Keep it in the common dependency until ownership is
        // known; suppressing it would miss late identity for an existing id.
        let unowned = rows
            .iter()
            .filter(|row| {
                !matches!(
                    identity.owners.get(&(root, row.request_id.as_str())),
                    Some(Some(_))
                )
            })
            .collect::<Vec<_>>();
        let invalid_family = identity.requests.iter().any(|((session, _), row)| {
            *session == root && row.map_or(true, |row| !validate_claude_api_row(row, root))
        }) || identity.owners.iter().any(|((session, _), row)| {
            *session == root
                && row.map_or(true, |row| {
                    row.capture_revision != "claude_llm_request_ownership:v1"
                        || !claude_trace_evidence_fingerprint_is_valid(row)
                })
        });
        let common = sha256_hex(&[
            "claude_child_common_evidence:v1",
            &serde_json::to_string(&(
                accounts,
                &identity.memberships,
                unowned,
                invalid_family,
                identity.unhealthy_roots.contains(root),
            ))
            .expect("serializable extracted evidence"),
        ]);
        let mut by_member = BTreeMap::<String, Vec<_>>::new();
        for (&(session, request), owner) in &identity.owners {
            if session != root {
                continue;
            }
            let Some(owner) = owner else {
                continue;
            };
            let member = claude_trace_owner_session_id(root, &owner.agent_id);
            by_member.entry(member).or_default().push((
                request,
                match identity.requests.get(&(session, request)) {
                    Some(Some(row)) => vec![*row],
                    Some(None) => rows
                        .iter()
                        .filter(|row| row.request_id == request)
                        .collect(),
                    None => Vec::new(),
                },
                owner,
            ));
        }
        let members = by_member
            .into_iter()
            .map(|(member, rows)| {
                let digest = sha256_hex(&[
                    "claude_child_request_evidence:v1",
                    &serde_json::to_string(&rows).expect("serializable extracted requests"),
                ]);
                (member, digest)
            })
            .collect();
        Dependencies {
            common,
            members,
            // This is the SAME account/count input used by invalidates above.
            // Include it only for children relying on the legacy family proof.
            legacy: sha256_hex(&[
                "claude_family_account_dependency:v1",
                &serde_json::to_string(&(
                    self.account_hash,
                    self.evidence_request_count,
                    self.rows
                        .iter()
                        .map(|row| (row.request_id.as_str(), row.request_count))
                        .collect::<BTreeSet<_>>(),
                ))
                .expect("serializable account proof inputs"),
            ]),
        }
    }
}
#[derive(Default)]
pub(super) struct Dependencies {
    common: String,
    members: BTreeMap<String, String>,
    legacy: String,
}
impl Dependencies {
    pub(super) fn child_digest(&self, member: &str, uses_legacy: bool) -> String {
        sha256_hex(&[
            "claude_child_consumed_sidecars:v2",
            &self.common,
            self.members.get(member).map(String::as_str).unwrap_or(""),
            if uses_legacy { &self.legacy } else { "" },
        ])
    }
}
crate::heap_layout_bound::fields!(Dependencies; common, members, legacy);

// Process-local liveness hints belong to the account proof, never the digest cache.
#[derive(Clone, Debug, Default)]
pub(super) struct Reproof {
    window: String,
    roots: BTreeSet<String>,
}
crate::heap_layout_bound::fields!(Reproof; window, roots);
pub(super) fn reproof(index: &mut ScanIndex, window: &str, mut roots: BTreeSet<String>) {
    if roots.is_empty() {
        return;
    }
    let progress = index
        .claude_account_reproof
        .get_or_insert_with(Default::default);
    if progress.window != window {
        progress.window = window.to_owned();
        progress.roots.clear();
    }
    roots.retain(|root| progress.roots.insert(root.clone()));
    clear_members(index, &roots, |_, _| true, true);
}

/// Existing reproof and legacy-witness paths share this single clear operation.
pub(super) fn clear_members(
    index: &mut ScanIndex,
    roots: &BTreeSet<String>,
    eligible: impl Fn(&str, &str) -> bool,
    counted: bool,
) {
    for (key, entry) in &mut index.files {
        if claude_index_path_family_member(Path::new(key))
            .is_some_and(|(root, member)| roots.contains(&root) && eligible(&root, &member))
        {
            if counted {
                crate::local_resource_diagnostics::claude_reread::clear(
                    crate::local_resource_diagnostics::claude_reread::ClearSite::AccountReproof,
                    !entry.source_file_fingerprint.is_empty(),
                );
            }
            entry.source_file_fingerprint.clear();
        }
    }
}
