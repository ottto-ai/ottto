//! Borrowed projections let callers read compact custody fields without
//! materializing a census record or duplicating its unused bookkeeping fields.
use super::super::super::claude_request_census::{
    ClaudeFamilyMemo, ClaudeLedgerSweep, ClaudeRequestCensusRecord as Record,
    ClaudeTelemetryTailState,
};
use super::{Memo, Scalar, Sweep};
use std::sync::Arc;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Message {
    pub(super) revision: [u8; 32],
    pub(super) observed: u64,
    pub(super) hashes: Option<Arc<[u64]>>,
    pub(super) known: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    pub(super) revision: [u8; 32],
    pub(super) hashes: Option<Arc<[u64]>>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Value {
    Evidence(Box<Record>),
    Message(Message),
    Scalar(Scalar),
    Seen(Seen),
    Sweep(Sweep),
    Memo(Memo),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind<'a> {
    Evidence(&'a Record),
    Message(&'a Message),
    Scalar(&'a Scalar),
    Seen(&'a Seen),
    Sweep(&'a Sweep),
    Memo(&'a Memo),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordRef<'a> {
    kind: Kind<'a>,
}
impl<'a> From<&'a Record> for RecordRef<'a> {
    fn from(record: &'a Record) -> Self {
        Self {
            kind: Kind::Evidence(record),
        }
    }
}
impl<'a> From<&RecordRef<'a>> for RecordRef<'a> {
    fn from(record: &RecordRef<'a>) -> Self {
        *record
    }
}
impl<'a, 'b> From<&'b &'a Record> for RecordRef<'a> {
    fn from(record: &'b &'a Record) -> Self {
        Self::from(*record)
    }
}
impl Value {
    pub(super) fn from_record(key: &str, record: Record) -> Self {
        if key.starts_with("otel:") {
            return Self::Evidence(Box::new(record));
        }
        if key.starts_with("mh:") {
            return Self::Message(Message {
                revision: record.money_revision(),
                observed: record.window(),
                hashes: record.shared_request_hashes(),
                known: record.custody_is_current(),
            });
        }
        if let Some((cursor, start, sweep)) = record.sweep() {
            return Self::Sweep(Sweep {
                cursor: *cursor,
                start,
                complete: sweep.complete_through,
                debt: sweep.debt,
            });
        }
        if let Some((revision, memo)) = record.family_memo() {
            return Self::Memo(Memo {
                revision: *revision,
                observed: record.window(),
                requests: memo.removed_requests,
                tokens: memo.removed_tokens,
                snapshot: memo.snapshot,
                ambiguous: false,
            });
        }
        if key.starts_with("watch:r:") || key.starts_with("watch:m:") {
            return Self::Seen(Seen {
                revision: record.money_revision(),
                hashes: record.shared_request_hashes(),
            });
        }
        Self::Scalar(Scalar {
            revision: record.money_revision(),
            time: record.window(),
        })
    }
    pub(super) fn view(&self) -> RecordRef<'_> {
        RecordRef {
            kind: match self {
                Self::Evidence(v) => Kind::Evidence(v),
                Self::Message(v) => Kind::Message(v),
                Self::Scalar(v) => Kind::Scalar(v),
                Self::Seen(v) => Kind::Seen(v),
                Self::Sweep(v) => Kind::Sweep(v),
                Self::Memo(v) => Kind::Memo(v),
            },
        }
    }
    pub(super) fn into_record(self) -> Record {
        match self {
            Self::Evidence(record) => *record,
            other => other.view().to_owned_record(),
        }
    }
    pub(super) fn money_revision(&self) -> [u8; 32] {
        self.view().money_revision()
    }
    pub(super) fn window(&self) -> u64 {
        self.view().window()
    }
    pub(super) fn request_hashes(&self) -> &[u64] {
        self.view().request_hashes()
    }
    pub(super) fn sweep(&self) -> Option<(&[u8; 32], u64, ClaudeLedgerSweep)> {
        self.view().sweep()
    }
    pub(super) fn current_for(&self, fingerprint: &str) -> bool {
        self.view().current_for(fingerprint)
    }
}
impl<'a> RecordRef<'a> {
    pub(crate) fn money_revision(self) -> [u8; 32] {
        match self.kind {
            Kind::Evidence(v) => v.money_revision(),
            Kind::Message(v) => v.revision,
            Kind::Scalar(v) => v.revision,
            Kind::Seen(v) => v.revision,
            Kind::Sweep(v) => v.cursor,
            Kind::Memo(v) => v.revision,
        }
    }
    pub(crate) fn window(self) -> u64 {
        match self.kind {
            Kind::Evidence(v) => v.window(),
            Kind::Message(v) => v.observed,
            Kind::Scalar(v) => v.time,
            Kind::Seen(_) => 0,
            Kind::Sweep(v) => v.start,
            Kind::Memo(v) => v.observed,
        }
    }
    pub(crate) fn request_hashes(self) -> &'a [u64] {
        match self.kind {
            Kind::Evidence(v) => v.request_hashes(),
            Kind::Message(v) => v.hashes.as_deref().unwrap_or(&[]),
            Kind::Seen(v) => v.hashes.as_deref().unwrap_or(&[]),
            _ => &[],
        }
    }
    pub(crate) fn shared_request_hashes(self) -> Option<Arc<[u64]>> {
        match self.kind {
            Kind::Evidence(v) => v.shared_request_hashes(),
            Kind::Message(v) => v.hashes.clone(),
            Kind::Seen(v) => v.hashes.clone(),
            _ => None,
        }
    }
    pub(crate) fn facts(self) -> Option<&'a [u8]> {
        match self.kind {
            Kind::Evidence(v) => v.facts(),
            _ => None,
        }
    }
    pub(crate) fn tail(self) -> Option<&'a ClaudeTelemetryTailState> {
        match self.kind {
            Kind::Evidence(v) => v.tail(),
            _ => None,
        }
    }
    pub(crate) fn retired(self) -> Option<u64> {
        match self.kind {
            Kind::Evidence(v) => v.retired(),
            _ => None,
        }
    }
    pub(crate) fn over_budget(self) -> bool {
        match self.kind {
            Kind::Evidence(v) => v.over_budget(),
            Kind::Message(v) => !v.known,
            _ => false,
        }
    }
    pub(crate) fn is_birth_stub(self) -> bool {
        match self.kind {
            Kind::Evidence(v) => v.is_birth_stub(),
            _ => false,
        }
    }
    pub(crate) fn current_for(self, fingerprint: &str) -> bool {
        match self.kind {
            Kind::Evidence(v) => v.current_for(fingerprint),
            Kind::Message(v) => {
                v.known
                    && super::super::super::claude_request_census::decode_fingerprint(fingerprint)
                        == Some(v.revision)
            }
            _ => false,
        }
    }
    pub(crate) fn sweep(self) -> Option<(&'a [u8; 32], u64, ClaudeLedgerSweep)> {
        match self.kind {
            Kind::Sweep(v) => Some((
                &v.cursor,
                v.start,
                ClaudeLedgerSweep {
                    complete_through: v.complete,
                    debt: v.debt,
                },
            )),
            Kind::Evidence(v) => v.sweep(),
            _ => None,
        }
    }
    pub(crate) fn family_memo(self) -> Option<(&'a [u8; 32], ClaudeFamilyMemo)> {
        match self.kind {
            Kind::Memo(v) if !v.ambiguous => Some((
                &v.revision,
                ClaudeFamilyMemo {
                    removed_requests: v.requests,
                    removed_tokens: v.tokens,
                    snapshot: v.snapshot,
                },
            )),
            Kind::Evidence(v) => v.family_memo(),
            _ => None,
        }
    }
    pub(crate) fn money_watch(self, revision: [u8; 32]) -> Record {
        Record::custody_shared_watch(revision, self.shared_request_hashes())
    }
    pub(crate) fn matches(self, record: &Record) -> bool {
        match self.kind {
            Kind::Evidence(value) => value == record,
            Kind::Message(value) => {
                value.revision == record.money_revision()
                    && value.observed == record.window()
                    && value.known == record.custody_is_current()
                    && self.request_hashes() == record.request_hashes()
            }
            Kind::Scalar(value) => {
                value.revision == record.money_revision()
                    && value.time == record.window()
                    && record.request_hashes().is_empty()
                    && record.sweep().is_none()
                    && record.family_memo().is_none()
            }
            Kind::Seen(value) => {
                value.revision == record.money_revision()
                    && self.request_hashes() == record.request_hashes()
            }
            Kind::Sweep(value) => {
                record.sweep()
                    == Some((
                        &value.cursor,
                        value.start,
                        ClaudeLedgerSweep {
                            complete_through: value.complete,
                            debt: value.debt,
                        },
                    ))
            }
            Kind::Memo(value) => {
                !value.ambiguous
                    && record.family_memo()
                        == Some((
                            &value.revision,
                            ClaudeFamilyMemo {
                                removed_requests: value.requests,
                                removed_tokens: value.tokens,
                                snapshot: value.snapshot,
                            },
                        ))
                    && record.window() == value.observed
            }
        }
    }
    pub(crate) fn to_owned_record(self) -> Record {
        match self.kind {
            Kind::Evidence(record) => record.clone(),
            Kind::Message(value) => Record::custody_message(
                value.revision,
                value.observed,
                value.hashes.clone(),
                value.known,
            ),
            Kind::Scalar(value) => Record::money_debt(value.revision, value.time),
            Kind::Seen(value) => Record::custody_shared_watch(value.revision, value.hashes.clone()),
            Kind::Sweep(value) => Record::sweep_record(
                value.cursor,
                value.start,
                ClaudeLedgerSweep {
                    complete_through: value.complete,
                    debt: value.debt,
                },
            ),
            Kind::Memo(value) => Record::family_record(
                value.revision,
                value.observed,
                ClaudeFamilyMemo {
                    removed_requests: value.requests,
                    removed_tokens: value.tokens,
                    snapshot: value.snapshot,
                },
            ),
        }
    }
}
impl serde::Serialize for RecordRef<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.kind {
            Kind::Evidence(record) => serde::Serialize::serialize(record, s),
            _ => serde::Serialize::serialize(&self.to_owned_record(), s),
        }
    }
}
