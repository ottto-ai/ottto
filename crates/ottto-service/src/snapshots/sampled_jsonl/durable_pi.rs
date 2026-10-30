//! Pi's durable record body: the shared reduction with the usage ledger moved
//! out, `Rederive`, then one ledger section,
//! `varint 1 ‖ u64 LE length ‖ PiSection`. The section is body-internal: it
//! has no envelope field and no format number. `A_P` binds it through the
//! `ottto-dt-ext:pi-ledger:v1` domain and `PiSection`'s shape. Ledger keys and
//! occurrence digests are SOURCE option A `H` values (64-char lower hex).
//!
//! The section also carries the first prompt's wire outputs (SOURCE
//! 2026-10-30, Addendum 1): the values one upload actually sent, after the
//! upload policy, restored into the same upload fields at finish. Nothing else
//! may read them: not identity, grouping, dedupe, logs or diagnostics. They
//! live and die with the record, and its context binding ties them to the
//! upload policy and key they were captured under.
pub(in crate::snapshots) use super::pi_wire_stub::{current_hmac_key_epoch, HmacKeyEpoch};
use super::pi_wire_stub::{key_epoch_changed, PlText, WIRE_PROMPT_DOMAIN};
use super::*;
use crate::session_attribution::{FirstPromptWire, WireFact};

/// Response-id keys, not occurrences. Oversized ledgers refuse, never truncate.
pub(crate) const PI_LEDGER_MAX_KEYS: usize = 65_536;

/// The codec refusal class of a ledger over `PI_LEDGER_MAX_KEYS`.
pub(crate) const PI_LEDGER_CAP: &str = "pi_ledger_cap";

const SECTION_TAG: u64 = 1;

/// Cold titles keep at most 255 chars of at most 4 bytes each.
const TITLE_BOUND: usize = 4 * 255;
const PREFIX_LABEL_BOUND: usize =
    crate::session_attribution::MAX_SESSION_ATTRIBUTION_DISPLAY_LABEL_BYTES;
const SKILL_ID_BOUND: usize = crate::session_attribution::MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES;

/// What one upload sent for the first prompt and the title. A `None` field was
/// not uploaded: no such value existed, or its setting was off.
#[derive(Clone, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct PiWirePrompt {
    prefix_label: Option<PlText<PREFIX_LABEL_BOUND>>,
    template_id: Option<[u8; 32]>,
    skill_id: Option<PlText<SKILL_ID_BOUND>>,
    skill_label: Option<PlText<PREFIX_LABEL_BOUND>>,
    title: Option<PlText<TITLE_BOUND>>,
}
crate::heap_layout_bound::fields!(PiWirePrompt; prefix_label, template_id, skill_id, skill_label, title);
crate::durable_tail_codec::durable_struct!(PiWirePrompt {
    N prefix_label: Option<PlText<PREFIX_LABEL_BOUND>>,
    H template_id: Option<[u8; 32]>,
    N skill_id: Option<PlText<SKILL_ID_BOUND>>,
    N skill_label: Option<PlText<PREFIX_LABEL_BOUND>>,
    N title: Option<PlText<TITLE_BOUND>>,
});

impl std::fmt::Debug for PiWirePrompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PiWirePrompt(redacted)")
    }
}

/// `SnapshotAccumulator.pi_prompt`: the section's prompt fields while the
/// record's reduction is live. `wire` alone fills the first-prompt upload
/// fields of a restored copy, whose first-prompt material stays absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct PiPromptCarry {
    wire: Option<PiWirePrompt>,
    prompt_seen: bool,
    key_epoch: Option<HmacKeyEpoch>,
    not_uploaded: bool,
}
crate::heap_layout_bound::fields!(PiPromptCarry; wire, prompt_seen, key_epoch, not_uploaded);

struct PiSection {
    usage_keys: BTreeMap<String, PiUsageDedupState>,
    wire_prompt: Option<PiWirePrompt>,
    prompt_seen: bool,
    hmac_key_epoch: Option<HmacKeyEpoch>,
    not_uploaded: bool,
}
crate::durable_tail_codec::durable_struct!(borrowed PiSection {
    H usage_keys: BTreeMap<String, PiUsageDedupState>,
    N wire_prompt: Option<PiWirePrompt>,
    N prompt_seen: bool,
    H hmac_key_epoch: Option<HmacKeyEpoch>,
    N not_uploaded: bool,
});

/// What `A_P` adds after the shared shapes.
pub(super) fn shape_extension(shape: &mut Shape) {
    shape.push("ottto-dt-ext:pi-ledger:v1");
    PiSection::shape(shape);
}

/// The Pi body from the borrowed live parts, in `CachedJsonlReduction` field
/// order. The ledger leaves the shared body as the moved `E` field and is
/// written once, into the section, without a clone.
pub(in crate::snapshots) fn put_body(
    e: &mut Enc,
    acc: &SnapshotAccumulator,
    report: &JsonlReadReport,
    scalars: (usize, usize, bool),
    rederive: &Rederive,
) -> Result<(), Refuse> {
    if acc.source != SnapshotSource::Pi {
        return Err(Refuse::NotRederivable("SnapshotAccumulator.source"));
    }
    let keys = &acc.seen_pi_usage_keys;
    if keys.len() > PI_LEDGER_MAX_KEYS {
        // Not an E field: only this static class leaves the codec.
        return Err(Refuse::NonEmpty(PI_LEDGER_CAP));
    }
    e.with_pi_ledger(|e| {
        acc.put(e)?;
        report.put(e)?;
        scalars.0.put(e)?;
        scalars.1.put(e)?;
        scalars.2.put(e)
    })?;
    rederive.put(e)?;
    let carry = acc.pi_prompt.as_deref();
    let none = None;
    let wire = carry.map_or(&none, |carry| &carry.wire);
    let key_epoch = carry.and_then(|carry| carry.key_epoch);
    e.section(SECTION_TAG, |e| {
        PiSection::put_borrowed(
            e,
            keys,
            wire,
            &acc.pi_prompt_seen(),
            &key_epoch,
            &acc.pi_not_uploaded(),
        )
    })
}

/// Header-dispatched Pi verification row; the table admits only format 3.
pub(in crate::snapshots) fn verify(body: &[u8]) -> Result<(), Corrupt> {
    verify_body(&mut Dec::new(body))
}

/// Structural verification of a Pi body, without allocation.
pub(crate) fn verify_body(d: &mut Dec<'_>) -> Result<(), Corrupt> {
    d.require_section();
    CachedJsonlReduction::verify(d)?;
    Rederive::verify(d)?;
    d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        PiSection::verify(d)
    })?;
    d.refilled_section();
    d.ended()
}

/// Decodes a Pi body. The ledger refills the accumulator before the end check,
/// so a section that is absent, short, long or not refilled is corrupt.
pub(crate) fn take_body(d: &mut Dec<'_>) -> Result<Decoded, Corrupt> {
    d.require_section();
    let mut reduction = CachedJsonlReduction::take(d)?;
    let rederive = Rederive::take(d)?;
    if reduction.accumulator.source != SnapshotSource::Pi {
        return Err(Corrupt);
    }
    let section = take_section(d)?;
    reduction.accumulator.seen_pi_usage_keys = section.usage_keys;
    reduction.accumulator.pi_prompt =
        (section.prompt_seen || section.wire_prompt.is_some() || section.not_uploaded).then(|| {
            Box::new(PiPromptCarry {
                wire: section.wire_prompt,
                prompt_seen: section.prompt_seen,
                key_epoch: section.hmac_key_epoch,
                not_uploaded: section.not_uploaded,
            })
        });
    d.refilled_section();
    d.ended()?;
    Ok(Decoded {
        reduction,
        rederive,
    })
}

fn take_section(d: &mut Dec<'_>) -> Result<PiSection, Corrupt> {
    d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        PiSection::take(d)
    })
}

/// The key count, checked before the ledger allocates or charges anything.
fn ledger_bound(d: &Dec<'_>) -> Result<(), Corrupt> {
    (d.peek_len()? <= PI_LEDGER_MAX_KEYS)
        .then_some(())
        .ok_or(Corrupt)
}

/// The upload settings that gate the first-prompt fields, for one pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UploadGates {
    titles: bool,
    attribution: bool,
    labels: bool,
}
impl From<SnapshotUploadPolicy> for UploadGates {
    fn from(policy: SnapshotUploadPolicy) -> Self {
        Self {
            titles: policy.session_titles_enabled,
            attribution: policy.session_attribution_enabled,
            labels: policy.session_attribution_labels_enabled,
        }
    }
}

impl PiWirePrompt {
    /// The first-prompt fields of this set under `gates`, title aside.
    fn first_prompt_fields(&self, gates: UploadGates) -> Self {
        Self {
            prefix_label: self.prefix_label.clone().filter(|_| gates.labels),
            template_id: self.template_id,
            skill_id: self.skill_id.clone(),
            skill_label: self.skill_label.clone().filter(|_| gates.labels),
            title: None,
        }
    }

    /// The values `first_prompt_wire` produced, in their stored form. `None`
    /// when one does not fit: the set is stored whole or not at all.
    fn from_uploaded(uploaded: &FirstPromptWire) -> Option<Self> {
        let template = uploaded.template.as_ref();
        let skill = uploaded.slash_skill.as_ref();
        fn text<const CAP: usize>(value: Option<&String>) -> Option<Option<PlText<CAP>>> {
            match value {
                Some(value) => PlText::new(value).map(Some),
                None => Some(None),
            }
        }
        Some(Self {
            prefix_label: text(template.and_then(|fact| fact.label.as_ref()))?,
            template_id: match template {
                Some(fact) => Some(crate::session_attribution::opaque_hmac_bytes(&fact.value)?),
                None => None,
            },
            skill_id: text(skill.map(|fact| &fact.value))?,
            skill_label: text(skill.and_then(|fact| fact.label.as_ref()))?,
            title: None,
        })
    }

    fn uploaded(&self) -> FirstPromptWire {
        let label = |text: &Option<PlText<PREFIX_LABEL_BOUND>>| {
            text.as_ref().map(|text| text.wire().to_owned())
        };
        FirstPromptWire {
            template: self.template_id.map(|id| WireFact {
                value: crate::session_attribution::opaque_hmac_text(&id),
                label: label(&self.prefix_label),
            }),
            slash_skill: self.skill_id.as_ref().map(|id| WireFact {
                value: id.wire().to_owned(),
                label: label(&self.skill_label),
            }),
        }
    }
}

impl SnapshotAccumulator {
    /// No first-prompt or title value was uploaded under the known policy.
    pub(in crate::snapshots) fn pi_not_uploaded(&self) -> bool {
        self.pi_prompt
            .as_ref()
            .is_some_and(|carry| carry.not_uploaded)
    }

    /// Any prompt was assigned, here or before this copy was restored.
    pub(in crate::snapshots) fn pi_prompt_seen(&self) -> bool {
        self.first_prompt_material.is_some()
            || self.first_prompt_title.is_some()
            || self
                .pi_prompt
                .as_ref()
                .is_some_and(|carry| carry.prompt_seen)
    }

    /// `prompt_seen` freezes the first-prompt fields of a restored copy.
    pub(in crate::snapshots) fn pi_first_prompt_frozen(&self) -> bool {
        self.first_prompt_material.is_none()
            && self
                .pi_prompt
                .as_ref()
                .is_some_and(|carry| carry.prompt_seen)
    }

    /// The uploaded title a restored copy carries.
    pub(in crate::snapshots) fn pi_carried_title(&self) -> Option<&str> {
        let wire = self.pi_prompt.as_ref()?.wire.as_ref()?;
        wire.title.as_ref().map(|title| title.wire())
    }

    /// The carried first-prompt facts for finish. A copy that still holds its
    /// material derives them natively instead.
    pub(in crate::snapshots) fn pi_carried_first_prompt(&self) -> Option<FirstPromptWire> {
        if self.first_prompt_material.is_some() {
            return None;
        }
        Some(self.pi_prompt.as_ref()?.wire.as_ref()?.uploaded())
    }

    /// Fills the record's wire set from what this upload will send, after its
    /// policy: the same builders, truncation, redaction and encoding. Runs at
    /// read completion, before the retained copy is cloned from this state.
    /// Stores nothing when no field is uploaded, or when `gates` is unknown.
    pub(in crate::snapshots) fn capture_pi_wire_prompt(
        &mut self,
        context: Option<&crate::session_attribution::SessionAttributionContext>,
        gates: Option<UploadGates>,
    ) {
        if self.source != SnapshotSource::Pi {
            return;
        }
        let seen = self.pi_prompt_seen();
        let carried = self.pi_prompt.take();
        let context = context.filter(|_| gates.is_some_and(|gates| gates.attribution));
        let not_uploaded = gates.is_some_and(|gates| !gates.titles && !gates.attribution);
        let wire = gates.and_then(|gates| self.pi_wire_prompt(context, gates, carried.as_deref()));
        let key_epoch = current_hmac_key_epoch(context).filter(|_| wire.is_some());
        self.pi_prompt = seen.then(|| {
            Box::new(PiPromptCarry {
                wire,
                prompt_seen: seen,
                key_epoch,
                not_uploaded,
            })
        });
    }

    fn pi_wire_prompt(
        &self,
        context: Option<&crate::session_attribution::SessionAttributionContext>,
        gates: UploadGates,
        carried: Option<&PiPromptCarry>,
    ) -> Option<PiWirePrompt> {
        if carried.is_some_and(|carry| carry.not_uploaded) && self.first_prompt_material.is_none() {
            return None;
        }
        if !gates.titles && context.is_none() {
            return None;
        }
        let mut wire = match (self.first_prompt_material.as_deref(), carried) {
            (Some(material), _) => match context {
                Some(context) => {
                    let uploaded = context.first_prompt_wire(self.source, material)?;
                    PiWirePrompt::from_uploaded(&uploaded)?.first_prompt_fields(gates)
                }
                None => PiWirePrompt::default(),
            },
            (None, Some(carried)) => carried.wire.as_ref()?.first_prompt_fields(gates),
            (None, None) => PiWirePrompt::default(),
        };
        if gates.titles {
            let title = match (&self.title, &self.first_prompt_title) {
                (Some(title), _) => Some(title.clone()),
                // A prompt title that fallback would discard cannot freeze a
                // later prompt's assignment, so such a set is not carried.
                (None, Some(title)) => {
                    Some(normalize_display_title(title.clone(), "first_prompt")?)
                }
                (None, None) => carried
                    .and_then(|carried| carried.wire.as_ref()?.title.as_ref())
                    .map(|title| title.wire().to_owned()),
            };
            wire.title = match title {
                Some(title) => Some(PlText::new(&title)?),
                None => None,
            };
        }
        Some(wire)
    }
}

/// The digest a Pi record holds in place of the shared first-prompt digest
/// while it carries wire values, or `None` when the shared digest applies.
/// A seen prompt with neither its values nor its material could only restore
/// empty, so that copy refuses and stays with a Full.
pub(super) fn wire_obligation(acc: &SnapshotAccumulator) -> Result<Option<[u8; 32]>, Refuse> {
    if acc.source != SnapshotSource::Pi {
        return Ok(None);
    }
    match acc.pi_prompt.as_deref() {
        Some(PiPromptCarry {
            wire: Some(wire), ..
        }) => digest(WIRE_PROMPT_DOMAIN, |e| wire.put(e)).map(Some),
        Some(carry) if carry.not_uploaded => Ok(None),
        Some(_) if acc.first_prompt_material.is_none() && acc.first_prompt_title.is_none() => Err(
            Refuse::NotRederivable("SnapshotAccumulator.first_prompt_material"),
        ),
        _ => Ok(None),
    }
}

impl Decoded {
    /// Admits the carried wire values in place of a re-derivation, under the
    /// HMAC key they were made with. Anything else leaves the digest standing,
    /// so `content_charge` refuses into today's counted Full.
    pub(crate) fn settle_pi_wire_prompt(&mut self, current: Option<HmacKeyEpoch>) {
        let acc = &mut self.reduction.accumulator;
        let Some(carry) = acc.pi_prompt.as_deref_mut() else {
            return;
        };
        if carry.not_uploaded {
            self.rederive.first_prompt = None;
            self.rederive.title = None;
            return;
        }
        let Some(wire) = carry.wire.as_ref() else {
            return;
        };
        if key_epoch_changed(carry.key_epoch, current) {
            carry.wire = None;
            crate::local_resource_diagnostics::cache_lifecycle::record(
                crate::local_resource_diagnostics::cache_lifecycle::Event::PiUploadedLiteralKeyChanged,
            );
            return;
        }
        let matches = digest(WIRE_PROMPT_DOMAIN, |e| wire.put(e))
            .is_ok_and(|digest| self.rederive.first_prompt == Some(digest));
        if !matches {
            carry.wire = None;
            return;
        }
        // An explicit title is the set's own; a fallback title waits for finish.
        if acc.title_source.is_some() {
            acc.title = carry
                .wire
                .as_ref()
                .and_then(|wire| wire.title.as_ref())
                .map(|title| title.wire().to_owned());
        }
        self.rederive.first_prompt = None;
        self.rederive.title = None;
    }
}

/// What a stored body's literals say about a pass that has left its context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiteralVerdict {
    Keep,
    Purge,
    KeyChanged,
}

/// Reads the section's prompt fields only; the rest is walked, not built.
pub(crate) fn stored_literal_verdict(
    body: &[u8],
    gates: UploadGates,
    current: Option<HmacKeyEpoch>,
) -> Result<LiteralVerdict, Corrupt> {
    let mut d = Dec::new(body);
    d.require_section();
    CachedJsonlReduction::verify(&mut d)?;
    Rederive::verify(&mut d)?;
    let (wire, key_epoch) = d.section(SECTION_TAG, |d| {
        ledger_bound(d)?;
        <BTreeMap<String, PiUsageDedupState> as crate::durable_tail_codec::HDigest>::verify_h(d)?;
        let wire = <Option<PiWirePrompt> as Durable>::take(d)?;
        bool::verify(d)?;
        let key_epoch = <Option<HmacKeyEpoch> as crate::durable_tail_codec::HDigest>::take_h(d)?;
        bool::verify(d)?;
        Ok((wire, key_epoch))
    })?;
    d.refilled_section();
    d.ended()?;
    let Some(wire) = wire else {
        return Ok(LiteralVerdict::Keep);
    };
    let keyed = wire.template_id.is_some() || wire.skill_id.is_some();
    let labelled = wire.prefix_label.is_some() || wire.skill_label.is_some();
    Ok(
        if keyed && gates.attribution && key_epoch_changed(key_epoch, current) {
            LiteralVerdict::KeyChanged
        } else if (keyed && !gates.attribution)
            || (labelled && !gates.labels)
            || (wire.title.is_some() && !gates.titles)
        {
            LiteralVerdict::Purge
        } else {
            LiteralVerdict::Keep
        },
    )
}

#[cfg(test)]
#[path = "durable_pi_tests.rs"]
mod tests;
