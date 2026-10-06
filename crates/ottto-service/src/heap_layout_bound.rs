//! Checked requested-layout accounting for optional overlap of owned scan state.
//! Fixed container assumptions are admitted only on the validated toolchain.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem::{align_of, size_of, size_of_val};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub(crate) struct Counter {
    pub(crate) bytes: usize,
    limit: usize,
    visits: usize,
}
impl Counter {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: 0,
            limit,
            visits: 0,
        }
    }
    pub(crate) fn add(&mut self, bytes: usize) -> Option<()> {
        self.visits = self.visits.checked_add(1)?;
        if self.visits > 4096 {
            return None;
        }
        self.bytes = self.bytes.checked_add(bytes)?;
        (self.bytes <= self.limit).then_some(())
    }
}
pub(crate) trait HeapLayoutBound {
    fn heap_bound(&self, c: &mut Counter) -> Option<()>;
}
pub(crate) fn bound<T: HeapLayoutBound>(value: &T, limit: usize) -> Option<usize> {
    if !layout_supported() {
        return None;
    }
    let mut c = Counter::new(limit);
    c.add(size_of_val(value))?;
    value.heap_bound(&mut c)?;
    Some(c.bytes)
}
pub(crate) fn layout_supported() -> bool {
    cfg!(target_os = "macos")
        && cfg!(target_pointer_width = "64")
        && env!("OTTTO_SCAN_LAYOUT_RUSTC").starts_with("rustc 1.88.0 ")
}
macro_rules! scalar { ($($t:ty),*) => { $(impl HeapLayoutBound for $t {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> { c.add(0) }
})* }; }
scalar!(
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    i8,
    i16,
    i32,
    i64,
    i128,
    usize,
    isize,
    f32,
    f64,
    ()
);
impl HeapLayoutBound for String {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity())
    }
}
impl HeapLayoutBound for PathBuf {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Option<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)?;
        if let Some(x) = self {
            x.heap_bound(c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Vec<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity().checked_mul(size_of::<T>())?)?;
        for x in self {
            x.heap_bound(c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for VecDeque<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity().checked_mul(size_of::<T>())?)?;
        for x in self {
            x.heap_bound(c)?;
        }
        Some(())
    }
}
fn tree_nodes<K, V>(len: usize, c: &mut Counter) -> Option<()> {
    // Rust1.88 B=6:11 key/value slots and12 edges. Charging one full node per
    // entry plus one root overcounts unused slots and internal/leaf grouping.
    // A zero-length map may retain its empty allocated root after removal.
    let node = 256usize
        .checked_add(12 * size_of::<usize>())?
        .checked_add(11usize.checked_mul(size_of::<K>().checked_add(size_of::<V>())?)?)?;
    c.add(len.checked_add(1)?.checked_mul(node)?)
}
impl<K: HeapLayoutBound, V: HeapLayoutBound> HeapLayoutBound for BTreeMap<K, V> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        tree_nodes::<K, V>(self.len(), c)?;
        for (k, v) in self {
            k.heap_bound(c)?;
            v.heap_bound(c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for BTreeSet<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        tree_nodes::<T, ()>(self.len(), c)?;
        for x in self {
            x.heap_bound(c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Box<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(size_of::<T>().checked_add(align_of::<T>())?)?;
        (**self).heap_bound(c)
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Arc<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(
            size_of::<T>()
                .checked_add(align_of::<T>())?
                .checked_add(2 * size_of::<usize>())?,
        )?;
        (**self).heap_bound(c)
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Mutex<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.try_lock().ok()?.heap_bound(c)
    }
}
impl<T: HeapLayoutBound, const N: usize> HeapLayoutBound for [T; N] {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        for x in self {
            x.heap_bound(c)?;
        }
        Some(())
    }
}
impl<A: HeapLayoutBound, B: HeapLayoutBound> HeapLayoutBound for (A, B) {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.heap_bound(c)?;
        self.1.heap_bound(c)
    }
}
impl<A: HeapLayoutBound, B: HeapLayoutBound, D: HeapLayoutBound> HeapLayoutBound for (A, B, D) {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.heap_bound(c)?;
        self.1.heap_bound(c)?;
        self.2.heap_bound(c)
    }
}
macro_rules! fields {
    ($t:ty; $($(#[$field_attr:meta])* $f:ident),* $(,)?) => {
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            fn heap_bound(&self,c:&mut crate::heap_layout_bound::Counter)->Option<()> {
                // Exhaustive destructuring makes a newly added owned field a
                // compile error until admission accounts for it.
                let Self { $($(#[$field_attr])* $f),* } = self;
                $( $(#[$field_attr])* crate::heap_layout_bound::HeapLayoutBound::heap_bound($f,c)?;)*
                Some(())
            }
        }
    };
}
pub(crate) use fields;

impl HeapLayoutBound for &'static str {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}
impl HeapLayoutBound for serde_json::Value {
    // Existing Codex bootstrap rows and opaque cache graphs stay on the
    // synchronous path. Never park a raw row or guess a Value allocation bound.
    fn heap_bound(&self, _: &mut Counter) -> Option<()> {
        None
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentStatusSnapshot; source, status, collection_method, captured_at, expires_at, account, model, quota_windows, credit_balances, context, capabilities, plan_observations, diagnostics, runtime_defaults);

crate::heap_layout_bound::fields!(ottto_protocol::AgentRuntimeDefaults; captured_at, provenance, machine_id, model, service_tier, speed_mode, fast_mode_enabled, priority_enabled, reasoning_effort, approval_policy, sandbox_mode, selector_context, selector_sources);

crate::heap_layout_bound::fields!(ottto_protocol::AgentStatusDiagnostic; code, severity, message, observed_at, account_identifier_hash, organization_identifier_hash, account_label, scope);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentDiagnosticScope {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Source | Self::Account | Self::Organization => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentDiagnosticSeverity {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Info | Self::Warning | Self::Error => c.add(0),
        }
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentStatusPlanObservation; observed_at, evidence_method, source_session_id, provider, billing_provider, model_provider, billing_channel, auth_mode, gateway_provider, subscription_product, plan_type, account_label, account_id, organization_label, organization_id, account_identifier_hash, organization_identifier_hash, superseded_account_identifier_hash, superseded_organization_identifier_hash, credential_fingerprint_hash, billing_identity_evidence, billing_identity_confidence, confidence, is_current);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentStatusConfidence {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::High | Self::Medium | Self::Low | Self::Unknown => c.add(0),
        }
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentCapabilityGap; capability, status, detail);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentCapabilityStatus {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Supported | Self::Unsupported | Self::Unknown => c.add(0),
        }
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextStatus; status, active_tokens, max_tokens, used_percent, remaining_tokens, source, recent_samples, observed_at, completeness, reason, posture);

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextPostureSummary; sessions_analyzed, window_days, typical_first_turn_tokens, peak_session_count, window_evidenced_session_count, deep_session_count, over_window_session_count, session_peaks, compaction_count, reread_tokens);

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextSessionPeak; peak_fill_tokens, context_window_tokens, peak_fill_percent, over_window);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentContextCompleteness {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::FullPressure | Self::WindowSizeOnly | Self::Unavailable | Self::Unknown => {
                c.add(0)
            }
        }
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextPressureSample; at, active_tokens, max_tokens, used_percent, remaining_tokens);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentContextState {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Available | Self::Unsupported | Self::Unknown => c.add(0),
        }
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentCreditBalance; name, status, freshness, unit, account_label, account_identifier_hash, organization_identifier_hash, remaining, used, quota, unlimited, updated_at, currency, resets_at, used_percent, enabled, spend_control_reached, rate_limit_reached_type, limit_id);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentCreditBalanceUnit {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Credits | Self::Usd | Self::Tokens | Self::Resets | Self::Unknown => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentQuotaWindowFreshness {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Fresh | Self::Stale | Self::Unsupported | Self::Error | Self::Unknown => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentCreditBalanceStatus {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Ok
            | Self::Low
            | Self::Exhausted
            | Self::Unlimited
            | Self::Unsupported
            | Self::Stale
            | Self::Error
            | Self::Unknown => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentQuotaWindowStatus {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Ok
            | Self::NearLimit
            | Self::Exhausted
            | Self::RateLimited
            | Self::Unsupported
            | Self::Stale
            | Self::Error
            | Self::Unknown => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentQuotaWindowScope {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Source | Self::Account | Self::Organization | Self::Model | Self::Unknown => {
                c.add(0)
            }
        }
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentModelStatus; active_model, default_model, provider, available_models, available_model_details, context_window_tokens);

crate::heap_layout_bound::fields!(ottto_protocol::AgentAvailableModelStatus; id, provider, model_provider, billing_provider, billing_channel, auth_mode, gateway_provider, subscription_product, source_category, account_identifier_hash, organization_identifier_hash, credential_fingerprint_hash, billing_identity_evidence, billing_identity_confidence, context_window_tokens, max_output_tokens, supports_thinking, supports_images);

crate::heap_layout_bound::fields!(ottto_protocol::AgentAccountStatus; login_state, provider, auth_method, email, account_id, organization_id, organization_label, plan_type, subscription_product, billing_channel, subscription_period_start, subscription_period_end, subscription_period_last_checked_at, account_identifier_hash, organization_identifier_hash, superseded_account_identifier_hash, superseded_organization_identifier_hash, credential_fingerprint_hash, billing_identity_evidence, claude_quota_access_state, claude_anchor_durability, claude_anchor_health, billing_identity_confidence, confidence);

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::ClaudeAccountAnchorHealthV1 {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Healthy
            | Self::TemporarilyUnavailable
            | Self::ReconnectRequired
            | Self::Paused
            | Self::AttentionRequired => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::ClaudeAccountAnchorDurabilityV1 {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Anchored | Self::DefaultOnly | Self::Unresolved => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::ClaudeQuotaAccessState {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Full
            | Self::Partial
            | Self::TemporarilyUnavailable
            | Self::ReconnectRequired
            | Self::Paused
            | Self::AttentionRequired => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentLoginState {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::SignedIn | Self::SignedOut | Self::Unknown | Self::Unsupported => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentStatusCollectionMethod {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::AppServer
            | Self::CliJson
            | Self::CliText
            | Self::ConfigFile
            | Self::StatusLine
            | Self::CommandProbe
            | Self::ManualFallback
            | Self::Unsupported => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::AgentStatusState {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Available
            | Self::Degraded
            | Self::AuthRequired
            | Self::NotInstalled
            | Self::Unsupported
            | Self::Error
            | Self::Unknown => c.add(0),
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ottto_protocol::SourceKind {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Codex | Self::ClaudeCode | Self::Pi => c.add(0),
        }
    }
}

impl<T: zeroize::Zeroize + HeapLayoutBound> HeapLayoutBound for zeroize::Zeroizing<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        (**self).heap_bound(c)
    }
}
impl HeapLayoutBound for std::time::SystemTime {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentQuotaWindow; name, scope, status, freshness, observed_at, model, account_label, account_identifier_hash, organization_identifier_hash, window_seconds, started_at, started_at_basis, resets_at, quota, remaining, used_percent, left_percent, limit_cents, used_cents, remaining_cents, group, severity, is_active, spend_control_reached, rate_limit_reached_type, limit_id);

impl HeapLayoutBound for ottto_protocol::LocalAccountState {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        match self {
            Self::NotConnected
            | Self::ClaimPending
            | Self::ReattachRequired
            | Self::Connected
            | Self::ResetRequired
            | Self::Error => c.add(0),
        }
    }
}
