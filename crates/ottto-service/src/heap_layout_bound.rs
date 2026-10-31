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
    #[cfg(test)]
    pub(crate) fn visits_for_test(&self) -> usize {
        self.visits
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
    /// True only for types proved to own no heap allocation. Unknown/custom
    /// types keep recursive traversal; never infer this from size or capacity.
    const INLINE_ONLY: bool = false;
    /// A summary stays valid without mutable access to this value.
    /// Externally mutable or opaque graphs must never opt in.
    const STABLE_HEAP: bool = false;
    fn stable_heap(&self) -> bool {
        Self::STABLE_HEAP
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()>;
    /// Completion-only composition. Each owned collection element has its own
    /// ordinary 4096-visit counter, after charging its container storage. Never
    /// call this whole-graph traversal in a parser's per-line budget check.
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.heap_bound(c)
    }
}
pub(crate) fn completed_bound<T: HeapLayoutBound>(value: &T, limit: usize) -> Option<usize> {
    if !layout_supported() {
        return None;
    }
    let mut c = Counter::new(limit);
    c.add(size_of_val(value))?;
    value.completed_heap_bound(&mut c)?;
    Some(c.bytes)
}
fn completed_elements<'a, T: HeapLayoutBound + 'a>(
    elements: impl Iterator<Item = &'a T>,
    c: &mut Counter,
) -> Option<()> {
    let mut bytes = 0usize;
    for value in elements {
        let remaining = c.limit.checked_sub(c.bytes)?.checked_sub(bytes)?;
        // The slot is already charged; only the element's heap is new here.
        let mut child = Counter::new(remaining);
        value.completed_heap_bound(&mut child)?;
        bytes = bytes.checked_add(child.bytes)?;
    }
    c.add(bytes)
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
    // Linux unit-test builds use the same std container layouts on the same
    // 64-bit toolchain, so PR checks run the shipped macOS path. Non-test
    // Linux builds keep refusing.
    (cfg!(target_os = "macos") || cfg!(all(test, target_os = "linux")))
        && cfg!(target_pointer_width = "64")
        && compiler_layout_supported(env!("OTTTO_SCAN_LAYOUT_RUSTC"))
}
fn compiler_layout_supported(compiler: &str) -> bool {
    // These exact versions have source-layout and native allocation coverage.
    // Refuse future compilers until their container assumptions are validated.
    compiler.starts_with("rustc 1.88.0 ") || compiler.starts_with("rustc 1.95.0 ")
}
macro_rules! scalar { ($($t:ty),*) => { $(impl HeapLayoutBound for $t {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
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
    serde::de::IgnoredAny,
    ()
);
impl HeapLayoutBound for String {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity())
    }
}
impl HeapLayoutBound for PathBuf {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Option<T> {
    fn stable_heap(&self) -> bool {
        self.as_ref().map_or(true, HeapLayoutBound::stable_heap)
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)?;
        if let Some(x) = self {
            x.heap_bound(c)?;
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)?;
        if let Some(x) = self {
            x.completed_heap_bound(c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for std::cell::OnceCell<T> {
    fn stable_heap(&self) -> bool {
        self.get().map_or(true, HeapLayoutBound::stable_heap)
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)?;
        if let Some(x) = self.get() {
            x.heap_bound(c)?;
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)?;
        if let Some(x) = self.get() {
            x.completed_heap_bound(c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Vec<T> {
    fn stable_heap(&self) -> bool {
        self.iter().all(HeapLayoutBound::stable_heap)
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity().checked_mul(size_of::<T>())?)?;
        if !T::INLINE_ONLY {
            for x in self {
                x.heap_bound(c)?;
            }
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity().checked_mul(size_of::<T>())?)?;
        if !T::INLINE_ONLY {
            // Uncharged zero-sized unknown entries cannot bound traversal work.
            if size_of::<T>() == 0 && !self.is_empty() {
                return None;
            }
            completed_elements(self.iter(), c)?;
        }
        Some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for VecDeque<T> {
    fn stable_heap(&self) -> bool {
        self.iter().all(HeapLayoutBound::stable_heap)
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity().checked_mul(size_of::<T>())?)?;
        if !T::INLINE_ONLY {
            for x in self {
                x.heap_bound(c)?;
            }
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.capacity().checked_mul(size_of::<T>())?)?;
        if !T::INLINE_ONLY {
            if size_of::<T>() == 0 && !self.is_empty() {
                return None;
            }
            completed_elements(self.iter(), c)?;
        }
        Some(())
    }
}
/// The bytes `tree_nodes` charges per entry: one full node (see there).
pub(crate) fn tree_node_bytes<K, V>() -> Option<usize> {
    256usize
        .checked_add(12 * size_of::<usize>())?
        .checked_add(11usize.checked_mul(size_of::<K>().checked_add(size_of::<V>())?)?)
}
pub(crate) fn tree_nodes<K, V>(len: usize, c: &mut Counter) -> Option<()> {
    // Rust1.88/1.95 B=6:11 key/value slots and12 edges. Charging one full node per
    // entry plus one root overcounts unused slots and internal/leaf grouping.
    // A zero-length map may retain its empty allocated root after removal.
    let node = tree_node_bytes::<K, V>()?;
    c.add(len.checked_add(1)?.checked_mul(node)?)
}
impl<K: HeapLayoutBound, V: HeapLayoutBound> HeapLayoutBound for BTreeMap<K, V> {
    fn stable_heap(&self) -> bool {
        self.iter().all(|(k, v)| k.stable_heap() && v.stable_heap())
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        tree_nodes::<K, V>(self.len(), c)?;
        for (k, v) in self {
            k.heap_bound(c)?;
            v.heap_bound(c)?;
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        tree_nodes::<K, V>(self.len(), c)?;
        completed_elements(self.keys(), c)?;
        completed_elements(self.values(), c)
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for BTreeSet<T> {
    fn stable_heap(&self) -> bool {
        self.iter().all(HeapLayoutBound::stable_heap)
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        tree_nodes::<T, ()>(self.len(), c)?;
        for x in self {
            x.heap_bound(c)?;
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        tree_nodes::<T, ()>(self.len(), c)?;
        completed_elements(self.iter(), c)
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Box<T> {
    fn stable_heap(&self) -> bool {
        (**self).stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(size_of::<T>().checked_add(align_of::<T>())?)?;
        (**self).heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(size_of::<T>().checked_add(align_of::<T>())?)?;
        (**self).completed_heap_bound(c)
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Arc<T> {
    fn stable_heap(&self) -> bool {
        (**self).stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(
            size_of::<T>()
                .checked_add(align_of::<T>())?
                .checked_add(2 * size_of::<usize>())?,
        )?;
        (**self).heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        // Shared payload expansion remains one ordinary bounded subgraph.
        // A mutable shared allocation cannot yield a stable completion charge.
        self.heap_bound(c)?;
        self.stable_heap().then_some(())
    }
}
impl<T: HeapLayoutBound> HeapLayoutBound for Mutex<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.try_lock().ok()?.heap_bound(c)
    }
    fn completed_heap_bound(&self, _: &mut Counter) -> Option<()> {
        None
    }
}
impl<T: HeapLayoutBound, const N: usize> HeapLayoutBound for [T; N] {
    fn stable_heap(&self) -> bool {
        self.iter().all(HeapLayoutBound::stable_heap)
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        for x in self {
            x.heap_bound(c)?;
        }
        Some(())
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        if T::INLINE_ONLY {
            return c.add(0);
        }
        if size_of::<T>() == 0 && N != 0 {
            return None;
        }
        completed_elements(self.iter(), c)
    }
}
impl<A: HeapLayoutBound, B: HeapLayoutBound> HeapLayoutBound for (A, B) {
    fn stable_heap(&self) -> bool {
        self.0.stable_heap() && self.1.stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.heap_bound(c)?;
        self.1.heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.completed_heap_bound(c)?;
        self.1.completed_heap_bound(c)
    }
}
impl<A: HeapLayoutBound, B: HeapLayoutBound, D: HeapLayoutBound> HeapLayoutBound for (A, B, D) {
    fn stable_heap(&self) -> bool {
        self.0.stable_heap() && self.1.stable_heap() && self.2.stable_heap()
    }
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.heap_bound(c)?;
        self.1.heap_bound(c)?;
        self.2.heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        self.0.completed_heap_bound(c)?;
        self.1.completed_heap_bound(c)?;
        self.2.completed_heap_bound(c)
    }
}
macro_rules! fields {
    ($t:ty; $($(#[$field_attr:meta])* $f:ident),* $(,)? $(; shared $($shared:ident),+)? ) => {
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            fn stable_heap(&self)->bool {
                // Shared daemon allocations are charged by SnapshotCycleOwner::retained_bound.
                // Their pointer is already included in the enclosing inline size.
                let Self { $($(#[$field_attr])* $f,)* $($($shared: _,)+)? } = self;
                let stable = true;
                $( $(#[$field_attr])* let stable = stable && crate::heap_layout_bound::HeapLayoutBound::stable_heap($f);)*
                stable
            }
            fn heap_bound(&self,c:&mut crate::heap_layout_bound::Counter)->Option<()> {
                // Exhaustive destructuring makes a newly added owned field a
                // compile error until admission accounts for it.
                // Shared daemon allocations are charged by SnapshotCycleOwner::retained_bound.
                // Their pointer is already included in the enclosing inline size.
                let Self { $($(#[$field_attr])* $f,)* $($($shared: _,)+)? } = self;
                $( $(#[$field_attr])* crate::heap_layout_bound::HeapLayoutBound::heap_bound($f,c)?;)*
                Some(())
            }
            fn completed_heap_bound(&self,c:&mut crate::heap_layout_bound::Counter)->Option<()> {
                // Shared daemon allocations are charged by SnapshotCycleOwner::retained_bound.
                // Their pointer is already included in the enclosing inline size.
                let Self { $($(#[$field_attr])* $f,)* $($($shared: _,)+)? } = self;
                $( $(#[$field_attr])* crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound($f,c)?;)*
                Some(())
            }
        }
    };
}
pub(crate) use fields;

// Inline fields are paid by their containing slot and own no allocation.
// Visit only owned heaps: scalar-by-scalar walks otherwise exhaust the
// native frame's 4096-visit guard even when the frame uses under 1 MiB.
// Destructuring is exhaustive; a field moved into the inline group must
// prove INLINE_ONLY before the walk can succeed. Byte/visit caps stay native.
macro_rules! split_fields {
    ($t:ty; inline: [$($inline:ident),*]; heap: [$($heap:ident),*]) => {
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            fn stable_heap(&self) -> bool {
                let Self { $($inline,)* $($heap,)* } = self;
                true $(&& crate::heap_layout_bound::HeapLayoutBound::stable_heap($inline))*
                    $(&& crate::heap_layout_bound::HeapLayoutBound::stable_heap($heap))*
            }
            fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                let Self { $($inline,)* $($heap,)* } = self;
                $(crate::heap_layout_bound::require_inline($inline)?;)*
                $(crate::heap_layout_bound::HeapLayoutBound::heap_bound($heap, c)?;)*
                Some(())
            }
            fn completed_heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                let Self { $($inline,)* $($heap,)* } = self;
                $(crate::heap_layout_bound::require_inline($inline)?;)*
                $(crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound($heap, c)?;)*
                Some(())
            }
        }
    };
}
#[inline(always)]
pub(crate) fn require_inline<T: crate::heap_layout_bound::HeapLayoutBound>(_: &T) -> Option<()> {
    T::INLINE_ONLY.then_some(())
}
pub(crate) use split_fields;

// Types proved to own no heap: one walker visit, no bytes, INLINE_ONLY.
// The literal is STABLE_HEAP, kept per type. `T { a, b }` keeps an
// exhaustive field guard: a new field is a compile error until accounted for.
macro_rules! no_heap {
    ($stable:literal; $($t:ty $({ $($f:ident),* $(,)? })?),+ $(,)?) => { $(
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            const INLINE_ONLY: bool = true;
            const STABLE_HEAP: bool = $stable;
            fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                $(let Self { $($f: _,)* } = self;)?
                c.add(0)
            }
        }
    )+ };
}
pub(crate) use no_heap;

// Enums whose variants own no heap: an exhaustive match, one visit, no bytes.
// INLINE_ONLY stays false; the literal is STABLE_HEAP, kept per type.
macro_rules! unit_enum {
    ($stable:literal; $($t:ty: $($v:ident $({ $($vf:tt)* })?)|+);+ $(;)?) => { $(
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            const STABLE_HEAP: bool = $stable;
            fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                match self {
                    $(Self::$v $({ $($vf)* })?)|+ => c.add(0),
                }
            }
        }
    )+ };
}
pub(crate) use unit_enum;

/// Peak bytes of a `Vec<T>` collected to `n` elements from a lower size hint
/// of 0: 4 slots doubling, so the last `4 * 2^k` plus the half beside it
/// during the last growth (the allocation probe's overlap). `None` on overflow.
pub(crate) fn pushed_vec_peak<T>(n: usize) -> Option<usize> {
    if n == 0 {
        return Some(0);
    }
    let last = n.checked_next_power_of_two()?.max(4);
    let slots = if last > 4 {
        last.checked_add(last / 2)?
    } else {
        last
    };
    slots.checked_mul(size_of::<T>())
}

impl HeapLayoutBound for &'static str {
    const STABLE_HEAP: bool = true;
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

crate::heap_layout_bound::fields!(ottto_protocol::AgentRuntimeDefaults; captured_at, provenance, machine_id, model, service_tier, speed_mode, fast_mode_enabled, priority_enabled, reasoning_effort, reasoning_effort_by_model, approval_policy, sandbox_mode, selector_context, selector_sources);

crate::heap_layout_bound::fields!(ottto_protocol::AgentStatusDiagnostic; code, severity, message, observed_at, retry_after, account_identifier_hash, organization_identifier_hash, account_label, scope);

crate::heap_layout_bound::unit_enum!(false;
    ottto_protocol::AgentDiagnosticScope: Source | Account | Organization;
    ottto_protocol::AgentDiagnosticSeverity: Info | Warning | Error;
    ottto_protocol::AgentStatusConfidence: High | Medium | Low | Unknown;
    ottto_protocol::AgentCapabilityStatus: Supported | Unsupported | Unknown;
    ottto_protocol::AgentContextCompleteness: FullPressure | WindowSizeOnly | Unavailable | Unknown;
    ottto_protocol::AgentContextState: Available | Unsupported | Unknown;
    ottto_protocol::CreditBalanceKind: UsageCredits | PlanCredits | SavedResets | OneTimeCredit
        | WorkspaceAllowance | Unknown;
    ottto_protocol::CreditGrantsState: Complete | Capped | Partial | Unavailable | NotSupported;
    ottto_protocol::CreditGrantsUnavailableCause: Reader;
    ottto_protocol::CreditGrantType: RateLimitReset | Credit | Unknown;
    ottto_protocol::CreditGrantStatus: Available | Redeeming | Redeemed | Paused | Unknown;
    ottto_protocol::AgentCreditBalanceUnit: Credits | Usd | Tokens | Resets | Unknown;
    ottto_protocol::AgentQuotaWindowFreshness: Fresh | Stale | Unsupported | Error | Unknown;
    ottto_protocol::AgentCreditBalanceStatus: Ok | Low | Exhausted | Unlimited | Unsupported | Stale
        | Error | Unknown;
    ottto_protocol::AgentQuotaWindowStatus: Ok | NearLimit | Exhausted | RateLimited | Unsupported
        | Stale | Error | Unknown;
    ottto_protocol::AgentQuotaWindowScope: Source | Account | Organization | Model | Unknown;
    ottto_protocol::ClaudeAccountAnchorHealthV1: Healthy | TemporarilyUnavailable
        | ReconnectRequired | Paused | AttentionRequired;
    ottto_protocol::ClaudeAccountAnchorDurabilityV1: Anchored | DefaultOnly | Unresolved;
    ottto_protocol::ClaudeQuotaAccessState: Full | Partial | TemporarilyUnavailable
        | ReconnectRequired | Paused | AttentionRequired;
    ottto_protocol::AgentLoginState: SignedIn | SignedOut | Unknown | Unsupported;
    ottto_protocol::AgentStatusCollectionMethod: AppServer | CliJson | CliText | ConfigFile
        | StatusLine | CommandProbe | ManualFallback | Unsupported;
    ottto_protocol::AgentStatusState: Available | Degraded | AuthRequired | NotInstalled
        | Unsupported | Error | Unknown;
    ottto_protocol::SourceKind: Codex | ClaudeCode | Pi;
    ottto_protocol::LocalAccountState: NotConnected | ClaimPending | ReattachRequired | Connected
        | ResetRequired | Error;
);

crate::heap_layout_bound::fields!(ottto_protocol::AgentStatusPlanObservation; desktop_recent_at, observed_at, evidence_method, source_session_id, provider, billing_provider, model_provider, billing_channel, auth_mode, gateway_provider, subscription_product, plan_type, account_label, account_id, organization_label, organization_id, account_identifier_hash, organization_identifier_hash, superseded_account_identifier_hash, superseded_organization_identifier_hash, credential_fingerprint_hash, billing_identity_evidence, billing_identity_confidence, confidence, is_current);

crate::heap_layout_bound::fields!(ottto_protocol::AgentCapabilityGap; capability, status, detail);

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextStatus; status, active_tokens, max_tokens, used_percent, remaining_tokens, source, recent_samples, observed_at, completeness, reason, posture);

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextPostureSummary; sessions_analyzed, window_days, typical_first_turn_tokens, peak_session_count, window_evidenced_session_count, deep_session_count, over_window_session_count, session_peaks, compaction_count, reread_tokens);

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextSessionPeak; peak_fill_tokens, context_window_tokens, peak_fill_percent, over_window);

crate::heap_layout_bound::fields!(ottto_protocol::AgentContextPressureSample; at, active_tokens, max_tokens, used_percent, remaining_tokens);

crate::heap_layout_bound::fields!(ottto_protocol::AgentCreditBalance; name, status, freshness, unit, account_label, account_identifier_hash, organization_identifier_hash, remaining, used, quota, unlimited, updated_at, currency, resets_at, used_percent, enabled, spend_control_reached, rate_limit_reached_type, limit_id, observed_at, expires_at, disabled_reason, grant_count, grants, grants_state, grants_observed_at, kind, title, next_expires_at, latest_granted_at, eligible, at_limit, ineligible_reason, cooldown_until, grants_unavailable_cause);

crate::heap_layout_bound::fields!(ottto_protocol::AgentCreditGrant; grant_key, grant_type, status, granted_at, starts_at, expires_at, resets_included, resets_left, clears, title, usable_now);

crate::heap_layout_bound::fields!(ottto_protocol::AgentModelStatus; active_model, default_model, provider, available_models, available_model_details, context_window_tokens);

crate::heap_layout_bound::fields!(ottto_protocol::AgentAvailableModelStatus; id, provider, model_provider, billing_provider, billing_channel, auth_mode, gateway_provider, subscription_product, source_category, account_identifier_hash, organization_identifier_hash, credential_fingerprint_hash, billing_identity_evidence, billing_identity_confidence, context_window_tokens, max_output_tokens, supports_thinking, supports_images);

crate::heap_layout_bound::fields!(ottto_protocol::AgentAccountStatus; login_state, provider, auth_method, email, account_id, organization_id, organization_label, plan_type, subscription_product, billing_channel, subscription_period_start, subscription_period_end, subscription_period_last_checked_at, account_identifier_hash, organization_identifier_hash, superseded_account_identifier_hash, superseded_organization_identifier_hash, credential_fingerprint_hash, billing_identity_evidence, claude_quota_access_state, claude_anchor_durability, claude_anchor_health, billing_identity_confidence, confidence);

impl<T: zeroize::Zeroize + HeapLayoutBound> HeapLayoutBound for zeroize::Zeroizing<T> {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        (**self).heap_bound(c)
    }
}
impl HeapLayoutBound for std::time::SystemTime {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(0)
    }
}

crate::heap_layout_bound::fields!(ottto_protocol::AgentQuotaWindow; name, scope, status, freshness, observed_at, model, account_label, account_identifier_hash, organization_identifier_hash, window_seconds, started_at, started_at_basis, resets_at, quota, remaining, used_percent, left_percent, limit_cents, used_cents, remaining_cents, group, severity, is_active, spend_control_reached, rate_limit_reached_type, limit_id);

#[cfg(test)]
mod sampled_scalar_buffer_tests {
    use super::*;
    #[test]
    fn sampled_completed_accounting_composes_one_diminishing_byte_budget() {
        if !layout_supported() {
            return;
        }
        let values = vec![String::from("owned"); 12000];
        assert!(bound(&values, 1024 * 1024).is_none());
        let expected = size_of_val(&values)
            + values.capacity() * size_of::<String>()
            + values.iter().map(String::capacity).sum::<usize>();
        assert_eq!(completed_bound(&values, expected), Some(expected));
        assert!(completed_bound(&values, expected - 1).is_none());
        let pair = vec![
            String::with_capacity(600_000),
            String::with_capacity(600_000),
        ];
        assert!(completed_bound(&pair, 1024 * 1024).is_none());
        let shared = Arc::new(Mutex::new(String::from("mutable")));
        assert!(completed_bound(&vec![shared.clone()], usize::MAX).is_none());
        assert!(completed_bound(&(shared, 1u64), usize::MAX).is_none());
        assert!(
            completed_bound(&Box::new(Mutex::new(String::from("mutable"))), usize::MAX).is_none()
        );
        assert!(completed_bound(&vec![serde_json::Value::Null], usize::MAX).is_none());
        struct UnknownZero;
        impl HeapLayoutBound for UnknownZero {
            fn heap_bound(&self, c: &mut Counter) -> Option<()> {
                c.add(0)
            }
        }
        assert!(completed_bound(&vec![UnknownZero], usize::MAX).is_none());
    }
    // Test-only enforcement: requiring coverage never changes runtime admission.
    fn require_layout_coverage(
        supported: bool,
        requirement: Option<&str>,
    ) -> Result<(), &'static str> {
        if requirement == Some("1") && !supported {
            Err("OTTTO_REQUIRE_LAYOUT=1 requires a validated native layout")
        } else {
            Ok(())
        }
    }

    #[test]
    fn layout_gate_coverage_receipt() {
        let supported = layout_supported();
        let requirement = std::env::var("OTTTO_REQUIRE_LAYOUT").ok();
        println!(
            "layout_gate_coverage_receipt: compiled_rustc={} layout_supported={} required_layout={}",
            env!("OTTTO_SCAN_LAYOUT_RUSTC"),
            supported,
            requirement.as_deref() == Some("1"),
        );
        require_layout_coverage(supported, requirement.as_deref()).unwrap();
    }

    #[test]
    fn required_layout_coverage_enforces_supported_and_unsupported_cases() {
        for requirement in [None, Some("0"), Some("1")] {
            assert!(require_layout_coverage(true, requirement).is_ok());
            assert_eq!(
                require_layout_coverage(false, requirement).is_err(),
                requirement == Some("1"),
            );
        }
    }

    #[test]
    fn sampled_release_compiler_allowlist_refuses_unvalidated_versions() {
        assert!(compiler_layout_supported(
            "rustc 1.88.0 (6b00bc388 2025-06-23)"
        ));
        assert!(compiler_layout_supported(
            "rustc 1.95.0 (59807616e 2026-04-14)"
        ));
        for compiler in [
            "",
            "rustc 1.95.1 (unknown)",
            "rustc 1.195.0 (unknown)",
            "rustc 1.95.0-nightly (unknown)",
            "rustc 1.97.0 (unknown)",
        ] {
            assert!(!compiler_layout_supported(compiler));
        }
    }
    #[test]
    fn sampled_release_layout_bounds_nested_requested_allocations() {
        if !layout_supported() {
            return;
        }
        for count in [0, 1, 12, 64, 256] {
            let (map, allocations) = crate::retry_allocation_probe::measure(|| {
                let mut map = BTreeMap::new();
                for i in 0..count {
                    let mut value = Vec::with_capacity(257);
                    value.extend_from_slice(&[0_u8; 129]);
                    let mut deque = VecDeque::with_capacity(4);
                    deque.push_back(Arc::new(Mutex::new(value)));
                    map.insert(format!("entry-{i}"), deque);
                }
                map
            });
            let measured = usize::try_from(allocations.requested_live).unwrap();
            let charged = bound(&map, 8 * 1024 * 1024).unwrap();
            assert!(
                charged >= measured,
                "count={count}, charged={charged}, requested={measured}"
            );
            assert!(bound(&map, charged - 1).is_none());
            let (mut cleared, allocations) = crate::retry_allocation_probe::measure(|| map.clone());
            let before = bound(&cleared, 8 * 1024 * 1024).unwrap();
            assert!(before >= usize::try_from(allocations.requested_live).unwrap());
            cleared.clear();
            assert!(bound(&cleared, 8 * 1024 * 1024).is_some());
        }
    }
    #[test]
    fn sampled_scalar_buffers_charge_capacity_without_per_byte_traversal() {
        if !layout_supported() {
            return;
        }
        let mut bytes = Vec::with_capacity(32 * 1024);
        bytes.extend_from_slice(&[0_u8; 8192]);
        assert_eq!(
            bound(&bytes, 64 * 1024),
            Some(size_of_val(&bytes) + bytes.capacity())
        );
        let exact_bytes = size_of_val(&bytes) + bytes.capacity();
        assert_eq!(bound(&bytes, exact_bytes), Some(exact_bytes));
        assert!(bound(&bytes, exact_bytes - 1).is_none());
        let mut deque = VecDeque::from(vec![1_u64; 8192]);
        for _ in 0..6000 {
            let value = deque.pop_front().unwrap();
            deque.push_back(value);
        }
        assert!(!deque.as_slices().1.is_empty());
        assert_eq!(
            bound(&deque, 128 * 1024),
            Some(size_of_val(&deque) + deque.capacity() * size_of::<u64>())
        );
    }
    #[test]
    fn sampled_unknown_elements_keep_recursive_visit_and_heap_checks() {
        if !layout_supported() {
            return;
        }
        struct UnknownInline;
        impl HeapLayoutBound for UnknownInline {
            fn heap_bound(&self, c: &mut Counter) -> Option<()> {
                c.add(0)
            }
        }
        let unknown = (0..4096).map(|_| UnknownInline).collect::<Vec<_>>();
        assert!(bound(&unknown, 1024 * 1024).is_none());
        assert!(bound(&serde_json::json!({"opaque": "raw"}), usize::MAX).is_none());
        assert!(bound(&vec![serde_json::Value::Null], usize::MAX).is_none());
        let nested = vec![String::from("owned"); 4096];
        assert!(bound(&nested, 1024 * 1024).is_none());
        let single = vec![String::with_capacity(8192)];
        let expected =
            size_of_val(&single) + single.capacity() * size_of::<String>() + single[0].capacity();
        assert_eq!(bound(&single, expected), Some(expected));
        assert!(bound(&single, expected - 1).is_none());
    }
}
