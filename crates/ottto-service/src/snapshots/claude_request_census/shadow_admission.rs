//! Phase-B-only resource admission. The calibration fixture includes old/new
//! checkpoints, decode, retained safety, view construction and comparison.
use super::*;

pub(super) const ADDITIONAL_PEAK_CAP: usize = 128 * 1024 * 1024;
const PPM: usize = 1_000_000;
/// Conservative calibration ceiling, not a claimed measurement. CI measures
/// absolute estimator error on the admitted 1,024-file reference and requires
/// it to fit this allowance before the estimator may ship. Production applies
/// at least that measured error to both fixed caps, with checked ceil rounding.
pub(super) const ERROR_ALLOWANCE_PPM: usize = 500_000;

#[derive(Debug, Clone, Copy)]
pub(super) enum Refusal {
    Workspace,
    AdditionalPeak,
    EstimateUnavailable,
}
impl Refusal {
    #[cfg(test)]
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Workspace => "workspace_with_error_margin",
            Self::AdditionalPeak => "additional_peak_with_error_margin",
            Self::EstimateUnavailable => "estimate_unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Admission {
    pub(super) workspace_estimate: usize,
    pub(super) additional_estimate: usize,
}
impl Admission {
    pub(super) fn estimate(index: &ScanIndex, workspace: Option<usize>) -> Self {
        // Three serialized inventory equivalents reserve the checkpoint buffer,
        // normalized decode buffer and decoded evidence. Old/working copies
        // share immutable hash buffers; they are not extra encoded copies. The independent
        // layout estimate additionally reserves join/view workspace. Calibration
        // checks this model against the complete allocator scope, not just join.
        let additional = workspace.and_then(|workspace| {
            checked_serialized_len(index)?
                .checked_mul(3)?
                .checked_add(workspace)
        });
        Self::from_estimates(workspace, additional)
    }

    fn from_estimates(workspace: Option<usize>, additional: Option<usize>) -> Self {
        Self {
            workspace_estimate: workspace.unwrap_or(usize::MAX),
            additional_estimate: additional.unwrap_or(usize::MAX),
        }
    }
    pub(super) fn effective_workspace(self) -> usize {
        with_error_allowance(self.workspace_estimate).unwrap_or(usize::MAX)
    }
    pub(super) fn effective_additional(self) -> usize {
        with_error_allowance(self.additional_estimate).unwrap_or(usize::MAX)
    }
    pub(super) fn refused_by(self) -> Option<Refusal> {
        match (self.effective_workspace(), self.effective_additional()) {
            (usize::MAX, _) | (_, usize::MAX) => Some(Refusal::EstimateUnavailable),
            (workspace, _) if workspace > MAX_SHADOW_WORKSPACE_BYTES => Some(Refusal::Workspace),
            (_, additional) if additional > ADDITIONAL_PEAK_CAP => Some(Refusal::AdditionalPeak),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(super) fn refusal_receipt(self) -> (&'static str, usize, usize) {
        match self.refused_by() {
            Some(Refusal::Workspace) => (
                Refusal::Workspace.name(),
                MAX_SHADOW_WORKSPACE_BYTES,
                self.effective_workspace(),
            ),
            Some(Refusal::AdditionalPeak) => (
                Refusal::AdditionalPeak.name(),
                ADDITIONAL_PEAK_CAP,
                self.effective_additional(),
            ),
            Some(Refusal::EstimateUnavailable) => {
                (Refusal::EstimateUnavailable.name(), 0, usize::MAX)
            }
            None => ("none", ADDITIONAL_PEAK_CAP, self.effective_additional()),
        }
    }
}

pub(super) fn workspace_fits(estimate: usize) -> bool {
    with_error_allowance(estimate).is_some_and(|bound| bound <= MAX_SHADOW_WORKSPACE_BYTES)
}

fn with_error_allowance(estimate: usize) -> Option<usize> {
    let adjusted = (estimate as u128)
        .checked_mul((PPM + ERROR_ALLOWANCE_PPM) as u128)?
        .checked_add((PPM - 1) as u128)?
        / PPM as u128;
    usize::try_from(adjusted).ok()
}
fn checked_serialized_len(index: &ScanIndex) -> Option<usize> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("shadow estimate overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, index).ok()?;
    Some(count.0)
}

#[cfg(test)]
pub(super) fn measured_error_ppm(estimate: usize, actual: usize) -> usize {
    if estimate == 0 {
        return usize::MAX;
    }
    let error = (estimate.abs_diff(actual) as u128 * PPM as u128).div_ceil(estimate as u128);
    usize::try_from(error).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_below_cap_is_refused_when_error_adjusted_bound_exceeds_cap() {
        let raw_peak = ADDITIONAL_PEAK_CAP - 1;
        let admission = Admission::from_estimates(Some(1), Some(raw_peak));
        assert!(matches!(
            admission.refused_by(),
            Some(Refusal::AdditionalPeak)
        ));
        assert!(admission.effective_additional() > ADDITIONAL_PEAK_CAP);
        let workspace = Admission::from_estimates(Some(MAX_SHADOW_WORKSPACE_BYTES - 1), Some(1));
        assert!(matches!(workspace.refused_by(), Some(Refusal::Workspace)));
        assert!(workspace.effective_workspace() > MAX_SHADOW_WORKSPACE_BYTES);
    }
    #[test]
    fn admission_rounds_up_and_refuses_missing_or_overflowed_estimates() {
        assert_eq!(with_error_allowance(1), Some(2));
        let edge = ADDITIONAL_PEAK_CAP * 2 / 3;
        assert!(Admission::from_estimates(Some(1), Some(edge))
            .refused_by()
            .is_none());
        assert!(matches!(
            Admission::from_estimates(Some(1), Some(edge + 1)).refused_by(),
            Some(Refusal::AdditionalPeak)
        ));
        for estimates in [
            (None, Some(1)),
            (Some(1), None),
            (Some(1), Some(usize::MAX)),
        ] {
            assert!(matches!(
                Admission::from_estimates(estimates.0, estimates.1).refused_by(),
                Some(Refusal::EstimateUnavailable)
            ));
        }
    }
}
