//! Test-only daemon state setup methods.
//! Supplies injected source presence and state replacement for integration tests.
//! Called by the root daemon tests and local-control tests.

#[cfg(test)]
use crate::preserve_blocking_verification_state;
#[cfg(test)]
use crate::source_health::seed_registered_sources_with_presence;
#[cfg(test)]
use crate::LocalApiError;
use crate::LocalDaemon;
#[cfg(test)]
use ottto_core::LocalDeviceBinding;
#[cfg(test)]
use ottto_protocol::AuthResetResponse;
#[cfg(test)]
use ottto_protocol::SourceHealth;
#[cfg(test)]
use ottto_protocol::SourceKind;

impl LocalDaemon {
    /// Test-only variant of [`Self::with_registered_device_sources`] that injects
    /// the local-presence probe so each state (present / not-present) is
    /// deterministic regardless of what is installed on the machine running the
    /// tests.
    #[cfg(test)]
    pub(crate) fn with_registered_device_sources_presence(
        self,
        device: Option<LocalDeviceBinding>,
        present: impl Fn(&SourceKind) -> bool,
    ) -> Self {
        if let Ok(mut state) = self.inner.lock() {
            seed_registered_sources_with_presence(&mut state, device.as_ref(), present);
        }
        self
    }

    #[cfg(test)]
    pub fn reset_account_for_trusted_client(&self) -> Result<AuthResetResponse, LocalApiError> {
        self.reset_account_for_authorized_client()
    }

    #[cfg(test)]
    pub fn update_sources(
        &self,
        token: &str,
        mut sources: Vec<SourceHealth>,
    ) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        let mut state = self.state()?;
        for refreshed in &mut sources {
            if let Some(existing) = state
                .sources
                .iter()
                .find(|health| health.source == refreshed.source)
            {
                preserve_blocking_verification_state(refreshed, existing);
            }
        }
        state.sources = sources;
        Ok(())
    }
}
