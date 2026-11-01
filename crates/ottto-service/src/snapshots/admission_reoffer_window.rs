//! Q-W: an ordinary Claude retry hold keeps the scan window (default OFF).
//! Policy is pinned at first use, including absent/OFF markers.
super::terminal_off_policy::local_switch!(
    "claude_admission_reoffer_window_enabled",
    marker_enables = true,
    test_default = false
);

#[cfg(test)]
#[path = "admission_reoffer_window_tests.rs"]
mod tests;
