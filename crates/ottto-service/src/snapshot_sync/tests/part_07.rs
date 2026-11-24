mod history_upgrade_pipeline_tests {
    include!("history_upgrade_pipeline_tests.rs");
    mod first_read_latch_tests {
        include!("../first_read_latch_tests.rs");
    }
}
pub(in crate::snapshot_sync) mod claude_money_e2_pipeline_tests {
    include!("../claude_money_e2_pipeline_tests.rs");
    mod telemetry_only_oracle_tests {
        include!("../telemetry_only/oracle_tests.rs");
    }
    #[cfg(unix)]
    mod privacy_flip_money_tests {
        include!("privacy_flip_money_tests.rs");
    }
    #[cfg(unix)]
    mod claude_first_request_login_tests {
        include!("claude_first_request_login_tests.rs");
        mod first_read_latch_money_tests {
            include!("first_read_latch_money_tests.rs");
        }
    }
    #[cfg(unix)]
    mod claude_login_only_org_tests {
        include!("claude_login_only_org_tests.rs");
    }
    #[cfg(unix)]
    mod accepted_identity_cap_tests {
        include!("accepted_identity_cap_tests.rs");
    }
    #[cfg(unix)]
    mod claude_org_line_money_tests {
        include!("claude_org_line_money_tests.rs");
    }
    #[cfg(unix)]
    mod claude_telemetry_retention_tests {
        include!("claude_telemetry_retention_tests.rs");
    }
    mod scoped_cross_root_tests {
        include!("scoped_cross_root_tests.rs");
    }
}
mod p12_pipeline_original_tests {
    include!("p12_pipeline_original_tests.rs");
}
