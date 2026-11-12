use crate::snapshots::*;

#[test]
fn relisting_interval_leaves_margin_in_the_alarm_window() {
    assert_eq!(LISTING_INTERVAL_SECONDS, 3 * 60 * 60);
    const { assert!(2 * LISTING_INTERVAL_SECONDS <= super::ALARM_AFTER) };
}
