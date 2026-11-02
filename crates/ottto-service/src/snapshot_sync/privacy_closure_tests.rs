//! The 32-policy delivery-context table. A new policy field changes every row.
use super::*;

const TABLE_SHA256: &str = "63085adbb1c3f81ff09bbd4c4309fda133944d97a22358c30336f97ab1ea9347";

#[test]
fn closure_table_covers_every_policy_and_is_pinned() {
    let contexts = all_upload_policies()
        .map(|policy| cycle_upload_context(policy, None, false))
        .collect::<Vec<_>>();
    assert_eq!(contexts.iter().collect::<BTreeSet<_>>().len(), 32);
    assert_eq!(
        format!("{:x}", Sha256::digest(contexts.join("\n"))),
        TABLE_SHA256
    );
}

#[test]
fn acquisition_context_ignores_policy_and_key_but_not_money_modes() {
    let plain = cycle_acquisition_context(false, false, false);
    assert_eq!(plain, cycle_acquisition_context(false, false, false));
    for changed in [
        cycle_acquisition_context(true, false, false),
        cycle_acquisition_context(false, true, false),
        cycle_acquisition_context(false, true, true),
    ] {
        assert_ne!(plain, changed);
    }
}
