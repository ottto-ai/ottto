//! Recovery nonce introduction uses the existing catalogue migration path.
use super::super::*;

/// [format] An older catalogue may lack the nonce; saving introduces it, while
/// a missing nonce row in the current catalogue remains checkpoint damage.
#[test]
fn recovery_nonce_defaults_previous_layouts_and_persists_on_upgrade() {
    let home = crate::test_scratch::canonical_private_dir("copy-prefix-nonce-layout");
    for previous_layout in [1_u32, 2] {
        let path = home.join(format!("layout-{previous_layout}.v2.sqlite.import"));
        let mut db = money_test_support::populate(&path, &ScanIndex::default(), BTreeMap::new());
        let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
        let nonce_key = mapper::key("setting.copy_prefix_last_accepted_nonce", "", 0).unwrap();
        sqlite::delete_row_for_test(&db, &nonce_key);
        sqlite::delete_row_for_test(&db, &RowKey::Meta("catalogue_layout".into()));
        db.control("catalogue_layout", &previous_layout).unwrap();
        let (mut restored, mut cx) = kinds::hydrate(&mut db, identity.binding.clone()).unwrap();
        assert!(restored.copy_prefix_last_accepted_nonce.is_none());
        assert!(restored.copy_prefix_recovery_scope.is_empty());
        assert_eq!(cx.layout, previous_layout);
        let baseline = kinds::baseline(&restored, &mut cx).unwrap();
        restored.copy_prefix_last_accepted_nonce = Some("accepted-recovery".into());
        kinds::save_graph(&mut db, &identity, baseline, &mut restored, &mut cx).unwrap();
        drop(db);
        let mut db = sqlite::Sqlite::open(&path, &identity).unwrap();
        let (reopened, cx) = kinds::hydrate(&mut db, identity.binding.clone()).unwrap();
        assert_eq!(cx.layout, super::LAYOUT);
        assert_eq!(
            reopened.copy_prefix_last_accepted_nonce.as_deref(),
            Some("accepted-recovery")
        );
        sqlite::delete_row_for_test(&db, &nonce_key);
        assert!(kinds::hydrate(&mut db, identity.binding.clone()).is_err());
    }
    std::fs::remove_dir_all(home).unwrap();
}
