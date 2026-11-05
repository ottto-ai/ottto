//! Upload-context proof stamps move from the inline proof row to one row
//! per entity: a frozen release's inline stamps migrate on the next save.
use super::*;
// The production save, not the kinds tests' baseline-rebuilding wrapper.
use super::super::super::save_graph;

/// [regress] Each frozen release's inline upload-context stamps hydrate, and
/// the next save moves them to one row per entity at the current layout. The
/// reopened graph is equal, and one changed stamp writes one row more than an
/// unchanged save (controls write on every commit).
#[test]
fn upload_context_proof_stamps_split_and_migrate() {
    deep_stack(|| {
        for (path, layout) in RELEASES {
            proof_split_check(path, layout);
        }
    });
}
fn proof_split_check(path: &str, layout: u32) {
    let release: Release = serde_json::from_str(&read_fixture(path)).unwrap();
    let header = |rows: &[Row]| -> Json {
        let row = rows
            .iter()
            .find(|row| row.0 == "v1_field.upload_context_proof");
        serde_json::from_str(row.unwrap().3.get()).unwrap()
    };
    let inline = header(&release.rows)["entity_stamps"].clone();
    let count = inline.as_object().map_or(0, |stamps| stamps.len());
    assert!(count > 0, "{path}: inline stamps");
    let (scratch, db) = load(&release).unwrap();
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    db.finish_import().unwrap();
    let reopen = || {
        let path = scratch.0.join("index.v2.sqlite.import");
        let mut db = sqlite::Sqlite::open(&path, &identity).unwrap();
        db.path_extractor(private_paths);
        db.reference_extractor(references);
        db
    };
    let mut db = reopen();
    let (mut index, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, layout);
    let hydrated = serde_json::to_value(&index.upload_context_proof.entity_stamps).unwrap();
    assert_eq!(hydrated, inline, "{path}");
    let previous = baseline(&index, &mut cx).unwrap();
    save_graph(&mut db, &identity, previous, &mut index, &mut cx).unwrap();
    drop(db);
    let mut db = reopen();
    let (mut reopened, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.layout, catalogue::LAYOUT);
    assert_eq!(
        serde_json::to_vec(&reopened).unwrap(),
        serde_json::to_vec(&index).unwrap()
    );
    let rows = dump(&mut db).unwrap().rows;
    assert!(header(&rows).get("entity_stamps").is_none(), "{path}");
    let stamps: Vec<_> = rows
        .iter()
        .filter(|row| row.0 == "proof.upload_context")
        .collect();
    assert_eq!(stamps.len(), count + 1, "{path}: manifest and members");
    assert_eq!((stamps[0].2, stamps[0].3.get()), (0, &*count.to_string()));
    let mut previous = baseline(&reopened, &mut cx).unwrap();
    let mut writes = Vec::new();
    for change in [false, true] {
        if change {
            // A swap keeps every private string, so the existing erasure
            // bookkeeping adds no control row to the delta.
            let stamps = &mut reopened.upload_context_proof.entity_stamps;
            let stamp = stamps.values_mut().next().unwrap();
            std::mem::swap(&mut stamp.body_witness, &mut stamp.context_fingerprint);
        }
        let before = db.save_row_attempts().0;
        previous = save_graph(&mut db, &identity, previous, &mut reopened, &mut cx).unwrap();
        writes.push(db.save_row_attempts().0 - before);
    }
    assert_eq!(writes[1], writes[0] + 1, "{path}: one changed stamp row");
    let stamps = &mut reopened.upload_context_proof.entity_stamps; // [edge] add, remove, clear
    let stamp = stamps.values().next().cloned().unwrap();
    stamps.insert("~".into(), stamp);
    for left in [count + 1, count, 0] {
        let stamps = &mut reopened.upload_context_proof.entity_stamps;
        stamps.retain(|key, _| left > count || left > 0 && key != "~");
        save_graph(&mut db, &identity, previous, &mut reopened, &mut cx).unwrap();
        let want = serde_json::to_vec(&reopened).unwrap();
        drop(db);
        db = reopen();
        (reopened, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
        assert_eq!(serde_json::to_vec(&reopened).unwrap(), want, "{path}");
        previous = baseline(&reopened, &mut cx).unwrap();
        let mut rows = dump(&mut db).unwrap().rows;
        assert!(header(&rows).is_object(), "{path}: header kept");
        rows.retain(|row| row.0 == "proof.upload_context");
        assert_eq!(rows[0].3.get(), left.to_string(), "{path}: manifest");
        assert_eq!(rows.len(), left + 1, "{path}: manifest and members");
        assert_eq!(rows.iter().any(|row| row.1 == "~"), left > count);
    }
}
