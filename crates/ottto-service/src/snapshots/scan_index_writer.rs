//! N+1 publication, held behind the installed-reader release gate.
use super::*;
use scan_index_persistence::{
    BucketMap, Field, Fragments, GcBudget, GcCursor, LoadedRoot, LockedStore, Slot,
};

// Release owner flips only after integrated N is published AND installed with
// a successful save. No version/installation proof is invented by this PR.
pub(super) const ENABLED: bool = false;
// The fixed reserve funds descriptors, streamed JSON buffers, GC reachability
// and the three inline bucket range tables, within the shared parked budget.
const FIXED_SCRATCH: usize = 4 * 1024 * 1024;
const GC_ENTRIES: usize = 2048;
const GC_BYTES: u64 = 16 * 1024 * 1024 * 1024;

struct Plan<'a> {
    index: &'a ScanIndex,
    account: BucketMap<'a, lenient_decode::PersistenceValue<'a, ClaudeAccountFamilyPending>>,
    usage: BucketMap<'a, lenient_decode::PersistenceValue<'a, ClaudeUsageFamilyPending>>,
    census: BucketMap<'a, &'a claude_request_census::ClaudeRequestCensusRecord>,
}
impl<'a> Plan<'a> {
    fn new(index: &'a ScanIndex) -> Result<Self> {
        index.require_persistence_available()?;
        let mut budget = crate::source_rotation::PARKED_BUDGET
            .checked_sub(FIXED_SCRATCH)
            .ok_or_else(|| anyhow::anyhow!("scan_index_writer_admission"))?;
        Ok(Self {
            index,
            account: lenient_decode::persistence_buckets(
                &index.claude_account_family_pending,
                index,
                "claude_account_family_pending",
                &mut budget,
            )?,
            usage: lenient_decode::persistence_buckets(
                &index.claude_usage_family_pending,
                index,
                "claude_usage_family_pending",
                &mut budget,
            )?,
            census: BucketMap::new(
                index.claude_request_census.persistence_entries(),
                &mut budget,
            )?,
        })
    }
}
impl Fragments for Plan<'_> {
    fn slots(&self) -> Vec<Slot> {
        let mut slots = vec![Slot::Metadata];
        slots.extend(self.account.buckets().map(|bucket| Slot::Bucket {
            field: Field::AccountPending,
            bucket,
        }));
        slots.extend(self.usage.buckets().map(|bucket| Slot::Bucket {
            field: Field::UsagePending,
            bucket,
        }));
        slots.extend(self.census.buckets().map(|bucket| Slot::Bucket {
            field: Field::RequestCensus,
            bucket,
        }));
        slots
    }
    fn write(&self, slot: Slot, out: &mut dyn Write) -> Result<()> {
        let pretty = !self.index.decode_holds.is_empty();
        match slot {
            Slot::Metadata => lenient_decode::write_persistence_metadata(out, self.index),
            Slot::Bucket {
                field: Field::AccountPending,
                bucket,
            } => self.account.write(bucket, pretty, out),
            Slot::Bucket {
                field: Field::UsagePending,
                bucket,
            } => self.usage.write(bucket, pretty, out),
            Slot::Bucket {
                field: Field::RequestCensus,
                bucket,
            } => self.census.write(bucket, pretty, out),
        }
    }
    fn minimum_logical_bytes(&self, _: u64) -> Result<u64> {
        if self.index.decode_holds.is_empty() {
            Ok(0)
        } else {
            Ok(lenient_decode::written_len(self.index)?)
        }
    }
}

pub(super) fn publish(
    store: &LockedStore,
    expected: &LoadedRoot,
    index: &ScanIndex,
) -> Result<LoadedRoot> {
    index.require_persistence_available()?;
    // Existing opaque per-record legacy debt cannot migrate into a falsely
    // complete map. Keep its existing representation until it can validate.
    if [
        Field::AccountPending,
        Field::UsagePending,
        Field::RequestCensus,
    ]
    .into_iter()
    .any(|field| index.decode_holds.contains_field(field.name()))
    {
        return store.write_legacy(expected, index.generation, |out| {
            lenient_decode::write_index(out, index).map_err(Into::into)
        });
    }
    // Admission precedes optional GC and all payload staging. Insufficient
    // disk space is checked by commit against actual f_bavail, so incomplete
    // GC is never counted as free space or destructive cleanup authority.
    let plan = Plan::new(index)?;
    let committed = store.commit(expected, index.generation, &plan)?;
    let mut cursor = GcCursor::default();
    // One bounded cleanup pass per successful save. Failure/incomplete keeps
    // orphan state for a later boundary; it cannot invalidate a published root.
    let cleanup = store.collect(
        &committed.root,
        GcBudget {
            entries: GC_ENTRIES,
            bytes: GC_BYTES,
        },
        &mut cursor,
    );
    let (removed, bytes, incomplete) =
        cleanup.map_or((0, 0, true), |c| (c.removed, c.bytes, c.incomplete));
    crate::local_resource_diagnostics::traversal_point(
        "scan_index_write",
        "unattributed",
        &serde_json::json!({
            "written_bytes": committed.stats.written_bytes,
            "root_bytes": committed.stats.root_bytes,
            "written_objects": committed.stats.written_objects,
            "unchanged_objects": committed.stats.unchanged_objects,
            "gc_removed": removed, "gc_bytes": bytes, "gc_incomplete": incomplete,
        }),
    );
    Ok(committed.root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn admitted_writer_round_trip_uses_real_serializer_and_committed_generation() {
        let scratch = crate::test_scratch::private_dir("scanindex-writer-integration");
        let namespace = scratch.join("a".repeat(64));
        fs::create_dir(&namespace).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
        let path = namespace.join("claude_code-scan-index-v3.json");
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/scan_index/real-shaped-v1.json"
        ))
        .unwrap();
        fs::write(&path, serde_json::to_vec(&fixture["logical"]).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut index = ScanIndex::load(&path).unwrap();
        let (binding, expected) = index.persistence_root.clone().unwrap();
        let store = LockedStore::new(&path, binding, lenient_decode::FIELDS).unwrap();
        let old_generation = index.generation;
        index.generation += 1;
        let wire = serde_json::to_vec(&index).unwrap();
        let committed = publish(&store, &expected, &index).unwrap();
        assert_eq!(committed.generation(), Some(old_generation + 1));
        let raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["schema_version"], 3);
        for field in [
            Field::AccountPending,
            Field::UsagePending,
            Field::RequestCensus,
        ] {
            assert!(raw.get(field.name()).is_none());
        }
        let restored = ScanIndex::load(&path).unwrap();
        assert!(restored.persistence_available());
        assert_eq!(serde_json::to_vec(&restored).unwrap(), wire);
        assert_eq!(restored.generation, index.generation);
        // No malformed or unavailable baseline can reach payload/GC authority.
        let before = fs::read(&path).unwrap();
        index.persistence_unavailable[0] = Some(scan_index_persistence::MapUnavailable {
            map: Field::AccountPending,
            cause: scan_index_persistence::UnavailableCause::Decode,
        });
        assert!(publish(&store, &committed, &index).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(scratch).unwrap();
    }
}
