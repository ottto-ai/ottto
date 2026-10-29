# Archive index downgrade compatibility

No released writer persisted archive evidence or its budget/correction fields.
The previous stable 0.1.201 decoder is pinned to main
7997fe740064273ffc145d2168c299f5d8b9ee3d; the R1 decoder is pinned to main
0061a4b0cd2bb71510e67586e949a0362609e6ee. Their ScanIndexEntry definitions,
owner deserializer and nested tier-receipt deserializer are identical. Neither
entry definition contains archive evidence or a compressed hold enum position.
They ignore the entire unknown archive object, including its new cause labels,
and retain the file/body/counting evidence they understand, as today.

Linux-running synthetic fixtures vendor that exact entry decode path with both
commit pins and source-span hashes. They serialize the branch's actual index,
decode every entry with the released types, retain all known entry fields and
incidence, then load the downgraded serialization through the current loader.
The compatibility harness preserves unrelated top-level fields opaquely; it does
not reproduce the entire historical runtime or its unrelated repair/GC paths.
No index reset or quarantine is expected. These fixtures require no native
funded decoder; execution is deferred to the authorized CI lane.

Downgrade keeps custody; new budget/correction state is lost; at most today's
behavior; re-upgrading grants nothing new (user_change_spent absent = MAX).
This does not promise preservation of the new read budget across rollback.
Unreleased intermediate writers that retained only some correction fields can
hold unresolved debt conservatively; they are not a released migration format.
No legacy policy-digest migration is required or provided. Parser identity is
not a downgrade marker and is never repurposed for this boundary.

If archive-aware index decoding ships in an earlier stable release, that release
becomes the compatibility target. Recheck its known hold labels before merge:
write only a label that decoder accepts as a hold and carry any newer precise
reason in an optional field it ignores. The two pinned readers above do not
need that mapping because they never decode an archive cause.
