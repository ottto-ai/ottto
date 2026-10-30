# Claude restore: debt-carrier regression mirror

The Linux test target rejected an unconditional dependency ignore combined with
an ignore generated on non-macOS targets. Keep the unconditional #876 dependency
ignore and remove the redundant platform attribute. This fixture stays ignored
on every platform until generic growth discovery is integrated; native-layout
gating must remain part of that integration when the dependency ignore is removed.

Mirror the reviewed missing-entry debt controls from the large-restore branch.
A verified same-context record must report AuditCarrier before entry-derived
binding checks; a foreign namespace must report NoEntry. Both arms use a
write-only source descriptor and require unchanged record bytes, no invented
membership, zero restores and zero held coordinates. This branch has six hold
coordinates, so the mirror asserts all six rather than the other branch's seven.

The production carrier check already precedes membership and expected-binding
construction. No production reorder is required here. Preserve current live
context binding, exact stored-generation clean-save accounting, and same-store
predecessor authorization in both debt-save branches. The existing missing,
reset, rearm and actual replacement assertions remain intact.

Validation remains static locally: pinned all-target Clippy and formatting.
Runtime tests belong to CI; the integration owner dispatches the new frozen head.
