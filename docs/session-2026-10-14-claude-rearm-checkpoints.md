# Reparse debt across partial snapshot checkpoints

A scan may deliberately clear a file's source fingerprint when census or duplicate evidence requires another parse. A later partial upload checkpoint can retain the old accepted file entry. Retaining that entry must not restore a cleared fingerprint and silently cancel the outstanding parse.

`ScanIndex::committable_subset` now carries an explicit empty source fingerprint into a retained entry. The previously accepted entity fingerprint, body witness, file metadata and receipt ledger still follow the existing settlement rules. The change cannot accept a held revision, publish a deletion or clear a duplicate fence.

Regression coverage checks a held revision through serialization and verifies that an unchanged rearmed file remains selected after a sibling is held. A control preserves the normal old checkpoint when no rearm was requested.

This repairs checkpoint correctness. It does not by itself resolve repeated Claude census work or establish lower CPU or memory use. Census convergence and rendering performance need separate validation.
