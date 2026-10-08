# Stapling a launched app bundle

Two `0.1.155` stable release builds failed right after Apple accepted the app
notarization: `touch Ottto.app/Contents/CodeResources` returned "Operation not
permitted" even after clearing `com.apple.provenance`. The packaged-app launch
smoke had already run the bundle, so it carried `com.apple.macl`; once the
bundle is notarized, App Management refuses writes from processes without that
permission. `xcrun stapler staple` on the same bundle exits with error 73. Earlier
candidate builds passed the same step, so the refusal depends on timing.

`prepare_app_staple_target` now has a third step. If the placeholder still
cannot be created, it replaces the bundle with `ditto --noextattr --noacl` copy
that was never launched. The copy keeps the signature, which lives in the
bundle's files, and the swap is checked with `codesign --verify --strict` before
stapling. Verified by hand on the refused bundle: the copy accepted the
placeholder, stapled, and verified.

`scripts/test_macos_notarize_filter.sh` covers both paths:
- a provenance-only refusal does not restage;
- a launched bundle is restaged before stapling and leaves no scratch bundles
  behind.
