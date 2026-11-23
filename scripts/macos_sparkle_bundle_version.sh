#!/usr/bin/env bash

# Convert formula-safe release-candidate display versions into the prerelease
# form Sparkle's standard version comparator orders monotonically. Sparkle 2.9.2
# considers hyphenated X.Y.Z-rcN versions equal, while X.Y.ZfcN preserves
# rc1 < rc2 < X.Y.Z and keeps the user-facing version unchanged.
ottto_sparkle_bundle_version() {
  local display_version="${1:?display version is required}"

  if [[ "$display_version" =~ ^([0-9]+([.][0-9]+){1,3})-rc([0-9]+)$ ]]; then
    printf '%sfc%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}"
  else
    printf '%s\n' "$display_version"
  fi
}
