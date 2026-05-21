#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_manifest_check.sh"
BUNDLE_SCRIPT="$ROOT/scripts/public_repo_export_bundle.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_manifest() {
  local root="$1"
  python3 - "$root" <<'PY'
import datetime as _datetime
import hashlib
import json
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


records = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if not path.is_file():
        continue
    rel = path.relative_to(root).as_posix()
    if rel == "PUBLIC_EXPORT_MANIFEST.json":
        continue
    mode = stat.S_IMODE(path.stat().st_mode)
    records.append(
        {
            "path": rel,
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
            "mode": f"{mode:04o}",
            "executable": bool(mode & 0o111),
        }
    )
content_sha256 = hashlib.sha256(
    json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
).hexdigest()
manifest = {
    "schema_version": 1,
    "generated_by": "public_repo_export_bundle.sh",
    "generated_at": _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0).isoformat(),
    "source_commit": "0123456789abcdef",
    "candidate_file_count": 2,
    "output_file_count": len(records) + 1,
    "public_roots": ["README.md", "scripts/"],
    "rewrites_applied": {},
    "files": records,
    "content_sha256": content_sha256,
}
(root / "PUBLIC_EXPORT_MANIFEST.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

base="$tmp_dir/base"
mkdir -p "$base/scripts"
cat > "$base/README.md" <<'EOF'
# Public Manifest Fixture
EOF
cat > "$base/scripts/tool.sh" <<'EOF'
#!/usr/bin/env bash
echo ok
EOF
chmod +x "$base/scripts/tool.sh"
write_manifest "$base"
"$SCRIPT" --staged-output "$base" >/tmp/public-manifest-pass.out
grep -q "checked 2 file hash record" /tmp/public-manifest-pass.out

tampered="$tmp_dir/tampered"
cp -R "$base" "$tampered"
printf '\nchanged\n' >> "$tampered/README.md"
if "$SCRIPT" --staged-output "$tampered" >/tmp/public-manifest-tampered.out 2>&1; then
  echo "Expected tampered content to fail manifest check" >&2
  exit 1
fi
grep -q "manifest sha256 mismatch for README.md" /tmp/public-manifest-tampered.out

extra="$tmp_dir/extra"
cp -R "$base" "$extra"
printf 'extra\n' > "$extra/extra.txt"
if "$SCRIPT" --staged-output "$extra" >/tmp/public-manifest-extra.out 2>&1; then
  echo "Expected extra file to fail manifest check" >&2
  exit 1
fi
grep -q "manifest output_file_count does not match actual files" /tmp/public-manifest-extra.out

bad_digest="$tmp_dir/bad-digest"
cp -R "$base" "$bad_digest"
python3 - "$bad_digest/PUBLIC_EXPORT_MANIFEST.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
manifest = json.loads(path.read_text(encoding="utf-8"))
manifest["content_sha256"] = "0" * 64
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if "$SCRIPT" --staged-output "$bad_digest" >/tmp/public-manifest-digest.out 2>&1; then
  echo "Expected content_sha256 mismatch to fail manifest check" >&2
  exit 1
fi
grep -q "manifest content_sha256 mismatch" /tmp/public-manifest-digest.out

real_output="$tmp_dir/real-output"
"$BUNDLE_SCRIPT" --output-dir "$real_output" --force >/tmp/public-manifest-real-bundle.out
"$real_output/scripts/public_repo_manifest_check.sh" --staged-output "$real_output" >/tmp/public-manifest-real.out
grep -q "file hash record" /tmp/public-manifest-real.out

echo "public_repo_manifest_check tests passed"
