#!/usr/bin/env python3
"""Release privacy gate for the macOS stable release files.

The policy value, marker list grammar, roles, scan response, exit codes and
receipt are specified in docs/release-verification.md ("Release Privacy
Gate"). Run with `python3 -I`. Diagnostics name only fixed stages, roles,
classes, error codes and counts; never a marker, an excerpt or a raw path.
"""

import argparse
import ctypes
import ctypes.util
import hashlib
import html
import json
import os
import plistlib
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = ".github/workflows/macos-stable-release.yml"
EXIT_CLEAN, EXIT_BLOCKED, EXIT_USAGE, EXIT_INCOMPLETE = 0, 1, 2, 3
CHUNK = 8 << 20
MAX_FILE = 1 << 30
MAX_MEMBER = 512 << 20
MAX_TEXT = 32 << 20
MAX_ENTRIES = 20000
MAX_DEPTH = 40
TOOL_TIMEOUT = 900
STORE_MAX = 48 << 10
DEFAULT_STORE = "~/.config/ottto/release-privacy-markers.txt.v3"
MARKERS_ENV = "OTTTO_PRIVACY_MARKERS"
POLICY_ENV = "OTTTO_RELEASE_PRIVACY_POLICY"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TOOLS = {
    "codesign": "/usr/bin/codesign",
    "hdiutil": "/usr/bin/hdiutil",
    "security": "/usr/bin/security",
    "scutil": "/usr/sbin/scutil",
    "bash": "/bin/bash",
    "git": "/usr/bin/git",
}
# Developer ID Application: Apple anchor, Developer ID intermediate and leaf.
DEVID_REQ = ("=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6]"
             " and certificate leaf[field.1.2.840.113635.100.6.1.13]")

ROLE_FILES = {
    "app_dmg": "Ottto-macos-arm64.dmg",
    "cli_zip": "ottto-macos-arm64.zip",
    "service_zip": "ottto-service-macos-arm64.zip",
    "sbom": "ottto-local-platform-sbom.cdx.json",
    "launch_smoke": "packaged-app-launch-smoke.json",
    "manifest": "release-manifest.json",
    "manifest_sig": "release-manifest.json.sig",
    "checksums": "subject.checksums.txt",
    "installer": "install-macos.sh",
    "formula": "homebrew/ottto.rb",
    "rc_evidence": "stable-candidate-rc-qa.json",
    "clean_machine_evidence": "stable-clean-machine-qa.json",
    "appcast": "appcast.xml",
    "privacy_receipt": "privacy-receipt.json",
    "app_notary_zip": "ottto-app-notary.zip",
    "app_bundle": "Ottto.app",
    "cli_binary": "ottto",
    "service_binary": "ottto-service",
}
JSON_ROLES = {"sbom", "launch_smoke", "manifest", "rc_evidence", "clean_machine_evidence", "privacy_receipt"}
ZIP_EXECUTABLES = {"cli_zip": "ottto", "service_zip": "ottto-service"}
PRODUCT_SLOTS = {"Contents/MacOS/Ottto", "Contents/Helpers/ottto", "Contents/Helpers/ottto-service"}
SPARKLE_DIR = "Contents/Frameworks/Sparkle.framework/"
CPU_ARM64, CPU_X86_64 = 0x0100000C, 0x01000007
ARCH_NAMES = {CPU_ARM64: "arm64", CPU_X86_64: "x86_64"}
ADVISORY_NAMES = {"provenance": "com.apple.provenance", "macl": "com.apple.macl"}
LANES = ("candidate", "stable", "manual")
PROFILES = ("unsigned", "notary", "attest", "upload", "publish", "dispatch", "logs")
DISPATCH_INPUTS = ("VERSION", "CHANNEL", "ARTIFACT_BASE_URL", "RELEASE_NOTES",
                   "RELEASE_MODE", "OPERATOR_APPROVAL", "PUBLISH_INTENT")
SEPARATORS = "/\0\r\n\"'"
MACHINE_NAME_LINE = re.compile(r"^(?:\S+\s+)?Machine name: '[^'\n]*'\s*$", re.M)


class GateError(Exception):
    """Usage, policy or marker list error: exit 2, nothing scanned."""


class Incomplete(Exception):
    """An input the gate cannot fully check."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def norm(text):
    return unicodedata.normalize("NFC", text.casefold())


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


class NoDuplicateDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise ValueError("duplicate key")
        super().__setitem__(key, value)


# ---------------------------------------------------------------- policy

class Policy:
    KEYS = {"version", "mode", "advisory_xattrs", "leaf_sha256", "markers_sha256",
            "accept_runner_machine_name_line"}

    def __init__(self, text):
        try:
            obj = json.loads(text, object_pairs_hook=no_duplicate_keys)
        except ValueError:
            raise GateError("policy_parse")
        if not isinstance(obj, dict):
            raise GateError("policy_parse")
        if set(obj) - self.KEYS:
            raise GateError("policy_unknown_key")
        if (self.KEYS - {"accept_runner_machine_name_line"}) - set(obj):
            raise GateError("policy_missing_key")
        if type(obj["version"]) is not int or obj["version"] != 1:
            raise GateError("policy_version")
        if obj["mode"] not in ("enforce", "rehearsal"):
            raise GateError("policy_mode")
        adv, leaf = obj["advisory_xattrs"], obj["leaf_sha256"]
        if (not isinstance(adv, list) or len(set(map(str, adv))) != len(adv)
                or not all(isinstance(a, str) and a in ADVISORY_NAMES for a in adv)):
            raise GateError("policy_advisory_xattrs")
        if (not isinstance(leaf, list) or not 1 <= len(leaf) <= 2 or len(set(map(str, leaf))) != len(leaf)
                or not all(isinstance(x, str) and HEX64.match(x) for x in leaf)):
            raise GateError("policy_leaf_sha256")
        if not isinstance(obj["markers_sha256"], str) or not HEX64.match(obj["markers_sha256"]):
            raise GateError("policy_markers_sha256")
        accept = obj.get("accept_runner_machine_name_line", False)
        if not isinstance(accept, bool):
            raise GateError("policy_machine_name_line")
        self.mode = obj["mode"]
        self.advisory = set(adv)
        self.leaf = set(leaf)
        self.markers_sha256 = obj["markers_sha256"]
        self.accept_machine_name_line = accept
        self.canonical = {"version": 1, "mode": self.mode, "advisory_xattrs": sorted(adv),
                          "leaf_sha256": sorted(leaf), "markers_sha256": self.markers_sha256,
                          "accept_runner_machine_name_line": accept}
        self.sha256 = sha256(json.dumps(self.canonical, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=True).encode("ascii"))


# ---------------------------------------------------------------- markers

TAG_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+-]*):")
TAGS = {"owner": (True, False), "signer": (False, True), "owner+signer": (True, True)}


class Marker:
    __slots__ = ("value", "cls", "owner", "signer")

    def __init__(self, value, cls, owner=False, signer=False):
        self.value, self.cls, self.owner, self.signer = value, cls, owner, signer


def parse_markers(data):
    """Parse a marker list; returns (markers, digest)."""
    if len(data) > STORE_MAX:
        raise GateError("markers_too_large")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise GateError("markers_encoding")
    if "\r" in text:
        if re.search(r"\r(?!\n)", text):
            raise GateError("markers_bare_cr")
        if re.search(r"(?<!\r)\n", text):
            raise GateError("markers_mixed_newlines")
        text = text.replace("\r\n", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    if not re.fullmatch(r"id:[0-9a-f]{32}", lines[0]):
        raise GateError("markers_id")
    records, markers, seen = [lines[0]], [], set()
    for line in lines[1:]:
        if line == "" or line.startswith("#"):
            continue
        owner = signer = False
        value = line
        tag = TAG_RE.match(line)
        if tag:
            if tag.group(1) == "id":
                raise GateError("markers_duplicate_id")
            if tag.group(1) not in TAGS:
                raise GateError("markers_unknown_tag")
            owner, signer = TAGS[tag.group(1)]
            value = line[tag.end():]
        if not 4 <= len(value) <= 256 or value != value.strip():
            raise GateError("markers_literal_shape")
        if any(unicodedata.category(c) == "Cc" for c in value):
            raise GateError("markers_literal_control")
        key = norm(value)
        if key in seen:
            raise GateError("markers_duplicate_literal")
        seen.add(key)
        cls = ("owner+signer" if owner and signer else "owner" if owner
               else "signer" if signer else "private")
        markers.append(Marker(value, cls, owner, signer))
        records.append(line)
    if not markers:
        raise GateError("markers_empty")
    return markers, sha256("".join(r + "\n" for r in records).encode("utf-8"))


def read_store(path):
    try:
        fd = os.open(os.path.expanduser(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise GateError("markers_store_open")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise GateError("markers_store_permissions")
        if st.st_size > STORE_MAX:
            raise GateError("markers_too_large")
        return read_fd(fd)
    finally:
        os.close(fd)


def read_fd(fd):
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > STORE_MAX:
            raise GateError("markers_too_large")
        chunks.append(chunk)


def in_release_workflow():
    env = os.environ
    return (env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and re.search(r"/" + re.escape(WORKFLOW) + r"@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+\Z",
                          env.get("GITHUB_WORKFLOW_REF", "")) is not None
            and bool(env.get("RUNNER_TEMP")))


def load_policy():
    text = os.environ.get(POLICY_ENV, "")
    if not text.strip():
        raise GateError("policy_missing")
    return Policy(text)


def load_markers(args, policy):
    env_value = os.environ.pop(MARKERS_ENV, None)
    if getattr(args, "markers_fd", None) is not None:
        try:
            data = read_fd(args.markers_fd)
            os.close(args.markers_fd)
        except OSError:
            raise GateError("markers_fd")
    elif getattr(args, "markers_store", None):
        data = read_store(args.markers_store)
    elif env_value is not None and in_release_workflow():
        data = env_value.encode("utf-8")
    else:
        raise GateError("markers_missing")
    markers, digest = parse_markers(data)
    if digest != policy.markers_sha256:
        raise GateError("markers_digest_mismatch")
    return markers, digest


def run_tool(name, argv, cwd=None, inp=None, check=False):
    """Run an Apple tool by absolute path with no marker variables and no shell."""
    env = {k: v for k, v in os.environ.items()
           if k not in (MARKERS_ENV,) and not k.startswith("OTTTO_DISPATCH_")}
    try:
        result = subprocess.run([TOOLS[name]] + argv, cwd=cwd, input=inp, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=TOOL_TIMEOUT, close_fds=True)
    except (OSError, subprocess.TimeoutExpired):
        raise Incomplete("tool_" + name)
    if check and result.returncode != 0:
        raise Incomplete("tool_" + name)
    return result


GENERIC_VALUES = {"localhost", "localhost.localdomain"}


def with_host_literals(markers):
    """Marker list plus this host's strings. A host string equal to a listed literal (NFC, casefold)
    is dropped: the listed literal keeps its own class and scoped omissions and still covers it."""
    listed = {norm(m.value) for m in markers}
    return markers + [m for m in host_literals() if norm(m.value) not in listed]


def host_literals():
    """Strings of this machine and job: user, home, full name, host and runner names, work roots."""
    found = []

    def add(cls, value, path=False):
        value = (value or "").strip()
        if len(value) >= 4 and value.lower() not in GENERIC_VALUES:
            found.append(Marker(value, cls))
        if path and value:
            real = os.path.realpath(value)
            if real != value and len(real) >= 4:
                found.append(Marker(real, cls))

    try:
        entry = pwd.getpwuid(os.getuid())
    except KeyError:
        raise GateError("host_lookup")
    add("user", entry.pw_name)
    add("user", entry.pw_gecos.split(",")[0])
    for value in (entry.pw_dir, os.environ.get("HOME")):
        add("user", value, path=True)
    for var in ("USER", "LOGNAME"):
        add("user", os.environ.get(var))
    hostname = socket.gethostname()
    add("host", hostname)
    add("host", hostname.split(".")[0])
    if sys.platform == "darwin":
        for key in ("ComputerName", "LocalHostName", "HostName"):
            result = run_tool("scutil", ["--get", key])
            if result.returncode == 0:
                add("host", result.stdout.decode("utf-8", "replace"))
            elif b"not set" not in result.stderr and b"not set" not in result.stdout:
                raise GateError("host_lookup")
    add("runner", os.environ.get("RUNNER_NAME"))
    for var in ("GITHUB_WORKSPACE", "RUNNER_TEMP", "RUNNER_WORKSPACE", "RUNNER_TOOL_CACHE", "TMPDIR"):
        add("runner", os.environ.get(var), path=True)
    unique, seen = [], set()
    for marker in found:
        if norm(marker.value) not in seen:
            seen.add(norm(marker.value))
            unique.append(marker)
    return unique


# ---------------------------------------------------------------- matching

PATH_HOMES = ("/" + "users/", "/home/")
PATH_ALWAYS = ("/var/" + "folders/", "/_work/", "actions-runner")
PATH_ENCODINGS = (("latin-1", "utf-8", 1), ("utf-16-le", "utf-16-le", 2), ("utf-16-be", "utf-16-be", 2))


def home_component_hit(prefix, rest):
    """True when a home root is followed by a user component (not the public Shared folder)."""
    if not rest or rest[0] in SEPARATORS:
        return False
    if prefix == PATH_HOMES[0] and rest.startswith("shared") and (len(rest) == 6 or rest[6] in SEPARATORS):
        return False
    return True


def path_hits_text(lowered):
    for prefix in PATH_HOMES:
        index = lowered.find(prefix)
        while index >= 0:
            end = index + len(prefix)
            if home_component_hit(prefix, lowered[end:end + 8]):
                yield index, end + 1
            index = lowered.find(prefix, index + 1)
    for prefix in PATH_ALWAYS:
        index = lowered.find(prefix)
        while index >= 0:
            yield index, index + len(prefix)
            index = lowered.find(prefix, index + 1)


def path_hits_bytes(lowered):
    for decode_as, encode_as, unit in PATH_ENCODINGS:
        for prefix in PATH_HOMES + PATH_ALWAYS:
            pattern = prefix.encode(encode_as)
            index = lowered.find(pattern)
            while index >= 0:
                end = index + len(pattern)
                if prefix in PATH_HOMES:
                    tail = lowered[end:end + 8 * unit]
                    tail = tail[:len(tail) // unit * unit].decode(decode_as, "replace")
                    if home_component_hit(prefix, tail):
                        yield index, end + unit
                else:
                    yield index, end
                index = lowered.find(pattern, index + 1)


class Matcher:
    def __init__(self, markers):
        self.markers = markers
        patterns = {}
        for index, marker in enumerate(markers):
            value = marker.value
            folded = value.casefold()
            forms = {value, folded}
            for form in (value, folded):
                forms.add(unicodedata.normalize("NFC", form))
                forms.add(unicodedata.normalize("NFD", form))
            for form in forms:
                for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                    patterns.setdefault(form.encode(encoding).lower(), set()).add(index)
        self.patterns = sorted(patterns.items())
        self.longest = max((len(p) for p in patterns), default=1)
        self.text_keys = [(norm(m.value), i) for i, m in enumerate(markers)]

    def raw(self, lowered):
        for pattern, indexes in self.patterns:
            at = lowered.find(pattern)
            while at >= 0:
                for index in indexes:
                    yield index, at, at + len(pattern)
                at = lowered.find(pattern, at + 1)

    def text(self, normalized):
        for key, index in self.text_keys:
            at = normalized.find(key)
            while at >= 0:
                yield index, at, at + len(key)
                at = normalized.find(key, at + 1)


# ---------------------------------------------------------------- extended attributes

_libc = None


def _xattr_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    return _libc


def list_xattrs(path):
    """Extended attribute names and values of a path, without following links."""
    if hasattr(os, "listxattr"):
        try:
            names = os.listxattr(path, follow_symlinks=False)
            return [(n, os.getxattr(path, n, follow_symlinks=False)) for n in names]
        except OSError as error:
            if error.errno in (95, 61):  # unsupported filesystem or no data
                return []
            raise Incomplete("xattr_read")
    if sys.platform != "darwin":
        return []
    libc, nofollow = _xattr_libc(), 0x0001
    encoded = os.fsencode(path)
    size = libc.listxattr(encoded, None, 0, nofollow)
    if size < 0:
        raise Incomplete("xattr_read")
    buffer = ctypes.create_string_buffer(size)
    if size and libc.listxattr(encoded, buffer, size, nofollow) != size:
        raise Incomplete("xattr_read")
    result = []
    for raw_name in buffer.raw[:size].split(b"\0")[:-1] if size else []:
        length = libc.getxattr(encoded, raw_name, None, 0, 0, nofollow)
        if length < 0 or length > MAX_TEXT:
            raise Incomplete("xattr_read")
        value = ctypes.create_string_buffer(max(length, 1))
        if libc.getxattr(encoded, raw_name, value, length, 0, nofollow) != length:
            raise Incomplete("xattr_read")
        result.append((raw_name.decode("utf-8", "surrogateescape"), value.raw[:length]))
    return result


# ---------------------------------------------------------------- Mach-O

def u32(data, offset, little):
    if offset + 4 > len(data):
        raise Incomplete("macho_bounds")
    return int.from_bytes(data[offset:offset + 4], "little" if little else "big")


def u64(data, offset, little):
    if offset + 8 > len(data):
        raise Incomplete("macho_bounds")
    return int.from_bytes(data[offset:offset + 8], "little" if little else "big")


MACHO_MAGICS = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}


def is_macho(head):
    return head[:4] in MACHO_MAGICS


def macho_slices(data):
    """Bounds-checked slices of a thin or fat 64-bit Mach-O: [(cputype, offset, size)]."""
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        little = magic in (b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca")
        wide = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        count = u32(data, 4, little)
        if not 1 <= count <= 8:
            raise Incomplete("macho_fat_count")
        entry = 32 if wide else 20
        header_end = 8 + count * entry
        slices = []
        for i in range(count):
            base = 8 + i * entry
            cpu = u32(data, base, little)
            if wide:
                offset, size, align = u64(data, base + 8, little), u64(data, base + 16, little), u32(data, base + 24, little)
            else:
                offset, size, align = u32(data, base + 8, little), u32(data, base + 12, little), u32(data, base + 16, little)
            if align > 20 or offset % (1 << align) or offset < header_end or size == 0 or offset + size > len(data):
                raise Incomplete("macho_fat_slice")
            slices.append((cpu, offset, size))
        ordered = sorted(slices, key=lambda s: s[1])
        for (_, a_off, a_size), (_, b_off, _) in zip(ordered, ordered[1:]):
            if a_off + a_size > b_off:
                raise Incomplete("macho_fat_overlap")
        for cpu, offset, _ in slices:
            if u32(data, offset + 4, data[offset:offset + 4] == b"\xcf\xfa\xed\xfe") != cpu:
                raise Incomplete("macho_fat_cpu")
        return slices
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return [(u32(data, 4, magic == b"\xcf\xfa\xed\xfe"), 0, len(data))]
    raise Incomplete("macho_kind")


def macho_slice_info(data, offset, size):
    """UUID, stab count (B's OPT record excluded) and debug sections of one 64-bit slice."""
    view = data[offset:offset + size]
    if view[:4] not in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        raise Incomplete("macho_kind")
    little = view[:4] == b"\xcf\xfa\xed\xfe"
    ncmds, sizeofcmds = u32(view, 16, little), u32(view, 20, little)
    if ncmds > 4096 or 32 + sizeofcmds > len(view):
        raise Incomplete("macho_commands")
    position, uuid, stabs, debug, signature = 32, None, 0, False, None
    for _ in range(ncmds):
        cmd, cmdsize = u32(view, position, little), u32(view, position + 4, little)
        if cmdsize < 8 or cmdsize % 8 or position + cmdsize > 32 + sizeofcmds:
            raise Incomplete("macho_commands")
        if cmd == 0x1B:
            if cmdsize != 24 or uuid is not None:
                raise Incomplete("macho_uuid")
            raw = view[position + 8:position + 24].hex().upper()
            uuid = "-".join((raw[:8], raw[8:12], raw[12:16], raw[16:20], raw[20:]))
        elif cmd == 0x19:
            segname = view[position + 8:position + 24].rstrip(b"\0")
            nsects = u32(view, position + 64, little)
            if 72 + nsects * 80 != cmdsize:
                raise Incomplete("macho_segment")
            if segname == b"__DWARF":
                debug = True
            for s in range(nsects):
                if view[position + 72 + s * 80:position + 72 + s * 80 + 16].startswith(b"__debug_"):
                    debug = True
        elif cmd == 0x02:
            symoff, nsyms = u32(view, position + 8, little), u32(view, position + 12, little)
            stroff, strsize = u32(view, position + 16, little), u32(view, position + 20, little)
            if symoff + nsyms * 16 > len(view) or stroff + strsize > len(view):
                raise Incomplete("macho_symtab")
            for n in range(nsyms):
                entry = symoff + n * 16
                ntype = view[entry + 4]
                if not ntype & 0xE0:
                    continue
                strx = u32(view, entry, little)
                name = view[stroff + strx:view.find(b"\0", stroff + strx)] if strx < strsize else b""
                if not (ntype == 0x3C and name == b"radr://5614542"):
                    stabs += 1
        elif cmd == 0x1D:
            dataoff, datasize = u32(view, position + 8, little), u32(view, position + 12, little)
            if dataoff + datasize > len(view):
                raise Incomplete("macho_signature")
            signature = (dataoff, datasize)
        position += cmdsize
    if position != 32 + sizeofcmds:
        raise Incomplete("macho_commands")
    return uuid, stabs, debug, signature


def load_sparkle_table():
    path = os.path.join(ROOT, "release", "sparkle-build-ids.tsv")
    table = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#") or not line.strip():
                continue
            version, rel, arch, uuid = line.rstrip("\n").split("\t")
            table.setdefault(version, {})[(rel, arch)] = uuid.upper()
    return table


# ---------------------------------------------------------------- DER (CMS)

def der(data, position, end, depth=0):
    """One BER element (definite or constructed indefinite length): (tag, content, content_end, end)."""
    if position + 2 > end or depth > 32:
        raise Incomplete("cms_der")
    tag, length = data[position], data[position + 1]
    position += 2
    if tag & 0x1F == 0x1F:
        raise Incomplete("cms_der")
    if length == 0x80:
        if not tag & 0x20:
            raise Incomplete("cms_der")
        cursor = position
        while True:
            if data[cursor:cursor + 2] == b"\0\0":
                return tag, position, cursor, cursor + 2
            cursor = der(data, cursor, end, depth + 1)[3]
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4 or position + count > end or data[position] == 0:
            raise Incomplete("cms_der")
        length = int.from_bytes(data[position:position + count], "big")
        if length < 128:
            raise Incomplete("cms_der")
        position += count
    if position + length > end:
        raise Incomplete("cms_der")
    return tag, position, position + length, position + length


def der_children(data, start, end):
    children, position = [], start
    while position < end:
        tag, content, content_end, stop = der(data, position, end)
        children.append((tag, position, content, content_end, stop))
        position = stop
    return children


def cms_signer_certificate(data):
    """DER of the single signer's certificate in a CMS SignedData blob (structure only)."""
    tag, content, content_end, stop = der(data, 0, len(data))
    if tag != 0x30 or stop != len(data):
        raise Incomplete("cms_envelope")
    info = der_children(data, content, content_end)
    if len(info) != 2 or info[0][0] != 0x06 or data[info[0][2]:info[0][3]] != bytes.fromhex("2a864886f70d010702") \
            or info[1][0] != 0xA0:
        raise Incomplete("cms_envelope")
    inner = der_children(data, info[1][2], info[1][3])
    if len(inner) != 1 or inner[0][0] != 0x30:
        raise Incomplete("cms_envelope")
    signed = der_children(data, inner[0][2], inner[0][3])
    certificates = [c for c in signed if c[0] == 0xA0]
    if len(signed) < 4 or signed[-1][0] != 0x31 or len(certificates) != 1:
        raise Incomplete("cms_envelope")
    signers = der_children(data, signed[-1][2], signed[-1][3])
    if len(signers) != 1:
        raise Incomplete("cms_signer_count")
    fields = der_children(data, signers[0][2], signers[0][3])
    if len(fields) < 2 or fields[1][0] != 0x30:
        raise Incomplete("cms_signer_id")
    sid = der_children(data, fields[1][2], fields[1][3])
    if len(sid) != 2:
        raise Incomplete("cms_signer_id")
    issuer, serial = data[sid[0][1]:sid[0][4]], data[sid[1][1]:sid[1][4]]
    matches = []
    for cert in der_children(data, certificates[0][2], certificates[0][3]):
        tbs = der_children(data, cert[2], cert[3])[0]
        parts = der_children(data, tbs[2], tbs[3])
        if parts and parts[0][0] == 0xA0:
            parts = parts[1:]
        if len(parts) >= 3 and data[parts[0][1]:parts[0][4]] == serial and data[parts[2][1]:parts[2][4]] == issuer:
            matches.append(data[cert[1]:cert[4]])
    if len(matches) != 1:
        raise Incomplete("cms_signer_certificate")
    return matches[0]


# ---------------------------------------------------------------- ZIP

ZIP_EXTRAS = {0x5455, 0x5855, 0x7875, 0x000D}


def zip_members(data):
    """Strictly framed ZIP members: [(name, mode, stored_interval or None, bytes)]."""
    window = data[-(65535 + 22):]
    base = len(data) - len(window)
    ends = [m.start() + base for m in re.finditer(b"PK\x05\x06", window)]
    if len(ends) != 1:
        raise Incomplete("zip_eocd")
    eocd = ends[0]
    if eocd + 22 > len(data):
        raise Incomplete("zip_eocd")
    fields = [int.from_bytes(data[eocd + o:eocd + o + n], "little")
              for o, n in ((4, 2), (6, 2), (8, 2), (10, 2), (12, 4), (16, 4), (20, 2))]
    disk, cd_disk, here, total, cd_size, cd_offset, comment = fields
    if disk or cd_disk or here != total or eocd + 22 + comment != len(data) or 0xFFFF in (here, total) \
            or 0xFFFFFFFF in (cd_size, cd_offset) or cd_offset + cd_size != eocd or total > MAX_ENTRIES:
        raise Incomplete("zip_eocd")
    members, position, records, names, inflated = [], cd_offset, [], set(), 0
    for _ in range(total):
        if data[position:position + 4] != b"PK\x01\x02" or position + 46 > eocd:
            raise Incomplete("zip_central")
        made, flags, method = (int.from_bytes(data[position + o:position + o + 2], "little") for o in (4, 8, 10))
        crc, csize, usize = (int.from_bytes(data[position + o:position + o + 4], "little") for o in (16, 20, 24))
        nlen, elen, clen, start_disk = (int.from_bytes(data[position + o:position + o + 2], "little")
                                        for o in (28, 30, 32, 34))
        external = int.from_bytes(data[position + 38:position + 42], "little")
        local = int.from_bytes(data[position + 42:position + 46], "little")
        raw_name = data[position + 46:position + 46 + nlen]
        extra = data[position + 46 + nlen:position + 46 + nlen + elen]
        position += 46 + nlen + elen + clen
        if position > eocd or start_disk or flags & ~0x0808 or method not in (0, 8) \
                or 0xFFFFFFFF in (csize, usize, local) or usize > MAX_MEMBER:
            raise Incomplete("zip_central")
        inflated += usize  # every member is held in memory: bound the total before inflating any
        if inflated > MAX_FILE:
            raise Incomplete("size_limit")
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            raise Incomplete("zip_name")
        if not name or name.startswith("/") or "\\" in name or "\0" in name or ".." in name.split("/") \
                or name in names:
            raise Incomplete("zip_name")
        names.add(name)
        check_zip_extra(extra)
        if data[local:local + 4] != b"PK\x03\x04":
            raise Incomplete("zip_local")
        l_flags, l_method = (int.from_bytes(data[local + o:local + o + 2], "little") for o in (6, 8))
        l_crc, l_csize, l_usize = (int.from_bytes(data[local + o:local + o + 4], "little") for o in (14, 18, 22))
        l_nlen, l_elen = (int.from_bytes(data[local + o:local + o + 2], "little") for o in (26, 28))
        if l_flags != flags or l_method != method or data[local + 30:local + 30 + l_nlen] != raw_name:
            raise Incomplete("zip_local")
        check_zip_extra(data[local + 30 + l_nlen:local + 30 + l_nlen + l_elen])
        if not flags & 0x08 and (l_crc, l_csize, l_usize) != (crc, csize, usize):
            raise Incomplete("zip_local")
        begin = local + 30 + l_nlen + l_elen
        if begin + csize > cd_offset:
            raise Incomplete("zip_bounds")
        stream = data[begin:begin + csize]
        if method == 0:
            if csize != usize:
                raise Incomplete("zip_stored")
            content = stream
        else:
            inflater = zlib.decompressobj(-15)
            try:
                content = inflater.decompress(stream, usize + 1)
            except zlib.error:
                raise Incomplete("zip_deflate")
            if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or len(content) != usize:
                raise Incomplete("zip_deflate")
        if zlib.crc32(content) & 0xFFFFFFFF != crc:
            raise Incomplete("zip_crc")
        end = begin + csize
        if flags & 0x08:
            descriptor = data[end:end + 16]
            if descriptor[:4] == b"PK\x07\x08":
                values, end = descriptor[4:16], end + 16
            else:
                values, end = descriptor[:12], end + 12
            if values != crc.to_bytes(4, "little") + csize.to_bytes(4, "little") + usize.to_bytes(4, "little"):
                raise Incomplete("zip_descriptor")
        records.append((local, end))
        mode = (external >> 16) & 0xFFFF if made >> 8 == 3 else 0
        members.append((name, mode, (begin, begin + csize) if method == 0 else None, content))
    if position != eocd:
        raise Incomplete("zip_central")
    records.sort()
    cursor = 0
    for start, end in records:
        if start != cursor:
            raise Incomplete("zip_gap")
        cursor = end
    if cursor != cd_offset:
        raise Incomplete("zip_gap")
    return members


def check_zip_extra(extra):
    position = 0
    while position < len(extra):
        if position + 4 > len(extra):
            raise Incomplete("zip_extra")
        kind = int.from_bytes(extra[position:position + 2], "little")
        size = int.from_bytes(extra[position + 2:position + 4], "little")
        if kind not in ZIP_EXTRAS or position + 4 + size > len(extra):
            raise Incomplete("zip_extra")
        position += 4 + size


# ---------------------------------------------------------------- scanner

class Representation:
    """One searched view of bytes; omit marks verified-signed or approved-legal intervals."""

    def __init__(self, role, key, signed=False, legal=False, intervals=()):
        self.role, self.key, self.signed, self.legal, self.intervals = role, key, signed, legal, intervals

    def omitted(self, marker, start, end):
        if marker.signer and self.signed:
            return True
        if marker.owner and self.legal:
            return True
        for low, high, signed, legal in self.intervals:
            if low <= start and end <= high and ((marker.signer and signed) or (marker.owner and legal)):
                return True
        return False


class Gate:
    def __init__(self, policy, markers, profile, scratch=None):
        self.policy, self.profile, self.markers = policy, profile, markers
        self.matcher = Matcher(markers)
        self.findings, self.diagnostics = {}, {}
        self.advisory = {name: 0 for name in ADVISORY_NAMES}
        self.loose_xattrs = 0
        self.incomplete = 0
        self.seen = set()
        self.scratch = scratch
        self.legal_hashes = None
        self.sparkle = None
        self.trust_cache = {}

    # --- results
    def finding(self, role, cls, code, count=1):
        self.findings[cls] = self.findings.get(cls, 0) + count
        key = (role, cls, code)
        self.diagnostics[key] = self.diagnostics.get(key, 0) + count

    def incomplete_input(self, role, code):
        self.incomplete += 1
        key = (role, "incomplete", code)
        self.diagnostics[key] = self.diagnostics.get(key, 0) + 1

    def verdict(self):
        if self.incomplete:
            return "incomplete"
        return "blocked" if self.findings else "clean"

    def record(self, rep, marker_index, start, end, code, cls=None):
        marker = self.markers[marker_index]
        if rep.omitted(marker, start, end):
            return
        cls = cls or marker.cls
        key = (rep.key, code, cls, marker_index, start, end)
        if key not in self.seen:
            self.seen.add(key)
            self.finding(rep.role, cls, code)

    def record_path(self, rep, start, end, code):
        key = (rep.key, code, "path", start, end)
        if key not in self.seen:
            self.seen.add(key)
            self.finding(rep.role, "path", code)

    # --- byte and text passes
    def scan_buffer(self, buffer, base, rep):
        lowered = buffer.lower()
        for index, start, end in self.matcher.raw(lowered):
            self.record(rep, index, base + start, base + end, "raw")
        for start, end in path_hits_bytes(lowered):
            self.record_path(rep, base + start, base + end, "raw")

    def scan_bytes(self, data, rep):
        overlap = max(self.matcher.longest, 64)
        if len(data) <= CHUNK:
            self.scan_buffer(data, 0, rep)
            return
        position = 0
        while position < len(data):
            start = max(0, position - overlap)
            self.scan_buffer(data[start:position + CHUNK], start, rep)
            position += CHUNK

    def scan_stream(self, handle, rep, limit=MAX_FILE):
        """Scan a file object in chunks; returns (size, sha256)."""
        overlap = max(self.matcher.longest, 64)
        digest, tail, base, size = hashlib.sha256(), b"", 0, 0
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise Incomplete("size_limit")
            digest.update(chunk)
            buffer = tail + chunk
            self.scan_buffer(buffer, base, rep)
            keep = min(len(buffer), overlap)
            base += len(buffer) - keep
            tail = buffer[len(buffer) - keep:]
        return size, digest.hexdigest()

    def scan_text(self, text, rep, field, code="text"):
        normalized = norm(text)
        for index, start, end in self.matcher.text(normalized):
            self.record(rep, index, start, end, "%s:%d" % (code, field))
        for start, end in path_hits_text(normalized):
            self.record_path(rep, start, end, "%s:%d" % (code, field))

    def scan_name(self, name, rep, field):
        self.scan_bytes(os.fsencode(name), Representation(rep.role, (rep.key, "name", field)))
        self.scan_text(name, Representation(rep.role, (rep.key, "name", field)), 0, "name")

    # --- typed formats
    def scan_json(self, data, rep):
        self.scan_bytes(data, rep)
        try:
            document = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
        except ValueError:
            raise Incomplete("json_parse")
        self.walk_values(document, rep)

    def walk_values(self, value, rep, key=""):
        counter = [0]

        def visit(item, field_key):
            counter[0] += 1
            if isinstance(item, dict):
                for k, v in item.items():
                    self.scan_text(str(k), rep, counter[0], "key")
                    visit(v, str(k))
            elif isinstance(item, list):
                for v in item:
                    visit(v, field_key)
            elif isinstance(item, str):
                self.scan_text(item, rep, counter[0])
                if "%" in item and (item.lower().startswith(("http://", "https://"))
                                    or field_key.lower().endswith("url")):
                    self.scan_text(url_decoded(item), rep, counter[0], "url")
            elif isinstance(item, (bytes, bytearray)):
                self.scan_bytes(bytes(item), Representation(rep.role, (rep.key, "data", counter[0])))
        visit(value, key)

    def scan_plist(self, data, rep):
        self.scan_bytes(data, rep)
        if re.search(rb"<!ENTITY", data, re.I):
            raise Incomplete("plist_entity")
        try:
            document = plistlib.loads(data, dict_type=NoDuplicateDict)
        except Exception:
            raise Incomplete("plist_parse")
        self.walk_values(document, rep)

    def scan_xml(self, data, rep):
        self.scan_bytes(data, rep)
        if re.search(rb"<!(DOCTYPE|ENTITY)", data, re.I):
            raise Incomplete("xml_declaration")
        try:
            root = ET.fromstring(data)
        except ET.ParseError:
            raise Incomplete("xml_parse")
        field = 0
        for element in root.iter():
            for text in (element.tag, element.text, element.tail):
                if text:
                    field += 1
                    self.scan_text(text, rep, field)
            for name, value in element.attrib.items():
                field += 1
                self.scan_text(name + "=" + value, rep, field)
                if "%" in value and value.lower().startswith(("http://", "https://")):
                    self.scan_text(url_decoded(value), rep, field, "url")

    def scan_plain_text(self, data, rep, html_page=False):
        self.scan_bytes(data, rep)
        try:
            text = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Incomplete("text_encoding")
        self.scan_text(text, rep, 0)
        if html_page:
            self.scan_text(html.unescape(text), rep, 1, "entity")

    # --- legal exception
    def legal_ok(self, name, data):
        if self.legal_hashes is None:
            self.legal_hashes = approved_legal_hashes()
        return self.legal_hashes.get(name) == sha256(data)

    # --- trust
    def trust_tool_available(self):
        return sys.platform == "darwin" and os.path.exists(TOOLS["codesign"])

    def verified_signature(self, path, role, deep=False):
        """Native Developer ID verification of a signed path plus the pinned leaf."""
        if not self.trust_tool_available():
            raise Incomplete("trust_unavailable")
        parent, name = os.path.split(os.path.abspath(path))
        args = ["--verify", "--strict"] + (["--deep"] if deep else []) + ["-R", DEVID_REQ, name]
        if run_tool("codesign", args, cwd=parent).returncode != 0:
            self.finding(role, "signature", "verify")
            return False
        work = tempfile.mkdtemp(dir=self.scratch)
        try:
            run_tool("codesign", ["-d", "--extract-certificates=" + os.path.join(work, "cert"), name],
                     cwd=parent, check=True)
            try:
                with open(os.path.join(work, "cert0"), "rb") as handle:
                    leaf = sha256(handle.read())
            except OSError:
                raise Incomplete("trust_leaf")
        finally:
            remove_tree(work)
        if leaf not in self.policy.leaf:
            self.finding(role, "signature", "leaf_pin")
            return False
        return True

    def verified_bytes(self, data, role, name):
        work = tempfile.mkdtemp(dir=self.scratch)
        try:
            path = os.path.join(work, name)
            with open(path, "wb") as handle:
                handle.write(data)
            os.chmod(path, 0o755)
            return self.verified_signature(path, role)
        finally:
            remove_tree(work)

    # --- Mach-O policy
    def check_macho(self, data, role, slot):
        """slot: 'product', 'sparkle:<rel>' or None (an unexpected Mach-O)."""
        if slot is None:
            self.finding(role, "structure", "unexpected_macho")
            return
        slices = macho_slices(data)
        arches = {}
        for cpu, offset, size in slices:
            uuid, stabs, debug, _ = macho_slice_info(data, offset, size)
            if debug:
                self.finding(role, "structure", "debug_sections")
            arches[ARCH_NAMES.get(cpu, "other")] = (uuid, stabs)
        if slot in ("product", "companion"):
            if set(arches) != {"arm64"}:
                self.finding(role, "structure", "product_arch")
            elif slot == "companion" and arches["arm64"][1]:
                self.finding(role, "structure", "debug_map")
            return
        if self.sparkle is None:
            self.sparkle = sparkle_expected()
        rel = slot.split(":", 1)[1]
        expected = {arch: uuid for (path, arch), uuid in self.sparkle.items() if path == rel}
        actual = {arch: value[0] for arch, value in arches.items()}
        if not expected or actual != expected:
            self.finding(role, "structure", "sparkle_uuid")

    # --- files and trees
    def scan_member(self, rel, data, role, rep_key, signed_ok, legal_name=None):
        """Scan one file's bytes by its relative path in an app tree or archive."""
        legal = legal_name is not None and self.legal_ok(legal_name, data)
        rep = Representation(role, rep_key, legal=legal)
        if is_macho(data[:4]):
            slot = ("companion" if rel == "Contents/MacOS/Ottto" else "product") if rel in PRODUCT_SLOTS else None
            if rel.startswith(SPARKLE_DIR):
                slot = "sparkle:" + rel[len(SPARKLE_DIR):]
            self.check_macho(data, role, slot)
            rep.signed = bool(signed_ok and signed_ok(rel, data))
            self.scan_bytes(data, rep)
        elif rel.endswith(".plist") or rel.endswith("/_CodeSignature/CodeResources"):
            self.scan_plist(data, rep)
        elif rel.endswith(".json"):
            self.scan_json(data, rep)
        else:
            self.scan_bytes(data, rep)
            if len(data) <= MAX_TEXT:
                try:
                    text = data.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    text = None
                if text is not None:
                    self.scan_text(text, rep, 0)
                    if rel.endswith(".html"):
                        self.scan_text(html.unescape(text), rep, 1, "entity")

    def scan_xattrs(self, path, role, key, shipped):
        for name, value in list_xattrs(path):
            rep = Representation(role, (key, "xattr", name))
            self.scan_name(name, rep, 0)
            self.scan_bytes(value, Representation(role, (key, "xattr-value", name)))
            short = {v: k for k, v in ADVISORY_NAMES.items()}.get(name)
            if not shipped:
                self.loose_xattrs += 1
            elif short and short in self.policy.advisory:
                self.advisory[short] += 1
            else:
                self.finding(role, "xattr_presence", short or "unexpected")

    def walk_tree(self, top, role, shipped, signed_ok=None, link_ok=None, legal_dir=None, inventory=None):
        """Walk a folder without following links; scan names, links, attributes and files."""
        count = [0]

        def visit(directory, rel_dir, depth):
            if depth > MAX_DEPTH:
                raise Incomplete("tree_depth")
            with os.scandir(directory) as entries:
                listing = sorted(entries, key=lambda e: e.name)
            for entry in listing:
                count[0] += 1
                if count[0] > MAX_ENTRIES:
                    raise Incomplete("tree_entries")
                rel = rel_dir + entry.name
                key = (role, "tree", rel)
                self.scan_name(rel, Representation(role, key), 0)
                st = os.lstat(entry.path)
                self.scan_xattrs(entry.path, role, key, shipped)
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(entry.path)
                    self.scan_name(target, Representation(role, (key, "link")), 0)
                    if not (link_ok and link_ok(rel, target)):
                        self.finding(role, "structure", "unexpected_link")
                    if inventory is not None:
                        inventory[rel] = ("l", target)
                elif stat.S_ISDIR(st.st_mode):
                    if inventory is not None:
                        inventory[rel + "/"] = ("d", stat.S_IMODE(st.st_mode))
                    visit(entry.path, rel + "/", depth + 1)
                elif stat.S_ISREG(st.st_mode):
                    if st.st_nlink != 1:
                        self.finding(role, "structure", "hard_link")
                    if st.st_size > MAX_FILE:
                        raise Incomplete("size_limit")
                    with open(entry.path, "rb") as handle:
                        data = handle.read()
                    legal_name = entry.name if legal_dir is not None and rel_dir == legal_dir else None
                    self.scan_member(rel, data, role, key, signed_ok, legal_name)
                    if inventory is not None:
                        inventory[rel] = ("f", stat.S_IMODE(st.st_mode), sha256(data))
                else:
                    self.finding(role, "structure", "special_file")

        visit(top, "", 0)

    # --- roles
    def scan_app_tree(self, path, role, signed, shipped, inventory=None):
        """Ottto.app: unsigned before signing, or a verified signed bundle."""
        tree_ok = signed and self.verified_signature(path, role, deep=True)
        leaf_cache = {}

        def signed_ok(rel, _data):
            if not tree_ok:
                return False
            if rel not in leaf_cache:
                leaf_cache[rel] = self.verified_signature(os.path.join(path, rel), role)
            return leaf_cache[rel]

        if self.sparkle is None:
            self.sparkle = sparkle_expected()
        seen_macho = set()

        def tracking_ok(rel, data):
            seen_macho.add(rel)
            return signed_ok(rel, data)

        self.scan_xattrs(path, role, (role, "tree", ""), shipped)
        self.walk_tree(path, role, shipped, tracking_ok, app_link_ok, "Contents/Resources/", inventory)
        expected = PRODUCT_SLOTS | {SPARKLE_DIR + rel for rel, _ in self.sparkle}
        if seen_macho != expected:
            self.finding(role, "structure", "macho_slots")

    def scan_binary_zip(self, path, role, data):
        members = zip_members(data)
        exe = ZIP_EXECUTABLES[role]
        legal = set(legal_names(archive=True))
        names = {m[0] for m in members}
        if names != {exe} | legal:
            self.finding(role, "structure", "zip_members")
        intervals = []
        for name, mode, stored, content in members:
            rep_key = (role, "member", name)
            self.scan_name(name, Representation(role, rep_key), 0)
            if name == exe:
                if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o755:
                    self.finding(role, "structure", "zip_mode")
                self.check_macho(content, role, "product")
                ok = self.verified_bytes(content, role, exe)
                self.scan_bytes(content, Representation(role, rep_key, signed=ok))
                if stored:
                    intervals.append((stored[0], stored[1], ok, False))
            else:
                approved = name in legal and self.legal_ok(name, content)
                self.scan_plain_text(content, Representation(role, rep_key, legal=approved),
                                     html_page=name.endswith(".html"))
                if stored:
                    intervals.append((stored[0], stored[1], False, approved))
        self.scan_bytes(data, Representation(role, (role, "raw"), intervals=intervals))

    def scan_app_zip(self, data, role, expect_app):
        """The temporary app ZIP: exactly the checked, verified app tree."""
        inventory = {}
        tree_ok = self.verified_signature(expect_app, role, deep=True)
        leaf_cache = {}

        def tree_signed(rel, _data=None):
            if not tree_ok:
                return False
            if rel not in leaf_cache:
                leaf_cache[rel] = self.verified_signature(os.path.join(expect_app, rel), role)
            return leaf_cache[rel]

        self.walk_tree(expect_app, role, False, tree_signed, app_link_ok, "Contents/Resources/", inventory)
        members = zip_members(data)
        actual = {}
        intervals = []
        for name, mode, stored, content in members:
            if not name.startswith("Ottto.app/") or "/._" in "/" + name or name.startswith("__MACOSX"):
                self.finding(role, "structure", "zip_members")
                continue
            rel = name[len("Ottto.app/"):]
            rep_key = (role, "member", name)
            self.scan_name(name, Representation(role, rep_key), 0)
            if name.endswith("/"):
                actual[rel] = ("d", stat.S_IMODE(mode))
                continue
            if stat.S_ISLNK(mode):
                actual[rel] = ("l", content.decode("utf-8", "replace"))
                self.scan_name(content.decode("utf-8", "replace"), Representation(role, (rep_key, "link")), 0)
                continue
            actual[rel] = ("f", stat.S_IMODE(mode), sha256(content))

            def signed_ok(r, d, _rel=rel):
                return inventory.get(_rel, (None,))[-1] == sha256(d) and tree_signed(_rel)

            legal_name = rel.rsplit("/", 1)[-1] if rel.startswith("Contents/Resources/") and rel.count("/") == 2 else None
            self.scan_member(rel, content, role, rep_key, signed_ok, legal_name)
            if stored:
                signed = is_macho(content[:4]) and signed_ok(rel, content)
                legal = legal_name is not None and self.legal_ok(legal_name, content)
                intervals.append((stored[0], stored[1], signed, legal))
        directories = {k for k, v in actual.items() if v[0] == "d"}
        if {k: v for k, v in actual.items() if v[0] != "d"} != {k: v for k, v in inventory.items() if v[0] != "d"} \
                or not directories <= {k for k, v in inventory.items() if v[0] == "d"} | {""}:
            self.finding(role, "structure", "zip_inventory")
        self.scan_bytes(data, Representation(role, (role, "raw"), intervals=intervals))

    def scan_dmg(self, path, role):
        if not self.trust_tool_available():
            raise Incomplete("trust_unavailable")
        signed = self.verified_signature(path, role)
        parent, name = os.path.split(os.path.abspath(path))
        if run_tool("hdiutil", ["verify", "-quiet", name], cwd=parent).returncode != 0:
            self.finding(role, "structure", "dmg_verify")
        with open(path, "rb") as handle:
            self.scan_stream(handle, Representation(role, (role, "raw"), signed=signed))
        device = self.attach(name, parent, ["-nomount"])
        try:
            with open("/dev/r" + device[len("/dev/"):], "rb") as disk:
                self.scan_stream(disk, Representation(role, (role, "disk"), signed=signed), limit=4 * MAX_FILE)
        except OSError:
            raise Incomplete("dmg_read")
        finally:
            self.detach(device)
        mount = tempfile.mkdtemp(dir=self.scratch)
        device = self.attach(name, parent, ["-mountpoint", mount], mount)
        try:
            entries = set(os.listdir(mount))
            if not {"Ottto.app", "Applications"} <= entries or entries - {"Ottto.app", "Applications", ".fseventsd"}:
                self.finding(role, "structure", "dmg_root")
            self.scan_app_tree(os.path.join(mount, "Ottto.app"), role, True, True)
            for extra in sorted(entries - {"Ottto.app"}):
                full = os.path.join(mount, extra)
                self.scan_name(extra, Representation(role, (role, "root", extra)), 0)
                self.scan_xattrs(full, role, (role, "root", extra), True)
                if os.path.islink(full):
                    if extra != "Applications" or os.readlink(full) != "/Applications":
                        self.finding(role, "structure", "unexpected_link")
                elif os.path.isdir(full) and extra == ".fseventsd":
                    self.walk_tree(full, role, True)
                else:
                    self.finding(role, "structure", "dmg_root")
        finally:
            self.detach(device)
            os.rmdir(mount)

    def attach(self, name, parent, extra, mount=None):
        result = run_tool("hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-plist"] + extra + [name],
                          cwd=parent)
        if result.returncode != 0:
            raise Incomplete("dmg_attach")
        try:
            entities = plistlib.loads(result.stdout).get("system-entities", [])
        except Exception:
            raise Incomplete("dmg_attach")
        devices = sorted({e.get("dev-entry", "") for e in entities})
        whole = sorted((d for d in devices if re.fullmatch(r"/dev/disk[0-9]+", d)), key=lambda d: int(d[9:]))
        mounts = [e["mount-point"] for e in entities if "mount-point" in e]
        if not whole or (mount is None and mounts) or (mount is not None and mounts != [mount]):
            if whole:
                self.detach(whole[0])
            raise Incomplete("dmg_attach")
        return whole[0]

    def detach(self, device):
        if run_tool("hdiutil", ["detach", device]).returncode != 0:
            if run_tool("hdiutil", ["detach", "-force", device]).returncode != 0:
                raise Incomplete("dmg_detach")

    def scan_cms(self, data, role, manifest):
        certificate = cms_signer_certificate(data)
        if not self.trust_tool_available():
            raise Incomplete("trust_unavailable")
        if manifest is None:
            raise Incomplete("cms_manifest")
        decoded = run_tool("security", ["cms", "-D", "-u", "6"], inp=data)
        verified = decoded.returncode == 0 and decoded.stdout == manifest
        if not verified:
            self.finding(role, "signature", "cms_verify")
        elif sha256(certificate) not in self.policy.leaf:
            self.finding(role, "signature", "leaf_pin")
            verified = False
        self.scan_bytes(data, Representation(role, (role, "raw"), signed=verified))

    def scan_checksums(self, data, role, expected_names, files):
        self.scan_plain_text(data, Representation(role, (role, "raw")))
        lines = data.decode("utf-8").split("\n")
        if lines[-1] != "":
            self.finding(role, "structure", "checksums_format")
        rows = {}
        for line in lines[:-1]:
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
            if not match or match.group(2) in rows:
                self.finding(role, "structure", "checksums_format")
                continue
            rows[match.group(2)] = match.group(1)
        if set(rows) != set(expected_names):
            self.finding(role, "structure", "checksums_subjects")
        for name, digest in rows.items():
            if name in files and files[name] != digest:
                self.finding(role, "structure", "checksums_digest")

    def scan_role(self, role, path, context):
        if role == "app_bundle":
            inventory = {}
            self.scan_app_tree(path, role, context.get("signed", False), False, inventory)
            return inventory_row(inventory)
        if os.path.islink(path) or not os.path.isfile(path):
            raise Incomplete("role_type")
        size = os.path.getsize(path)
        if size > MAX_FILE:
            raise Incomplete("size_limit")
        self.scan_xattrs(path, role, (role, "file"), False)
        rep = Representation(role, (role, "raw"))
        if role == "app_dmg":
            self.scan_dmg(path, role)
            return size, file_sha256(path)
        with open(path, "rb") as handle:
            data = handle.read()
        if role in ("cli_binary", "service_binary"):
            self.check_macho(data, role, "product")
            self.scan_bytes(data, rep)
        elif role in ZIP_EXECUTABLES:
            self.scan_binary_zip(path, role, data)
        elif role == "app_notary_zip":
            self.scan_app_zip(data, role, context["expect_app"])
        elif role in JSON_ROLES:
            self.scan_json(data, rep)
        elif role == "manifest_sig":
            self.scan_cms(data, role, context.get("manifest"))
        elif role == "checksums":
            self.scan_checksums(data, role, context["checksum_names"], context.get("files", {}))
        elif role == "installer":
            if not data.startswith((b"#!/usr/bin/env bash\n", b"#!/bin/bash\n")):
                self.finding(role, "structure", "installer_shebang")
            self.scan_plain_text(data, rep)
        elif role == "formula":
            self.scan_plain_text(data, rep)
        elif role == "appcast":
            self.scan_xml(data, rep)
        else:
            raise Incomplete("role_unknown")
        return size, sha256(data)


def url_decoded(value):
    try:
        return urllib.parse.unquote(value, errors="strict")
    except UnicodeDecodeError:
        raise Incomplete("url_escape")


def remove_tree(path):
    """Clear immutable flags (folders first), then remove the tree."""
    unfreeze(path)
    for directory, dirs, files in os.walk(path):
        for name in dirs + files:
            unfreeze(os.path.join(directory, name))
    shutil.rmtree(path)


def unfreeze(path):
    if hasattr(os, "chflags"):
        try:
            flags = os.lstat(path).st_flags
            if flags & stat.UF_IMMUTABLE:
                os.chflags(path, flags & ~stat.UF_IMMUTABLE, follow_symlinks=False)
        except OSError:
            pass


def inventory_row(inventory):
    listing = json.dumps(sorted(inventory.items()), separators=(",", ":")).encode("utf-8")
    size = len(inventory)
    return size, sha256(listing)


def app_link_ok(rel, target):
    """The only links in Ottto.app are Sparkle.framework's standard version links."""
    if not rel.startswith(SPARKLE_DIR):
        return False
    inner = rel[len(SPARKLE_DIR):]
    if inner == "Versions/Current":
        return target == "B"
    return "/" not in inner and target == "Versions/Current/" + inner


_legal_cache = {}


def legal_names(archive=False):
    """A's license file names (app Resources, or the binary ZIP root subset)."""
    key = "archive" if archive else "app"
    if key not in _legal_cache:
        result = run_tool("bash", ["-c", 'source "$1"; ottto_app_license_resource_names; '
                                         'ottto_archive_license_names; printf "%s\\n" "$OTTTO_SPARKLE_LICENSE_SHA256"',
                                   "gate", "scripts/macos_license_notices.sh"], cwd=ROOT)
        lines = result.stdout.decode("utf-8").split("\n") if result.returncode == 0 else []
        if len(lines) != 9:
            raise Incomplete("legal_names")
        _legal_cache["app"], _legal_cache["archive"], _legal_cache["sparkle"] = lines[0:4], lines[4:7], lines[7]
    return _legal_cache[key]


def approved_legal_hashes():
    """Exact approved bytes: the public source commit's license files and the pinned Sparkle license.

    In a git checkout the committed blobs are read (a build cannot change them); in an exported
    tree (git archive) the files themselves. A missing file stops the scan."""
    hashes = {}
    legal_names()
    in_checkout = os.path.exists(os.path.join(ROOT, ".git"))
    for name in _legal_cache["archive"]:
        if in_checkout:
            result = run_tool("git", ["cat-file", "blob", "HEAD:" + name], cwd=ROOT)
            if result.returncode != 0:
                raise Incomplete("legal_files")
            data = result.stdout
        else:
            try:
                with open(os.path.join(ROOT, name), "rb") as handle:
                    data = handle.read()
            except OSError:
                raise Incomplete("legal_files")
        hashes[name] = sha256(data)
    sparkle = [n for n in _legal_cache["app"] if n not in _legal_cache["archive"]]
    if len(sparkle) != 1 or not HEX64.match(_legal_cache["sparkle"]):
        raise Incomplete("legal_files")
    hashes[sparkle[0]] = _legal_cache["sparkle"]
    return hashes


def sparkle_expected():
    result = run_tool("bash", ["-c", 'source "$1"; printf "%s" "$OTTTO_SPARKLE_LICENSE_VERSION"', "gate",
                               "scripts/macos_license_notices.sh"], cwd=ROOT)
    table = load_sparkle_table().get(result.stdout.decode("utf-8"))
    if result.returncode != 0 or not table:
        raise Incomplete("sparkle_table")
    return table


# ---------------------------------------------------------------- profiles

CHECKSUM_SUBJECTS = ("app_dmg", "cli_zip", "service_zip", "sbom", "manifest")


def lane_roles(profile, lane, appcast=None):
    """(required, optional) role sets for a profile and lane."""
    if lane not in LANES:
        raise GateError("lane")
    base = {"app_dmg", "cli_zip", "service_zip", "sbom", "launch_smoke", "manifest", "manifest_sig", "checksums"}
    if lane in ("stable", "manual"):
        base |= {"installer", "formula"}
    if lane == "stable":
        base.add("rc_evidence")
    if profile == "upload":
        return base | {"privacy_receipt"}, set()
    if profile == "publish":
        if lane == "stable":
            if appcast == "absent":
                raise GateError("appcast_lane")
            return base | {"clean_machine_evidence", "appcast"}, set()
        if lane == "manual":
            if appcast == "present":
                raise GateError("appcast_lane")
            return base, set()
        if appcast == "present":
            return base | {"appcast"}, set()
        return base, set() if appcast == "absent" else {"appcast"}
    if profile == "attest":
        if lane == "manual":
            raise GateError("attest_lane")
        subjects = set(checksum_subjects(lane)) | {"checksums"}
        return subjects, set()
    raise GateError("profile")


def checksum_subjects(lane):
    return CHECKSUM_SUBJECTS + (("installer",) if lane in ("stable", "manual") else ())


def list_files(root):
    found = set()
    for directory, dirs, files in os.walk(root):
        for name in files + [d for d in dirs if os.path.islink(os.path.join(directory, d))]:
            found.add(os.path.relpath(os.path.join(directory, name), root))
    return found


def seal(source, dest, roles):
    """Copy role files by no-follow descriptors into a new 0700 folder."""
    parent = os.path.dirname(os.path.abspath(dest))
    st = os.lstat(parent)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise GateError("seal_parent")
    os.mkdir(dest, 0o700)
    for role in sorted(roles):
        rel = ROLE_FILES[role]
        parts = rel.split("/")
        directory = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in parts[:-1]:
                inner = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = inner
            try:
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except OSError:
                raise Incomplete("seal_source")
        finally:
            os.close(directory)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise Incomplete("seal_source")
            target_dir = os.path.join(dest, *parts[:-1])
            os.makedirs(target_dir, 0o700, exist_ok=True)
            out = os.open(os.path.join(target_dir, parts[-1]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(out, "wb") as target:
                for chunk in iter(lambda: handle.read(CHUNK), b""):
                    target.write(chunk)


def freeze(root, policy):
    """Make every file and folder under root immutable (uchg), deepest first."""
    if not hasattr(os, "chflags"):
        if policy.mode == "enforce":
            raise Incomplete("freeze_unavailable")
        return
    for directory, dirs, files in os.walk(root, topdown=False):
        for name in files + dirs:
            path = os.path.join(directory, name)
            os.chflags(path, os.lstat(path).st_flags | stat.UF_IMMUTABLE, follow_symlinks=False)
    os.chflags(root, os.lstat(root).st_flags | stat.UF_IMMUTABLE)


def check_frozen(root, policy):
    if not hasattr(os, "chflags"):
        if policy.mode == "enforce":
            raise Incomplete("freeze_unavailable")
        return
    for directory, dirs, files in os.walk(root):
        for name in [directory] + [os.path.join(directory, n) for n in files + dirs]:
            if not os.lstat(name).st_flags & stat.UF_IMMUTABLE:
                raise Incomplete("not_frozen")


NOTARY_ROLES = ("app_notary_zip", "app_dmg", "cli_zip", "service_zip")


def lane_stages(lane):
    """Gate stages one workflow attempt must pass, in order, before its upload."""
    stages = ["dispatch", "unsigned"] + ["notary:" + r for r in NOTARY_ROLES]
    if lane != "manual":
        stages += ["attest-1", "attest-2"]
    return stages + ["upload"]


def recorded_stages(args, gate):
    """Stage name -> verdict from this attempt's state; every record clean and on this policy and list."""
    stages, attest = {}, 0
    for name in sorted(os.listdir(args.state)) if args.state else []:
        if not (name.startswith("stage-") and name.endswith(".json")):
            continue
        with open(os.path.join(args.state, name), encoding="utf-8") as handle:
            record = json.load(handle)
        profile = record.get("profile")
        if profile == "notary" and len(record.get("roles", [])) == 1:
            stage = "notary:" + record["roles"][0]
        elif profile == "attest":
            attest += 1
            stage = "attest-%d" % attest
        else:
            stage = profile
        if stage in stages or record.get("verdict") != "clean" \
                or record.get("policy_sha256") != gate.policy.sha256 \
                or record.get("markers_sha256") != args.markers_digest:
            raise Incomplete("receipt_stages")
        stages[stage] = "clean"
    stages["upload"] = gate.verdict()
    if sorted(stages) != sorted(lane_stages(args.lane)) or set(stages.values()) != {"clean"}:
        raise Incomplete("receipt_stages")
    return stages


def make_receipt(args, gate, rows, root):
    stages = recorded_stages(args, gate)
    with open(os.path.join(root, ROLE_FILES["manifest"]), "rb") as handle:
        manifest = json.loads(handle.read().decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    materials = manifest.get("supply_chain", {}).get("materials", [])
    app_source = [m.get("commit") for m in materials if m.get("kind") == "private_source"]
    public_source = [m.get("commit") for m in materials if m.get("kind") == "git_repository"]
    app_commit = os.environ.get("OTTTO_MACOS_APP_SOURCE_COMMIT", "")
    source = os.environ.get("GITHUB_SHA", "")
    run_id, attempt = os.environ.get("GITHUB_RUN_ID", ""), os.environ.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[0-9a-f]{40}", app_commit) or app_source != [app_commit] \
            or not re.fullmatch(r"[0-9a-f]{40}", source) or public_source != [source] \
            or not isinstance(manifest.get("version"), str) or not manifest["version"] \
            or not re.fullmatch(r"[1-9][0-9]{0,19}", run_id) or not re.fullmatch(r"[1-9][0-9]{0,4}", attempt):
        raise Incomplete("receipt_inputs")
    return {
        "schema": "ottto.release-privacy-receipt", "schema_version": 1, "workflow": WORKFLOW,
        "run_id": int(run_id), "run_attempt": int(attempt),
        "source_commit": source, "app_source_commit": app_commit, "lane": args.lane,
        "version": manifest["version"], "policy_sha256": gate.policy.sha256, "markers_sha256": args.markers_digest,
        "stages": stages, "advisory_xattrs": gate.advisory, "files": rows,
    }


def write_state(args, gate, roles):
    if not args.state:
        return
    os.makedirs(args.state, 0o700, exist_ok=True)
    index = len([n for n in os.listdir(args.state) if n.startswith("stage-")])
    record = {"profile": args.profile, "roles": sorted(roles), "verdict": gate.verdict(),
              "policy_sha256": gate.policy.sha256, "markers_sha256": args.markers_digest,
              "advisory_xattrs": gate.advisory, "rows": args.rows}
    with open(os.path.join(args.state, "stage-%02d-%s.json" % (index, args.profile)), "w", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True)


def command_scan(args):
    policy = load_policy()
    markers, digest = load_markers(args, policy)
    args.markers_digest = digest
    if args.host_literals == "off" and policy.mode == "enforce":
        raise GateError("host_literals_required")
    if args.host_literals != "off":
        markers = with_host_literals(markers)
    scratch = args.scratch or os.environ.get("OTTTO_PRIVACY_WORK") or (
        "/private/tmp" if os.path.isdir("/private/tmp") else None)
    gate = Gate(policy, markers, args.profile)
    for value in [scratch or "", os.path.abspath(args.root) if args.seal_from else ""]:
        if value:
            probe = Gate(policy, markers, "probe")
            probe.scan_text(value, Representation("scratch", "scratch"), 0)
            if probe.findings:
                raise GateError("scratch_not_neutral")
    gate.scratch = tempfile.mkdtemp(prefix="gate.", dir=scratch)
    try:
        roles, context, rows = run_profile(args, gate, policy)
    except Incomplete as error:
        gate.incomplete_input(args.profile, str(error))
        roles, rows = [], []
    finally:
        remove_tree(gate.scratch)
    args.rows = rows
    write_state(args, gate, roles)
    response = {"schema": "ottto.release-privacy-scan", "schema_version": 1, "profile": args.profile,
                "lane": args.lane, "verdict": gate.verdict(), "policy_sha256": policy.sha256,
                "markers_sha256": digest, "roles": rows, "findings": dict(sorted(gate.findings.items())),
                "advisory_xattrs": gate.advisory, "incomplete": gate.incomplete}
    for (role, cls, code), count in sorted(gate.diagnostics.items()):
        print("privacy-gate: profile=%s role=%s class=%s code=%s count=%d" % (args.profile, role, cls, code, count),
              file=sys.stderr)
    for name, count in sorted(gate.advisory.items()):
        if count:
            print("privacy-gate: profile=%s advisory=%s count=%d" % (args.profile, name, count), file=sys.stderr)
    if gate.loose_xattrs:
        print("privacy-gate: profile=%s loose_xattrs count=%d" % (args.profile, gate.loose_xattrs), file=sys.stderr)
    print("privacy-gate: profile=%s verdict=%s" % (args.profile, gate.verdict()), file=sys.stderr)
    payload = (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if args.response_fd is not None:
        os.write(args.response_fd, payload)
        os.close(args.response_fd)
    else:
        sys.stdout.buffer.write(payload)
        sys.stdout.flush()
    return {"clean": EXIT_CLEAN, "blocked": EXIT_BLOCKED, "incomplete": EXIT_INCOMPLETE}[gate.verdict()]


def run_profile(args, gate, policy):
    profile, context = args.profile, {}
    if profile == "dispatch":
        return scan_dispatch(gate), context, []
    if profile == "logs":
        return scan_logs(gate, args.root, policy), context, []
    if profile == "unsigned":
        required, optional = {"app_bundle", "cli_binary", "service_binary"}, set()
        context["signed"] = False
    elif profile == "notary":
        if args.role not in ("app_notary_zip", "app_dmg", "cli_zip", "service_zip"):
            raise GateError("notary_role")
        required, optional = {args.role}, set()
        if args.role == "app_notary_zip":
            if not args.expect_app:
                raise GateError("expect_app")
            context["expect_app"] = args.expect_app
    else:
        required, optional = lane_roles(profile, args.lane, args.appcast)
    if args.seal_from:
        source_present = {r for r in required | optional
                          if os.path.lexists(os.path.join(args.seal_from, ROLE_FILES[r]))}
        if required - source_present - {"privacy_receipt"}:
            raise Incomplete("missing_role")
        seal(args.seal_from, args.root, source_present - {"privacy_receipt"})
        freeze_later = True
    else:
        freeze_later = False
    present = list_files(args.root)
    expected = {ROLE_FILES[r]: r for r in required | optional}
    if profile == "unsigned":
        present = {p for p in present if not p.startswith("Ottto.app/")} | ({"Ottto.app"} if os.path.isdir(
            os.path.join(args.root, "Ottto.app")) else set())
    unexpected = present - set(expected) - ({ROLE_FILES["privacy_receipt"]} if profile == "upload" else set())
    if unexpected:
        gate.finding(profile, "structure", "unexpected_file", len(unexpected))
    roles = sorted(expected[p] for p in present if p in expected)
    if (required - {"privacy_receipt"}) - set(roles):
        raise Incomplete("missing_role")
    if profile == "unsigned":
        check_frozen(os.path.join(args.root, "Ottto.app"), policy)
        for role in ("cli_binary", "service_binary"):
            check_frozen(os.path.join(args.root, ROLE_FILES[role]), policy)
    elif freeze_later:
        for role in roles:
            if role != "privacy_receipt":
                freeze(os.path.join(args.root, ROLE_FILES[role]), policy)
    files = {}
    for role in roles:
        if role in ("app_dmg", "cli_zip", "service_zip", "sbom", "manifest", "installer"):
            files[ROLE_FILES[role]] = file_sha256(os.path.join(args.root, ROLE_FILES[role]))
    if "manifest" in roles:
        with open(os.path.join(args.root, ROLE_FILES["manifest"]), "rb") as handle:
            context["manifest"] = handle.read()
    if args.lane:
        context["checksum_names"] = [ROLE_FILES[r] for r in checksum_subjects(args.lane)]
    context["files"] = files
    rows = []
    for role in roles:
        if role == "privacy_receipt":
            continue
        try:
            size, digest = gate.scan_role(role, os.path.join(args.root, ROLE_FILES[role]), context)
        except Incomplete as error:
            gate.incomplete_input(role, str(error))
            continue
        rows.append({"role": role, "path": ROLE_FILES[role], "size": size, "sha256": digest})
    if profile == "upload" and gate.verdict() == "clean":
        receipt = make_receipt(args, gate, rows, args.root)
        path = os.path.join(args.root, ROLE_FILES["privacy_receipt"])
        if os.path.lexists(path):
            raise Incomplete("receipt_exists")
        with open(path, "x", encoding="utf-8") as handle:
            json.dump(receipt, handle, sort_keys=True, indent=2)
            handle.write("\n")
        size, digest = gate.scan_role("privacy_receipt", path, context)
        rows.append({"role": "privacy_receipt", "path": ROLE_FILES["privacy_receipt"], "size": size,
                     "sha256": digest})
        roles = sorted(set(roles) | {"privacy_receipt"})
    if freeze_later:
        freeze(args.root, policy)
        check_frozen(args.root, policy)
        for row in rows:
            if file_sha256(os.path.join(args.root, row["path"])) != row["sha256"]:
                raise Incomplete("seal_changed")
    return roles, context, sorted(rows, key=lambda r: r["role"])


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_dispatch(gate):
    """Workflow inputs (OTTTO_DISPATCH_<NAME>): every value searched; fixed shapes checked."""
    values = {name: os.environ.get("OTTTO_DISPATCH_" + name, "") for name in DISPATCH_INPUTS}
    for index, name in enumerate(DISPATCH_INPUTS):
        rep = Representation("dispatch", ("dispatch", name))
        gate.scan_bytes(values[name].encode("utf-8"), rep)
        gate.scan_text(values[name], rep, index)
        if "%" in values[name]:
            gate.scan_text(url_decoded(values[name]), rep, index, "url")
    channel, version = values["CHANNEL"], values["VERSION"]
    if channel not in ("stable-candidate", "stable") or not re.fullmatch(r"[0-9]+(\.[0-9]+){1,3}(-rc[0-9]+)?", version) \
            or values["ARTIFACT_BASE_URL"] != "https://install.ottto.net/ottto-local-platform/releases/%s/%s" % (
                channel, version):
        gate.finding("dispatch", "structure", "dispatch_shape")
    return ["dispatch"]


def scan_logs(gate, root, policy):
    """Job logs: every text searched; the runner's Machine name line is counted on its own."""
    roles = []
    for index, rel in enumerate(sorted(list_files(root))):
        path = os.path.join(root, rel)
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_FILE:
            raise Incomplete("log_type")
        with open(path, "rb") as handle:
            data = handle.read()
        try:
            text = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Incomplete("log_encoding")
        label = "log%d" % index
        machine_lines = [m.span() for m in MACHINE_NAME_LINE.finditer(text)]
        rest = MACHINE_NAME_LINE.sub("", text)
        gate.scan_plain_text(rest.encode("utf-8"), Representation(label, (label, "rest")))
        gate.scan_name(rel, Representation(label, (label, "name")), 0)
        for number, (start, end) in enumerate(machine_lines):
            probe = Gate(policy, gate.markers, "probe")
            probe.scan_plain_text(text[start:end].encode("utf-8"), Representation(label, "line"))
            if probe.findings or probe.incomplete:
                if policy.accept_machine_name_line:
                    gate.diagnostics[(label, "host_runner_line", "accepted")] = 1
                else:
                    gate.finding(label, "host_runner_line", "machine_name")
        roles.append(label)
    return roles


def command_markers(args):
    path = args.store or DEFAULT_STORE
    markers, digest = parse_markers(read_store(path))
    counts = {}
    for marker in markers:
        counts[marker.cls] = counts.get(marker.cls, 0) + 1
    print("markers: ok literals=%d %s markers_sha256=%s" % (
        len(markers), " ".join("%s=%d" % kv for kv in sorted(counts.items())), digest))
    return EXIT_CLEAN


def command_policy(_args):
    policy = load_policy()
    print("policy: ok mode=%s advisory=%s leaf_pins=%d policy_sha256=%s" % (
        policy.mode, ",".join(sorted(policy.advisory)) or "none", len(policy.leaf), policy.sha256))
    return EXIT_CLEAN


def command_leaf(args):
    """SHA-256 of the leaf certificate of a signed file, for the policy's leaf_sha256."""
    if sys.platform != "darwin":
        raise GateError("leaf_requires_macos")
    work = tempfile.mkdtemp(dir="/private/tmp")
    parent, name = os.path.split(os.path.abspath(args.path))
    try:
        run_tool("codesign", ["-d", "--extract-certificates=" + os.path.join(work, "cert"), name],
                 cwd=parent, check=True)
        with open(os.path.join(work, "cert0"), "rb") as handle:
            print(sha256(handle.read()))
    finally:
        remove_tree(work)
    return EXIT_CLEAN


def mask_escape(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def command_register_masks(_args):
    """Register every literal and host string as an Actions log mask; create the neutral work folder."""
    if not in_release_workflow():
        raise GateError("masks_outside_release_workflow")
    policy = load_policy()
    if policy.mode != "enforce":
        raise GateError("policy_mode")
    env_value = os.environ.pop(MARKERS_ENV, None)
    if env_value is None:
        raise GateError("markers_missing")
    markers, digest = parse_markers(env_value.encode("utf-8"))
    if digest != policy.markers_sha256:
        raise GateError("markers_digest_mismatch")
    values = set()
    for marker in with_host_literals(markers):
        value = marker.value
        for form in (value, value.casefold(), value.lower(), value.upper()):
            values.add(unicodedata.normalize("NFC", form))
            values.add(unicodedata.normalize("NFD", form))
    for value in sorted(values):
        sys.stdout.write("::add-mask::%s\n" % mask_escape(value))
    sys.stdout.flush()
    work = tempfile.mkdtemp(prefix="ottto-privacy.", dir="/private/tmp" if os.path.isdir("/private/tmp") else None)
    probe = Gate(policy, with_host_literals(markers), "probe")
    probe.scan_text(work, Representation("work", "work"), 0)
    if probe.findings:
        raise GateError("scratch_not_neutral")
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as handle:
        handle.write("OTTTO_PRIVACY_WORK=%s\n" % work)
    print("privacy-gate: masks registered count=%d policy_sha256=%s" % (len(values), policy.sha256), file=sys.stderr)
    return EXIT_CLEAN


def command_roles(args):
    required, optional = lane_roles(args.profile, args.lane, args.appcast)
    print(json.dumps({"profile": args.profile, "lane": args.lane,
                      "required": {r: ROLE_FILES[r] for r in sorted(required)},
                      "optional": {r: ROLE_FILES[r] for r in sorted(optional)}}, sort_keys=True))
    return EXIT_CLEAN


def command_check_record(args):
    """The prepared unsigned tree still has the inventory its clean unsigned scan recorded."""
    records = []
    for name in sorted(os.listdir(args.state)):
        if name.startswith("stage-") and name.endswith("-unsigned.json"):
            with open(os.path.join(args.state, name), encoding="utf-8") as handle:
                records.append(json.load(handle))
    if not records or records[-1]["verdict"] != "clean":
        raise GateError("unsigned_record")
    gate = Gate(Policy(json.dumps({"version": 1, "mode": "rehearsal", "advisory_xattrs": [],
                                   "leaf_sha256": ["0" * 64], "markers_sha256": "0" * 64})),
                [Marker("\0unused\0", "private")], "record")
    current = []
    for row in records[-1]["rows"]:
        path = os.path.join(args.root, row["path"])
        if row["role"] == "app_bundle":
            inventory = {}
            gate.walk_tree(path, "record", False, None, lambda r, t: True, None, inventory)
            size, digest = inventory_row(inventory)
        else:
            size, digest = os.path.getsize(path), file_sha256(path)
        current.append({"role": row["role"], "path": row["path"], "size": size, "sha256": digest})
    if current != records[-1]["rows"]:
        raise GateError("unsigned_changed")
    print("privacy-gate: unsigned record matches", file=sys.stderr)
    return EXIT_CLEAN


def main(argv=None):
    parser = argparse.ArgumentParser(description="Release privacy gate (docs/release-verification.md).")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("--profile", choices=PROFILES, required=True)
    scan.add_argument("--root", default=".")
    scan.add_argument("--lane", choices=LANES)
    scan.add_argument("--appcast", choices=("present", "absent"))
    scan.add_argument("--role")
    scan.add_argument("--expect-app")
    scan.add_argument("--seal-from")
    scan.add_argument("--markers-fd", type=int)
    scan.add_argument("--markers-store")
    scan.add_argument("--response-fd", type=int)
    scan.add_argument("--state")
    scan.add_argument("--scratch")
    scan.add_argument("--host-literals", choices=("on", "off"), default="on")
    markers = sub.add_parser("markers")
    markers.add_argument("--store")
    markers.add_argument("--owner-store-v3", action="store_true")
    sub.add_parser("policy")
    leaf = sub.add_parser("leaf")
    leaf.add_argument("path")
    sub.add_parser("register-masks")
    roles = sub.add_parser("roles")
    roles.add_argument("--profile", choices=("attest", "upload", "publish"), required=True)
    roles.add_argument("--lane", choices=LANES, required=True)
    roles.add_argument("--appcast", choices=("present", "absent"))
    record = sub.add_parser("check-record")
    record.add_argument("--state", required=True)
    record.add_argument("--root", required=True)
    args = parser.parse_args(argv)
    if args.command == "scan" and args.profile in ("attest", "upload", "publish") and not args.lane:
        parser.error("--lane is required for this profile")
    handlers = {"scan": command_scan, "markers": command_markers, "policy": command_policy,
                "leaf": command_leaf, "register-masks": command_register_masks, "roles": command_roles,
                "check-record": command_check_record}
    try:
        return handlers[args.command](args)
    except GateError as error:
        print("privacy-gate: error code=%s" % error, file=sys.stderr)
        return EXIT_USAGE
    except Incomplete as error:
        print("privacy-gate: incomplete code=%s" % error, file=sys.stderr)
        return EXIT_INCOMPLETE
    except Exception as error:  # fixed label only: never a path or a value
        print("privacy-gate: error code=internal_%s" % type(error).__name__, file=sys.stderr)
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    sys.exit(main())
