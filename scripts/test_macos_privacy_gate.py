#!/usr/bin/env python3
"""Tests for scripts/macos_privacy_gate.py. Synthetic markers and fixtures only."""

import argparse
import hashlib
import importlib.util
import io
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GATE = os.path.join(HERE, "macos_privacy_gate.py")
_spec = importlib.util.spec_from_file_location("macos_privacy_gate", GATE)
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)

ID_LINE = "id:" + "0" * 31 + "1"
PRIVATE = "zyxq-private-value"
OWNER = "Zyxq Example Holder"
SIGNER = "Qwvz Signing Name"
# Home and temp roots are assembled at run time so this file carries none.
HOME_ROOT = "/" + "Us" + "ers/"
TEMP_ROOT = "/var/" + "fold" + "ers/"


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def store(*lines):
    return ("\n".join((ID_LINE,) + lines) + "\n").encode("utf-8")


def policy_text(digest, **extra):
    value = {"version": 1, "mode": "rehearsal", "advisory_xattrs": [], "leaf_sha256": ["a" * 64],
             "markers_sha256": digest}
    value.update(extra)
    return json.dumps(value)


def make_gate(*lines, **extra):
    markers, digest = g.parse_markers(store(*(lines or ("private-default-value",))))
    gate = g.Gate(g.Policy(policy_text(digest, **extra)), markers, "test")
    gate.scratch = tempfile.mkdtemp()
    return gate


def rep(**kw):
    return g.Representation("role", "key", **kw)


def macho(cpu=g.CPU_ARM64, uuid=b"\x11" * 16, payload=b"", stab=False, dwarf=False):
    strings = b"\0radr://5614542\0src/main.o\0"
    symbols = struct.pack("<IBBHQ", 1, 0x3C, 0, 0, 0)  # B's allowed OPT record
    if stab:
        symbols += struct.pack("<IBBHQ", 16, 0x66, 0, 0, 0)  # N_OSO debug map entry
    commands = struct.pack("<II16s", 0x1B, 24, uuid)
    commands += struct.pack("<II16sQQQQiiII", 0x19, 72, b"__DWARF" if dwarf else b"__TEXT", 0, 0, 0, 0, 0, 0, 0, 0)
    symtab_size = 24
    symoff = 32 + len(commands) + symtab_size
    stroff = symoff + len(symbols)
    commands += struct.pack("<IIIIII", 0x02, 24, symoff, len(symbols) // 16, stroff, len(strings))
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, 0, 2, 3, len(commands), 0, 0)
    return header + commands + symbols + strings + payload


def fat(slices):
    align = 14
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    body, offset, table = b"", 1 << align, b""
    for cpu, data in slices:
        table += struct.pack(">IIIII", cpu, 0, offset, len(data), align)
        pad = (-(offset + len(data))) % (1 << align)
        body += data + b"\0" * pad
        offset += len(data) + pad
    head = header + table
    return head + b"\0" * ((1 << align) - len(head)) + body


def der(tag, content):
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    size = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(size)]) + size + content


def certificate(serial, issuer):
    tbs = der(0x30, der(0xA0, der(0x02, b"\x02")) + der(0x02, serial) + der(0x30, b"") + issuer + der(0x30, b""))
    return der(0x30, tbs + der(0x30, b"") + der(0x03, b"\0"))


ISSUER = der(0x30, der(0x31, der(0x30, der(0x06, b"\x55\x04\x03") + der(0x0C, b"Synthetic CA"))))


def cms(signer_count=1, trailing=b""):
    issuer = ISSUER
    certs = certificate(b"\x07", issuer) + certificate(b"\x08", issuer)
    signer = der(0x30, der(0x02, b"\x01") + der(0x30, issuer + der(0x02, b"\x08")) + der(0x30, b""))
    signed = der(0x30, der(0x02, b"\x01") + der(0x31, b"") + der(0x30, der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"))
                 + der(0xA0, certs) + der(0x31, signer * signer_count))
    return der(0x30, der(0x06, bytes.fromhex("2a864886f70d010702")) + der(0xA0, signed)) + trailing


class patched_env:
    """Set (or with None, remove) environment variables for a block."""

    def __init__(self, values):
        self.values, self.saved = values, {}

    def __enter__(self):
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def __exit__(self, *_exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class PolicyAndMarkers(unittest.TestCase):
    def test_policy_canonical_digest_and_grammar(self):
        a = g.Policy(policy_text("b" * 64, advisory_xattrs=["provenance", "macl"]))
        b = g.Policy(json.dumps({"markers_sha256": "b" * 64, "leaf_sha256": ["a" * 64], "mode": "rehearsal",
                                 "advisory_xattrs": ["macl", "provenance"], "version": 1,
                                 "accept_runner_machine_name_line": False}))
        self.assertEqual(a.sha256, b.sha256)
        self.assertFalse(a.accept_machine_name_line)
        bad = [
            '{"version":1,"version":1,"mode":"enforce","advisory_xattrs":[],"leaf_sha256":["%s"],"markers_sha256":"%s"}'
            % ("a" * 64, "b" * 64),
            policy_text("b" * 64, extra=1),
            policy_text("b" * 64, version=True),
            policy_text("b" * 64, mode="report"),
            policy_text("b" * 64, advisory_xattrs=["quarantine"]),
            policy_text("b" * 64, leaf_sha256=["a" * 64, "b" * 64, "c" * 64]),
            policy_text("b" * 64, leaf_sha256=["A" * 64]),
            policy_text("B" * 64),
            policy_text("b" * 64, accept_runner_machine_name_line="yes"),
        ]
        for text in bad:
            with self.assertRaises(g.GateError):
                g.Policy(text)

    def test_marker_grammar_and_digest(self):
        markers, digest = g.parse_markers(store(PRIVATE, "# comment", "", "owner:" + OWNER,
                                                "owner+signer:" + SIGNER, "Plain Name: with colon"))
        self.assertEqual([m.cls for m in markers], ["private", "owner", "owner+signer", "private"])
        expected = "".join(line + "\n" for line in (ID_LINE, PRIVATE, "owner:" + OWNER,
                                                    "owner+signer:" + SIGNER, "Plain Name: with colon"))
        self.assertEqual(digest, hashlib.sha256(expected.encode()).hexdigest())
        crlf = store(PRIVATE, "owner:" + OWNER, "owner+signer:" + SIGNER, "Plain Name: with colon")
        crlf_digest = g.parse_markers(crlf.replace(b"\n", b"\r\n"))[1]
        self.assertEqual(crlf_digest, g.parse_markers(crlf)[1])
        for data in (store("abc"), store("vendor:" + PRIVATE), store(PRIVATE, PRIVATE.upper()),
                     store("Café value", "CAFÉ VALUE"), store(" padded value"), store(),
                     store(PRIVATE).replace(b"\n", b"\r", 1), ("id:xyz\n" + PRIVATE + "\n").encode(),
                     store(ID_LINE), store("tab\there")):
            with self.assertRaises(g.GateError):
                g.parse_markers(data)


class Matching(unittest.TestCase):
    def found(self, data, *lines):
        gate = make_gate(*lines or (PRIVATE,))
        gate.scan_bytes(data, rep())
        return gate.findings

    def test_raw_encodings_case_and_normalization(self):
        for data in (b"x" + PRIVATE.encode("utf-16-le"), b"xy" + PRIVATE.upper().encode("utf-16-be"),
                     b"\0" + PRIVATE.upper().encode()):
            self.assertEqual(self.found(data), {"private": 1})
        self.assertEqual(self.found("café marker".encode(), "Café Marker"), {"private": 1})
        self.assertEqual(self.found("STRASSE value".encode(), "straße value"), {"private": 1})
        self.assertEqual(self.found(b"nothing here"), {})

    def test_overlapping_literals_are_independent(self):
        self.assertEqual(self.found(b"--abcdefgh--", "abcdef", "cdefgh"), {"private": 2})

    def test_chunk_boundary(self):
        gate = make_gate(PRIVATE)
        saved = g.CHUNK
        g.CHUNK = 64
        try:
            data = b"a" * 60 + PRIVATE.encode() + b"b" * 200
            gate.scan_stream(io.BytesIO(data), rep())
        finally:
            g.CHUNK = saved
        self.assertEqual(gate.findings, {"private": 1})

    def test_home_path_split_across_chunks(self):
        # A chunk that ends right after the Shared folder's name cannot see that the name goes on.
        saved = g.CHUNK
        g.CHUNK = 64
        try:
            data = b"x" * (64 - len(HOME_ROOT + "Shared")) + (HOME_ROOT + "Sharedperson/lib").encode()
            gate = make_gate(PRIVATE)
            gate.scan_bytes(data, rep())
            self.assertEqual(gate.findings, {"path": 1})
            gate = make_gate(PRIVATE)
            gate.scan_stream(io.BytesIO(data), rep())
            self.assertEqual(gate.findings, {"path": 1})
        finally:
            g.CHUNK = saved

    def test_generic_paths(self):
        self.assertEqual(self.found((HOME_ROOT + "jdoe/lib").encode()), {"path": 1})
        self.assertEqual(self.found((HOME_ROOT + "J Doe").encode("utf-16-le")), {"path": 1})
        self.assertEqual(self.found((TEMP_ROOT + "ab").encode()), {"path": 1})
        self.assertEqual(self.found((HOME_ROOT + "Shared2/x").encode()), {"path": 1})
        self.assertEqual(self.found((HOME_ROOT + "Shared/x").encode()), {})
        self.assertEqual(self.found((HOME_ROOT + "\0").encode()), {})

    def test_typed_json_plist_xml(self):
        gate = make_gate(PRIVATE)
        escaped = "".join("\\u%04x" % ord(c) for c in PRIVATE)
        gate.scan_json(('{"notes": "%s"}' % escaped).encode(), rep())
        self.assertEqual(gate.findings, {"private": 1})
        gate = make_gate(PRIVATE)
        quoted = "".join("%%%02X" % ord(c) for c in PRIVATE)
        gate.scan_json(('{"download_url": "https://example.invalid/%s"}' % quoted).encode(), rep())
        self.assertEqual(gate.findings, {"private": 1})
        with self.assertRaises(g.Incomplete):
            make_gate(PRIVATE).scan_json(b'{"a": 1, "a": 2}', rep())
        gate = make_gate(PRIVATE)
        gate.scan_plist(plistlib.dumps({"blob": PRIVATE.encode()}), rep())
        self.assertEqual(gate.findings, {"private": 1})
        with self.assertRaises(g.Incomplete):
            make_gate(PRIVATE).scan_xml(b'<!DOCTYPE x [<!ENTITY e "v">]><rss>&e;</rss>', rep())

    def test_signer_and_legal_omissions(self):
        lines = (PRIVATE, "owner:" + OWNER, "signer:" + "Signer Alias One", "owner+signer:" + SIGNER)
        data = " ".join((PRIVATE, OWNER, "Signer Alias One", SIGNER)).encode()
        gate = make_gate(*lines)
        gate.scan_bytes(data, rep(signed=True))
        self.assertEqual(gate.findings, {"private": 1, "owner": 1})
        gate = make_gate(*lines)
        gate.scan_bytes(data, rep(legal=True))
        self.assertEqual(gate.findings, {"private": 1, "signer": 1})
        gate = make_gate(*lines)
        gate.scan_bytes(data, rep())
        self.assertEqual(gate.findings, {"private": 1, "owner": 1, "signer": 1, "owner+signer": 1})

    def test_legal_file_needs_the_exact_bytes(self):
        notice = ("Copyright " + OWNER + "\n").encode()
        # Changed bytes lose the exception; approved bytes still report every non-owner marker.
        with_private = notice + PRIVATE.encode()
        for content, approved, expected in ((notice, notice, {}), (notice + b"x", notice, {"owner": 1}),
                                            (with_private, with_private, {"private": 1})):
            gate = make_gate(PRIVATE, "owner:" + OWNER)
            gate.legal_hashes = {"NOTICE": hashlib.sha256(approved).hexdigest()}
            gate.scan_member("Contents/Resources/NOTICE", content, "role", "k", None, "NOTICE")
            self.assertEqual(set(gate.findings), set(expected))


class Formats(unittest.TestCase):
    def test_macho_policy(self):
        gate = make_gate()
        gate.check_macho(macho(), "r", "product")
        gate.check_macho(macho(), "r", "companion")
        self.assertEqual(gate.findings, {})
        for data, slot, code in ((macho(cpu=g.CPU_X86_64), "product", "product_arch"),
                                 (macho(stab=True), "companion", "debug_map"),
                                 (macho(dwarf=True), "product", "debug_sections"),
                                 (macho(), None, "unexpected_macho")):
            gate = make_gate()
            gate.check_macho(data, "r", slot)
            self.assertIn(("r", "structure", code), gate.diagnostics)
        with self.assertRaises(g.Incomplete):
            make_gate().check_macho(macho()[:40], "r", "product")

    def test_sparkle_uuid_table(self):
        arm, intel = b"\x21" * 16, b"\x22" * 16
        data = fat([(g.CPU_ARM64, macho(uuid=arm)), (g.CPU_X86_64, macho(cpu=g.CPU_X86_64, uuid=intel))])
        uuid = lambda raw: "-".join((raw.hex().upper()[:8], raw.hex().upper()[8:12], raw.hex().upper()[12:16],
                                     raw.hex().upper()[16:20], raw.hex().upper()[20:]))
        gate = make_gate()
        gate.sparkle = {("Versions/B/Sparkle", "arm64"): uuid(arm), ("Versions/B/Sparkle", "x86_64"): uuid(intel)}
        gate.check_macho(data, "r", "sparkle:Versions/B/Sparkle")
        self.assertEqual(gate.findings, {})
        gate.sparkle[("Versions/B/Sparkle", "x86_64")] = uuid(arm)
        gate.check_macho(data, "r", "sparkle:Versions/B/Sparkle")
        self.assertEqual(gate.findings, {"structure": 1})

    def binary_zip(self, extra=(), method=zipfile.ZIP_DEFLATED, executable=None):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in (("ottto", executable or macho(payload=b"signed")),) + tuple(
                    (n, read_bytes(os.path.join(ROOT, n))) for n in g.legal_names(archive=True)) + extra:
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100755 if name == "ottto" else 0o100644) << 16
                info.compress_type = method
                archive.writestr(info, data)
        return buffer.getvalue()

    def scan_zip(self, data, *lines):
        gate = make_gate(*lines or (PRIVATE,))
        gate.verified_bytes = lambda content, *_: [(0, len(content))]
        gate.scan_binary_zip("cli_zip", data)
        return gate

    def test_zip_framing_and_members(self):
        self.assertEqual(self.scan_zip(self.binary_zip()).findings, {})
        self.assertIn(("cli_zip", "structure", "zip_members"),
                      self.scan_zip(self.binary_zip(extra=(("._ottto", b"x"),))).diagnostics)
        data = self.binary_zip()
        with self.assertRaises(g.Incomplete):
            g.zip_members(data + b"junk")
        local = data.index(b"PK\x03\x04") + 30
        with self.assertRaises(g.Incomplete):
            g.zip_members(data[:local] + b"X" + data[local + 1:])
        with self.assertRaises(g.Incomplete):
            g.zip_members(data + data[-22:])

    def test_zip_payload_and_signed_stored_member(self):
        hidden = self.binary_zip(executable=macho(payload=PRIVATE.encode()))
        self.assertEqual(set(self.scan_zip(hidden).findings), {"private"})
        signed = self.binary_zip(executable=macho(payload=SIGNER.encode()), method=zipfile.ZIP_STORED)
        self.assertEqual(self.scan_zip(signed, "owner+signer:" + SIGNER).findings, {})
        owner_only = self.binary_zip(executable=macho(payload=OWNER.encode()), method=zipfile.ZIP_STORED)
        self.assertEqual(set(self.scan_zip(owner_only, "owner:" + OWNER).findings), {"owner"})

    def test_zip_total_inflated_size_is_bounded(self):
        data = self.binary_zip()
        saved, g.MAX_FILE = g.MAX_FILE, 64
        try:
            with self.assertRaisesRegex(g.Incomplete, "size_limit"):
                g.zip_members(data)
        finally:
            g.MAX_FILE = saved

    def app_tree(self, payload=b"", helper=None):
        top = tempfile.mkdtemp(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)
        self.addCleanup(shutil.rmtree, top)
        app = os.path.join(top, "Ottto.app")
        helper = helper or os.path.join(app, "Contents", "Helpers", "ottto")
        os.makedirs(os.path.dirname(helper))
        with open(helper, "wb") as handle:
            handle.write(macho(payload=payload))
        return top, app

    def app_zip(self, app, entries=()):
        """A ZIP of the tree with Unix modes, plus extra (name, mode, data) entries."""
        buffer = io.BytesIO()
        replaced = {name for name, _mode, _data in entries}
        with zipfile.ZipFile(buffer, "w") as archive:
            for directory, dirs, files in os.walk(app):
                for name in sorted(dirs) + sorted(files):
                    full = os.path.join(directory, name)
                    rel = "Ottto.app/" + os.path.relpath(full, app) + ("/" if name in dirs else "")
                    if rel in replaced:
                        continue
                    info = zipfile.ZipInfo(rel, (2026, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = os.lstat(full).st_mode << 16
                    archive.writestr(info, b"" if name in dirs else read_bytes(full))
            for name, mode, data in entries:
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = mode << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
        return buffer.getvalue()

    def scan_app_zip(self, data, app, verified=True, lines=("owner+signer:" + SIGNER,)):
        gate = make_gate(*lines)
        gate.verified_signature = lambda *_args, _v=verified, **_kw: _v
        work = tempfile.mkdtemp(dir=gate.scratch)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:  # a stand-in for ditto -x off macOS
            for info in archive.infolist():
                if not info.filename.endswith("/"):
                    target = os.path.join(work, info.filename)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as handle:
                        handle.write(archive.read(info))
                    os.chmod(target, (info.external_attr >> 16) & 0o777)
        gate.extract_app_zip = lambda _path: os.path.join(work, "Ottto.app")
        gate.scan_app_zip(None, data, "app_zip", app)
        return gate

    def test_app_zip_omits_signer_only_in_verified_tree(self):
        _top, app = self.app_tree(payload=SIGNER.encode())
        data = self.app_zip(app)
        for verified, expected in ((True, set()), (False, {"owner+signer"})):
            gate = self.scan_app_zip(data, app, verified)
            self.assertEqual(set(gate.findings), expected, gate.diagnostics)

    def test_app_zip_directory_members_are_empty_typed_and_moded(self):
        _top, app = self.app_tree()
        clean = self.scan_app_zip(self.app_zip(app), app)
        self.assertEqual(clean.findings, {}, clean.diagnostics)
        hidden = PRIVATE.encode() * 50
        cases = (("Ottto.app/Contents/Extra/", 0o040755, hidden, "zip_directory"),   # payload in a directory
                 ("Ottto.app/Contents/Helpers/", 0o040700, b"", "zip_directory"),    # mode differs
                 ("Ottto.app/Contents/Other/", 0o100644, b"", "zip_member_type"),    # slash name, file type
                 ("Ottto.app/Contents/Plain", 0o040755, b"", "zip_member_type"))     # directory type, no slash
        for name, mode, data, code in cases:
            gate = self.scan_app_zip(self.app_zip(app, ((name, mode, data),)), app, lines=(PRIVATE,))
            self.assertIn(("app_zip", "structure", code), gate.diagnostics, name)
        gate = self.scan_app_zip(self.app_zip(app, (("Ottto.app/Contents/Extra/", 0o040755, hidden),)), app,
                                 lines=(PRIVATE,))
        self.assertIn("private", gate.findings)

    def test_app_zip_extracted_tree_must_match(self):
        _top, app = self.app_tree()
        data = self.app_zip(app)
        gate = make_gate()
        gate.verified_signature = lambda *_a, **_k: True
        other = os.path.join(tempfile.mkdtemp(dir=gate.scratch), "Ottto.app")
        os.makedirs(os.path.join(other, "Contents", "Helpers"))
        with open(os.path.join(other, "Contents", "Helpers", "ottto"), "wb") as handle:
            handle.write(macho(payload=b"different"))
        gate.extract_app_zip = lambda _path: other
        gate.scan_app_zip(None, data, "app_zip", app)
        self.assertIn(("app_zip", "structure", "zip_extracted"), gate.diagnostics)

    def test_app_zip_layout_is_checked_before_extraction(self):
        _top, app = self.app_tree()
        cases = (("Ottto.app/Contents/Escape", 0o120755, b"../../outside"),          # link outside Sparkle
                 ("Ottto.app/Contents/Helpers/extra", 0o100644, b"x"),                 # inventory differs
                 ("Ottto.app/Contents/Helpers/ottto", 0o100755, macho(payload=b"z")))  # other bytes
        for name, mode, data in cases:
            gate = make_gate(PRIVATE)
            gate.verified_signature = lambda *_a, **_k: True

            def refuse(_path):
                raise AssertionError("ditto must not see this archive")

            gate.extract_app_zip = refuse
            gate.scan_app_zip(None, self.app_zip(app, ((name, mode, data),)), "app_zip", app)
            self.assertIn(("app_zip", "structure", "zip_layout"), gate.diagnostics, name)

    @unittest.skipUnless(sys.platform == "darwin" and os.path.exists("/usr/bin/ditto"), "native ditto")
    def test_real_ditto_app_zip_is_accepted(self):
        top, app = self.app_tree(payload=SIGNER.encode())
        zip_path = os.path.join(top, "ottto-app-notary.zip")
        subprocess.run(["/usr/bin/ditto", "-c", "-k", "--keepParent", "--norsrc", "--noextattr", app, zip_path],
                       check=True)
        gate = make_gate("owner+signer:" + SIGNER)
        gate.verified_signature = lambda *_a, **_k: True
        gate.scan_app_zip(zip_path, read_bytes(zip_path), "app_zip", app)
        self.assertEqual((gate.findings, gate.incomplete), ({}, 0), gate.diagnostics)

    def test_signer_omission_only_in_each_verified_slice(self):
        arm, intel = macho(payload=SIGNER.encode()), macho(cpu=g.CPU_X86_64, payload=SIGNER.encode())
        data = bytearray(fat([(g.CPU_ARM64, arm), (g.CPU_X86_64, intel)]))
        slices = g.macho_slices(bytes(data))
        padding = slices[0][1] + slices[0][2]  # fat padding after the first slice
        data[padding:padding + len(SIGNER)] = SIGNER.encode()
        data = bytes(data)
        for failing, expected in ((None, 1), ("x86_64", 3)):
            gate = make_gate("owner+signer:" + SIGNER)
            calls = []

            def verify(_path, _role, deep=False, arch=None, _failing=failing):
                calls.append(arch)
                return arch != _failing

            gate.verified_signature = verify
            intervals = gate.verified_intervals("unused", "r", data)
            self.assertEqual(calls, ["arm64", "x86_64"][:len(calls)])
            gate.scan_bytes(data, g.Representation("r", "k", intervals=[(lo, hi, True, False) for lo, hi in intervals]))
            # The padding copy always blocks; a failing slice drops every omission.
            self.assertEqual(gate.findings, {"owner+signer": expected}, failing)
        duplicate = fat([(g.CPU_ARM64, macho()), (g.CPU_ARM64, macho(uuid=b"\x33" * 16))])
        with self.assertRaisesRegex(g.Incomplete, "macho_fat_duplicate"):
            g.macho_slices(duplicate)

    def test_binary_property_lists_are_decoded_by_format(self):
        rel = "Contents/Frameworks/Sparkle.framework/Versions/B/Resources/en.lproj/Sparkle.strings"
        # Found only after decoding: the binary plist stores this as UTF-16BE with a sharp s.
        data = plistlib.dumps({"Title": "STRA\u00dfE EXAMPLE"}, fmt=plistlib.FMT_BINARY)
        gate = make_gate("strasse example")
        gate.scan_bytes(data, rep())
        self.assertEqual(gate.findings, {})
        gate.scan_member(rel, data, "r", "k", None)
        self.assertEqual(gate.findings, {"private": 1})
        with self.assertRaisesRegex(g.Incomplete, "plist_parse"):
            make_gate().scan_member(rel, data[:-12], "r", "k", None)

    def test_json_numbers_cover_reserialized_forms(self):
        gate = make_gate("12345000")
        gate.scan_json(b'{"bom": {"version": 1.2345e7}}', rep())
        self.assertEqual(gate.findings, {"private": 1})
        self.assertIn("10000000000000000000000", g.number_forms(1e22))
        # JSON.stringify spells 0.0000001 as 1e-7.
        self.assertIn("1e-7", g.number_forms(0.0000001))
        with self.assertRaisesRegex(g.Incomplete, "json_number"):
            g.number_forms(10 ** 400)

    def test_ecmascript_number_and_json_serializer(self):
        # Number::toString cases (ECMA-262 Number.prototype.toString, radix 10).
        for value, text in ((0.0, "0"), (-0.0, "0"), (1.0, "1"), (100.0, "100"), (123.456, "123.456"),
                            (0.000001, "0.000001"), (1e-7, "1e-7"), (1.5e-7, "1.5e-7"), (-2.5, "-2.5"),
                            (1e20, "100000000000000000000"), (1e21, "1e+21"), (1.2345e22, "1.2345e+22"),
                            (5e-324, "5e-324"), (float(12345678901234567890), "12345678901234567000")):
            self.assertEqual(g.es_number(value), text, value)
        document = g.parse_es_json(b'{"b": "x\\u00e9\\u0001\\ud800", "1": [true, null, 0.0000001], "0": 10}')
        self.assertEqual(g.es_json(document), '{"0":10,"1":[true,null,1e-7],"b":"x\u00e9\\u0001\\ud800"}')
        with self.assertRaisesRegex(g.Incomplete, "json_number"):
            g.es_json(g.parse_es_json(b'{"n": 1e400}'))

    def test_sbom_predicate_is_searched_as_the_attestation_action_sends_it(self):
        # Literals that appear only in JSON.stringify(JSON.parse(file)): the reordered index keys
        # and the reserialized number.
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        path = os.path.join(folder, g.ROLE_FILES["sbom"])
        with open(path, "wb") as handle:
            handle.write(b'{"1": "zq-b", "0": "zq-a", "n": 0.0000001}')
        for literal in ('zq-a","1', '"n":1e-7'):
            gate = make_gate(literal)
            gate.scan_role("sbom", path, {})
            self.assertEqual(set(gate.findings), {"private"}, literal)

    def test_dmg_topology_and_profile(self):
        entities = [{"content-hint": "GUID_partition_scheme", "dev-entry": "/dev/disk4"},
                    {"content-hint": "Apple_APFS", "dev-entry": "/dev/disk4s1"},
                    {"content-hint": g.APFS_CONTAINER_HINT, "dev-entry": "/dev/disk5"},
                    {"content-hint": "41504653-0000-11AA-AA11-00306543ECAC", "dev-entry": "/dev/disk5s1",
                     "volume-kind": "apfs"}]
        self.assertEqual(g.dmg_topology(entities), ("/dev/disk4", "/dev/disk5s1"))
        for broken in (entities[:3], entities + [{"dev-entry": "/dev/disk6"}],
                       [dict(entities[0], **{"content-hint": "FDisk_partition_scheme"})] + entities[1:],
                       entities[:3] + [dict(entities[3], **{"dev-entry": "/dev/disk7s1"})]):
            with self.assertRaisesRegex(g.Incomplete, "dmg_topology"):
                g.dmg_topology(broken)
        info = {"Format": "UDZO", "Segments": ["one"], "Properties": {"Encrypted": False, "Compressed": True},
                "Size Information": {"Sector Count": 100, "Total Bytes": 51200},
                "partitions": {"partition-scheme": "GUID", "block-size": 512, "partitions": [
                    {"partition-hint": "MBR", "partition-synthesized": True},
                    {"partition-hint": "Apple_APFS", "partition-filesystems": {"APFS": "Name"}}]}}
        for change, expected in (({}, {}), ({"Format": "UDRW"}, {"structure": 1}),
                                 ({"Segments": ["one", "two"]}, {"structure": 1})):
            gate = make_gate()
            output = argparse.Namespace(returncode=0, stdout=plistlib.dumps(dict(info, **change)), stderr=b"")
            saved, g.run_tool = g.run_tool, lambda *_a, **_k: output
            try:
                self.assertEqual(gate.dmg_profile("x.dmg", "/", "app_dmg"), 51200)
            finally:
                g.run_tool = saved
            self.assertEqual(gate.findings, expected)
        missing = argparse.Namespace(returncode=0, stdout=plistlib.dumps({"Format": "UDZO"}), stderr=b"")
        saved, g.run_tool = g.run_tool, lambda *_a, **_k: missing
        try:
            with self.assertRaisesRegex(g.Incomplete, "dmg_imageinfo"):
                make_gate().dmg_profile("x.dmg", "/", "app_dmg")
        finally:
            g.run_tool = saved

    @unittest.skipUnless(sys.platform == "darwin" and os.path.exists("/usr/bin/hdiutil"), "native hdiutil")
    def test_native_dmg_profile_topology_and_read(self):
        top = tempfile.mkdtemp(dir="/private/tmp")
        self.addCleanup(g.remove_tree, top)
        source = os.path.join(top, "src")
        helper = os.path.join(source, "Ottto.app", "Contents", "Helpers", "ottto")
        os.makedirs(os.path.dirname(helper))
        with open(helper, "wb") as handle:
            handle.write(macho())
        os.symlink("/Applications", os.path.join(source, "Applications"))

        def image(name, filesystem):
            path = os.path.join(top, name)
            subprocess.run(["/usr/bin/hdiutil", "create", "-quiet", "-fs", filesystem, "-format", "UDZO",
                            "-srcfolder", source, "-volname", "Synthetic", path], check=True)
            return path

        apfs = image("apfs.dmg", "APFS")
        gate = make_gate(PRIVATE)
        gate.verified_signature = lambda *_a, **_k: False
        gate.scan_dmg(apfs, "app_dmg")
        self.assertEqual(gate.incomplete, 0, gate.diagnostics)
        codes = {code for (_role, cls, code) in gate.diagnostics if cls == "structure"}
        self.assertNotIn("dmg_profile", codes)
        self.assertNotIn("dmg_root", codes)
        # A decoded disk shorter or longer than the image metadata says is incomplete.
        gate = make_gate(PRIVATE)
        gate.verified_signature = lambda *_a, **_k: False
        gate.dmg_profile = lambda *_a: 512
        with self.assertRaisesRegex(g.Incomplete, "dmg_read_size"):
            gate.scan_dmg(apfs, "app_dmg")
        # Another filesystem profile is refused and never mounted.
        gate = make_gate(PRIVATE)
        gate.verified_signature = lambda *_a, **_k: False
        with self.assertRaisesRegex(g.Incomplete, "dmg_topology"):
            gate.scan_dmg(image("hfs.dmg", "HFS+"), "app_dmg")
        self.assertIn(("app_dmg", "structure", "dmg_profile"), gate.diagnostics)

    def test_cms_structure(self):
        self.assertEqual(g.cms_signer_certificate(cms()), certificate(b"\x08", ISSUER))
        for blob in (cms(signer_count=2), cms(trailing=b"\0")):
            with self.assertRaises(g.Incomplete):
                g.cms_signer_certificate(blob)


class ReceiptAndContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)
        self.addCleanup(g.remove_tree, self.tmp)

    def state(self, gate, digest, lane, verdicts=None, rows=None, name=None):
        state = os.path.join(self.tmp, name or "state-" + lane)
        os.mkdir(state)
        for stage in g.lane_stages(lane)[:-1]:
            record = {"stage": stage, "verdict": (verdicts or {}).get(stage, "clean"),
                      "policy_sha256": gate.policy.sha256, "markers_sha256": digest,
                      "rows": (rows or {}).get(stage, [])}
            with open(g.stage_path(state, stage), "w") as handle:
                json.dump(record, handle)
        return state

    def test_receipt_stages_and_types(self):
        gate = make_gate(PRIVATE)
        digest = gate.policy.markers_sha256
        for lane in g.LANES:
            args = argparse.Namespace(state=self.state(gate, digest, lane), lane=lane, markers_digest=digest)
            self.assertEqual(sorted(g.recorded_stages(args, gate)), sorted(g.lane_stages(lane)))
        manifest = os.path.join(self.tmp, g.ROLE_FILES["manifest"])
        with open(manifest, "w") as handle:
            json.dump({"version": "1.2.3-rc1", "supply_chain": {"materials": [
                {"kind": "private_source", "commit": "b" * 40}, {"kind": "git_repository", "commit": "c" * 40}]}},
                handle)
        environment = {"OTTTO_MACOS_APP_SOURCE_COMMIT": "b" * 40, "GITHUB_SHA": "c" * 40,
                       "GITHUB_RUN_ID": "123456", "GITHUB_RUN_ATTEMPT": "2"}
        with patched_env(environment):
            receipt = g.make_receipt(args, gate, [], self.tmp)
        self.assertEqual((receipt["run_id"], receipt["run_attempt"], receipt["lane"]), (123456, 2, args.lane))
        self.assertEqual(set(receipt["stages"].values()), {"clean"})
        self.assertIn("notary:app_notary_zip", receipt["stages"])

    def test_receipt_refuses_missing_blocked_foreign_or_rotated_stages(self):
        gate = make_gate(PRIVATE)
        digest = gate.policy.markers_sha256
        missing = self.state(gate, digest, "stable")
        os.remove(g.stage_path(missing, "attest-2"))
        foreign = self.state(gate, digest, "manual")
        shutil.copy(g.stage_path(missing, "attest-1"), g.stage_path(foreign, "attest-1"))
        cases = [argparse.Namespace(state=missing, lane="stable", markers_digest=digest),
                 argparse.Namespace(state=self.state(gate, digest, "candidate", {"notary:app_dmg": "blocked"}),
                                    lane="candidate", markers_digest=digest),
                 argparse.Namespace(state=foreign, lane="manual", markers_digest=digest),
                 argparse.Namespace(state=self.state(gate, digest, "stable", name="rotated"), lane="stable",
                                    markers_digest="d" * 64)]
        for args in cases:
            with self.assertRaisesRegex(g.Incomplete, "receipt_stages"):
                g.recorded_stages(args, gate)

    def test_boundaries_bind_the_same_bytes(self):
        gate = make_gate(PRIVATE)
        digest = gate.policy.markers_sha256

        def rows(**changed):
            return [{"role": r, "path": g.ROLE_FILES[r], "size": 1, "sha256": changed.get(r, "a" * 64)}
                    for r in g.checksum_subjects("stable") + ("checksums",)]

        earlier = {"notary:cli_zip": rows(), "notary:service_zip": rows(), "attest-1": rows(), "attest-2": rows()}
        state = self.state(gate, digest, "stable", rows=earlier)
        args = argparse.Namespace(state=state, lane="stable", markers_digest=digest)
        g.check_bindings(args, gate, "attest-1", rows())
        # The binder changes the manifest and checksums between the two attestations; nothing else.
        g.check_bindings(args, gate, "attest-2", rows(manifest="b" * 64, checksums="b" * 64))
        g.check_bindings(args, gate, "upload", rows())
        self.assertEqual(gate.verdict(), "clean")
        # A subject replaced after the first attestation, with checksums refreshed to match.
        for stage, changed in (("attest-2", {"cli_zip": "c" * 64, "checksums": "c" * 64}),
                               ("attest-1", {"service_zip": "c" * 64}),
                               ("upload", {"sbom": "c" * 64, "checksums": "c" * 64}),
                               ("upload", {"checksums": "c" * 64})):
            probe = make_gate(PRIVATE)
            g.check_bindings(args, probe, stage, rows(**changed))
            self.assertEqual(probe.verdict(), "blocked", stage)
            self.assertIn((stage, "structure", "binding_changed"), probe.diagnostics)
        manual = self.state(gate, digest, "manual", rows=earlier)
        probe = make_gate(PRIVATE)
        g.check_bindings(argparse.Namespace(state=manual, lane="manual", markers_digest=digest), probe, "upload",
                         rows(cli_zip="c" * 64))
        self.assertEqual(probe.verdict(), "blocked")
        os.remove(g.stage_path(state, "attest-1"))
        with self.assertRaisesRegex(g.Incomplete, "binding_missing"):
            g.check_bindings(args, make_gate(PRIVATE), "attest-2", rows())

    def test_baseline_pins_the_attempt(self):
        gate = make_gate(PRIVATE)
        digest = gate.policy.markers_sha256
        state = os.path.join(self.tmp, "state")
        attempt = {"GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "1", "OTTTO_RELEASE_LANE": "stable"}
        with patched_env(attempt):
            g.write_baseline(state, gate.policy, digest)
            g.check_baseline(state, gate.policy, digest, "stable")
            for policy, markers, lane in ((gate.policy, "d" * 64, None), (gate.policy, digest, "candidate"),
                                          (g.Policy(policy_text(digest, advisory_xattrs=["macl"])), digest, None)):
                with self.assertRaisesRegex(g.GateError, "baseline_mismatch"):
                    g.check_baseline(state, policy, markers, lane)
        with patched_env(dict(attempt, GITHUB_RUN_ATTEMPT="2")):
            with self.assertRaisesRegex(g.GateError, "baseline_mismatch"):
                g.check_baseline(state, gate.policy, digest)
        enforce = g.Policy(policy_text(digest, mode="enforce"))
        with self.assertRaisesRegex(g.GateError, "baseline_missing"):
            g.check_baseline(os.path.join(self.tmp, "none"), enforce, digest)

    def test_only_the_full_name_alias_takes_a_listed_tag(self):
        saved = g.host_literals
        sharp = "Stra\u00dfe Example"
        listed, digest = g.parse_markers(store("owner+signer:" + SIGNER, "STRASSE EXAMPLE"))
        g.host_literals = lambda: [g.Marker(SIGNER, "user", full_name=True),
                                   g.Marker(SIGNER.upper(), "user", full_name=True),
                                   g.Marker(sharp, "user", full_name=True), g.Marker("synthetic-account", "user"),
                                   g.Marker(SIGNER.lower(), "host")]
        try:
            combined = g.with_host_literals(listed)
        finally:
            g.host_literals = saved
        self.assertEqual([(m.value, m.cls, m.owner, m.signer) for m in combined],
                         [(SIGNER, "owner+signer", True, True), ("STRASSE EXAMPLE", "private", False, False),
                          (SIGNER.upper(), "owner+signer", True, True), (sharp, "private", False, False),
                          ("synthetic-account", "user", False, False), (SIGNER.lower(), "host", False, False)])
        # The full-name spelling is still found in raw bytes, which casefold patterns of the listed form miss.
        gate = g.Gate(g.Policy(policy_text(digest)), combined, "test")
        gate.scan_bytes(sharp.encode("utf-8"), rep(signed=True))
        self.assertEqual(gate.findings, {"private": 1})
        # A host name equal to the signer literal is its own class and blocks in signed bytes.
        gate = g.Gate(g.Policy(policy_text(digest)), combined, "test")
        gate.scan_bytes(SIGNER.encode("utf-8"), rep(signed=True))
        self.assertEqual(gate.findings, {"host": 1})

    def host_strings(self, name, full_name, home="/" + "Us" + "ers/synthetic-home"):
        """host_literals() for a synthetic account on a machine with no host names set."""
        saved = (g.pwd.getpwuid, g.socket.gethostname, g.run_tool)
        entry = argparse.Namespace(pw_name=name, pw_gecos=full_name + ",,,", pw_dir=home)
        no_value = argparse.Namespace(returncode=1, stdout=b"", stderr=b"not set")
        g.pwd.getpwuid = lambda _uid: entry
        g.socket.gethostname = lambda: "localhost"
        g.run_tool = lambda *_a, **_k: no_value
        try:
            with patched_env({"USER": name, "LOGNAME": name, "HOME": home, "RUNNER_NAME": None,
                              "GITHUB_WORKSPACE": None, "RUNNER_TEMP": None, "RUNNER_WORKSPACE": None,
                              "RUNNER_TOOL_CACHE": None, "TMPDIR": None}):
                return g.host_literals()
        finally:
            g.pwd.getpwuid, g.socket.gethostname, g.run_tool = saved

    def test_neutral_release_account_names_are_not_markers(self):
        # The installer text the stable lane generates (the generator's heredoc body).
        generator = read_bytes(os.path.join(HERE, "hosted_native_installer.sh"))
        installer = generator.split(b"<<'INSTALLER'\n", 1)[1].split(b"\nINSTALLER\n", 1)[0]
        self.assertIn(g.NEUTRAL_RELEASE_ACCOUNT[1].lower().encode(), installer.lower())  # the collision
        listed, digest = g.parse_markers(store(PRIVATE, OWNER))
        neutral = self.host_strings(*g.NEUTRAL_RELEASE_ACCOUNT)
        self.assertNotIn(g.NEUTRAL_RELEASE_ACCOUNT[0], [m.value for m in neutral])
        self.assertNotIn(g.NEUTRAL_RELEASE_ACCOUNT[1], [m.value for m in neutral])
        gate = g.Gate(g.Policy(policy_text(digest)), listed + neutral, "test")
        gate.scan_plain_text(installer, g.Representation("installer", "installer"))
        self.assertEqual(gate.findings, {})
        # Another account with the same full name keeps it as a marker, and so would hold.
        other = self.host_strings("synthetic-operator", g.NEUTRAL_RELEASE_ACCOUNT[1])
        gate = g.Gate(g.Policy(policy_text(digest)), listed + other, "test")
        gate.scan_plain_text(installer, g.Representation("installer", "installer"))
        self.assertIn("user", gate.findings)
        # The neutral account with a personal full name keeps that name as a marker.
        personal = self.host_strings(g.NEUTRAL_RELEASE_ACCOUNT[0], "Qwvz Personal Person")
        self.assertIn("Qwvz Personal Person", [m.value for m in personal])
        # On the neutral account, a personal name from the list in personal-data context still blocks,
        # and so does the account's own home path.
        text = installer + ("\n# maintainer: %s <%s>\n" % (OWNER, "/" + "Us" + "ers/synthetic-home/x")).encode()
        gate = g.Gate(g.Policy(policy_text(digest)), listed + neutral, "test")
        gate.scan_plain_text(text, g.Representation("installer", "installer"))
        self.assertEqual(set(gate.findings), {"private", "user", "path"})

    def test_seal_takes_single_regular_files_only(self):
        policy = g.Policy(policy_text("b" * 64))
        for kind in ("fifo", "hard_link", "symlink"):
            source = tempfile.mkdtemp(dir=self.tmp)
            os.chmod(source, 0o700)
            target = os.path.join(source, g.ROLE_FILES["sbom"])
            if kind == "fifo":
                os.mkfifo(target)
            else:
                other = os.path.join(source, "other")
                with open(other, "w") as handle:
                    handle.write("{}")
                (os.link if kind == "hard_link" else os.symlink)(other, target)
            with self.assertRaisesRegex(g.Incomplete, "seal_source"):
                g.seal(source, os.path.join(source, "sealed"), {"sbom"})
        loose = os.path.join(self.tmp, "loose")
        with open(loose, "w") as handle:
            handle.write("x")
        if hasattr(os, "chflags"):
            with self.assertRaisesRegex(g.Incomplete, "not_frozen"):
                g.check_frozen(loose, policy)
            g.freeze(loose, policy)
            g.check_frozen(loose, policy)

    def test_legal_bytes_from_exported_tree(self):
        export = os.path.join(self.tmp, "export")
        os.makedirs(os.path.join(export, "scripts"))
        shutil.copy(os.path.join(ROOT, "scripts", "macos_license_notices.sh"), os.path.join(export, "scripts"))
        names = g.legal_names(archive=True)
        for name in names:
            shutil.copy(os.path.join(ROOT, name), os.path.join(export, name))
        saved_root, saved_cache = g.ROOT, dict(g._legal_cache)
        g.ROOT = export
        g._legal_cache.clear()
        try:
            hashes = g.approved_legal_hashes()
            with open(os.path.join(ROOT, "NOTICE"), "rb") as handle:
                self.assertEqual(hashes["NOTICE"], g.sha256(handle.read()))
            os.remove(os.path.join(export, "NOTICE"))
            with self.assertRaisesRegex(g.Incomplete, "legal_files"):
                g.approved_legal_hashes()
        finally:
            g.ROOT = saved_root
            g._legal_cache.clear()
            g._legal_cache.update(saved_cache)


SETUP_LOG = ("\ufeff2026-01-01T00:00:00.1000000Z Current runner version: '2.300.0'\n"
             "2026-01-01T00:00:00.2000000Z Machine name: '%s'\n"
             "2026-01-01T00:00:00.3000000Z Complete job name: Build\n")
END_LOG = "\ufeff2026-01-01T00:00:09.1000000Z Cleaning up orphan processes\n"
BUILD_LOG = "2026-01-01T00:00:02.0000000Z ##[group]Run make\n2026-01-01T00:00:03.0000000Z done\n"


def job_logs(tmp, name, setup=None, build=BUILD_LOG, end=END_LOG, omit=(), extra=(), system=None, record=None):
    """A job's step folder as the runner's log archive holds it (skipped steps have no file; step
    numbers have gaps) and the job's API record. Returns the logs-profile scan argv."""
    folder = tempfile.mkdtemp(prefix="logs.", dir=tmp)
    steps = [(1, "Set up job", "success", SETUP_LOG % name if setup is None else setup),
             (2, "Checkout", "success", "2026-01-01T00:00:01.0000000Z ##[group]Run actions/checkout\n"),
             (3, "Optional step", "skipped", None),
             (4, "Build", "success", build),
             (7, "Complete job", "success", end)]
    files = [("%d_%s.txt" % (n, step), text) for n, step, _c, text in steps if text is not None and n not in omit]
    files += list(extra) + ([("system.txt", system)] if system is not None else [])
    for rel, text in files:
        os.makedirs(os.path.dirname(os.path.join(folder, rel)), exist_ok=True)
        with open(os.path.join(folder, rel), "w", encoding="utf-8") as handle:
            handle.write(text)
    value = {"id": 1, "run_id": 4242, "run_attempt": 1, "status": "completed", "conclusion": "success",
             "steps": [{"number": n, "name": step, "status": "completed", "conclusion": c}
                       for n, step, c, _text in steps]}
    text = json.dumps(record(value) if record else value)
    path = os.path.join(tmp, "job-%s.json" % os.path.basename(folder))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return ["scan", "--profile", "logs", "--root", folder, "--run-id", "4242", "--run-attempt", "1",
            "--job-record", path]


class LogScan(unittest.TestCase):
    """The logs profile in process, with a host-name class marker (host literals are this
    machine's own strings, so the subprocess tests turn them off)."""
    HOST = "synthetic-host"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)

    def tearDown(self):
        g.remove_tree(self.tmp)

    def scan(self, args, expected_name=HOST, accept=True, extra=()):
        markers = [g.Marker(PRIVATE, "private"), g.Marker(self.HOST, "host")] + list(extra)
        gate = g.Gate(g.Policy(policy_text("b" * 64, accept_runner_machine_name_line=accept)), markers, "logs")
        value = dict(zip(args[1::2], args[2::2]))
        g.scan_logs(gate, value["--root"], gate.policy, expected_name, value["--run-id"],
                    value["--run-attempt"], value["--job-record"])
        return gate

    def test_machine_name_field(self):
        host, tmp = self.HOST, self.tmp
        cases = [
            # (scan argv, admitted name, accept switch, extra markers, verdict)
            (job_logs(tmp, host), None, False, (), "blocked"),       # the name blocks by default
            (job_logs(tmp, host), host, True, (), "clean"),          # host name class, switch, admitted
            (job_logs(tmp, host), "other-host", True, (), "blocked"),  # not the admitted name
            (job_logs(tmp, "neutral-name"), "other-host", False, (), "blocked"),  # unexpected name
            (job_logs(tmp, "neutral-name"), "neutral-name", False, (), "clean"),
            (job_logs(tmp, host, setup=(SETUP_LOG % host) * 2), host, True, (), "blocked"),  # second field
            (job_logs(tmp, host, build=BUILD_LOG + "2026-01-01T00:00:04Z Machine name: '%s'\n" % host),
             host, True, (), "blocked"),                                # a second field in another step
            (job_logs(tmp, host, build=BUILD_LOG + "later " + host + "\n"), host, True, (), "blocked"),
            (job_logs(tmp, host, system="2026-01-01T00:00:00Z queued " + PRIVATE + "\n"), host, True, (),
             "blocked"),                                                # system.txt is searched
            # Inside the admitted value only the host-name literal equal to the whole name passes.
            (job_logs(tmp, host), host, True, (g.Marker("thetic-ho", "private"),), "blocked"),
            (job_logs(tmp, host), host, True, (g.Marker(": 'synth", "private"),), "blocked"),
            (job_logs(tmp, host), host, True, (g.Marker("ic-host'", "private"),), "blocked"),
        ]
        for args, name, accept, extra, verdict in cases:
            gate = self.scan(args, name, accept, extra)
            self.assertEqual(gate.verdict(), verdict, (args, name, accept, gate.diagnostics))
        # An independent literal equal to the admitted value blocks with its own class.
        for marker in (g.Marker(host, "private"), g.Marker(host, "signer", signer=True),
                       g.Marker(host, "owner", owner=True), g.Marker(host, "user"), g.Marker(host, "runner")):
            gate = self.scan(job_logs(tmp, host), extra=(marker,))
            self.assertEqual(gate.verdict(), "blocked", marker.cls)
            self.assertEqual(set(gate.findings), {marker.cls}, gate.diagnostics)
            self.assertIn(("log0", "host_runner_line", "accepted"), gate.diagnostics)

    def test_complete_job_only(self):
        host, tmp = self.HOST, self.tmp

        def steps(change):
            return lambda record: dict(record, steps=change(record["steps"]))

        cases = [
            (job_logs(tmp, host, omit=(2,)), "log_partial"),          # a missing middle step
            (job_logs(tmp, host, omit=(4,)), "log_partial"),
            (job_logs(tmp, host, omit=(7,)), "log_partial"),          # no job end
            (job_logs(tmp, host, extra=(("3_Optional step.txt", "x\n"),)), "log_partial"),  # a skipped step's file
            (job_logs(tmp, host, extra=(("5_Other.txt", "x\n"),)), "log_partial"),           # not in the record
            (job_logs(tmp, host, extra=(("Build/4_Build.txt", "x\n"),)), "log_partial"),
            (job_logs(tmp, host, omit=(2,), extra=(("2_checkout.txt", "x\n"),)), "log_partial"),  # renamed
            (job_logs(tmp, host, setup=SETUP_LOG.replace("Machine name", "Machine") % host), "log_partial"),
            (job_logs(tmp, host, setup="x\n", build=BUILD_LOG + "2026-01-01T00:00:04Z Machine name: 'n1'\n"),
             "log_partial"),                                            # the field outside "Set up job"
            (job_logs(tmp, host, end="2026-01-01T00:00:08Z Cleaning\n"), "log_partial"),
            (job_logs(tmp, host, end=END_LOG + "2026-01-01T00:00:10Z more\n"), "log_partial"),
            (job_logs(tmp, host, end=""), "log_empty"),
            (job_logs(tmp, host, record=lambda r: dict(r, run_id=4243)), "log_run"),
            (job_logs(tmp, host, record=lambda r: dict(r, run_attempt=2)), "log_run"),
            (job_logs(tmp, host, record=lambda r: dict(r, run_attempt="1")), "log_run"),
            (job_logs(tmp, host, record=lambda r: dict(r, status="in_progress")), "log_record"),
            (job_logs(tmp, host, record=steps(lambda s: s[1:])), "log_record"),      # no "Set up job"
            (job_logs(tmp, host, record=steps(lambda s: s[:-1])), "log_record"),     # no "Complete job"
            (job_logs(tmp, host, record=steps(lambda s: [s[0], s[3], s[1], s[2], s[4]])), "log_record"),
            (job_logs(tmp, host, record=steps(lambda s: s[:1] + [dict(s[1], status="in_progress")] + s[2:])),
             "log_record"),
            # The record lists a step the folder lacks: the folder is not the whole job.
            (job_logs(tmp, host, record=steps(lambda s: s[:4] + [
                {"number": 5, "name": "Upload", "status": "completed", "conclusion": "success"}] + s[4:])),
             "log_partial"),
        ]
        for args, code in cases:
            with self.assertRaisesRegex(g.Incomplete, "^%s$" % code, msg=args):
                self.scan(args)
        args = job_logs(tmp, host)
        with open(args[-1], "w") as handle:
            handle.write('{"run_id": 4242, "run_id": 4242}')
        with self.assertRaisesRegex(g.Incomplete, "^log_record$"):
            self.scan(args)
        empty = job_logs(tmp, host)
        for name in os.listdir(empty[4]):
            os.remove(os.path.join(empty[4], name))
        with self.assertRaisesRegex(g.Incomplete, "^log_empty$"):
            self.scan(empty)


class CommandLine(unittest.TestCase):
    def setUp(self):
        # A neutral scratch root: macOS per-user temp folders are home-like paths.
        self.tmp = tempfile.mkdtemp(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)

    def tearDown(self):
        g.remove_tree(self.tmp)

    def run_gate(self, args, lines=(PRIVATE,), env=None, machine_name=None, **extra):
        data = store(*lines)
        digest = g.parse_markers(data)[1]
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp,
                       g.POLICY_ENV: policy_text(digest, **extra)}
        environment.update(env or {})
        read, write = os.pipe()
        os.write(write, data)
        os.close(write)
        fds = [read]
        command = [sys.executable, "-I", GATE] + args
        if args[0] == "scan":
            command += ["--markers-fd", str(read), "--host-literals", "off", "--scratch", self.tmp]
        if machine_name is not None:
            name_read, name_write = os.pipe()
            os.write(name_write, machine_name.encode())
            os.close(name_write)
            fds.append(name_read)
            command += ["--machine-name-fd", str(name_read)]
        result = subprocess.run(command, env=environment, pass_fds=tuple(fds), capture_output=True)
        for fd in fds:
            os.close(fd)
        for stream in (result.stdout, result.stderr):
            for line in lines:
                self.assertNotIn(line.split(":", 1)[-1].encode(), stream)
        return result

    def dispatch_env(self, notes="Bug fixes"):
        return {"OTTTO_DISPATCH_VERSION": "1.2.3-rc1", "OTTTO_DISPATCH_CHANNEL": "stable-candidate",
                "OTTTO_DISPATCH_ARTIFACT_BASE_URL":
                    "https://install.ottto.net/ottto-local-platform/releases/stable-candidate/1.2.3-rc1",
                "OTTTO_DISPATCH_RELEASE_NOTES": notes, "OTTTO_DISPATCH_RELEASE_MODE": "standard",
                "OTTTO_DISPATCH_PUBLISH_INTENT": "none"}

    def test_dispatch_profile_and_response(self):
        result = self.run_gate(["scan", "--profile", "dispatch"], env=self.dispatch_env())
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual((response["schema"], response["verdict"], response["roles"]),
                         ("ottto.release-privacy-scan", "clean", []))
        result = self.run_gate(["scan", "--profile", "dispatch"], env=self.dispatch_env("Fix " + PRIVATE.upper()))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(set(json.loads(result.stdout)["findings"]), {"private"})
        self.assertIn(b"class=private", result.stderr)

    def test_usage_errors(self):
        self.assertEqual(self.run_gate(["scan", "--profile", "dispatch"], env={g.POLICY_ENV: "{}"}).returncode, 2)
        self.assertEqual(self.run_gate(["scan", "--profile", "dispatch"], markers_sha256="c" * 64).returncode, 2)
        self.assertEqual(self.run_gate(["scan", "--profile", "dispatch"], mode="enforce").returncode, 2)
        result = self.run_gate(["register-masks"], env={g.MARKERS_ENV: store(PRIVATE).decode()})
        self.assertEqual(result.returncode, 2)

    def test_logs_cli(self):
        neutral = "/opt/ottto-release/runners/4242/_work"
        cases = [
            ("Temporarily overriding HOME='%s/_temp/0a1b'" % neutral, 0),
            ("Working directory is '%s/repo/repo'" % neutral, 0),
            ("HOME='/opt/ottto-release/runners/4243/_work/_temp'", 1),  # another run's folder
            ("HOME='/x/opt/ottto-release/runners/4242/_work/_temp'", 1),  # another root
            ("HOME='/srv/actions/_work/_temp'", 1),
            ("HOME='%s/_temp' and %s" % (neutral, HOME_ROOT + "someone/x"), 1),
        ]
        for line, status in cases:
            args = job_logs(self.tmp, "neutral-name", build=line + "\n")
            result = self.run_gate(args, machine_name="neutral-name")
            self.assertEqual(result.returncode, status, (line, result.stderr))
        # An independent literal equal to the admitted runner name blocks under the switch:
        # without host literals the name is only a listed private literal.
        result = self.run_gate(job_logs(self.tmp, "synthetic-host"), lines=(PRIVATE, "synthetic-host"),
                               machine_name="synthetic-host", accept_runner_machine_name_line=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"class=private code=machine_name_equal", result.stderr)
        # A missing middle step is incomplete.
        result = self.run_gate(job_logs(self.tmp, "neutral-name", omit=(2,)), machine_name="neutral-name")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(b"code=log_partial", result.stderr)
        # The logs profile needs the run, the attempt and the job record; no other profile takes them.
        args = job_logs(self.tmp, "neutral-name")
        for drop in ("--run-id", "--run-attempt", "--job-record"):
            at = args.index(drop)
            self.assertEqual(self.run_gate(args[:at] + args[at + 2:], machine_name="neutral-name").returncode, 2)
        bad = list(args)
        bad[bad.index("--run-attempt") + 1] = "x1"
        self.assertEqual(self.run_gate(bad, machine_name="neutral-name").returncode, 2)
        for extra in (["--run-id", "4242"], ["--run-attempt", "1"], ["--job-record", args[-1]]):
            self.assertEqual(self.run_gate(["scan", "--profile", "dispatch"] + extra,
                                           env=self.dispatch_env()).returncode, 2)

    def release_env(self, **extra):
        env_file = os.path.join(self.tmp, "github_env")
        open(env_file, "w").close()
        env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_TEMP": self.tmp,
               "GITHUB_WORKFLOW_REF": "owner/repo/" + g.WORKFLOW + "@refs/tags/v1.2.3", "GITHUB_ENV": env_file,
               "GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "1", "OTTTO_RELEASE_LANE": "candidate",
               "OTTTO_NOTARY_PROFILE": "release-notary",
               "OTTTO_MACOS_CODESIGN_IDENTITY": "Developer ID Application: %s (ABCDE12345)" % SIGNER}
        env.update(extra)
        return env, env_file

    def test_register_masks_in_release_workflow(self):
        # Literals with "%" so the escaped mask lines never repeat them verbatim.
        signer = "Qwvz%Signer Name"
        env, env_file = self.release_env(
            OTTTO_MACOS_CODESIGN_IDENTITY="Developer ID Application: %s (ABCDE12345)" % signer)
        env[g.MARKERS_ENV] = store("per%cent value", "owner+signer:" + signer).decode()
        result = self.run_gate(["register-masks"], lines=("per%cent value", "owner+signer:" + signer), env=env,
                               mode="enforce")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.decode().splitlines()
        self.assertTrue(lines and all(line.startswith("::add-mask::") for line in lines))
        self.assertIn("::add-mask::per%25cent value", lines)
        self.assertNotIn(ID_LINE[3:].encode(), result.stdout)
        work = read_bytes(env_file).decode().strip().split("=", 1)[1]
        self.assertTrue(os.path.isdir(work))
        self.addCleanup(g.remove_tree, work)
        baseline = json.loads(read_bytes(os.path.join(work, "state", "baseline.json")))
        self.assertEqual((baseline["run_id"], baseline["run_attempt"], baseline["lane"]), (4242, 1, "candidate"))

    def test_register_masks_checks_selectors(self):
        lines = (PRIVATE, "owner+signer:" + SIGNER)
        for extra in ({"OTTTO_NOTARY_PROFILE": "profile with space"}, {"OTTTO_NOTARY_PROFILE": PRIVATE},
                      {"OTTTO_MACOS_CODESIGN_IDENTITY": "Apple Development: x (ABCDE12345)"},
                      {"OTTTO_MACOS_CODESIGN_IDENTITY": "Developer ID Application: %s (ABCDE12345)" % PRIVATE}):
            env, env_file = self.release_env(**extra)
            env[g.MARKERS_ENV] = store(*lines).decode()
            result = self.run_gate(["register-masks"], lines=lines, env=env, mode="enforce")
            self.assertEqual(result.returncode, 2, extra)
            self.assertIn(b"code=selector_", result.stderr)
            self.assertEqual(read_bytes(env_file), b"")

    def test_dispatch_inputs_come_from_the_event_inside_the_workflow(self):
        env, _env_file = self.release_env()
        event = os.path.join(self.tmp, "event.json")
        inputs = {"version": "1.2.3-rc1", "channel": "stable-candidate", "release_notes": "Bug fixes",
                  "artifact_base_url":
                      "https://install.ottto.net/ottto-local-platform/releases/stable-candidate/1.2.3-rc1",
                  "release_mode": "standard", "publish_intent": "none", "github_release_mirror": False}
        env["GITHUB_EVENT_PATH"] = event
        # Step environment values are ignored inside the workflow.
        env.update({k: "ignored" for k in self.dispatch_env()})
        for notes, extra, status in (("Bug fixes", {}, 0), ("Fix " + PRIVATE.title(), {}, 1),  # mixed case: no mask would cover it
                                     ("Bug fixes", {"operator_" + "note": PRIVATE}, 1)):
            with open(event, "w") as handle:
                json.dump({"inputs": dict(inputs, release_notes=notes, **extra)}, handle)
            result = self.run_gate(["scan", "--profile", "dispatch"], env=env)
            self.assertEqual(result.returncode, status, (notes, extra, result.stderr))
        os.remove(event)
        self.assertEqual(self.run_gate(["scan", "--profile", "dispatch"], env=env).returncode, 3)

    def test_policy_rotation_between_stages_stops_the_next_scan(self):
        state = os.path.join(self.tmp, "state")
        attempt = {"GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "1", "OTTTO_RELEASE_LANE": "candidate"}
        markers, digest = g.parse_markers(store(PRIVATE))
        with patched_env(attempt):
            g.write_baseline(state, g.Policy(policy_text(digest)), digest)
        args = ["scan", "--profile", "dispatch", "--state", state]
        env = dict(self.dispatch_env(), **attempt)
        self.assertEqual(self.run_gate(args, env=env).returncode, 0)
        # The same stage twice, or any stage with a rotated list or policy, is refused before scanning.
        self.assertEqual(self.run_gate(args, env=env).returncode, 2)
        unsigned = ["scan", "--profile", "unsigned", "--root", self.tmp, "--state", state]
        result = self.run_gate(unsigned, lines=(PRIVATE, "rotated-value"), env=env)
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertIn(b"code=baseline_mismatch", result.stderr)
        result = self.run_gate(unsigned, env=env, advisory_xattrs=["macl"])
        self.assertEqual((result.returncode, result.stdout), (2, b""))
        self.assertFalse(os.path.exists(g.stage_path(state, "unsigned")))

    def test_roles_and_missing_files(self):
        result = self.run_gate(["roles", "--profile", "publish", "--lane", "stable"])
        roles = json.loads(result.stdout)
        self.assertIn("appcast", roles["required"])
        self.assertIn("clean_machine_evidence", roles["required"])
        result = self.run_gate(["scan", "--profile", "publish", "--lane", "manual", "--root", self.tmp])
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["verdict"], "incomplete")

    def build_app(self, root):
        app = os.path.join(root, "Ottto.app", "Contents")
        for folder in ("MacOS", "Helpers", "Resources", "Frameworks/Sparkle.framework/Versions/B"):
            os.makedirs(os.path.join(app, folder))
        with open(os.path.join(app, "Info.plist"), "wb") as handle:
            plistlib.dump({"CFBundleIdentifier": "net.example.app"}, handle)
        for rel in ("MacOS/Ottto", "Helpers/ottto", "Helpers/ottto-service"):
            with open(os.path.join(app, rel), "wb") as handle:
                handle.write(macho())
        for name in ("ottto", "ottto-service"):
            with open(os.path.join(root, name), "wb") as handle:
                handle.write(macho())
        for name in g.legal_names():
            source = os.path.join(ROOT, name) if name != "LICENSE-Sparkle.txt" else os.path.join(
                ROOT, "licenses", "Sparkle-2.9.2-LICENSE")
            shutil.copyfile(source, os.path.join(app, "Resources", name))
        table = g.sparkle_expected()
        framework = os.path.join(app, "Frameworks", "Sparkle.framework")
        for rel in sorted({r for r, _ in table}):
            slices = [(cpu, macho(cpu=cpu, uuid=bytes.fromhex(table[(rel, arch)].replace("-", ""))))
                      for cpu, arch in ((g.CPU_ARM64, "arm64"), (g.CPU_X86_64, "x86_64"))]
            os.makedirs(os.path.dirname(os.path.join(framework, rel)), exist_ok=True)
            with open(os.path.join(framework, rel), "wb") as handle:
                handle.write(fat(slices))
        os.symlink("B", os.path.join(framework, "Versions", "Current"))
        os.symlink("Versions/Current/Sparkle", os.path.join(framework, "Sparkle"))
        return app

    def test_unsigned_profile_and_record(self):
        root = os.path.join(self.tmp, "dist")
        os.mkdir(root)
        app = self.build_app(root)
        policy = g.Policy(policy_text("b" * 64))
        g.freeze(os.path.join(root, "Ottto.app"), policy)
        for name in ("ottto", "ottto-service"):
            g.freeze(os.path.join(root, name), policy)
        state = os.path.join(self.tmp, "state")
        result = self.run_gate(["scan", "--profile", "unsigned", "--root", root, "--state", state])
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(result.stdout)["roles"]
        self.assertEqual([r["role"] for r in rows], ["app_bundle", "cli_binary", "service_binary"])
        record = [sys.executable, "-I", GATE, "check-record", "--state", state, "--root", root]
        self.assertEqual(subprocess.run(record, capture_output=True).returncode, 0)
        # In the workflow (policy set) the record must also belong to this attempt's baseline.
        digest = g.parse_markers(store(PRIVATE))[1]
        attempt = {"GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "1", "OTTTO_RELEASE_LANE": "stable"}
        with patched_env(attempt):
            g.write_baseline(os.path.join(self.tmp, "baseline-only"), g.Policy(policy_text(digest)), digest)
        shutil.copy(os.path.join(self.tmp, "baseline-only", "baseline.json"), os.path.join(state, "baseline.json"))
        workflow_env = dict(os.environ, **attempt)
        workflow_env[g.POLICY_ENV] = policy_text(digest)
        self.assertEqual(subprocess.run(record, capture_output=True, env=workflow_env).returncode, 0)
        workflow_env["GITHUB_RUN_ATTEMPT"] = "2"
        self.assertEqual(subprocess.run(record, capture_output=True, env=workflow_env).returncode, 2)
        # With a baseline (here an enforce attempt's, as at --stage finish), a blank policy or a
        # missing attempt is refused, never a skipped check.
        enforced = os.path.join(self.tmp, "enforced")
        with patched_env(attempt):
            g.write_baseline(enforced, g.Policy(policy_text(digest, mode="enforce")), digest)
        shutil.copy(g.stage_path(state, "unsigned"), g.stage_path(enforced, "unsigned"))
        no_policy = dict(os.environ, **attempt)
        no_policy.pop(g.POLICY_ENV, None)
        finish = [sys.executable, "-I", GATE, "check-record", "--state", enforced, "--root", root]
        result = subprocess.run(finish, capture_output=True, env=no_policy)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"code=policy_missing", result.stderr)
        no_attempt = {k: v for k, v in workflow_env.items() if k != "GITHUB_RUN_ATTEMPT"}
        result = subprocess.run(record, capture_output=True, env=no_attempt)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"code=baseline_context", result.stderr)
        g.unfreeze(os.path.join(root, "ottto"))
        with open(os.path.join(root, "ottto"), "ab") as handle:
            handle.write(b"changed")
        workflow_env["GITHUB_RUN_ATTEMPT"] = "1"
        result = subprocess.run(record, capture_output=True, env=workflow_env)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"code=unsigned_changed", result.stderr)
        g.unfreeze(os.path.join(app, "Info.plist"))
        with open(os.path.join(app, "Info.plist"), "wb") as handle:
            plistlib.dump({"CFBundleIdentifier": "net.example.app", "Note": PRIVATE}, handle)
        g.freeze(os.path.join(app, "Info.plist"), policy)
        g.freeze(os.path.join(root, "ottto"), policy)
        result = self.run_gate(["scan", "--profile", "unsigned", "--root", root])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(set(json.loads(result.stdout)["findings"]), {"private"})


if __name__ == "__main__":
    unittest.main()
