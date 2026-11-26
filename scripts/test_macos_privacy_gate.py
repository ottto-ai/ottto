#!/usr/bin/env python3
"""Tests for scripts/macos_privacy_gate.py. Synthetic markers and fixtures only."""

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
        for content, expected in ((notice, {}), (notice + b"x", {"owner": 1}),
                                  (notice + PRIVATE.encode(), {"private": 1})):
            gate = make_gate(PRIVATE, "owner:" + OWNER)
            gate.legal_hashes = {"NOTICE": hashlib.sha256(notice).hexdigest()}
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
                    (n, open(os.path.join(ROOT, n), "rb").read()) for n in g.legal_names(archive=True)) + extra:
                info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (0o100755 if name == "ottto" else 0o100644) << 16
                info.compress_type = method
                archive.writestr(info, data)
        return buffer.getvalue()

    def scan_zip(self, data, *lines):
        gate = make_gate(*lines or (PRIVATE,))
        gate.verified_bytes = lambda *_: True
        gate.scan_binary_zip(None, "cli_zip", data)
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

    def test_app_zip_omits_signer_only_in_verified_source_tree(self):
        top = tempfile.mkdtemp(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)
        self.addCleanup(shutil.rmtree, top)
        app = os.path.join(top, "Ottto.app")
        helper = os.path.join(app, "Contents", "Helpers", "ottto")
        os.makedirs(os.path.dirname(helper))
        with open(helper, "wb") as handle:
            handle.write(macho(payload=SIGNER.encode()))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.write(helper, "Ottto.app/Contents/Helpers/ottto")
        for verified, expected in ((True, set()), (False, {"owner+signer"})):
            gate = make_gate("owner+signer:" + SIGNER)
            gate.verified_signature = lambda *_args, _v=verified, **_kw: _v
            gate.scan_app_zip(buffer.getvalue(), "app_zip", app)
            self.assertEqual(set(gate.findings), expected, gate.diagnostics)

    def test_cms_structure(self):
        self.assertEqual(g.cms_signer_certificate(cms()), certificate(b"\x08", ISSUER))
        for blob in (cms(signer_count=2), cms(trailing=b"\0")):
            with self.assertRaises(g.Incomplete):
                g.cms_signer_certificate(blob)


class CommandLine(unittest.TestCase):
    def setUp(self):
        # A neutral scratch root: macOS per-user temp folders are home-like paths.
        self.tmp = tempfile.mkdtemp(dir="/private/tmp" if os.path.isdir("/private/tmp") else None)

    def tearDown(self):
        g.remove_tree(self.tmp)

    def run_gate(self, args, lines=(PRIVATE,), env=None, **extra):
        data = store(*lines)
        digest = g.parse_markers(data)[1]
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.tmp,
                       g.POLICY_ENV: policy_text(digest, **extra)}
        environment.update(env or {})
        read, write = os.pipe()
        os.write(write, data)
        os.close(write)
        command = [sys.executable, "-I", GATE] + args
        if args[0] == "scan":
            command += ["--markers-fd", str(read), "--host-literals", "off", "--scratch", self.tmp]
        result = subprocess.run(command, env=environment, pass_fds=(read,), capture_output=True)
        os.close(read)
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

    def test_logs_machine_name_line(self):
        os.mkdir(os.path.join(self.tmp, "logs"))
        with open(os.path.join(self.tmp, "logs", "job.txt"), "w") as handle:
            handle.write("2026-01-01T00:00:00Z Machine name: 'synthetic-host'\n2026-01-01T00:00:01Z done\n")
        args = ["scan", "--profile", "logs", "--root", os.path.join(self.tmp, "logs")]
        self.assertEqual(self.run_gate(args, lines=("synthetic-host",)).returncode, 1)
        result = self.run_gate(args, lines=("synthetic-host",), accept_runner_machine_name_line=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(os.path.join(self.tmp, "logs", "job.txt"), "a") as handle:
            handle.write("later synthetic-host\n")
        self.assertEqual(self.run_gate(args, lines=("synthetic-host",),
                                       accept_runner_machine_name_line=True).returncode, 1)

    def test_register_masks_in_release_workflow(self):
        env_file = os.path.join(self.tmp, "github_env")
        open(env_file, "w").close()
        env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_TEMP": self.tmp,
               "GITHUB_WORKFLOW_REF": "owner/repo/" + g.WORKFLOW + "@refs/tags/v1.2.3", "GITHUB_ENV": env_file,
               g.MARKERS_ENV: store("per%cent value").decode()}
        result = self.run_gate(["register-masks"], lines=("per%cent value",), env=env, mode="enforce")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.decode().splitlines()
        self.assertTrue(lines and all(line.startswith("::add-mask::") for line in lines))
        self.assertIn("::add-mask::per%25cent value", lines)
        self.assertNotIn(ID_LINE[3:].encode(), result.stdout)
        work = open(env_file).read().strip().split("=", 1)[1]
        self.assertTrue(os.path.isdir(work))
        os.rmdir(work)

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
        g.unfreeze(os.path.join(root, "ottto"))
        with open(os.path.join(root, "ottto"), "ab") as handle:
            handle.write(b"changed")
        self.assertEqual(subprocess.run(record, capture_output=True).returncode, 2)
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
