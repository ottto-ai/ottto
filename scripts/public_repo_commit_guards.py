#!/usr/bin/env python3
"""Check the public commit identities and history for an exact revision range."""

# Known gaps: percent-encoded or fullwidth @ signs, domain literals, RFC
# comments in addresses, and message bytes after an embedded NUL.

import argparse
import os
import re
import subprocess
import sys


SHA = re.compile(r"[0-9a-fA-F]{40}")
MAX_COMMITS = 250
IDENTITY_DOMAINS = {"ottto.net", "users.noreply.github.com"}
MESSAGE_ADDRESSES = {
    ("noreply", "anthropic.com"),
    ("noreply", "openai.com"),
    # Dependabot signs off its commits with this GitHub address.
    ("support", "github.com"),
}
SYNTHETIC_DOMAIN_SUFFIXES = (
    ".example", ".invalid", ".test", ".localhost", ".example.com", ".example.org", ".example.net",
)
# Match the whole domain before looking at its suffix. GitHub's bot aliases
# include brackets in the local part.
ATOM = r"[\w.!#$%&'*+/=?^`{|}~-]"
EMAIL = re.compile(
    rf'''("(?:[^"\\\r\n]|\\[^\r\n])*"|(?<!{ATOM}){ATOM}+(?:\[bot\])?)'''
    r"@([\w-]+(?:\.[\w-]+)*)"
)


class GuardError(Exception):
    pass


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise GuardError("invalid arguments")


def git(*args, reason="git command failed"):
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        raise GuardError(reason) from None


def verify_commit(sha, reason):
    if not SHA.fullmatch(sha):
        raise GuardError(reason)
    git("cat-file", "-e", f"{sha}^{{commit}}", reason=reason)
    # A tag object can peel to a commit, but the supplied object must itself be a commit.
    if git("cat-file", "-t", sha, reason=reason) != b"commit\n":
        raise GuardError(reason)


def verify_history(base, head):
    verify_commit(base, "base commit is missing or invalid")
    verify_commit(head, "head commit is missing or invalid")
    if git("rev-parse", "--is-shallow-repository") != b"false\n":
        raise GuardError("complete history required")
    base_roots = git("rev-list", "--max-parents=0", base).splitlines()
    if len(base_roots) != 1:
        raise GuardError("base must have one root")
    pinned_root = os.environ.get("PUBLIC_REPO_ROOT", "")
    if pinned_root and (
        not SHA.fullmatch(pinned_root) or pinned_root.lower().encode() != base_roots[0]
    ):
        raise GuardError("configured root does not match base root")
    if git("rev-list", "--max-parents=0", head).splitlines() != base_roots:
        raise GuardError("head does not share the single base root")


def commit_fields(base, head):
    fields = git(
        "log", "-z", "--no-mailmap", "--no-notes", "--no-show-signature", "--encoding=none",
        f"--max-count={MAX_COMMITS + 1}", "--format=tformat:%H%x00%ae%x00%ce%x00%an%x00%cn%x00%e%x00%B",
        f"{base}..{head}", "--",
    ).split(b"\0")
    width = 7
    if fields.pop() or len(fields) % width:
        raise GuardError("invalid git log output")
    count = len(fields) // width
    if not count:
        raise GuardError("empty commit range")
    if count > MAX_COMMITS:
        raise GuardError("commit range exceeds 250 commits")
    return (fields[offset:offset + width] for offset in range(0, len(fields), width))


def decode_message(sha, encoding, message):
    # The pretty formatter can transcode a message with a declared encoding
    # even with --encoding=none. Validate the original bytes in that case.
    if encoding:
        _, separator, message = git("cat-file", "commit", sha).partition(b"\n\n")
        if not separator:
            raise GuardError("invalid commit data")
    return message.decode("utf-8")


def allowed_identity(address, *, committer=False):
    match = EMAIL.fullmatch(address)
    if match is None:
        return False
    local, domain = match.groups()
    if local.startswith('"'):
        return False
    domain = domain.lower()
    return domain in IDENTITY_DOMAINS or (committer and (local, domain) == ("noreply", "github.com"))


def allowed_message(message):
    for match in EMAIL.finditer(message):
        local, domain = match.groups()
        if local.startswith('"') and not allowed_message(local[1:-1]):
            return False
        domain = domain.lower()
        if "." not in domain:
            continue
        tld = domain.rsplit(".", 1)[-1]
        if len(tld) < 2 or not tld.isalpha():
            continue
        if not (
            domain in IDENTITY_DOMAINS
            or (local, domain) in MESSAGE_ADDRESSES
            or f".{domain}".endswith(SYNTHETIC_DOMAIN_SUFFIXES)
        ):
            return False
    return True


def main():
    display_sha = "------------"
    try:
        parser = ArgumentParser(allow_abbrev=False)
        mode = parser.add_mutually_exclusive_group(required=True)
        mode.add_argument("--base")
        mode.add_argument("--root-only", action="store_true")
        parser.add_argument("--head", required=True)
        parser.add_argument("--require-ancestor", action="store_true")
        args = parser.parse_args()
        if not SHA.fullmatch(args.head):
            raise GuardError("invalid head SHA")
        head = args.head.lower()
        display_sha = head[:12]
        base = (
            git("rev-parse", "--verify", "refs/remotes/origin/main").decode("ascii").strip()
            if args.root_only
            else args.base.lower()
        )
        verify_history(base, head)
        if args.root_only:
            return 0
        if args.require_ancestor:
            git("merge-base", "--is-ancestor", base, head, reason="cannot verify base ancestry")
        for oid, author, committer, author_name, committer_name, encoding, message in commit_fields(base, head):
            sha = oid.decode("ascii")
            if not SHA.fullmatch(sha):
                raise GuardError("invalid git log output")
            display_sha = sha[:12]
            if not allowed_identity(author.decode("utf-8")):
                raise GuardError("disallowed author email")
            if not allowed_identity(committer.decode("utf-8"), committer=True):
                raise GuardError("disallowed committer email")
            if not all(allowed_message(name.decode("utf-8")) for name in (author_name, committer_name)):
                raise GuardError("disallowed author or committer name email")
            if not allowed_message(decode_message(sha, encoding, message)):
                raise GuardError("disallowed commit message email")
    except GuardError as error:
        reason = str(error)
    except UnicodeDecodeError:
        reason = "invalid UTF-8 commit data"
    else:
        return 0
    print(f"{display_sha} {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
