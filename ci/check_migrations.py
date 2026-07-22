#!/usr/bin/env python3
"""Migration-corpus check (ADR-0006 §4; fail-loudly + injected-control
pattern modeled on ci/check_crypto_confinement.py).

Enforces the CORE rules of the canonical-migration decision:

- exactly one production corpus: no crates/*/migrations/ except
  citadel-migrations, exactly one sqlx::migrate! call (in
  citadel-migrations), and only citadel-migrations declares sqlx's
  `migrate` feature (via `cargo metadata --no-deps`);
- no production source enables `ignore_missing`, disables sqlx locking, or
  sets no_tx (crates/*/src scan);
- manifest versions are positive, globally unique, and strictly append
  after the base manifest's maximum;
- every base-manifest entry survives unchanged (same entry, same filename)
  and its recorded SHA-384 still matches the SQL file — a paired
  manifest+file edit cannot disguise a history rewrite;
- current manifest entries carry recognized responsible service, tx mode,
  risk class, recovery, and ADR reference, and match the corpus files by
  name and SHA-384;
- .gitattributes LF pins for the corpus and manifest are present.

All hashing is over GIT BLOB BYTES (`git show <ref>:<path>`), never
platform-normalized working-tree bytes (review flag 3: a CRLF checkout must
not change what the checker sees, just as it must not change what
sqlx::migrate! embeds — the .gitattributes pins cover the embedding side).

--base-sha is REQUIRED: the append-only verdict compares against the
protected base manifest, and ADR-0006 §4 makes the absence of that
immutable comparison base a failure, never a skip. CI passes
pull_request.base.sha (PRs) or github.event.before (main pushes); both are
immutable. This branch INTRODUCES the manifest, so a base SHA whose tree
has no manifest yet yields an empty base manifest — the only legal
"no base entries" case, exercised exactly once.

Exit 0 = clean and proven. Exit 1 = violation, self-test failure, or the
workspace/git shape is not what this check expects (never pass vacuously).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys

CORPUS_DIR = "crates/citadel-migrations/migrations"
MANIFEST_PATH = "crates/citadel-migrations/manifest.json"
CANONICAL_PACKAGE = "citadel-migrations"
GITATTRIBUTES_PATH = ".gitattributes"

RISK_CLASSES = {"expand", "contract", "data"}
TX_MODES = {"tx", "no-tx"}
REQUIRED_ENTRY_FIELDS = {
    "version",
    "filename",
    "sha384",
    "responsible_service",
    "tx",
    "risk",
    "recovery",
    "adr",
}

# Production-source bans (ADR-0006 §1): enabling ignore_missing, disabling
# migrator locking, or non-transactional migrations. Matches assignments/
# builder calls with the dangerous VALUE only, so doc comments naming the
# flag do not false-positive.
BANNED_SOURCE_PATTERNS = [
    (re.compile(r"ignore_missing\s*(?:=|\()\s*true"), "ignore_missing enabled"),
    (re.compile(r"\blocking\s*=\s*false"), "sqlx migrator locking disabled"),
    (re.compile(r"\bno_tx\s*=\s*true"), "non-transactional migration"),
]


def git(*args: str) -> bytes:
    proc = subprocess.run(["git", *args], capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"migration-check: `git {' '.join(args)}` failed: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout


def git_show(ref: str, path: str) -> bytes | None:
    """Blob bytes for path at ref, or None when absent (no normalization)."""
    proc = subprocess.run(["git", "show", f"{ref}:{path}"], capture_output=True)
    if proc.returncode != 0:
        return None
    return proc.stdout


def sha384_hex(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def load_workspace_packages() -> list[dict]:
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("migration-check: `cargo metadata` failed; cannot prove anything")
    return json.loads(proc.stdout)["packages"]


def production_sources() -> dict[str, str]:
    """crates/*/src/**/*.rs — production code only (tests/ excluded by path)."""
    out: dict[str, str] = {}
    crates = "crates"
    for crate in sorted(os.listdir(crates)):
        src = os.path.join(crates, crate, "src")
        if not os.path.isdir(src):
            continue
        for root, _dirs, files in os.walk(src):
            for name in files:
                if name.endswith(".rs"):
                    path = os.path.join(root, name)
                    with open(path, encoding="utf-8") as fh:
                        out[path.replace(os.sep, "/")] = fh.read()
    return out


def gather(base_sha: str) -> dict:
    # Corpus listing + blob bytes at HEAD (never working-tree bytes).
    listing = (
        git("ls-tree", "-r", "--name-only", "HEAD", "--", CORPUS_DIR)
        .decode()
        .splitlines()
    )
    corpus: dict[str, bytes] = {}
    for path in listing:
        if path.endswith(".sql"):
            corpus[os.path.basename(path)] = git_show("HEAD", path) or b""

    manifest_blob = git_show("HEAD", MANIFEST_PATH)
    if manifest_blob is None:
        raise SystemExit(f"migration-check: {MANIFEST_PATH} missing at HEAD")
    manifest = json.loads(manifest_blob)

    base_blob = git_show(base_sha, MANIFEST_PATH)
    if base_blob is None:
        # Legal exactly once: the PR that INTRODUCES the canonical manifest.
        base_manifest: list[dict] = []
    else:
        base_manifest = json.loads(base_blob)

    # Service-local migration directories anywhere under crates/.
    migration_dirs: list[str] = []
    for crate in sorted(os.listdir("crates")):
        candidate = os.path.join("crates", crate, "migrations")
        if os.path.isdir(candidate):
            migration_dirs.append(candidate.replace(os.sep, "/"))

    # Every sqlx::migrate! call site in crate sources.
    migrate_calls: list[str] = []
    for path, text in production_sources().items():
        if "sqlx::migrate!" in text:
            migrate_calls.append(path)

    packages = load_workspace_packages()

    with open(GITATTRIBUTES_PATH, encoding="utf-8") as fh:
        gitattributes = fh.read()

    return {
        "corpus": corpus,
        "manifest": manifest,
        "base_manifest": base_manifest,
        "migration_dirs": migration_dirs,
        "migrate_calls": migrate_calls,
        "packages": packages,
        "sources": production_sources(),
        "gitattributes": gitattributes,
    }


def violations(ctx: dict) -> list[str]:
    found: list[str] = []
    corpus: dict[str, bytes] = ctx["corpus"]
    manifest: list[dict] = ctx["manifest"]
    base_manifest: list[dict] = ctx["base_manifest"]

    # --- One corpus, one runner, one migrate feature. ---
    if ctx["migration_dirs"] != [CORPUS_DIR]:
        found.append(
            f"migration directories must be exactly [{CORPUS_DIR}], "
            f"found {ctx['migration_dirs']} (ADR-0006 §1: no service-local corpus)"
        )
    if ctx["migrate_calls"] != [f"{CORPUS_DIR.rsplit('/', 1)[0]}/src/lib.rs"]:
        found.append(
            "exactly one sqlx::migrate! call may exist, in "
            f"crates/citadel-migrations/src/lib.rs; found {ctx['migrate_calls']}"
        )
    for pkg in ctx["packages"]:
        for dep in pkg.get("dependencies", []):
            if dep["name"] == "sqlx" and "migrate" in dep.get("features", []):
                if pkg["name"] != CANONICAL_PACKAGE:
                    found.append(
                        f"{pkg['name']}: declares sqlx's `migrate` feature; only "
                        f"{CANONICAL_PACKAGE} may (ADR-0006 §1)"
                    )

    # --- Production-source bans. ---
    for path, text in ctx["sources"].items():
        for pattern, label in BANNED_SOURCE_PATTERNS:
            if pattern.search(text):
                found.append(f"{path}: {label} (ADR-0006 §1)")

    # --- Manifest shape and recognized values. ---
    service_names = {p["name"] for p in ctx["packages"]} | {"shared"}
    versions: list[int] = []
    for entry in manifest:
        missing = REQUIRED_ENTRY_FIELDS - entry.keys()
        if missing:
            found.append(
                f"manifest entry {entry.get('version', '?')}: missing fields {sorted(missing)}"
            )
            continue
        v = entry["version"]
        versions.append(v)
        if not isinstance(v, int) or v <= 0:
            found.append(f"manifest version {v!r} must be a positive integer")
        if entry["responsible_service"] not in service_names:
            found.append(
                f"manifest v{v}: responsible_service {entry['responsible_service']!r} "
                "is not a workspace service or 'shared'"
            )
        if entry["tx"] not in TX_MODES:
            found.append(f"manifest v{v}: unrecognized tx mode {entry['tx']!r}")
        if entry["risk"] not in RISK_CLASSES:
            found.append(f"manifest v{v}: unrecognized risk class {entry['risk']!r}")
        if not entry["recovery"]:
            found.append(f"manifest v{v}: recovery method is required")
        if not entry["adr"]:
            found.append(f"manifest v{v}: ACCEPTED ADR reference is required")
        # Entry ↔ corpus: filename present, version-prefixed, checksum match.
        filename = entry["filename"]
        if not filename.startswith(f"{v:04d}_"):
            found.append(f"manifest v{v}: filename {filename!r} lacks the version prefix")
        blob = corpus.get(filename)
        if blob is None:
            found.append(f"manifest v{v}: SQL file {filename} missing from the corpus")
        elif sha384_hex(blob) != entry["sha384"]:
            found.append(
                f"manifest v{v}: recorded SHA-384 does not match {filename} "
                "(manifest and file must never drift)"
            )
    if len(set(versions)) != len(versions):
        found.append("manifest versions must be globally unique (duplicates found)")
    if versions != sorted(versions):
        found.append("manifest entries must be ordered by version (append-only corpus)")

    # --- Corpus files without manifest entries are invisible to review. ---
    manifest_files = {e.get("filename") for e in manifest}
    for filename in corpus:
        if filename not in manifest_files:
            found.append(f"corpus file {filename} has no manifest entry")

    # --- Base-manifest immutability and strict appending. ---
    base_versions = [e["version"] for e in base_manifest]
    if base_versions:
        base_max = max(base_versions)
        for v in versions:
            if v not in base_versions and v <= base_max:
                found.append(
                    f"new migration v{v} does not append after the base maximum "
                    f"v{base_max}; rebase and take the next integer (ADR-0006 §2)"
                )
    current_by_version = {e["version"]: e for e in manifest}
    for base_entry in base_manifest:
        v = base_entry["version"]
        current = current_by_version.get(v)
        if current is None:
            found.append(f"base migration v{v} was deleted from the manifest")
            continue
        if current != base_entry:
            found.append(
                f"base migration v{v}: manifest entry was rewritten; history is "
                "immutable once merged (ADR-0006 §2)"
            )
        blob = corpus.get(base_entry["filename"])
        if blob is None:
            found.append(f"base migration v{v}: SQL file {base_entry['filename']} was deleted")
        elif sha384_hex(blob) != base_entry["sha384"]:
            found.append(
                f"base migration v{v}: SQL file {base_entry['filename']} was edited "
                "(SHA-384 mismatch vs the base manifest)"
            )

    # --- LF pins (review flag 3). ---
    for pattern in (
        "crates/citadel-migrations/migrations/*.sql text eol=lf",
        "crates/citadel-migrations/manifest.json text eol=lf",
    ):
        if pattern not in ctx["gitattributes"]:
            found.append(
                f".gitattributes must pin `{pattern}` — sqlx::migrate! embeds "
                "working-tree bytes and a CRLF checkout would shift checksums"
            )

    return found


def self_test(ctx: dict) -> list[str]:
    """Injected probes: every one MUST make the checker fail, or the checker
    itself is broken (confinement-checker pattern). Returns failures of the
    self-test itself (empty = all probes fired)."""

    def expect_fires(name: str, mutate) -> str | None:
        probe = copy.deepcopy(ctx)
        mutate(probe)
        if not violations(probe):
            return f"self-test probe {name!r} did NOT produce a violation"
        return None

    failures: list[str] = []

    def dup_version(p):
        p["manifest"] = p["manifest"] + [dict(p["manifest"][0])]

    failures.append(expect_fires("duplicate version", dup_version))

    def deleted_file(p):
        p["corpus"].pop(next(iter(p["corpus"])))

    failures.append(expect_fires("deleted SQL file", deleted_file))

    def edited_file(p):
        name = next(iter(p["corpus"]))
        p["corpus"][name] = p["corpus"][name] + b"\n"

    failures.append(expect_fires("edited SQL file", edited_file))

    def service_local(p):
        p["migration_dirs"] = p["migration_dirs"] + ["crates/auth-service/migrations"]

    failures.append(expect_fires("service-local migration dir", service_local))

    def rewritten_base(p):
        # This branch introduces the manifest (empty base): synthesize a base
        # from the current manifest, then rewrite one entry — the comparison
        # must catch it either way.
        if not p["base_manifest"]:
            p["base_manifest"] = copy.deepcopy(p["manifest"])
        entry = p["manifest"][0]
        entry["risk"] = "contract" if entry["risk"] != "contract" else "expand"

    failures.append(expect_fires("manifest rewrite of a base entry", rewritten_base))

    def ignore_missing(p):
        p["sources"]["crates/auth-service/src/store.rs"] = (
            "pub async fn migrate() { let mut m = sqlx::migrate!(\"./migrations\"); "
            "m.ignore_missing = true; }"
        )

    failures.append(expect_fires("ignore_missing in source", ignore_missing))

    return [f for f in failures if f]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-sha",
        help="immutable comparison base (ADR-0006 §4: absence is a failure)",
    )
    args = parser.parse_args()
    if not args.base_sha:
        print(
            "migration-check: --base-sha is required; the append-only verdict "
            "needs the immutable comparison base and absence is a failure "
            "(ADR-0006 §4)",
            file=sys.stderr,
        )
        return 1
    # The base must resolve, or nothing downstream means anything.
    proc = subprocess.run(
        ["git", "cat-file", "-e", f"{args.base_sha}^{{commit}}"], capture_output=True
    )
    if proc.returncode != 0:
        print(
            f"migration-check: base SHA {args.base_sha} does not resolve to a "
            "commit (checkout needs history: fetch-depth 0)",
            file=sys.stderr,
        )
        return 1

    ctx = gather(args.base_sha)

    packages = {p["name"] for p in ctx["packages"]}
    if CANONICAL_PACKAGE not in packages:
        print(
            f"migration-check: canonical package {CANONICAL_PACKAGE} not found "
            "in workspace metadata; refusing to pass vacuously",
            file=sys.stderr,
        )
        return 1

    for failure in self_test(ctx):
        print(f"migration-check: {failure}", file=sys.stderr)
        return 1

    found = violations(ctx)
    if found:
        for line in found:
            print(f"migration-check: {line}", file=sys.stderr)
        return 1

    base_note = (
        f"{len(ctx['base_manifest'])} base entries"
        if ctx["base_manifest"]
        else "no base manifest (introducing change)"
    )
    print(
        f"migration-check: OK - {len(ctx['manifest'])} manifest entries, "
        f"{len(ctx['corpus'])} corpus files, {base_note}, base {args.base_sha[:12]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
