#!/usr/bin/env python3
"""Crypto-confinement check (AGENTS.md rule 6, ADR-0002, docs/issues/002).

Fails if any of the four service crates takes a DIRECT dependency — normal,
dev, build, or target-specific — on a crypto-primitive crate. Services touch
cryptography only through the citadel-service-crypto facade (verify, sha256,
OS-CSPRNG bytes); kt-log's encapsulated tree-head signing is the single
sanctioned exception (ADR-0001 §3).

Scope is deliberate: only the four service crates are inspected. Client
crates (citadel-core, apps/desktop) legitimately own crypto (INV-2) and are
governed by INV-9/INV-10 plus Opus blocking review, not by this check.
Transitive dependencies of external crates (sqlx -> sha2, rustls -> ring,
uuid -> getrandom, ...) are out of scope: this check enforces what a service
crate DECLARES, which is what code review and rule 6 govern.

Uses `cargo metadata --no-deps`: dependency entries carry the real package
name in `name` even when the manifest renames it (`alias = { package = ...
}`), so rename evasion does not bypass the check.

Exit 0 = clean. Exit 1 = violation found, self-test failed, or the workspace
shape is not what this check expects (a check that cannot see the service
crates must fail loudly, never pass vacuously).
"""

from __future__ import annotations

import json
import subprocess
import sys

SERVICE_CRATES = {
    "auth-service",
    "delivery-service",
    "directory-service",
    "blobstore-service",
}

# Direct-dependency blocklist for service crates. deny.toml is NOT the
# canonical list for this confinement rule (cargo-deny bans are graph-wide;
# see docs/issues/005) — this list is. Grouped by evasion family; extend via
# docs/issues/ escalation, never quietly.
BLOCKED: dict[str, str] = {
    # Issue 002 original list (signatures, hashes, AEAD, MACs, KDFs, RNGs).
    "ed25519-dalek": "signature primitive",
    "sha2": "hash primitive",
    "sha1": "hash primitive",
    "md-5": "hash primitive",
    "ring": "crypto toolkit",
    "aes-gcm": "AEAD primitive",
    "chacha20poly1305": "AEAD primitive",
    "hmac": "MAC primitive",
    "hkdf": "KDF primitive",
    "rand": "randomness (services use facade random_bytes)",
    "rand_core": "randomness (services use facade random_bytes)",
    "getrandom": "randomness (services use facade random_bytes)",
    # Alternative signature / ECDH stacks (evade the ed25519-dalek ban).
    "ed25519": "signature primitive",
    "x25519-dalek": "ECDH primitive",
    "curve25519-dalek": "EC primitive",
    "k256": "signature primitive",
    "p256": "signature primitive",
    "rsa": "signature primitive",
    "schnorrkel": "signature primitive",
    # TLS crypto backends (rustls is the TLS stack; its crypto never belongs
    # in a service manifest).
    "aws-lc-rs": "TLS crypto backend",
    # Group crypto: a service linking OpenMLS links decryption paths (INV-1).
    "openmls": "group crypto (INV-1)",
    "openmls_rust_crypto": "group crypto (INV-1)",
    "openmls_traits": "group crypto (INV-1)",
    "openmls_basic_credential": "group crypto (INV-1)",
    # Alternative hashes / ciphers / KDFs (evade sha2/AEAD/KDF bans).
    "blake2": "hash primitive",
    "blake3": "hash primitive",
    "sha3": "hash primitive",
    "aes": "cipher primitive",
    "chacha20": "cipher primitive",
    "pbkdf2": "KDF primitive",
    "argon2": "KDF primitive",
    "scrypt": "KDF primitive",
    "merlin": "transcript primitive",
}


def load_workspace_packages() -> list[dict]:
    proc = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit("crypto-confinement: `cargo metadata` failed; cannot prove anything")
    return json.loads(proc.stdout)["packages"]


def violations(packages: list[dict]) -> list[str]:
    found: list[str] = []
    for pkg in packages:
        if pkg["name"] not in SERVICE_CRATES:
            continue
        for dep in pkg.get("dependencies", []):
            # `name` is the real package name; `rename` is only the alias.
            if dep["name"] in BLOCKED:
                kind = dep.get("kind") or "normal"
                found.append(
                    f"{pkg['name']}: direct {kind} dependency on "
                    f"'{dep['name']}' ({BLOCKED[dep['name']]}) violates crypto "
                    f"confinement (AGENTS.md rule 6, ADR-0002); services use "
                    f"citadel-service-crypto"
                )
    return found


def main() -> int:
    packages = load_workspace_packages()

    seen = {p["name"] for p in packages} & SERVICE_CRATES
    if seen != SERVICE_CRATES:
        missing = sorted(SERVICE_CRATES - seen)
        print(
            "crypto-confinement: expected service crate(s) not found in "
            f"workspace metadata: {', '.join(missing)}; refusing to pass "
            "vacuously",
            file=sys.stderr,
        )
        return 1

    # Control self-test (canary-scan convention): the detector must fire on
    # an injected violation, or the check itself is broken.
    probe = {
        "name": "auth-service",
        "dependencies": [{"name": "sha2", "kind": None}],
    }
    if not violations([probe]):
        print(
            "crypto-confinement: self-test failed: injected sha2 dependency "
            "was not detected",
            file=sys.stderr,
        )
        return 1

    found = violations(packages)
    if found:
        for line in found:
            print(f"crypto-confinement: {line}", file=sys.stderr)
        return 1

    print(
        "crypto-confinement: OK - no direct crypto dependencies in "
        f"{len(seen)} service crates ({len(BLOCKED)} crates blocked)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
