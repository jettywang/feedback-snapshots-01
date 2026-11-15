#!/usr/bin/env python3
"""Offline demonstration of post-verification publisher constraints in Signify.

Everything here is generated on the fly and runs without network or a system
keychain:

* a private test root CA;
* leaf code-signing certificates that either reuse a key (renewal) or rotate to a
  new key, including two leaves that share a subject display name;
* minimal PE files carrying real, verifiable Authenticode signatures.

It demonstrates three things:

1.  Same name, different key  - a look-alike certificate with the identical subject
    display name but a different SPKI is NOT trusted. Publisher identity follows the
    key, not the name.
2.  Renewal, same key         - a renewed certificate with the same public key (same
    SPKI) IS trusted on the renewed validity window.
3.  Key rotation, overlap     - old and new keys are both pinned with overlapping
    windows; each is accepted on its own SPKI, and after the old window closes only
    the new key remains valid.

Finally it shows the isolation guarantee: a file that carries a valid signature from
a trusted publisher alongside a signature with a corrupted code signature. The broken
signature fails full verification and never obtains publisher identity from the valid
chain next to it.

Run with:  .venv/bin/python demo/publisher_constraint_demo.py
"""

from __future__ import annotations

import datetime
import io
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from signify.authenticode import TrustedPublisher, PublisherPolicy
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.exceptions import VerificationError
from signify.x509 import CertificateStore

from tests import _publisher_harness as harness

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 6, 1, tzinfo=UTC)
PAST = datetime.datetime(2020, 1, 1, tzinfo=UTC)
FUTURE = datetime.datetime(2035, 1, 1, tzinfo=UTC)


def short(value: str) -> str:
    return value[:12] + "..."


def check(label: str, condition: bool) -> str:
    return f"[{'ALLOW' if condition else 'DENY '}] {label}"


def main() -> int:
    print("=" * 78)
    print("Signify publisher constraints - offline demonstration")
    print(f"Evaluation timestamp: {NOW.isoformat()}")
    print("=" * 78)

    ca = harness.create_root_ca(not_before=PAST, not_after=FUTURE)
    trusted_store = CertificateStore([ca.certificate], trusted=True)

    # ------------------------------------------------------------------ keys ----
    renewal_public, renewal_private = harness.generate_rsa_key()
    old_public, old_private = harness.generate_rsa_key()  # rotation: previous key
    new_public, new_private = harness.generate_rsa_key()  # rotation: replacement key

    # ------------------------------------------------- 1. same name, diff key ----
    print("\n[1] Same subject display name, different key (look-alike attack)")
    real, real_key = harness.issue_leaf(
        ca, "Acme Corp", serial=301, not_before=PAST, not_after=FUTURE
    )
    lookalike, lookalike_key = harness.issue_leaf(
        ca, "Acme Corp", serial=302, not_before=PAST, not_after=FUTURE
    )
    print(f"  real cert       subject={real.subject.dn!r}")
    print(f"                   SPKI={short(real.spki_sha256_fingerprint)}")
    print(f"  look-alike cert subject={lookalike.subject.dn!r}")
    print(f"                   SPKI={short(lookalike.spki_sha256_fingerprint)}")
    print(f"  identical subject name : {real.subject == lookalike.subject}")
    same_spki = real.spki_sha256_fingerprint == lookalike.spki_sha256_fingerprint
    print(f"  identical SPKI (key)   : {same_spki}")

    name_policy = PublisherPolicy(
        [
            TrustedPublisher(
                real.spki_sha256_fingerprint, PAST, FUTURE,
                label="pinned-real-key",
            )
        ]
    )

    real_pe = harness.build_minimal_pe()
    harness.sign_pe_file(real_pe, real, real_key, [ca.certificate])
    real_decision = SignedPEFile(io.BytesIO(bytes(real_pe))).verify_publishers(
        name_policy, at=NOW, trusted_certificate_store=trusted_store
    )[0]

    fake_pe = harness.build_minimal_pe()
    harness.sign_pe_file(fake_pe, lookalike, lookalike_key, [ca.certificate])
    fake_file = SignedPEFile(io.BytesIO(bytes(fake_pe)))
    fake_allowed = True
    try:
        fake_file.verify_publishers(
            name_policy, at=NOW, trusted_certificate_store=trusted_store
        )
    except VerificationError:
        fake_allowed = False

    print("  " + check("pinned key, matching SPKI", real_decision.allowed))
    print("  " + check("same name, different SPKI", fake_allowed))

    # -------------------------------------------------- 2. renewal, same key ----
    print("\n[2] Certificate renewal keeping the same public key")
    renewed, _ = harness.issue_leaf(
        ca,
        "Acme Corp Renewed",
        serial=402,
        not_before=datetime.datetime(2026, 2, 1, tzinfo=UTC),
        not_after=FUTURE,
        public_key=renewal_public,
        private_key=renewal_private,
    )
    original, _ = harness.issue_leaf(
        ca,
        "Acme Corp",
        serial=401,
        not_before=PAST,
        not_after=datetime.datetime(2026, 3, 1, tzinfo=UTC),
        public_key=renewal_public,
        private_key=renewal_private,
    )
    print(f"  original subject={original.subject.dn!r}")
    print(f"  renewed  subject={renewed.subject.dn!r}")
    renewed_same_key = (
        original.spki_sha256_fingerprint == renewed.spki_sha256_fingerprint
    )
    print(f"  same SPKI across renewal: {renewed_same_key}")

    renewal_policy = PublisherPolicy(
        [
            TrustedPublisher(
                original.spki_sha256_fingerprint, PAST,
                datetime.datetime(2026, 3, 1, tzinfo=UTC), label="renewal-window-1"
            ),
            TrustedPublisher(
                renewed.spki_sha256_fingerprint,
                datetime.datetime(2026, 2, 1, tzinfo=UTC), FUTURE,
                label="renewal-window-2",
            ),
        ]
    )
    renewed_pe = harness.build_minimal_pe()
    harness.sign_pe_file(renewed_pe, renewed, renewal_private, [ca.certificate])
    renewed_decision = SignedPEFile(io.BytesIO(bytes(renewed_pe))).verify_publishers(
        renewal_policy, at=NOW, trusted_certificate_store=trusted_store
    )[0]
    print("  " + check(
        f"renewed cert accepted on {renewed_decision.matches[0].label!r}",
        renewed_decision.allowed,
    ))

    # --------------------------------------------- 3. key rotation, overlap ----
    print("\n[3] Genuine key rotation with overlapping validity windows")
    old_leaf, _ = harness.issue_leaf(
        ca, "Acme Corp", serial=501, not_before=PAST,
        not_after=FUTURE, public_key=old_public, private_key=old_private
    )
    new_leaf, _ = harness.issue_leaf(
        ca, "Acme Corp", serial=502, not_before=PAST,
        not_after=FUTURE, public_key=new_public, private_key=new_private
    )
    print(f"  old key SPKI={short(old_leaf.spki_sha256_fingerprint)}")
    print(f"  new key SPKI={short(new_leaf.spki_sha256_fingerprint)}")
    rotated = old_leaf.spki_sha256_fingerprint != new_leaf.spki_sha256_fingerprint
    print(f"  rotation changed the SPKI: {rotated}")

    rotation_policy = PublisherPolicy(
        [
            TrustedPublisher(
                old_leaf.spki_sha256_fingerprint, PAST,
                datetime.datetime(2026, 12, 31, tzinfo=UTC), label="old-key"
            ),
            TrustedPublisher(
                new_leaf.spki_sha256_fingerprint,
                datetime.datetime(2026, 1, 1, tzinfo=UTC), FUTURE, label="new-key"
            ),
        ]
    )

    def rotation_result(leaf, key, when):
        pe = harness.build_minimal_pe()
        harness.sign_pe_file(pe, leaf, key, [ca.certificate])
        try:
            decision = SignedPEFile(io.BytesIO(bytes(pe))).verify_publishers(
                rotation_policy, at=when, trusted_certificate_store=trusted_store
            )[0]
            return decision.allowed, (
                decision.matches[0].label if decision.matches else "-"
            )
        except VerificationError:
            return False, "-"

    old_now, old_now_basis = rotation_result(old_leaf, old_private, NOW)
    new_now, new_now_basis = rotation_result(new_leaf, new_private, NOW)
    later = datetime.datetime(2027, 6, 1, tzinfo=UTC)
    old_later, _ = rotation_result(old_leaf, old_private, later)
    new_later, new_later_basis = rotation_result(new_leaf, new_private, later)
    print("  " + check(f"old key during overlap (basis={old_now_basis!r})", old_now))
    print("  " + check(f"new key during overlap (basis={new_now_basis!r})", new_now))
    print("  " + check("old key after its window closes", old_later))
    new_later_label = f"new key after old window (basis={new_later_basis!r})"
    print("  " + check(new_later_label, new_later))

    # ---------------------- 4. isolation: rejected signature vs valid chain ----
    print("\n[4] Rejected signature cannot inherit identity from a valid chain")
    good_leaf, good_key = harness.issue_leaf(
        ca, "Trusted Publisher", serial=801, not_before=PAST, not_after=FUTURE
    )
    bad_leaf, bad_key = harness.issue_leaf(
        ca, "Untrusted Publisher", serial=802, not_before=PAST, not_after=FUTURE
    )
    combined = harness.build_minimal_pe()
    harness.sign_pe_file(combined, good_leaf, good_key, [ca.certificate])
    harness.sign_pe_file(combined, bad_leaf, bad_key, [ca.certificate])
    harness.corrupt_last_signature(combined)  # break only the second signature

    combined_file = SignedPEFile(io.BytesIO(bytes(combined)))
    embedded = list(combined_file.iter_embedded_signatures())
    isolation_policy = PublisherPolicy(
        [
            TrustedPublisher(
                good_leaf.spki_sha256_fingerprint, PAST, FUTURE, label="good"
            )
        ]
    )

    all_mode_failed = False
    try:
        combined_file.verify_publishers(
            isolation_policy, at=NOW, multi_verify_mode="all",
            trusted_certificate_store=trusted_store,
        )
    except VerificationError:
        all_mode_failed = True

    surviving = combined_file.verify_publishers(
        isolation_policy, at=NOW, multi_verify_mode="any",
        trusted_certificate_store=trusted_store,
    )
    print(f"  embedded signatures in file      : {len(embedded)}")
    print("  " + check("strict (all) rejects the corrupted signature", all_mode_failed))
    print(
        "  " + check(
            "only the intact publisher is accepted",
            len(surviving) == 1
            and surviving[0].leaf.spki_sha256_fingerprint
            == good_leaf.spki_sha256_fingerprint,
        )
    )
    print(
        "  " + check(
            "corrupted leaf never granted publisher identity",
            all(d.leaf.spki_sha256_fingerprint != bad_leaf.spki_sha256_fingerprint
                for d in surviving),
        )
    )

    print("\n" + "=" * 78)
    print("Conclusion: publisher identity is bound to the fully-verified signer")
    print("leaf's SPKI plus a validity window. Names, chain CAs, nested signatures")
    print("and unverified signatures can never satisfy the constraint.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
