# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline fork forensics demonstration.

Run with::

    python examples/fork_forensics/demo.py

The script builds fully signed repositories with real ed25519 keys and walks
through five scenarios for each signature semantics (traditional Metadata and
DSSE SimpleEnvelope):

1. two valid, same-version observations with conflicting content (a proven
   publisher fork),
2. the same content re-serialized with different whitespace and signature
   ordering, plus an additional valid signature (not a fork),
3. two different versions (not a same-version conflict),
4. one valid package and one package tampered with by a third party
   (inconclusive: it must never be treated as proof of publisher
   misbehavior),
5. a proven fork reached through a rotated root and a delegated targets
   role, exercising both authorization-path dimensions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from repository_builder import RepositoryBuilder  # noqa: E402
from securesystemslib.signer import CryptoSigner  # noqa: E402

from tuf.forensics import (  # noqa: E402
    EnvelopeType,
    ForkStatus,
    ObservationPackage,
    analyze_fork,
)

GOOD_HASH = "a1" * 32
EVIL_HASH = "b2" * 32
NEXT_HASH = "c3" * 32


def _print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def _print_report(report: object) -> None:
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))


def _packages(
    builder: RepositoryBuilder,
    root: bytes,
    envelope_a: bytes,
    envelope_b: bytes,
) -> tuple[ObservationPackage, ObservationPackage]:
    first = ObservationPackage(
        envelope_a, root, envelope_type=builder.envelope_type
    )
    second = ObservationPackage(
        envelope_b, root, envelope_type=builder.envelope_type
    )
    return first, second


def run_scenarios(envelope_type: EnvelopeType) -> bool:
    label = envelope_type.name
    _print_header(f"Signature semantics: {label}")
    builder = RepositoryBuilder(envelope_type)
    root = builder.build_root()
    success = True

    # Scenario 1: genuine same-version conflict signed by the publisher.
    _print_header(f"[{label}] 1. Two valid conflicting same-version packages")
    targets_good = builder.build_targets(1, "release.tar.gz", GOOD_HASH)
    targets_evil = builder.build_targets(1, "release.tar.gz", EVIL_HASH)
    report = analyze_fork(
        *_packages(builder, root, targets_good, targets_evil)
    )
    _print_report(report)
    assert report.status is ForkStatus.PROVEN
    assert report.conflict_fields is not None
    assert report.conflict_fields.field_paths
    success &= report.fork_proven

    # Scenario 2: whitespace/order/extra-signature differences only.
    _print_header(f"[{label}] 2. Same content, different formatting/signatures")
    targets_reformatted = builder.reformat_envelope(targets_good)
    root_extra, extra_signer = builder.build_root_with_extra_targets_key()
    targets_extra_sig = builder.sign_targets(
        targets_reformatted, extra_signer
    )
    report = analyze_fork(
        *_packages(builder, root_extra, targets_good, targets_extra_sig)
    )
    _print_report(report)
    assert report.status is ForkStatus.REFUTED
    success &= not report.fork_proven

    # Scenario 3: different versions are not same-version conflicts.
    _print_header(f"[{label}] 3. Different versions")
    targets_v2 = builder.build_targets(2, "release.tar.gz", NEXT_HASH)
    report = analyze_fork(
        *_packages(builder, root, targets_good, targets_v2)
    )
    _print_report(report)
    assert report.status is ForkStatus.REFUTED
    success &= not report.fork_proven

    # Scenario 4: third-party tampering must not implicate the publisher.
    _print_header(f"[{label}] 4. One package tampered with by a third party")
    targets_tampered = builder.tamper_payload(targets_good)
    report = analyze_fork(
        *_packages(builder, root, targets_good, targets_tampered)
    )
    _print_report(report)
    assert report.status is ForkStatus.INCONCLUSIVE
    assert report.second.errors
    success &= not report.fork_proven

    # Scenario 5: proven fork reached through a rotated root and a delegation.
    _print_header(f"[{label}] 5. Fork via rotated root and delegated role")
    root_v2 = builder.build_rotated_root(2)
    delegated_signer = CryptoSigner.generate_ed25519()
    top_targets = builder.build_targets_with_delegation(
        "vetted", delegated_signer
    )
    delegated_good = builder.build_delegated_targets(
        1, "release.tar.gz", GOOD_HASH, delegated_signer
    )
    delegated_evil = builder.build_delegated_targets(
        1, "release.tar.gz", EVIL_HASH, delegated_signer
    )
    delegated_kwargs = {
        "envelope_type": builder.envelope_type,
        "root_chain": [root_v2],
        "role_name": "vetted",
        "delegations": {"targets": top_targets},
        "delegation_chain": [],
    }
    report = analyze_fork(
        ObservationPackage(delegated_good, root, **delegated_kwargs),
        ObservationPackage(delegated_evil, root, **delegated_kwargs),
    )
    _print_report(report)
    assert report.status is ForkStatus.PROVEN
    root_versions = [
        hop.root_version
        for hop in report.first.authorization_path.root_chain
    ]
    assert root_versions == [1, 2]
    role_hops = [
        (hop.delegator, hop.role)
        for hop in report.first.authorization_path.role_path
    ]
    assert role_hops == [("root", "targets"), ("targets", "vetted")]
    success &= report.fork_proven

    return success


def main() -> int:
    results = [
        run_scenarios(EnvelopeType.METADATA),
        run_scenarios(EnvelopeType.SIMPLE),
    ]
    _print_header("Summary")
    if all(results):
        print("All scenarios behaved as expected for both semantics.")
        return 0
    print("At least one scenario did not match the expected outcome.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
