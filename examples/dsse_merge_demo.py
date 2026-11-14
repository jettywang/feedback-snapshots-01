#!/usr/bin/env python3
"""Auditable DSSE envelope co-signing demo.

Run with the project virtualenv::

    .venv/bin/python examples/dsse_merge_demo.py

The same DSSE payload is signed locally by offline signing stations using
Ed25519 (deterministic) and RSA-PSS (randomized). The returned envelopes are
fed back through the auditable merge entry point in deliberately adversarial
orders and shapes.

Scenarios:
  1. Happy path: shuffled input, repeated stations, distinct PSS signatures.
  2. One payload byte changed.
  3. Payload re-serialized (semantically equal JSON, different bytes).
  4. Signature from an unknown (untrusted) station.
  5. Deterministic Ed25519 conflict.

The demo prints the audit record (source and verification status) of every
input signature, and shows that a failed merge never overwrites the artifact
that was published by the successful merge.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
from pathlib import Path

from securesystemslib.dsse import Envelope
from securesystemslib.dsse_merge import (
    SIGNATURE_CONFLICT,
    SIGNATURE_DUPLICATE,
    SIGNATURE_INVALID,
    SIGNATURE_RANDOMIZED,
    SIGNATURE_UNKNOWN_SIGNER,
    SIGNATURE_VERIFIED,
    merge_envelopes,
    publish_merged_envelope,
)
from securesystemslib.exceptions import EnvelopeMergeError
from securesystemslib.signer import CryptoSigner, Key, Signature

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATUSES = {
    SIGNATURE_VERIFIED: "VERIFIED  (retained)",
    SIGNATURE_DUPLICATE: "DUPLICATE (deduplicated)",
    SIGNATURE_RANDOMIZED: "RANDOMIZED (distinct valid PSS, not retained)",
    SIGNATURE_CONFLICT: "CONFLICT  (deterministic mismatch, merge rejected)",
    SIGNATURE_INVALID: "INVALID   (verification failed)",
    SIGNATURE_UNKNOWN_SIGNER: "UNKNOWN   (no trusted key, rejected)",
}


def check(condition: bool, message: str) -> None:
    """Raise if a demo invariant does not hold."""
    if not condition:
        raise RuntimeError(message)


def sign_at_station(
    payload: bytes, payload_type: str, signer: CryptoSigner
) -> Envelope:
    """Simulate one offline signing station returning an envelope."""
    envelope = Envelope(payload, payload_type, {})
    envelope.sign(signer)
    return envelope


def print_report(report) -> None:
    """Print one audit line per input signature."""
    for record in report.records:
        print(
            f"    - {record.source_label:<22} keyid={record.keyid[:12]}... "
            f"scheme={record.scheme or '-':<18} -> {STATUSES[record.status]}"
        )
    if report.errors:
        for error in report.errors:
            print(f"    ! {error}")


def run_scenario(title: str, envelopes, keys, labels, expect_success: bool):
    print(f"\n=== {title} ===")
    try:
        merged, report = merge_envelopes(envelopes, keys, labels)
    except EnvelopeMergeError as error:
        print("    result: MERGE REJECTED (no merged envelope produced)")
        print_report(error.report)
        check(not expect_success, f"{title} unexpectedly failed")
        return None

    print("    result: MERGE OK")
    print_report(report)
    print(
        "    retained keyids (first-seen order):",
        ", ".join(report.accepted_keyids),
    )
    check(expect_success, f"{title} unexpectedly succeeded")
    return merged


def main() -> None:
    # Trusted offline stations: one Ed25519, one RSA-PSS, plus a backup PSS key.
    ed_station = CryptoSigner.generate_ed25519(keyid="ed25519-station-a")
    pss_station = CryptoSigner.generate_rsa(keyid="rsa-pss-station-b", size=2048)
    trusted_keys: list[Key] = [
        ed_station.public_key,
        pss_station.public_key,
    ]

    # The canonical payload bytes every station must sign unchanged.
    payload = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "release-1.0.0", "digest": {"sha256": "abc"}}],
            "predicateType": "https://example.com/release",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    print(f"canonical payload ({len(payload)} bytes): {payload!r}")

    # --- Scenario 1: shuffled input, duplicated station, PSS randomization ---
    ed_env = sign_at_station(payload, PAYLOAD_TYPE, ed_station)
    pss_env_1 = sign_at_station(payload, PAYLOAD_TYPE, pss_station)
    pss_env_2 = sign_at_station(payload, PAYLOAD_TYPE, pss_station)
    ed_env_resend = sign_at_station(payload, PAYLOAD_TYPE, ed_station)

    pss_sig_1 = pss_env_1.signatures["rsa-pss-station-b"].signature
    pss_sig_2 = pss_env_2.signatures["rsa-pss-station-b"].signature
    print(
        "\nRSA-PSS produces distinct signatures per signing run: "
        f"{pss_sig_1 != pss_sig_2}"
    )
    ed_sig_1 = ed_env.signatures["ed25519-station-a"].signature
    ed_sig_2 = ed_env_resend.signatures["ed25519-station-a"].signature
    print(
        "Ed25519 produces identical signatures per signing run: "
        f"{ed_sig_1 == ed_sig_2}"
    )

    # Deliberately shuffled and with repeated stations.
    envelopes = [pss_env_2, ed_env_resend, pss_env_1, ed_env]
    labels = [
        "station-b/run-2",
        "station-a/resend",
        "station-b/run-1",
        "station-a/run-1",
    ]
    input_snapshots = copy.deepcopy(envelopes)
    merged = run_scenario(
        "1. happy path: shuffled input + repeated stations",
        envelopes,
        trusted_keys,
        labels,
        expect_success=True,
    )

    # Independently re-verify the merged envelope against trusted keys.
    accepted = merged.verify(trusted_keys, 2)
    print(f"    independent re-verification accepted {len(accepted)} trusted keys")
    check(envelopes == input_snapshots, "merge must not modify its inputs")

    # Publish atomically and remember the exact published bytes.
    output_dir = Path(tempfile.mkdtemp(prefix="dsse-demo-", dir=os.environ["TMPDIR"]))
    published_path = output_dir / "co-signed.json"
    publish_merged_envelope(published_path, merged)
    published_bytes = published_path.read_bytes()
    print(f"\n    published merged envelope to {published_path}")
    print(json.dumps(json.loads(published_bytes), indent=2).replace("\n", "\n    "))

    # --- Scenario 2: one payload byte changed ------------------------------
    tampered_payload = bytearray(payload)
    tampered_payload[-1] = ord("Z") if payload[-1] != ord("Z") else ord("Y")
    tampered_env = sign_at_station(
        bytes(tampered_payload), PAYLOAD_TYPE, ed_station
    )
    run_scenario(
        "2. one payload byte changed",
        [ed_env, tampered_env],
        trusted_keys,
        ["station-a/run-1", "station-a/tampered"],
        expect_success=False,
    )

    # --- Scenario 3: re-serialized (re-formatted) payload -------------------
    pretty_payload = json.dumps(json.loads(payload), indent=2).encode("utf-8")
    pretty_env = sign_at_station(pretty_payload, PAYLOAD_TYPE, ed_station)
    run_scenario(
        "3. payload re-formatted (same JSON, different bytes)",
        [ed_env, pretty_env],
        trusted_keys,
        ["station-a/compact", "station-a/pretty"],
        expect_success=False,
    )

    # --- Scenario 4: unknown signer -----------------------------------------
    rogue_station = CryptoSigner.generate_ed25519(keyid="untrusted-station-z")
    rogue_env = sign_at_station(payload, PAYLOAD_TYPE, rogue_station)
    run_scenario(
        "4. unknown signing station",
        [ed_env, pss_env_1, rogue_env],
        trusted_keys,
        ["station-a", "station-b", "station-z/untrusted"],
        expect_success=False,
    )

    # --- Scenario 5: deterministic Ed25519 conflict -------------------------
    # A genuine deterministic conflict cannot occur with honest Ed25519 keys:
    # there is exactly one valid signature per message. Simulate the condition
    # with a verification stub accepting a forged alternative signature, to
    # prove the merge treats it as a conflict rather than randomization.
    forged = Signature("ed25519-station-a", "aa" * 64)
    conflicting_env = Envelope(
        payload, PAYLOAD_TYPE, {"ed25519-station-a": forged}
    )

    class ConflictSimulatingKey(Key):
        def __init__(self, delegate: Key, forged_hex: str):
            super().__init__(
                delegate.keyid, delegate.keytype, delegate.scheme, delegate.keyval
            )
            self._delegate = delegate
            self._forged_hex = forged_hex

        @classmethod
        def from_dict(cls, keyid, key_dict):
            raise NotImplementedError

        def to_dict(self):
            return self._delegate.to_dict()

        def verify_signature(self, signature, data):
            if signature.signature != self._forged_hex:
                self._delegate.verify_signature(signature, data)

    simulated_keys = [
        ConflictSimulatingKey(ed_station.public_key, forged.signature),
        pss_station.public_key,
    ]
    run_scenario(
        "5. deterministic Ed25519 signature conflict",
        [ed_env, conflicting_env],
        simulated_keys,
        ["station-a/genuine", "station-a/forged"],
        expect_success=False,
    )

    # The rejected merges never touched the published artifact.
    check(
        published_path.read_bytes() == published_bytes,
        "failed merge overwrote the published artifact",
    )
    print(
        "\npublished artifact unchanged after all rejected merges: "
        f"{published_path}"
    )
    print("demo finished: no unverified material entered any completed merge.")


if __name__ == "__main__":
    main()
