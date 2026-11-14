# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate deterministic, offline TUF root fixtures for structural analysis.

Writes *trusted root* and *candidate root-chain* JSON files for two scenarios:

* ``shared``   - one physical key (identical public key material) is assigned to
                 more than one role, partly under *different keyid aliases* so
                 that keyid-based counting gets the answer wrong.
* ``separated``- every role uses disjoint physical keys (the control case).

Only public key material is ever written to disk. With ``--self-check`` private
keys live in memory just long enough to sign and verify via the real ``tuf``
code; they are never serialized and disappear when the process exits.

The generator is fully offline (no network, no on-disk private keys).
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.signer import CryptoSigner, Signature, SSlibKey

from tuf.api.metadata import Metadata, Role, Root

TOP_ROLES = ("root", "targets", "snapshot", "timestamp")
SPEC_VERSION = "1.0.31"
EXPIRES = datetime(2030, 1, 1, tzinfo=UTC)


def _make_physical_key(label: str) -> SSlibKey:
    """Deterministic ed25519 public key from a fixed label seed."""
    seed = (label.encode() * 32)[:32]
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return CryptoSigner(private).public_key


def make_public_key(label: str) -> SSlibKey:
    """Public deterministic ed25519 key (no private material is retained)."""
    return _make_physical_key(label)


def aliased_key(key: SSlibKey, keyid: str) -> SSlibKey:
    """Return the same physical key material under a chosen keyid alias."""
    return _alias(key, keyid)


def _make_signer(label: str) -> CryptoSigner:
    seed = (label.encode() * 32)[:32]
    return CryptoSigner(Ed25519PrivateKey.from_private_bytes(seed))


def _alias(key: SSlibKey, keyid: str) -> SSlibKey:
    """Return the same physical key material under an arbitrary keyid alias."""
    return SSlibKey(keyid, key.keytype, key.scheme, dict(key.keyval))


def _root_dict(
    version: int,
    role_keys: dict[str, list[SSlibKey]],
    thresholds: dict[str, int],
) -> dict[str, Any]:
    """Build a TUF root JSON dict (empty signature envelope)."""
    keys: dict[str, SSlibKey] = {}
    roles: dict[str, Role] = {}
    for role in TOP_ROLES:
        role_key_list = role_keys[role]
        roles[role] = Role(
            [key.keyid for key in role_key_list], thresholds[role]
        )
        for key in role_key_list:
            keys[key.keyid] = key

    root = Root(
        version=version,
        spec_version=SPEC_VERSION,
        expires=EXPIRES,
        keys=keys,
        roles=roles,
    )
    return Metadata(root).to_dict()


def _shared_scenario() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Six physical keys; TGT1 material is shared with the snapshot role.

    The shared key appears under two different keyid aliases (one per role) to
    prove that alias merging must be based on public key material, not keyid.
    """
    labels = ["ROOT1", "ROOT2", "TGT1", "TGT2", "SNAP1", "TIME1"]
    physical = {label: _make_physical_key(label) for label in labels}
    root1, root2 = physical["ROOT1"], physical["ROOT2"]
    tgt1, tgt2 = physical["TGT1"], physical["TGT2"]
    snap1, time1 = physical["SNAP1"], physical["TIME1"]

    shared_as_snapshot = _alias(tgt1, "alias-tgt1-as-snapshot")
    v1_role_keys = {
        "root": [root1, root2],
        "targets": [tgt1, tgt2],
        "snapshot": [shared_as_snapshot, snap1],
        "timestamp": [time1],
    }
    thresholds = {"root": 2, "targets": 2, "snapshot": 2, "timestamp": 1}
    root_v1 = _root_dict(1, v1_role_keys, thresholds)

    root3 = _make_physical_key("ROOT3")
    root4 = _make_physical_key("ROOT4")
    v2_role_keys = dict(v1_role_keys)
    v2_role_keys["root"] = [root3, root4]
    root_v2 = _root_dict(2, v2_role_keys, thresholds)

    label_keyids = {label: key.keyid for label, key in physical.items()}
    label_keyids["alias-tgt1-as-snapshot"] = shared_as_snapshot.keyid
    return [root_v1, root_v2], {
        "scenario": "shared",
        "description": (
            "TGT1 material is reused as a snapshot key under a different keyid "
            "alias; root threshold is 2 of 2 in both versions."
        ),
        "physical_labels": label_keyids,
    }


def _separated_scenario() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Control case: every role uses disjoint physical keys."""
    labels = [
        "S-ROOT1",
        "S-ROOT2",
        "S-TGT1",
        "S-TGT2",
        "S-SNAP1",
        "S-SNAP2",
        "S-TIME1",
    ]
    physical = {label: _make_physical_key(label) for label in labels}
    role_keys = {
        "root": [physical["S-ROOT1"], physical["S-ROOT2"]],
        "targets": [physical["S-TGT1"], physical["S-TGT2"]],
        "snapshot": [physical["S-SNAP1"], physical["S-SNAP2"]],
        "timestamp": [physical["S-TIME1"]],
    }
    thresholds = {"root": 2, "targets": 2, "snapshot": 2, "timestamp": 1}
    root_v1 = _root_dict(1, role_keys, thresholds)

    root3 = _make_physical_key("S-ROOT3")
    root4 = _make_physical_key("S-ROOT4")
    v2_role_keys = dict(role_keys)
    v2_role_keys["root"] = [root3, root4]
    root_v2 = _root_dict(2, v2_role_keys, thresholds)

    label_keyids = {label: key.keyid for label, key in physical.items()}
    return [root_v1, root_v2], {
        "scenario": "separated",
        "description": (
            "All role keys are distinct physical material; no sharing between "
            "roles and no overlap between root v1 and v2 key sets."
        ),
        "physical_labels": label_keyids,
    }


def _self_check(roots: list[dict[str, Any]], scenario: str) -> None:
    """Sign in memory and verify thresholds with the real tuf implementation."""
    labels = (
        ["ROOT1", "ROOT2", "TGT1", "TGT2", "SNAP1", "TIME1", "ROOT3", "ROOT4"]
        if scenario == "shared"
        else [
            "S-ROOT1",
            "S-ROOT2",
            "S-TGT1",
            "S-TGT2",
            "S-SNAP1",
            "S-SNAP2",
            "S-TIME1",
            "S-ROOT3",
            "S-ROOT4",
        ]
    )
    signers = {
        _make_signer(label).public_key.keyval["public"]: _make_signer(label)
        for label in labels
    }

    def material_of(keyid: str, root: Root) -> str:
        return root.keys[keyid].keyval["public"]

    parsed = [Metadata.from_dict(json.loads(json.dumps(r))) for r in roots]

    # Each role threshold must be satisfiable using that root's own keys.
    for md in parsed:
        root = md.signed
        payload = md.signed_bytes
        for role_name in TOP_ROLES:
            role = root.roles[role_name]
            signatures = {}
            for keyid in role.keyids[: role.threshold]:
                # The same material may be registered under a role-specific
                # keyid alias: the signature is keyed in the envelope by the
                # alias the role expects, not by the signer's default keyid.
                sig = signers[material_of(keyid, root)].sign(payload)
                signatures[keyid] = Signature(
                    keyid, sig.signature, sig.unrecognized_fields
                )
            result = root.get_verification_result(
                role_name, payload, signatures
            )
            assert result.verified, (scenario, role_name)

    # Dual-threshold root migration v1 -> v2 (mirrors update_root()).
    prev = parsed[0].signed
    new_md = parsed[1]
    new_root = new_md.signed
    payload = new_md.signed_bytes
    signatures = {}
    for source in (prev, new_root):
        for keyid in source.roles["root"].keyids:
            sig = signers[material_of(keyid, source)].sign(payload)
            signatures[keyid] = Signature(
                keyid, sig.signature, sig.unrecognized_fields
            )
    migration = new_root.get_root_verification_result(prev, payload, signatures)
    assert migration.verified, scenario
    print(
        f"[self-check] {scenario}: role thresholds and dual-threshold "
        "root migration verified by tuf"
    )


def build_scenarios() -> dict[str, tuple[list[dict[str, Any]], dict[str, Any]]]:
    """Return both fixture scenarios as in-memory root dictionaries."""
    return {
        "shared": _shared_scenario(),
        "separated": _separated_scenario(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent / "configs",
        help="Output directory for generated JSON fixtures.",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="Also sign in memory and verify via the real tuf code.",
    )
    args = parser.parse_args()

    for name, builder in (
        ("shared", _shared_scenario),
        ("separated", _separated_scenario),
    ):
        roots, meta = builder()
        out_dir = args.out / name
        out_dir.mkdir(parents=True, exist_ok=True)
        for root in roots:
            version = root["signed"]["version"]
            (out_dir / f"root_v{version}.json").write_text(
                json.dumps(root, indent=2) + "\n", encoding="utf-8"
            )
        (out_dir / "scenario.json").write_text(
            json.dumps(meta, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {len(roots)} root file(s) under {out_dir}")
        if args.self_check:
            _self_check(roots, name)


if __name__ == "__main__":
    main()
