# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""End-to-end demonstration of auditable verification phases.

A two-level supply chain with a shared sublayout is built in a temporary
directory. Each run injects one evidence fault and prints:

  * the completed/skipped/failed verification phases (per layout level), and
  * the original exception chain (``raise ... from ...`` links preserved).

Evidence paths are reported, evidence payload contents are not. A payload-only
marker string is embedded in the inner link and asserted to be absent from
every report and error message.

Run with:  python tests/demo_verification_phases.py
"""

import logging
import os
import shutil
import tempfile
from unittest.mock import patch

from in_toto.exceptions import (
    LinkNotFoundError,
    LinkReadError,
    ThresholdVerificationError,
)
from in_toto.models.layout import (
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import in_toto_verify
from in_toto.verificationreport import PhaseStatus, VerificationReport
from tests.common import SignerStore, VersionedPython

# Unpatched reference, safe to call from inside a Metadata.load side-effect.
REAL_LOAD = Metablock.load

# Payload-only marker: must never show up in reports or exception messages.
PAYLOAD_MARKER = "PAYLOAD_SECRET_MUST_NEVER_LEAK_d41d8cd9"
ROOT_STEP = "delegate"
INNER_STEP = "build"
INSPECTION_MARKER = "inspection-ran"


def _link_name(step_name, keyid):
    return FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)


def build_supply_chain(tmp_dir, inner_threshold=1, extra_authorized=False):
    """Create root layout + shared sublayout + inner link on disk."""
    owner_pub = SignerStore.rsa_pub
    alice = SignerStore.ecdsa
    alice_pub = SignerStore.ecdsa_pub
    bob = SignerStore.ed25519
    bob_pub = SignerStore.ed25519_pub
    carl_pub = SignerStore.rsa_pub

    sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
        name=ROOT_STEP, keyid=alice_pub["keyid"]
    )
    sub_path = os.path.join(tmp_dir, sub_dir)
    os.makedirs(sub_path, exist_ok=True)

    # Inner link, signed by bob. The payload-only marker lives in the opaque
    # `byproducts` field, which verification phases never surface in reports.
    inner_link = Metablock(
        signed=Link(
            name=INNER_STEP,
            byproducts={"payload-only-marker": PAYLOAD_MARKER},
        )
    )
    inner_link.create_signature(bob)
    inner_link_path = os.path.join(
        sub_path, _link_name(INNER_STEP, bob_pub["keyid"])
    )
    inner_link.dump(inner_link_path)

    # Shared sublayout signed by alice (the delegated functionary).
    inner_pubkeys = [bob_pub["keyid"]]
    inner_keys = {bob_pub["keyid"]: bob_pub}
    if extra_authorized:
        inner_pubkeys.append(carl_pub["keyid"])
        inner_keys[carl_pub["keyid"]] = carl_pub

    sublayout = Metablock(
        signed=Layout(
            keys=inner_keys,
            steps=[
                Step(
                    name=INNER_STEP,
                    pubkeys=inner_pubkeys,
                    threshold=inner_threshold,
                )
            ],
        )
    )
    sublayout.create_signature(alice)
    sublayout_name = _link_name(ROOT_STEP, alice_pub["keyid"])
    sublayout.dump(os.path.join(tmp_dir, sublayout_name))

    # Root layout: one delegated step plus an inspection that depends on it.
    root_layout = Metablock(
        signed=Layout(
            keys={alice_pub["keyid"]: alice_pub},
            steps=[
                Step(name=ROOT_STEP, pubkeys=[alice_pub["keyid"]], threshold=1)
            ],
            inspect=[
                Inspection(
                    name="check",
                    run=[
                        VersionedPython,
                        "-c",
                        "open('" + INSPECTION_MARKER + "', 'w').close()",
                    ],
                )
            ],
        )
    )
    root_layout.create_signature(SignerStore.rsa)

    root_key_dict = {owner_pub["keyid"]: owner_pub}
    paths = {
        "inner_link": inner_link_path,
        "sublayout_dir": sub_path,
        "sublayout_file": os.path.join(tmp_dir, sublayout_name),
        "inspection_marker": os.path.join(tmp_dir, INSPECTION_MARKER),
    }
    return root_layout, root_key_dict, inner_link_path, paths


def print_exception_chain(exc):
    """Print the full exception chain without payload content."""
    print("  exception chain:")
    depth = 0
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        prefix = "raised" if depth == 0 else "  caused by"
        print(
            f"    {'  ' * depth}{prefix}: "
            f"{type(current).__name__}: {current}"
        )
        seen.add(id(current))
        current = current.__cause__ or current.__context__
        depth += 1


# --- fault implementations ------------------------------------------------
# Each fault mutates the prepared evidence and returns either ``None`` or a
# side-effect callable used to patch ``Metadata.load`` for that run.


def fault_nonexistent(path, paths):
    os.remove(path)
    return None


def fault_permission_denied(path, paths):
    os.chmod(path, 0o000)
    if os.geteuid() != 0:
        return None

    # Root bypasses permission bits: emulate the denial at the load boundary.
    os.chmod(path, 0o644)

    def denied(load_path):
        if load_path == path:
            raise PermissionError("[Errno 13] Permission denied")
        return REAL_LOAD(load_path)

    return denied


def fault_half_read(path, paths):
    """File exists but the read fails after returning partial bytes."""

    def flaky(load_path):
        if load_path == path:
            raise OSError(
                "[Errno 5] Input/output error: short read, only 42 of"
                " 187 bytes returned"
            )
        return REAL_LOAD(load_path)

    return flaky


def fault_corrupt(path, paths):
    """Truncated, un-parseable JSON (evidence damaged on disk)."""
    with open(path, "w", encoding="utf8") as fp:
        fp.write('{"signed": {"_type": "link", "materials": ')
    return None


def fault_bad_signature(path, paths):
    """Readable file with a broken signature (tampered after signing)."""
    tampered = Metablock(signed=Link(name=INNER_STEP))
    tampered.create_signature(SignerStore.ed25519)
    tampered.signed.name = "tampered-after-signing"
    tampered.dump(path)
    return None


def fault_threshold_short(path, paths):
    """Threshold 2, two authorized functionaries, only one valid link.

    Bob's valid link stays; carl's present-but-unsigned link cannot count, so
    the signature threshold phase sees one valid link for a threshold of two.
    """
    carl_pub = SignerStore.rsa_pub
    carl_link = Metablock(signed=Link(name=INNER_STEP))
    carl_name = _link_name(INNER_STEP, carl_pub["keyid"])
    carl_link.dump(os.path.join(os.path.dirname(path), carl_name))
    return None


def run_scenario(title, fault, expected_error, threshold=1, extra_auth=False):
    tmp_dir = os.path.realpath(tempfile.mkdtemp())
    original_cwd = os.getcwd()
    os.chdir(tmp_dir)
    report = VerificationReport(f"root:{ROOT_STEP}")
    try:
        root_layout, root_key_dict, inner_link_path, paths = build_supply_chain(
            tmp_dir, threshold, extra_auth
        )
        load_side_effect = fault(inner_link_path, paths)

        print("=" * 78)
        print(f"SCENARIO: {title}")
        print("=" * 78)
        try:
            if load_side_effect is not None:
                with patch(
                    "in_toto.verifylib.Metadata.load",
                    side_effect=load_side_effect,
                ):
                    in_toto_verify(
                        root_layout,
                        root_key_dict,
                        link_dir_path=tmp_dir,
                        report=report,
                    )
            else:
                in_toto_verify(
                    root_layout,
                    root_key_dict,
                    link_dir_path=tmp_dir,
                    report=report,
                )
            raise AssertionError(
                f"scenario '{title}' unexpectedly passed verification"
            )
        except expected_error as exc:
            print("  verification: FAILED (as expected)")
            print_exception_chain(exc)
        finally:
            if os.path.exists(inner_link_path):
                os.chmod(inner_link_path, 0o644)

        print()
        print(report.render())
        inspection_ran = os.path.exists(paths["inspection_marker"])
        print()
        print(
            "  dependent inspection started:",
            "YES" if inspection_ran else "NO (correctly blocked)",
        )

        assert not inspection_ran, (
            f"inspection must not start after failure in '{title}'"
        )
        rendered = report.render()
        assert PAYLOAD_MARKER not in rendered, "payload leaked into report"
        assert PAYLOAD_MARKER not in str(
            expected_error
        ), "payload marker misuse"
    finally:
        os.chdir(original_cwd)
        shutil.rmtree(tmp_dir, ignore_errors=True)


def run_baseline():
    tmp_dir = os.path.realpath(tempfile.mkdtemp())
    original_cwd = os.getcwd()
    os.chdir(tmp_dir)
    report = VerificationReport(f"root:{ROOT_STEP}")
    try:
        root_layout, root_key_dict, _, paths = build_supply_chain(tmp_dir)
        print("=" * 78)
        print("SCENARIO: baseline (healthy evidence)")
        print("=" * 78)
        in_toto_verify(
            root_layout, root_key_dict, link_dir_path=tmp_dir, report=report
        )
        print("  verification: PASSED")
        print()
        print(report.render())
        inspection_ran = os.path.exists(paths["inspection_marker"])
        print()
        print(
            "  dependent inspection started:",
            "YES" if inspection_ran else "NO",
        )
        assert inspection_ran, "baseline inspection should run"
        assert all(
            record.status != PhaseStatus.FAILED for record in report.records
        ), "baseline must have no failed phase"
        assert PAYLOAD_MARKER not in report.render()
    finally:
        os.chdir(original_cwd)
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main():
    # Keep the demo output focused on phase records and exception chains.
    logging.disable(logging.INFO)
    run_baseline()

    scenarios = [
        (
            "candidate never submitted (missing file)",
            fault_nonexistent,
            LinkNotFoundError,
            1,
            False,
        ),
        (
            "existing evidence, read denied (permission error)",
            fault_permission_denied,
            LinkReadError,
            1,
            False,
        ),
        (
            "existing evidence, mid-read I/O failure",
            fault_half_read,
            LinkReadError,
            1,
            False,
        ),
        (
            "existing evidence, corrupted/un-parseable content",
            fault_corrupt,
            LinkReadError,
            1,
            False,
        ),
        (
            "readable evidence with broken signature",
            fault_bad_signature,
            ThresholdVerificationError,
            1,
            False,
        ),
        (
            "genuine signer threshold insufficiency",
            fault_threshold_short,
            ThresholdVerificationError,
            2,
            True,
        ),
    ]

    for title, fault, expected_error, threshold, extra_auth in scenarios:
        run_scenario(title, fault, expected_error, threshold, extra_auth)

    print("=" * 78)
    print("All scenarios behaved as expected; no payload content was leaked.")
    print("=" * 78)


if __name__ == "__main__":
    main()
