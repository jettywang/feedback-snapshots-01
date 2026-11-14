# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for verification phase reporting and evidence-read error handling.

These tests pin the distinction between:

- an optional candidate that a functionary never submitted (a missing file,
  which may be skipped), and
- existing evidence that cannot be read or parsed reliably (which must fail
  explicitly as LinkReadError, even when other files would meet the
  threshold),

and assert that a failed sublayout never yields a summary link or starts a
dependent inspection.
"""

import json
import os
import unittest
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
from in_toto.verifylib import in_toto_verify, load_links_for_layout
from in_toto.verificationreport import Phase, PhaseStatus, VerificationReport
from tests.common import SignerStore, TmpDirMixin, VersionedPython


def _link_name(step_name, keyid):
    return FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)


class TestLoadLinksErrorClassification(unittest.TestCase, TmpDirMixin):
    """Candidate discovery: missing vs. unreadable evidence."""

    def setUp(self):
        self.set_up_test_dir()
        self.alice = SignerStore.ecdsa
        self.alice_pub = SignerStore.ecdsa_pub
        self.bob = SignerStore.rsa
        self.bob_pub = SignerStore.rsa_pub
        self.step_name = "write"

    def tearDown(self):
        self.tear_down_test_dir()

    @staticmethod
    def _restore_mode(path):
        if os.path.exists(path):
            os.chmod(path, 0o644)

    def _make_link(self, signer, keyid):
        link = Metablock(signed=Link(name=self.step_name))
        link.create_signature(signer)
        path = _link_name(self.step_name, keyid)
        link.dump(path)
        return path

    def _layout(self, threshold):
        return Layout(
            keys={
                self.alice_pub["keyid"]: self.alice_pub,
                self.bob_pub["keyid"]: self.bob_pub,
            },
            steps=[
                Step(
                    name=self.step_name,
                    pubkeys=[
                        self.alice_pub["keyid"],
                        self.bob_pub["keyid"],
                    ],
                    threshold=threshold,
                )
            ],
        )

    def test_missing_candidate_is_skipped_when_threshold_met(self):
        """An unsubmitted candidate does not break a satisfiable step."""
        layout = self._layout(threshold=1)
        self._make_link(self.alice, self.alice_pub["keyid"])
        bob_path = _link_name(self.step_name, self.bob_pub["keyid"])
        self.assertFalse(os.path.exists(bob_path))

        report = VerificationReport("root")
        loaded = load_links_for_layout(layout, ".", report)

        self.assertIn(self.alice_pub["keyid"], loaded[self.step_name])
        record = report.records[-1]
        self.assertEqual(record.name, Phase.CANDIDATE_DISCOVERY)
        self.assertEqual(record.status, PhaseStatus.PASSED)
        outcomes = {
            os.path.basename(c["path"]): c["outcome"]
            for c in record.detail["candidates"]
        }
        self.assertEqual(outcomes[bob_path], "missing")
        self.assertEqual(
            outcomes[
                _link_name(self.step_name, self.alice_pub["keyid"])
            ],
            "loaded",
        )

    def test_missing_candidate_below_threshold_raises_link_not_found(self):
        layout = self._layout(threshold=2)
        self._make_link(self.alice, self.alice_pub["keyid"])

        report = VerificationReport("root")
        with self.assertRaises(LinkNotFoundError):
            load_links_for_layout(layout, ".", report)

        record = next(
            r for r in report.records if r.name == Phase.CANDIDATE_DISCOVERY
        )
        self.assertEqual(record.status, PhaseStatus.FAILED)
        self.assertIn("LinkNotFoundError", record.error)
        # Every later phase is recorded as skipped rather than continued.
        later = [
            r
            for r in report.records
            if list(Phase).index(r.name)
            > list(Phase).index(Phase.CANDIDATE_DISCOVERY)
        ]
        self.assertTrue(later)
        self.assertTrue(all(r.status == PhaseStatus.SKIPPED for r in later))

    def test_unreadable_existing_evidence_fails_even_with_enough_others(self):
        """A second readable link must not hide an unreadable candidate."""
        layout = self._layout(threshold=1)
        self._make_link(self.alice, self.alice_pub["keyid"])
        bob_path = self._make_link(self.bob, self.bob_pub["keyid"])
        os.chmod(bob_path, 0o000)
        self.addCleanup(self._restore_mode, bob_path)

        if os.geteuid() == 0:
            self.skipTest("root bypasses permission bits")

        report = VerificationReport("root")
        with self.assertRaises(LinkReadError) as ctx:
            load_links_for_layout(layout, ".", report)

        self.assertIn(bob_path, str(ctx.exception))
        record = next(
            r for r in report.records if r.name == Phase.CANDIDATE_DISCOVERY
        )
        self.assertEqual(record.status, PhaseStatus.FAILED)
        self.assertIn("LinkReadError", record.error)
        self.assertIn(
            bob_path, [os.path.basename(p) for p in record.evidence_paths]
        )

    def test_corrupt_existing_evidence_raises_link_read_error(self):
        layout = self._layout(threshold=1)
        self._make_link(self.alice, self.alice_pub["keyid"])
        bob_path = self._make_link(self.bob, self.bob_pub["keyid"])
        with open(bob_path, "w", encoding="utf8") as fp:
            fp.write('{"signed": {"_type": "link", "materials": ')

        report = VerificationReport("root")
        with self.assertRaises(LinkReadError) as ctx:
            load_links_for_layout(layout, ".", report)

        self.assertIn(bob_path, str(ctx.exception))
        self.assertIn("JSONDecodeError", str(ctx.exception))

    def test_permission_error_emulated_for_root(self):
        """The load boundary maps OSError to LinkReadError."""
        layout = self._layout(threshold=1)
        self._make_link(self.alice, self.alice_pub["keyid"])
        bob_path = self._make_link(self.bob, self.bob_pub["keyid"])

        real_load = Metablock.load
        denied_path = os.path.join(".", bob_path)

        def denied(path):
            if path == denied_path:
                raise PermissionError("[Errno 13] Permission denied")
            return real_load(path)

        with patch("in_toto.verifylib.Metadata.load", side_effect=denied):
            with self.assertRaises(LinkReadError) as ctx:
                load_links_for_layout(layout, ".")

        self.assertIn(bob_path, str(ctx.exception))

    def test_error_messages_never_contain_payload(self):
        layout = self._layout(threshold=1)
        self._make_link(self.alice, self.alice_pub["keyid"])
        bob_path = self._make_link(self.bob, self.bob_pub["keyid"])
        secret = "SECRET_PAYLOAD_VALUE_9f86"
        # Parseable JSON that is not in-toto metadata at all. The secret only
        # exists in the payload and must not be copied into the error message.
        with open(bob_path, "w", encoding="utf8") as fp:
            json.dump({"unexpected": secret}, fp)

        with self.assertRaises(LinkReadError) as ctx:
            load_links_for_layout(layout, ".")

        self.assertNotIn(secret, str(ctx.exception))
        self.assertIn(bob_path, str(ctx.exception))


class TestSublayoutFailureIsolation(unittest.TestCase, TmpDirMixin):
    """A failed sublayout blocks summary links and dependent inspections."""

    def setUp(self):
        self.set_up_test_dir()
        self.owner = SignerStore.rsa
        self.owner_pub = SignerStore.rsa_pub
        self.alice = SignerStore.ecdsa
        self.alice_pub = SignerStore.ecdsa_pub
        self.bob = SignerStore.ed25519
        self.bob_pub = SignerStore.ed25519_pub
        self.root_step = "delegate"
        self.inner_step = "build"
        self.marker = "inspection-ran"

    def tearDown(self):
        self.tear_down_test_dir()

    def _restore_inner_link(self):
        if os.path.exists(self.inner_link_path):
            os.chmod(self.inner_link_path, 0o644)

    def _build(self, *, threshold=1, extra_authorized=False, inspection=True):
        sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=self.root_step, keyid=self.alice_pub["keyid"]
        )
        os.makedirs(sub_dir, exist_ok=True)

        inner_link = Metablock(signed=Link(name=self.inner_step))
        inner_link.create_signature(self.bob)
        self.inner_link_path = os.path.join(
            sub_dir, _link_name(self.inner_step, self.bob_pub["keyid"])
        )
        inner_link.dump(self.inner_link_path)

        inner_pubkeys = [self.bob_pub["keyid"]]
        inner_keys = {self.bob_pub["keyid"]: self.bob_pub}
        if extra_authorized:
            inner_pubkeys.append(self.owner_pub["keyid"])
            inner_keys[self.owner_pub["keyid"]] = self.owner_pub

        sublayout = Metablock(
            signed=Layout(
                keys=inner_keys,
                steps=[
                    Step(
                        name=self.inner_step,
                        pubkeys=inner_pubkeys,
                        threshold=threshold,
                    )
                ],
            )
        )
        sublayout.create_signature(self.alice)
        sublayout.dump(_link_name(self.root_step, self.alice_pub["keyid"]))

        inspect = []
        if inspection:
            inspect = [
                Inspection(
                    name="check",
                    run=[
                        VersionedPython,
                        "-c",
                        "open('" + self.marker + "', 'w').close()",
                    ],
                )
            ]

        root_layout = Metablock(
            signed=Layout(
                keys={self.alice_pub["keyid"]: self.alice_pub},
                steps=[
                    Step(
                        name=self.root_step,
                        pubkeys=[self.alice_pub["keyid"]],
                        threshold=1,
                    )
                ],
                inspect=inspect,
            )
        )
        root_layout.create_signature(self.owner)
        return root_layout, {self.owner_pub["keyid"]: self.owner_pub}

    def test_healthy_sublayout_runs_inspection(self):
        root_layout, root_keys = self._build()
        report = VerificationReport("root")
        in_toto_verify(root_layout, root_keys, ".", report=report)

        self.assertTrue(os.path.exists(self.marker))
        statuses = [r.status for r in report.records]
        self.assertNotIn(PhaseStatus.FAILED, statuses)

    def test_unreadable_sublayout_evidence_raises_link_read_error(self):
        root_layout, root_keys = self._build()
        os.chmod(self.inner_link_path, 0o000)
        self.addCleanup(self._restore_inner_link)
        if os.geteuid() == 0:
            self.skipTest("root bypasses permission bits")

        report = VerificationReport("root")
        with self.assertRaises(LinkReadError) as ctx:
            in_toto_verify(root_layout, root_keys, ".", report=report)

        # The evidence directory of the failing sublayout is reported.
        sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name=self.root_step, keyid=self.alice_pub["keyid"]
        )
        self.assertIn(sub_dir, str(ctx.exception))
        # Original LinkReadError preserved via exception chaining.
        self.assertIsInstance(ctx.exception.__cause__, LinkReadError)
        # No dependent inspection was started.
        self.assertFalse(os.path.exists(self.marker))

        sub_phase = next(
            r for r in report.records if r.name == Phase.SUBLAYOUT_VERIFICATION
        )
        self.assertEqual(sub_phase.status, PhaseStatus.FAILED)
        self.assertTrue(sub_phase.subreports)
        # Inspection phases must be recorded as skipped.
        self.assertTrue(
            all(
                r.status == PhaseStatus.SKIPPED
                for r in report.records
                if r.name == Phase.INSPECTION_EXECUTION
            )
        )

    def test_bad_signature_keeps_threshold_exception_type(self):
        root_layout, root_keys = self._build()
        tampered = Metablock(signed=Link(name=self.inner_step))
        tampered.create_signature(self.bob)
        tampered.signed.name = "tampered"
        tampered.dump(self.inner_link_path)

        report = VerificationReport("root")
        with self.assertRaises(ThresholdVerificationError):
            in_toto_verify(root_layout, root_keys, ".", report=report)

        self.assertFalse(os.path.exists(self.marker))
        sub_phase = next(
            r for r in report.records if r.name == Phase.SUBLAYOUT_VERIFICATION
        )
        subreport = sub_phase.subreports[0]
        threshold_record = next(
            r for r in subreport.records if r.name == Phase.SIGNER_THRESHOLDS
        )
        self.assertEqual(threshold_record.status, PhaseStatus.FAILED)
        reason = threshold_record.detail["outcomes"][0]["reason"]
        self.assertIn("SignatureVerificationError", reason)

    def test_genuine_threshold_insufficiency(self):
        root_layout, root_keys = self._build(
            threshold=2, extra_authorized=True
        )
        # Second authorized functionary never submits a link.
        report = VerificationReport("root")
        with self.assertRaises(LinkNotFoundError):
            in_toto_verify(root_layout, root_keys, ".", report=report)

        self.assertFalse(os.path.exists(self.marker))

    def test_no_summary_link_on_sublayout_failure(self):
        """verify_sublayouts must not return a payload for a failed layout."""
        from in_toto.verifylib import verify_sublayouts

        root_layout, _root_keys = self._build(inspection=False)
        # Load root-level metadata, then break the inner evidence before
        # recursing into the sublayout.
        loaded = load_links_for_layout(root_layout.signed, ".")
        os.chmod(self.inner_link_path, 0o000)
        self.addCleanup(self._restore_inner_link)
        if os.geteuid() == 0:
            self.skipTest("root bypasses permission bits")

        with self.assertRaises(LinkReadError):
            verify_sublayouts(root_layout.signed, loaded, ".", 10)


if __name__ == "__main__":
    unittest.main()
