# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for signed artifact digest configuration."""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import in_toto.artifact_digest as digest
import in_toto.runlib as runlib
import in_toto.verifylib as verifylib
from in_toto.exceptions import (
    DigestConfigError,
    RuleVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.in_toto_run import main as run_main
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock, Metadata
from in_toto.rulelib import unpack_rule
from tests.common import PEMS, SignerStore, TmpDirMixin, VersionedPython

LINE_FEED = b"hello\ntoto\n"
CARRIAGE_RETURN_LINE_FEED = b"hello\r\ntoto\r\n"
CARRIAGE_RETURN = b"hello\rtoto\r"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class TestDigestConfigParsing(unittest.TestCase):
    """Test descriptor validation and canonicalization."""

    def test_legacy_none_passthrough(self):
        self.assertIsNone(digest.parse_artifact_digest_config(None))
        self.assertEqual(
            digest.effective_normalization(None, "materials", "sha256"),
            digest.NORMALIZATION_RAW,
        )

    def test_shorthands(self):
        expected = {
            "materials": {"*": "line-endings"},
            "products": {"*": "line-endings"},
        }
        for value in (
            "line-endings",
            {"normalization": "line-endings"},
            {"materials": "line-endings", "products": "line-endings"},
        ):
            self.assertEqual(
                digest.parse_artifact_digest_config(value), expected, value
            )

        self.assertEqual(
            digest.parse_artifact_digest_config({"sha256": "line-endings"}),
            {
                "materials": {"sha256": "line-endings"},
                "products": {"sha256": "line-endings"},
            },
        )

    def test_aliases_are_canonicalized(self):
        self.assertEqual(
            digest.parse_artifact_digest_config("CRLF-to-LF"),
            {
                "materials": {"*": "line-endings"},
                "products": {"*": "line-endings"},
            },
        )

    def test_unknown_normalization_raises(self):
        for value in (
            "bogus",
            {"normalization": "bogus"},
            {"materials": "bogus", "products": "raw"},
            {"sha256": "bogus"},
            {"materials": {"sha256": "bogus"}},
        ):
            with self.assertRaises(DigestConfigError):
                digest.parse_artifact_digest_config(value)

    def test_malformed_config_raises(self):
        for value in (
            1,
            [],
            {"materials": 1, "products": "raw"},
            {"materials": {"sha256": 1}, "products": "raw"},
            {"normalization": "raw", "materials": "raw"},
            {"normalization": "raw", "extra": "raw"},
            {"materials": {"sha256": "raw"}, "unknown": "raw"},
        ):
            with self.assertRaises(DigestConfigError):
                digest.parse_artifact_digest_config(value)

    def test_explicit_config_must_describe_recorded_algorithms(self):
        with self.assertRaises(DigestConfigError):
            Link(
                materials={"foo": {"sha512": "ab"}},
                artifact_digest_config={"materials": {"sha256": "raw"}},
            )


class TestLinkDigestConfig(unittest.TestCase):
    """Test descriptor serialization and signature protection."""

    def test_legacy_link_has_no_field_in_signed_payload(self):
        link = Link(name="step", materials={"foo": {"sha256": "ab"}})
        self.assertNotIn("artifact_digest_config", link.to_dict())
        self.assertNotIn(b"artifact_digest_config", link.signable_bytes)
        # Round-trip stays legacy and keeps the exact signed bytes.
        loaded = Link.read(json.loads(link.signable_bytes))
        self.assertIsNone(loaded.artifact_digest_config)
        self.assertEqual(loaded.signable_bytes, link.signable_bytes)

    def test_explicit_descriptor_is_signed(self):
        link = Link(
            name="step",
            materials={"foo": {"sha256": "ab"}},
            artifact_digest_config={"materials": "raw", "products": "raw"},
        )
        self.assertIn(b"artifact_digest_config", link.signable_bytes)

        metadata = Metablock(signed=link)
        metadata.create_signature(SignerStore.rsa)
        self.assertIn("artifact_digest_config", metadata.to_dict()["signed"])

        metadata.verify_signature(SignerStore.rsa_pub)

        metadata.signed.artifact_digest_config["materials"]["*"] = (
            "line-endings"
        )
        with self.assertRaises(SignatureVerificationError):
            metadata.verify_signature(SignerStore.rsa_pub)

    def test_descriptor_roundtrip_through_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "step.link")
            link = Link(
                name="step",
                materials={"foo": {"sha256": "ab"}},
                artifact_digest_config={
                    "materials": "raw",
                    "products": "line-endings",
                },
            )
            metadata = Metablock(signed=link)
            metadata.create_signature(SignerStore.rsa)
            metadata.dump(path)

            loaded = Metadata.load(path)
            loaded.verify_signature(SignerStore.rsa_pub)
            self.assertEqual(
                loaded.get_payload().artifact_digest_config,
                {
                    "materials": {"*": "raw"},
                    "products": {"*": "line-endings"},
                },
            )


class TestRecordAndRecompute(TmpDirMixin, unittest.TestCase):
    """End-to-end recording and byte-level re-computation tests."""

    def setUp(self):
        self.set_up_test_dir()
        self.signer = SignerStore.rsa
        self.pubkey = SignerStore.rsa_pub
        Path("lf.txt").write_bytes(LINE_FEED)
        Path("crlf.txt").write_bytes(CARRIAGE_RETURN_LINE_FEED)

    def tearDown(self):
        self.tear_down_test_dir()

    def test_raw_recording_rejects_newline_variant_on_recompute(self):
        link = runlib.in_toto_run(
            "step",
            ["lf.txt"],
            ["lf.txt"],
            [],
            signer=self.signer,
            artifact_digest_config={"materials": "raw", "products": "raw"},
        ).get_payload()

        self.assertEqual(
            link.artifact_digest_config,
            {
                "materials": {"sha256": "raw"},
                "products": {"sha256": "raw"},
            },
        )
        # The digest is the byte-exact SHA-256, not a text normalization.
        self.assertEqual(link.materials["lf.txt"]["sha256"], _sha256(LINE_FEED))
        self.assertNotEqual(
            link.materials["lf.txt"]["sha256"],
            _sha256(CARRIAGE_RETURN_LINE_FEED),
        )

        # Recomputing the CRLF file under the link's raw policy differs.
        artifacts = runlib.record_artifacts_as_dict(
            ["crlf.txt"],
            artifact_digest_config=link.artifact_digest_config,
            artifact_type="materials",
        )
        self.assertNotEqual(link.materials["lf.txt"], artifacts["crlf.txt"])

    def test_line_ending_recording_accepts_variants_but_respects_policy(self):
        link = runlib.in_toto_run(
            "step",
            ["lf.txt"],
            ["lf.txt"],
            [],
            signer=self.signer,
            artifact_digest_config={
                "materials": "line-endings",
                "products": "line-endings",
            },
        ).get_payload()

        self.assertEqual(
            link.materials["lf.txt"]["sha256"],
            _sha256(digest.normalize_line_endings_bytes(LINE_FEED)),
        )
        self.assertEqual(link.materials["lf.txt"]["sha256"], _sha256(LINE_FEED))

        artifacts = runlib.record_artifacts_as_dict(
            ["crlf.txt"],
            artifact_digest_config=link.artifact_digest_config,
            artifact_type="materials",
        )
        self.assertEqual(link.materials["lf.txt"], artifacts["crlf.txt"])

        # Under raw policy the same bytes do not compare.
        raw_artifacts = runlib.record_artifacts_as_dict(
            ["crlf.txt"],
            artifact_digest_config={"materials": "raw"},
            artifact_type="materials",
        )
        self.assertNotEqual(link.materials["lf.txt"], raw_artifacts["crlf.txt"])

    def test_record_start_stop_preserves_product_policy(self):
        runlib.in_toto_record_start(
            "step",
            ["lf.txt"],
            signer=self.signer,
            artifact_digest_config={
                "materials": "line-endings",
                "products": "line-endings",
            },
        )
        Path("lf.txt").write_bytes(CARRIAGE_RETURN_LINE_FEED)
        runlib.in_toto_record_stop("step", ["lf.txt"], signer=self.signer)
        link = Metablock.load(
            FILENAME_FORMAT.format(
                step_name="step", keyid=self.signer.public_key.keyid
            )
        ).signed
        self.assertEqual(
            link.artifact_digest_config,
            {
                "materials": {"sha256": "line-endings"},
                "products": {"sha256": "line-endings"},
            },
        )
        self.assertEqual(link.materials["lf.txt"], link.products["lf.txt"])

    def test_materials_only_config_records_explicit_products(self):
        link = runlib.in_toto_run(
            "step",
            ["lf.txt"],
            [],
            [],
            signer=self.signer,
            artifact_digest_config={"materials": "line-endings"},
        ).get_payload()
        self.assertEqual(
            link.artifact_digest_config,
            {"materials": {"sha256": "line-endings"}},
        )

        with self.assertRaises(DigestConfigError):
            runlib.in_toto_run(
                "step",
                ["lf.txt"],
                ["lf.txt"],
                [],
                signer=self.signer,
                artifact_digest_config={"materials": "line-endings"},
            )

    def test_normalize_flag_and_config_conflict(self):
        with self.assertRaises(DigestConfigError):
            runlib.in_toto_run(
                "step",
                ["lf.txt"],
                [],
                [],
                signer=self.signer,
                normalize_line_endings=True,
                artifact_digest_config={"materials": "raw"},
            )

    def test_default_metadata_is_explicit_raw(self):
        link = runlib.in_toto_run(
            "step", ["lf.txt"], ["lf.txt"], [], signer=self.signer
        ).get_payload()
        self.assertEqual(
            link.artifact_digest_config,
            {
                "materials": {"sha256": "raw"},
                "products": {"sha256": "raw"},
            },
        )

    def test_match_products_uses_signed_policy(self):
        link = runlib.in_toto_run(
            "step",
            [],
            ["lf.txt"],
            [],
            signer=self.signer,
            artifact_digest_config={"products": "line-endings"},
        ).get_payload()

        # Same path, but only newline variants: accepted only when recorded
        # with the link's declared normalization.
        Path("lf.txt").write_bytes(CARRIAGE_RETURN_LINE_FEED)
        only_products, not_in_products, differ = runlib.in_toto_match_products(
            link,
            paths=["lf.txt"],
            artifact_digest_config={"products": "line-endings"},
        )
        self.assertEqual(differ, set())

        only_products, not_in_products, differ = runlib.in_toto_match_products(
            link,
            paths=["lf.txt"],
            artifact_digest_config={"products": "raw"},
        )
        self.assertIn("lf.txt", differ)

    def test_match_products_legacy_link_uses_raw(self):
        link = Link(
            name="step", products={"crlf.txt": {"sha256": _sha256(LINE_FEED)}}
        )
        only_products, not_in_products, differ = runlib.in_toto_match_products(
            link, paths=["crlf.txt"]
        )
        self.assertIn("crlf.txt", differ)


class TestVerifyPolicy(unittest.TestCase):
    """Test MATCH, threshold, and summary policy propagation."""

    hash_dict = {"sha256": "a" * 64}

    def _link(self, name, side, normalization):
        return Link(
            name=name,
            **{side: {"foo": self.hash_dict}},
            artifact_digest_config={side: normalization},
        )

    def test_match_rejects_equal_digest_with_different_policy(self):
        source = self._link("source", "materials", "raw")
        dest = self._link("dest", "products", "line-endings")

        consumed = verifylib.verify_match_rule(
            unpack_rule(["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "dest"]),
            {"foo"},
            source.materials,
            {"dest": dest},
            source_link=source,
            source_type="materials",
        )
        self.assertEqual(consumed, set())

    def test_match_accepts_equal_digest_with_same_policy(self):
        for normalization in ("raw", "line-endings"):
            source = self._link("source", "materials", normalization)
            dest = self._link("dest", "products", normalization)
            consumed = verifylib.verify_match_rule(
                unpack_rule(
                    ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "dest"]
                ),
                {"foo"},
                source.materials,
                {"dest": dest},
                source_link=source,
                source_type="materials",
            )
            self.assertEqual(consumed, {"foo"})

    def test_match_legacy_source_is_raw(self):
        legacy_source = Link(name="source", materials={"foo": self.hash_dict})
        explicit_dest = self._link("dest", "products", "line-endings")
        consumed = verifylib.verify_match_rule(
            unpack_rule(["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "dest"]),
            {"foo"},
            legacy_source.materials,
            {"dest": explicit_dest},
            source_link=legacy_source,
            source_type="materials",
        )
        self.assertEqual(consumed, set())

    def test_match_unknown_policy_raises(self):
        source = self._link("source", "materials", "raw")
        dest = self._link("dest", "products", "raw")
        dest.artifact_digest_config["products"]["*"] = "made-up"
        with self.assertRaises(DigestConfigError):
            verifylib.verify_match_rule(
                unpack_rule(
                    ["MATCH", "foo", "WITH", "PRODUCTS", "FROM", "dest"]
                ),
                {"foo"},
                source.materials,
                {"dest": dest},
                source_link=source,
                source_type="materials",
            )

    def test_threshold_rejects_same_digest_different_policy(self):
        layout = Layout(steps=[Step(name="step", threshold=2)])
        link_a = self._link("step", "materials", "raw")
        link_b = self._link("step", "materials", "line-endings")
        with self.assertRaises(verifylib.ThresholdVerificationError):
            verifylib.verify_threshold_constraints(
                layout, {"step": {"a": link_a, "b": link_b}}
            )

    def test_threshold_accepts_same_digest_same_policy(self):
        layout = Layout(steps=[Step(name="step", threshold=2)])
        link_a = self._link("step", "materials", "line-endings")
        link_b = self._link("step", "materials", "line-endings")
        verifylib.verify_threshold_constraints(
            layout, {"step": {"a": link_a, "b": link_b}}
        )

    def test_summary_preserves_side_policies(self):
        first = Link(
            name="first",
            materials={"foo": self.hash_dict},
            artifact_digest_config={"materials": "line-endings"},
        )
        last = Link(
            name="last",
            products={"bar": self.hash_dict},
            artifact_digest_config={"products": "raw"},
        )
        layout = Layout(
            steps=[Step(name="first"), Step(name="last")],
        )
        summary = verifylib.get_summary_link(
            layout, {"first": first, "last": last}, "summary"
        )
        self.assertEqual(
            summary.artifact_digest_config,
            {
                "materials": {"sha256": "line-endings"},
                "products": {"sha256": "raw"},
            },
        )

    def test_summary_legacy_stays_legacy(self):
        first = Link(name="first", materials={"foo": self.hash_dict})
        last = Link(name="last", products={"bar": self.hash_dict})
        layout = Layout(steps=[Step(name="first"), Step(name="last")])
        summary = verifylib.get_summary_link(
            layout, {"first": first, "last": last}, "summary"
        )
        self.assertIsNone(summary.artifact_digest_config)
        self.assertNotIn(b"artifact_digest_config", summary.signable_bytes)


class TestFullVerificationPolicy(TmpDirMixin, unittest.TestCase):
    """Full verification with raw and normalized attestations.

    A two-step chain is chained with a MATCH rule. In the positive case both
    steps declare line-ending normalization and the second step sees a newline
    variant of the first step's product. In raw mode the same variant is
    rejected. Removing or changing either side's signed descriptor also fails
    verification.
    """

    def setUp(self):
        self.set_up_test_dir()
        self.layout_signer = SignerStore.rsa
        self.layout_pub = SignerStore.rsa_pub
        self.step_a_signer = SignerStore.ecdsa
        self.step_a_pub = SignerStore.ecdsa_pub
        self.step_b_signer = SignerStore.ed25519
        self.step_b_pub = SignerStore.ed25519_pub
        self.step_a_name = "step-a"
        self.step_b_name = "step-b"

        Path("artifact.txt").write_bytes(LINE_FEED)

    def tearDown(self):
        self.tear_down_test_dir()

    def _write_link(self, step_name, signer, materials, normalization):
        link = Link(
            name=step_name,
            materials=materials,
            products={},
            artifact_digest_config={
                "materials": normalization,
                "products": normalization,
            },
        )
        metadata = Metablock(signed=link)
        metadata.create_signature(signer)
        filename = FILENAME_FORMAT.format(
            step_name=step_name, keyid=signer.public_key.keyid
        )
        metadata.dump(filename)

    def _make_layout(self):
        layout = Layout(
            keys={
                self.step_a_pub["keyid"]: self.step_a_pub,
                self.step_b_pub["keyid"]: self.step_b_pub,
            },
            steps=[
                Step(
                    name=self.step_a_name,
                    pubkeys=[self.step_a_pub["keyid"]],
                    expected_products=[["ALLOW", "*"]],
                ),
                Step(
                    name=self.step_b_name,
                    pubkeys=[self.step_b_pub["keyid"]],
                    expected_materials=[
                        [
                            "MATCH",
                            "artifact.txt",
                            "WITH",
                            "PRODUCTS",
                            "FROM",
                            self.step_a_name,
                        ],
                        ["DISALLOW", "*"],
                    ],
                    expected_products=[["ALLOW", "*"]],
                ),
            ],
        )
        metadata = Metablock(signed=layout)
        metadata.create_signature(self.layout_signer)
        return metadata

    def _run_raw(self):
        link_a = runlib.in_toto_run(
            self.step_a_name,
            ["artifact.txt"],
            ["artifact.txt"],
            [],
            signer=self.step_a_signer,
            artifact_digest_config={"materials": "raw", "products": "raw"},
        )
        # Step B records a newline-only variant under its own raw declaration.
        Path("artifact.txt").write_bytes(CARRIAGE_RETURN_LINE_FEED)
        link_b = runlib.in_toto_run(
            self.step_b_name,
            ["artifact.txt"],
            ["artifact.txt"],
            [],
            signer=self.step_b_signer,
            artifact_digest_config={"materials": "raw", "products": "raw"},
        )
        return link_a, link_b

    def _run_normalized(self):
        link_a = runlib.in_toto_run(
            self.step_a_name,
            ["artifact.txt"],
            ["artifact.txt"],
            [],
            signer=self.step_a_signer,
            artifact_digest_config={
                "materials": "line-endings",
                "products": "line-endings",
            },
        )
        Path("artifact.txt").write_bytes(CARRIAGE_RETURN_LINE_FEED)
        link_b = runlib.in_toto_run(
            self.step_b_name,
            ["artifact.txt"],
            ["artifact.txt"],
            [],
            signer=self.step_b_signer,
            artifact_digest_config={
                "materials": "line-endings",
                "products": "line-endings",
            },
        )
        return link_a, link_b

    def test_raw_mode_rejects_newline_only_difference(self):
        link_a, link_b = self._run_raw()
        layout = self._make_layout()
        with self.assertRaises(RuleVerificationError):
            verifylib.in_toto_verify(
                layout, {self.layout_pub["keyid"]: self.layout_pub}
            )

    def test_jointly_declared_normalized_mode_accepts_difference(self):
        link_a, link_b = self._run_normalized()
        layout = self._make_layout()
        summary = verifylib.in_toto_verify(
            layout, {self.layout_pub["keyid"]: self.layout_pub}
        )
        self.assertEqual(
            summary.artifact_digest_config,
            {
                "materials": {"sha256": "line-endings"},
                "products": {"sha256": "line-endings"},
            },
        )

    def test_removing_one_descriptor_fails_full_verification(self):
        self._run_normalized()
        link_b_path = FILENAME_FORMAT.format(
            step_name=self.step_b_name, keyid=self.step_b_pub["keyid"]
        )
        metadata = Metablock.load(link_b_path)
        # Removing the descriptor makes B a legacy raw link, which must not be
        # treated as matching A's normalized declaration.
        metadata.signed.artifact_digest_config = None
        metadata.signatures = []
        metadata.create_signature(self.step_b_signer)
        metadata.dump(link_b_path)

        layout = self._make_layout()
        with self.assertRaises(RuleVerificationError):
            verifylib.in_toto_verify(
                layout, {self.layout_pub["keyid"]: self.layout_pub}
            )

    def test_changing_one_descriptor_fails_full_verification(self):
        self._run_normalized()
        link_b_path = FILENAME_FORMAT.format(
            step_name=self.step_b_name, keyid=self.step_b_pub["keyid"]
        )
        metadata = Metablock.load(link_b_path)
        # Declare its recorded material digest as raw instead of normalized.
        metadata.signed.artifact_digest_config["materials"]["sha256"] = "raw"
        metadata.signatures = []
        metadata.create_signature(self.step_b_signer)
        metadata.dump(link_b_path)

        layout = self._make_layout()
        with self.assertRaises(RuleVerificationError):
            verifylib.in_toto_verify(
                layout, {self.layout_pub["keyid"]: self.layout_pub}
            )

    def test_tampered_descriptor_without_resigning_fails_signature(self):
        self._run_normalized()
        link_b_path = FILENAME_FORMAT.format(
            step_name=self.step_b_name, keyid=self.step_b_pub["keyid"]
        )
        metadata = Metablock.load(link_b_path)
        # Change the descriptor in the signed payload without re-signing.
        metadata.signed.artifact_digest_config["materials"]["sha256"] = "raw"
        metadata.dump(link_b_path)

        layout = self._make_layout()
        # The tampered link no longer verifies; full verification fails because
        # the step then lacks a valid link.
        with self.assertRaises(
            (SignatureVerificationError, ThresholdVerificationError)
        ):
            verifylib.in_toto_verify(
                layout, {self.layout_pub["keyid"]: self.layout_pub}
            )

    def test_threshold_mismatch_of_policies_fails_full_verification(self):
        # Two functionaries provide the same digest values but one declares
        # raw and the other normalized. They must not count as agreement.
        digest_value = _sha256(LINE_FEED)
        layout = Layout(
            keys={
                self.step_a_pub["keyid"]: self.step_a_pub,
                self.step_b_pub["keyid"]: self.step_b_pub,
            },
            steps=[
                Step(
                    name=self.step_a_name,
                    pubkeys=[
                        self.step_a_pub["keyid"],
                        self.step_b_pub["keyid"],
                    ],
                    threshold=2,
                )
            ],
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(self.layout_signer)

        for signer, normalization in (
            (self.step_a_signer, "raw"),
            (self.step_b_signer, "line-endings"),
        ):
            link = Link(
                name=self.step_a_name,
                materials={"artifact.txt": {"sha256": digest_value}},
                artifact_digest_config={"materials": normalization},
            )
            metadata = Metablock(signed=link)
            metadata.create_signature(signer)
            metadata.dump(
                FILENAME_FORMAT.format(
                    step_name=self.step_a_name,
                    keyid=signer.public_key.keyid,
                )
            )

        with self.assertRaises(ThresholdVerificationError):
            verifylib.in_toto_verify(
                layout_metadata, {self.layout_pub["keyid"]: self.layout_pub}
            )


class TestCliPolicy(TmpDirMixin, unittest.TestCase):
    """Test CLI exposure of the digest configuration."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        cls.key_path = str(PEMS / "rsa_private_unencrypted.pem")
        cls.link_name = FILENAME_FORMAT.format(
            step_name="step", keyid=SignerStore.rsa_pub["keyid"]
        )

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def tearDown(self):
        if os.path.exists(self.link_name):
            os.remove(self.link_name)

    def test_cli_config_json(self):
        Path("lf.txt").write_bytes(LINE_FEED)
        args = [
            "-n",
            "step",
            "--signing-key",
            self.key_path,
            "--artifact-digest-config",
            '{"materials": "line-endings", "products": "raw"}',
            "-m",
            "lf.txt",
            "-p",
            "lf.txt",
            "--",
            VersionedPython,
            "--version",
        ]
        with (
            patch.object(sys, "argv", ["in-toto-run"] + args),
            self.assertRaises(SystemExit) as ctx,
        ):
            run_main()

        self.assertEqual(ctx.exception.code, 0)
        link = Metablock.load(self.link_name).signed
        self.assertEqual(
            link.artifact_digest_config,
            {
                "materials": {"sha256": "line-endings"},
                "products": {"sha256": "raw"},
            },
        )

    def test_cli_config_file(self):
        Path("lf.txt").write_bytes(LINE_FEED)
        Path("digest.json").write_text(
            json.dumps({"materials": "raw", "products": "raw"})
        )
        args = [
            "-n",
            "step",
            "--signing-key",
            self.key_path,
            "--artifact-digest-config",
            "digest.json",
            "-m",
            "lf.txt",
            "--",
            VersionedPython,
            "--version",
        ]
        with (
            patch.object(sys, "argv", ["in-toto-run"] + args),
            self.assertRaises(SystemExit) as ctx,
        ):
            run_main()

        self.assertEqual(ctx.exception.code, 0)
        link = Metablock.load(self.link_name).signed
        self.assertEqual(
            link.artifact_digest_config,
            {
                "materials": {"sha256": "raw"},
                "products": {"*": "raw"},
            },
        )


if __name__ == "__main__":
    unittest.main()
