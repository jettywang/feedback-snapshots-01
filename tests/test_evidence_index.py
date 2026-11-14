# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_evidence_index.py

<Purpose>
  Test the optional evidence index, including full verification with two
  functionaries whose keyids share an eight character prefix, and rejection of
  index bindings that reuse a file, name another step, or leave the evidence
  package (including from inside a sublayout).
"""

import json
import os
import shutil
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from securesystemslib.signer import CryptoSigner, SSlibKey

from in_toto.evidence_index import (
    EVIDENCE_INDEX_FILENAME,
    EvidenceIndex,
)
from in_toto.exceptions import (
    EvidenceIndexError,
    ThresholdVerificationError,
)
from in_toto.in_toto_verify import main as in_toto_verify_main
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import in_toto_verify, load_links_for_layout
from tests.common import TmpDirMixin

SHARED_PREFIX = "deadbeef"


def make_identity(prefix, tag):
    """Create a signer and public key dict with a caller-supplied keyid.

    ``tag`` distinguishes full keyids that share an eight character prefix.
    """
    keyid = prefix + tag * 56
    private_key = Ed25519PrivateKey.generate()
    public_key = SSlibKey.from_crypto(private_key.public_key(), keyid)
    signer = CryptoSigner(private_key, public_key)
    return signer, public_key


def public_key_dict(key):
    """Return the in-toto dict representation of an SSlibKey."""
    data = key.to_dict()
    data["keyid"] = key.keyid
    return data


def sign_link(name, signers, materials=None, products=None, tamper=False):
    """Create signed link metadata with payload name ``name``."""
    metadata = Metablock(
        signed=Link(
            name=name,
            materials=materials or {},
            products=products or {},
        )
    )
    for signer in signers:
        metadata.create_signature(signer)
    if tamper:
        # Mutate the payload after signing so signatures no longer verify.
        metadata.signed.byproducts["tampered"] = True
    return metadata


def sign_layout(layout, signers):
    metadata = Metablock(signed=layout)
    for signer in signers:
        metadata.create_signature(signer)
    return metadata


class EvidenceIndexTestCase(unittest.TestCase, TmpDirMixin):
    """Common fixtures for evidence index tests."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

        cls.owner, cls.owner_key = make_identity("00112233", "a")
        cls.alice, cls.alice_key = make_identity(SHARED_PREFIX, "a")
        cls.bob, cls.bob_key = make_identity(SHARED_PREFIX, "b")
        cls.carl, cls.carl_key = make_identity("cafebabe", "c")

        # The collision the feature exists for.
        assert cls.alice_key.keyid[:8] == cls.bob_key.keyid[:8]
        assert cls.alice_key.keyid != cls.bob_key.keyid

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def setUp(self):
        """Reset the evidence package before each test."""
        for entry in os.listdir("."):
            if entry.startswith(("evidence", EVIDENCE_INDEX_FILENAME)):
                path = entry
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
            for name in (
                "step.",
                "delegate.",
                "inner.",
            ):
                if entry.startswith(name):
                    path = entry
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)

        os.makedirs("evidence", exist_ok=True)

    def write_index(self, data, path=EVIDENCE_INDEX_FILENAME):
        with open(path, "w", encoding="utf8") as fp:
            json.dump(data, fp)
        return path

    def write_metadata(self, metadata, path):
        metadata.dump(path)
        return path

    def threshold_two_layout(self, **step_kwargs):
        layout = Layout(
            keys={
                self.alice_key.keyid: public_key_dict(self.alice_key),
                self.bob_key.keyid: public_key_dict(self.bob_key),
            },
            steps=[
                Step(
                    name="write-code",
                    pubkeys=[self.alice_key.keyid, self.bob_key.keyid],
                    threshold=2,
                    **step_kwargs,
                )
            ],
        )
        return sign_layout(layout, [self.owner])

    def verify(self, layout_metadata, evidence_index=None, link_dir="."):
        return in_toto_verify(
            layout_metadata,
            {self.owner_key.keyid: public_key_dict(self.owner_key)},
            link_dir_path=link_dir,
            evidence_index=evidence_index,
        )

    def canonical_index(self, entries):
        return {"version": 1, "entries": entries}

    def entry(self, step, key, link, sublayout=None):
        data = {"step": step, "keyid": key.keyid, "link": link}
        if sublayout is not None:
            data["sublayout"] = sublayout
        return data


class TestEvidenceIndexSuccessfulVerification(EvidenceIndexTestCase):
    """Demonstrate full verification with colliding short keyid prefixes."""

    def test_threshold_two_with_full_keyid_index(self):
        """Two functionaries share an prefix and each has its own evidence."""
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )

        index_path = self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )

        summary = self.verify(
            self.threshold_two_layout(), evidence_index=index_path
        )
        self.assertEqual(summary.name, "")

        # The same package verifies with automatic index discovery.
        summary = self.verify(self.threshold_two_layout())
        self.assertEqual(summary.name, "")

    def test_compact_steps_form_is_accepted(self):
        """The compact 'steps' form binds the same way as 'entries'."""
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )

        self.write_index(
            {
                "version": 1,
                "steps": {
                    "write-code": {
                        self.alice_key.keyid: "evidence/write-code.alice.link",
                        self.bob_key.keyid: {
                            "link": "evidence/write-code.bob.link"
                        },
                    }
                },
            }
        )

        self.verify(self.threshold_two_layout())

    def test_legacy_filenames_still_load_when_unambiguous(self):
        """An authorized key with a unique short prefix uses the old name."""
        layout = Layout(
            keys={self.carl_key.keyid: public_key_dict(self.carl_key)},
            steps=[
                Step(name="inner", pubkeys=[self.carl_key.keyid], threshold=1)
            ],
        )
        metadata = sign_layout(layout, [self.owner])
        self.write_metadata(
            sign_link("inner", [self.carl]),
            FILENAME_FORMAT.format(
                step_name="inner", keyid=self.carl_key.keyid
            ),
        )
        self.verify(metadata)

    def test_legacy_fallback_for_identity_not_in_index(self):
        """Indexed evidence and unambiguous legacy evidence can mix."""
        layout = Layout(
            keys={
                self.alice_key.keyid: public_key_dict(self.alice_key),
                self.bob_key.keyid: public_key_dict(self.bob_key),
                self.carl_key.keyid: public_key_dict(self.carl_key),
            },
            steps=[
                Step(
                    name="write-code",
                    pubkeys=[
                        self.alice_key.keyid,
                        self.bob_key.keyid,
                        self.carl_key.keyid,
                    ],
                    threshold=3,
                )
            ],
        )
        metadata = sign_layout(layout, [self.owner])

        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.carl]),
            FILENAME_FORMAT.format(
                step_name="write-code", keyid=self.carl_key.keyid
            ),
        )
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )
        self.verify(metadata)


class TestEvidenceIndexRejections(EvidenceIndexTestCase):
    """Index changes are rejected at the stage for the broken binding."""

    def setUp(self):
        super().setUp()
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )

    def assert_binding_error(self, message_fragment):
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(
                self.threshold_two_layout(),
                evidence_index=EVIDENCE_INDEX_FILENAME,
            )
        self.assertIn("binding failed", str(context.exception))
        self.assertIn(message_fragment, str(context.exception))

    def test_two_entries_pointing_at_one_file_are_rejected(self):
        """One file cannot stand in for two functionaries.

        A single file signed by both identities would pass per-entry signature
        identity checks, so only the shared-file binding stops it.
        """
        self.write_metadata(
            sign_link("write-code", [self.alice, self.bob]),
            "evidence/shared.link",
        )
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code", self.alice_key, "evidence/shared.link"
                    ),
                    self.entry(
                        "write-code", self.bob_key, "evidence/shared.link"
                    ),
                ]
            )
        )
        self.assert_binding_error("file binding failed")

    def test_entry_pointing_at_another_step_is_rejected(self):
        """An entry for one step cannot reuse evidence recorded for another."""
        layout = Layout(
            keys={
                self.alice_key.keyid: public_key_dict(self.alice_key),
                self.bob_key.keyid: public_key_dict(self.bob_key),
            },
            steps=[
                Step(
                    name="write-code",
                    pubkeys=[
                        self.alice_key.keyid,
                        self.bob_key.keyid,
                    ],
                    threshold=2,
                ),
                Step(
                    name="package",
                    pubkeys=[self.bob_key.keyid],
                    threshold=1,
                ),
            ],
        )
        metadata = sign_layout(layout, [self.owner])
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )

        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                    # Names "package" but points at a link whose payload is
                    # "write-code". The payload-to-step binding must fail.
                    self.entry(
                        "package",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(metadata, evidence_index=EVIDENCE_INDEX_FILENAME)
        self.assertIn("step binding failed", str(context.exception))
        self.assertIn("'write-code'", str(context.exception))

    def test_entry_naming_unknown_step_is_rejected(self):
        """An index cannot introduce a step the layout does not define."""
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/other.link",
        )
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                    self.entry(
                        "not-a-step", self.carl_key, "evidence/other.link"
                    ),
                ]
            )
        )
        self.assert_binding_error("step binding failed")

    def test_entry_with_unauthorized_keyid_is_rejected(self):
        """Indexing an identity does not authorize it."""
        self.write_metadata(
            sign_link("write-code", [self.carl]),
            "evidence/write-code.carl.link",
        )
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                    self.entry(
                        "write-code",
                        self.carl_key,
                        "evidence/write-code.carl.link",
                    ),
                ]
            )
        )
        self.assert_binding_error("identity binding failed")

    def test_entry_bound_to_file_signed_by_another_keyid_is_rejected(self):
        """The indexed full keyid must match the signature identity."""
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.bob.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )
        self.assert_binding_error("identity binding failed")

    def test_index_cannot_replace_signature_verification(self):
        """Indexed evidence with a broken signature still fails later."""
        self.write_metadata(
            sign_link("write-code", [self.alice], tamper=True),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )
        # Loading succeeds because the index is only a location hint; the
        # broken signature is rejected by the normal threshold verification.
        with self.assertRaises(ThresholdVerificationError) as context:
            self.verify(
                self.threshold_two_layout(),
                evidence_index=EVIDENCE_INDEX_FILENAME,
            )
        self.assertIn("write-code", str(context.exception))

    def test_ambiguous_legacy_filename_is_rejected_without_index(self):
        """Legacy names that match two identities fail instead of guessing."""
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            FILENAME_FORMAT.format(
                step_name="write-code", keyid=self.alice_key.keyid
            ),
        )
        layout = self.threshold_two_layout()
        with self.assertRaises(EvidenceIndexError) as context:
            load_links_for_layout(layout.get_payload(), ".")
        self.assertIn(
            "Legacy evidence filename binding failed", str(context.exception)
        )
        self.assertIn("ambiguous", str(context.exception))

    def test_partial_index_leaves_ambiguous_legacy_name_rejected(self):
        """Indexing one colliding identity does not make the legacy name safe."""
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            FILENAME_FORMAT.format(
                step_name="write-code", keyid=self.alice_key.keyid
            ),
        )
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    )
                ]
            )
        )
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(
                self.threshold_two_layout(),
                evidence_index=EVIDENCE_INDEX_FILENAME,
            )
        self.assertIn(
            "Legacy evidence filename binding failed", str(context.exception)
        )
        self.assertIn("ambiguous", str(context.exception))

    def test_missing_indexed_file_is_rejected(self):
        """An index entry that does not resolve to readable evidence fails."""
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/does-not-exist.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )
        self.assert_binding_error("link path binding failed")

    def test_malformed_index_is_rejected(self):
        """Structural index errors fail before any evidence is trusted."""
        for data, fragment in [
            ({"version": 1}, "exactly one"),
            ({"version": 2, "entries": []}, "version"),
            (
                {
                    "version": 1,
                    "entries": [
                        {
                            "step": "write-code",
                            "keyid": "not-hex",
                            "link": "evidence/x.link",
                        }
                    ],
                },
                "not a hex string",
            ),
            (
                {
                    "version": 1,
                    "entries": [
                        {
                            "step": "write-code",
                            "keyid": self.alice_key.keyid,
                            "link": "evidence/x.link",
                        },
                        {
                            "step": "write-code",
                            "keyid": self.alice_key.keyid.upper(),
                            "link": "evidence/y.link",
                        },
                    ],
                },
                "duplicate",
            ),
        ]:
            self.write_index(data)
            with self.assertRaises(EvidenceIndexError) as context:
                EvidenceIndex.load(EVIDENCE_INDEX_FILENAME, package_root=".")
            self.assertIn(fragment, str(context.exception))


class TestEvidenceIndexPathScope(EvidenceIndexTestCase):
    """Indexed paths cannot leave the evidence package."""

    def setUp(self):
        super().setUp()
        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )

    def _write_entries(self, alice_link):
        self.write_index(
            self.canonical_index(
                [
                    self.entry("write-code", self.alice_key, alice_link),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )

    def test_absolute_path_is_rejected(self):
        self._write_entries(os.path.abspath("evidence/write-code.alice.link"))
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(
                self.threshold_two_layout(),
                evidence_index=EVIDENCE_INDEX_FILENAME,
            )
        self.assertIn("absolute", str(context.exception))
        self.assertIn("link path binding", str(context.exception))

    def test_parent_relative_path_is_rejected(self):
        self._write_entries("../outside.link")
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(
                self.threshold_two_layout(),
                evidence_index=EVIDENCE_INDEX_FILENAME,
            )
        self.assertIn("outside evidence package", str(context.exception))

    def test_symlink_escape_is_rejected(self):
        outside_dir = os.path.realpath(
            os.path.join(self.test_dir, "..", "outside-package")
        )
        os.makedirs(outside_dir, exist_ok=True)
        outside_file = os.path.join(outside_dir, "outside.link")
        with open(outside_file, "w", encoding="utf8") as fp:
            fp.write("not evidence")

        os.symlink(outside_file, "evidence/escape.link")
        self._write_entries("evidence/escape.link")
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(
                self.threshold_two_layout(),
                evidence_index=EVIDENCE_INDEX_FILENAME,
            )
        self.assertIn("outside evidence package", str(context.exception))

    def test_index_file_outside_package_is_rejected(self):
        outside = os.path.join(self.test_dir, "..", "outside-index.json")
        outside = os.path.realpath(outside)
        with open(outside, "w", encoding="utf8") as fp:
            json.dump(self.canonical_index([]), fp)

        with self.assertRaises(EvidenceIndexError) as context:
            EvidenceIndex.load(outside, package_root=".")
        self.assertIn("package scope binding failed", str(context.exception))
        self.assertIn("outside evidence package", str(context.exception))


class TestEvidenceIndexSublayouts(EvidenceIndexTestCase):
    """Index locates sublayout directories within the evidence package."""

    def _build_root(self, index_data):
        # Inner layout: one step performed by carl (unique short prefix).
        inner_layout = Layout(
            keys={self.carl_key.keyid: public_key_dict(self.carl_key)},
            steps=[
                Step(name="inner", pubkeys=[self.carl_key.keyid], threshold=1)
            ],
        )
        inner_link = sign_link("inner", [self.carl])

        for subdir, signer in (
            ("delegate.alice", self.alice),
            ("delegate.bob", self.bob),
        ):
            os.makedirs(subdir)
            self.write_metadata(
                sign_layout(inner_layout, [signer]),
                f"{subdir}/delegate.link",
            )
            self.write_metadata(
                inner_link,
                os.path.join(
                    subdir,
                    FILENAME_FORMAT.format(
                        step_name="inner", keyid=self.carl_key.keyid
                    ),
                ),
            )

        root_layout = Layout(
            keys={
                self.alice_key.keyid: public_key_dict(self.alice_key),
                self.bob_key.keyid: public_key_dict(self.bob_key),
            },
            steps=[
                Step(
                    name="delegate",
                    pubkeys=[self.alice_key.keyid, self.bob_key.keyid],
                    threshold=2,
                )
            ],
        )
        root_metadata = sign_layout(root_layout, [self.owner])
        self.write_index(index_data)
        return root_metadata

    def _entries(self, alice_dir="delegate.alice", bob_dir="delegate.bob"):
        return self.canonical_index(
            [
                self.entry(
                    "delegate",
                    self.alice_key,
                    "delegate.alice/delegate.link",
                    alice_dir,
                ),
                self.entry(
                    "delegate",
                    self.bob_key,
                    "delegate.bob/delegate.link",
                    bob_dir,
                ),
            ]
        )

    def _write_inner_index(self, directory, data):
        with open(
            os.path.join(directory, "evidence-index.json"),
            "w",
            encoding="utf8",
        ) as fp:
            json.dump(data, fp)

    def test_full_verification_with_indexed_sublayouts(self):
        root = self._build_root(self._entries())
        self.verify(root, evidence_index=EVIDENCE_INDEX_FILENAME)

    def test_sublayout_index_cannot_escape_its_scope(self):
        """A sublayout's own index must stay inside that sublayout."""
        _alice_dir, bob_dir = ("delegate.alice", "delegate.bob")

        root = self._build_root(self._entries())

        self._write_inner_index(
            "delegate.alice",
            {
                "version": 1,
                "entries": [
                    {
                        "step": "inner",
                        "keyid": self.carl_key.keyid,
                        # Points outside the sublayout's own directory.
                        "link": os.path.join(
                            "..",
                            bob_dir,
                            FILENAME_FORMAT.format(
                                step_name="inner",
                                keyid=self.carl_key.keyid,
                            ),
                        ),
                    }
                ],
            },
        )

        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(root, evidence_index=EVIDENCE_INDEX_FILENAME)
        self.assertIn("outside evidence package", str(context.exception))
        self.assertIn("inner", str(context.exception))

    def test_sublayout_directory_must_stay_in_package(self):
        root = self._build_root(self._entries(alice_dir="../outside-sublayout"))
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(root, evidence_index=EVIDENCE_INDEX_FILENAME)
        self.assertIn("sublayout path binding", str(context.exception))
        self.assertIn("outside evidence package", str(context.exception))

    def test_two_functionaries_cannot_share_a_sublayout_directory(self):
        """Pointing both identities at one directory is a broken binding."""
        root = self._build_root(
            self._entries(alice_dir="delegate.alice", bob_dir="delegate.alice")
        )
        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(root, evidence_index=EVIDENCE_INDEX_FILENAME)
        self.assertIn(
            "sublayout directory binding failed", str(context.exception)
        )
        self.assertIn("delegate.alice", str(context.exception))

    def test_ambiguous_legacy_sublayout_directory_is_rejected(self):
        """A legacy sublayout dir shared by a prefix collision is not guessed."""
        from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT

        inner_layout = Layout(
            keys={self.carl_key.keyid: public_key_dict(self.carl_key)},
            steps=[
                Step(name="inner", pubkeys=[self.carl_key.keyid], threshold=1)
            ],
        )
        inner_link = sign_link("inner", [self.carl])

        legacy_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name="delegate", keyid=self.alice_key.keyid
        )
        os.makedirs(legacy_dir)
        sign_layout(inner_layout, [self.alice]).dump(
            os.path.join(legacy_dir, "delegate.link")
        )
        inner_link.dump(
            os.path.join(
                legacy_dir,
                FILENAME_FORMAT.format(
                    step_name="inner", keyid=self.carl_key.keyid
                ),
            )
        )

        # The top-level sublayout metadata is located by the index; only the
        # legacy directory name is left ambiguous.
        sign_layout(inner_layout, [self.alice]).dump("evidence/delegate.link")
        self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "delegate",
                        self.alice_key,
                        "evidence/delegate.link",
                    )
                ]
            )
        )

        root_layout = Layout(
            keys={
                self.alice_key.keyid: public_key_dict(self.alice_key),
                self.bob_key.keyid: public_key_dict(self.bob_key),
            },
            steps=[
                Step(
                    name="delegate",
                    pubkeys=[self.alice_key.keyid, self.bob_key.keyid],
                    threshold=1,
                )
            ],
        )
        root = sign_layout(root_layout, [self.owner])

        with self.assertRaises(EvidenceIndexError) as context:
            self.verify(root, evidence_index=EVIDENCE_INDEX_FILENAME)
        self.assertIn(
            "Legacy sublayout directory binding failed",
            str(context.exception),
        )
        self.assertIn("delegate.deadbeef", str(context.exception))


class TestEvidenceIndexScopeMismatch(EvidenceIndexTestCase):
    """An index object is bound to the evidence package it was loaded for."""

    def test_index_instance_for_other_package_is_rejected(self):
        os.makedirs("other", exist_ok=True)
        index = EvidenceIndex.from_dict(
            self.canonical_index([]), package_root="other"
        )
        with self.assertRaises(EvidenceIndexError) as context:
            load_links_for_layout(
                self.threshold_two_layout().get_payload(), ".", index
            )
        self.assertIn("package scope binding failed", str(context.exception))


class TestEvidenceIndexCLI(EvidenceIndexTestCase):
    """The in-toto-verify CLI exposes the evidence index."""

    def assert_cli_sys_exit(self, cli_args, status):
        with (
            patch.object(sys, "argv", ["in-toto-verify"] + cli_args),
            self.assertRaises(SystemExit) as raise_ctx,
        ):
            in_toto_verify_main()

        self.assertEqual(raise_ctx.exception.code, status)

    def _write_layout(self):
        # The CLI loads the layout verification key from PEM and computes a
        # default keyid, so use an owner key with that default keyid here.
        owner_private = Ed25519PrivateKey.generate()
        owner_key = SSlibKey.from_crypto(owner_private.public_key())
        owner_signer = CryptoSigner(owner_private, owner_key)

        layout = Layout(
            keys={
                self.alice_key.keyid: public_key_dict(self.alice_key),
                self.bob_key.keyid: public_key_dict(self.bob_key),
            },
            steps=[
                Step(
                    name="write-code",
                    pubkeys=[self.alice_key.keyid, self.bob_key.keyid],
                    threshold=2,
                )
            ],
        )
        sign_layout(layout, [owner_signer]).dump("root.layout")

        with open("owner_public.pem", "wb") as fp:
            fp.write(
                owner_key._crypto_key().public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )
            )

        self.write_metadata(
            sign_link("write-code", [self.alice]),
            "evidence/write-code.alice.link",
        )
        self.write_metadata(
            sign_link("write-code", [self.bob]),
            "evidence/write-code.bob.link",
        )
        return self.write_index(
            self.canonical_index(
                [
                    self.entry(
                        "write-code",
                        self.alice_key,
                        "evidence/write-code.alice.link",
                    ),
                    self.entry(
                        "write-code",
                        self.bob_key,
                        "evidence/write-code.bob.link",
                    ),
                ]
            )
        )

    def test_cli_verifies_with_explicit_evidence_index(self):
        index_path = self._write_layout()
        self.assert_cli_sys_exit(
            [
                "--layout",
                "root.layout",
                "--verification-keys",
                "owner_public.pem",
                "--evidence-index",
                index_path,
            ],
            0,
        )

    def test_cli_rejects_ambiguous_index(self):
        index_path = self._write_layout()
        with open(index_path, encoding="utf8") as fp:
            data = json.load(fp)
        for entry in data["entries"]:
            entry["link"] = "evidence/write-code.alice.link"
        with open(index_path, "w", encoding="utf8") as fp:
            json.dump(data, fp)

        self.assert_cli_sys_exit(
            [
                "--layout",
                "root.layout",
                "--verification-keys",
                "owner_public.pem",
                "--evidence-index",
                index_path,
            ],
            1,
        )


if __name__ == "__main__":
    unittest.main()
