"""Tests for the offline strong-name / Authenticode lab.

They build synthetic managed PEs in a temp directory and never execute them.
The external-corpus pefile tests are separate; these do not need tests/test_files.
"""

from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from strongname_lab import authenticode, crypto, der, external, fixtures, metadata, pe_builder, report, verify


class MetadataRoundTripTest(unittest.TestCase):
    def test_builder_reader_round_trip(self):
        builder = metadata.MetadataBuilder("Contoso.Utils", version="1.2.3.4")
        builder.public_key = b"\x06\x02\x00\x00" + b"\x00" * 20
        builder.add_assembly_ref("Other", "2.0.0.0", bytes.fromhex("ed20994d3bc2547f"))
        raw = builder.build()
        parsed = metadata.Metadata(raw, 0)
        self.assertEqual(parsed.version, metadata.METADATA_VERSION)
        self.assertEqual(parsed.assembly["Name"], "Contoso.Utils")
        self.assertEqual(parsed.assembly["MajorVersion"], 1)
        self.assertEqual(len(parsed.table_rows[metadata.TABLE_ASSEMBLYREF]), 1)

    def test_truncated_metadata_is_rejected(self):
        builder = metadata.MetadataBuilder("Contoso.Utils")
        raw = builder.build()
        with self.assertRaises(metadata.MetadataError):
            metadata.Metadata(raw[:24], 0)


class TokenIdentityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(__file__).parent.parent / "strongname_lab/out/pytest-token"
        if cls.tmp.exists():
            shutil.rmtree(cls.tmp)
        fixtures.build_all(cls.tmp)

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_token_is_sha1_tail_of_public_key_blob(self):
        keys = fixtures.keys()
        blob = crypto.public_key_blob(keys["signer"])
        import hashlib

        expected = hashlib.sha1(blob).digest()[-8:][::-1].hex()
        self.assertEqual(crypto.token_from_public_key_blob(blob), expected)

    def test_token_collision_story(self):
        """Equal token != equal key: the token is only 64 bits of a hash."""
        keys = fixtures.keys()
        token = crypto.token_from_public_key_blob(crypto.public_key_blob(keys["signer"]))
        token_forgery = verify.strong_name_check((self.tmp / "sn_token_forgery.bin").read_bytes())
        # The forged image reuses the real key blob, so the token necessarily
        # matches; the signature was made with a different private key.
        self.assertEqual(token_forgery["identity"]["public_key_token"], token)
        self.assertFalse(token_forgery["checks"]["rsa_signature_valid"])


class FixtureMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(__file__).parent.parent / "strongname_lab/out/pytest-fixtures"
        if cls.tmp.exists():
            shutil.rmtree(cls.tmp)
        cls.manifest = fixtures.build_all(cls.tmp)
        cls.anchor = verify.parse_certificate(fixtures._root_and_leaf("signer")[0])

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def image(self, name):
        return (self.tmp / f"{name}.bin").read_bytes()

    def test_full_strong_name_is_valid(self):
        result = verify.strong_name_check(self.image("sn_full"))
        self.assertTrue(result["checks"]["rsa_signature_valid"])
        self.assertTrue(result["checks"]["embedded_digest_matches_content"])
        self.assertEqual(result["verdict"]["signature_integrity"], "valid")

    def test_delay_signed_has_zero_slot(self):
        result = verify.strong_name_check(self.image("sn_delay"))
        self.assertFalse(result["checks"]["rsa_signature_valid"])
        self.assertIn("all zero", result["checks"]["rsa_verification_detail"])
        self.assertFalse(result["cli"]["strong_name_signed_flag"])

    def test_flag_only_is_not_evidence(self):
        result = verify.strong_name_check(self.image("sn_flag_only"))
        self.assertTrue(result["cli"]["strong_name_signed_flag"])
        self.assertIsNone(result["cli"]["signature_file_offset"])
        self.assertFalse(result["checks"]["rsa_signature_valid"])
        self.assertTrue(result["verdict"]["flag_alone_is_not_evidence"])

    def test_body_tamper_breaks_strong_name(self):
        result = verify.strong_name_check(self.image("sn_body_tampered"))
        self.assertFalse(result["checks"]["rsa_signature_valid"])
        self.assertFalse(result["checks"]["embedded_digest_matches_content"])

    def test_token_unchanged_but_signature_fails(self):
        full = verify.strong_name_check(self.image("sn_full"))
        forged = verify.strong_name_check(self.image("sn_token_forgery"))
        self.assertEqual(full["identity"]["public_key_token"], forged["identity"]["public_key_token"])
        self.assertTrue(full["checks"]["rsa_signature_valid"])
        self.assertFalse(forged["checks"]["rsa_signature_valid"])
        self.assertEqual(full["identity"]["public_key_sha256"], forged["identity"]["public_key_sha256"])

    def test_external_openssl_agrees_on_strong_name(self):
        if not external.available():
            self.skipTest("openssl not installed")
        image = self.image("sn_full")
        result = verify.strong_name_check(image)
        covered = b"".join(image[r["start"]:r["end"]] for r in result["covered_ranges"])
        info = verify.parse_managed(image)
        key = crypto.parse_public_key_blob(info["public_key"])
        signature = image[info["signature_offset"]:info["signature_offset"] + info["strong_name_size"]][::-1]
        check = external.openssl_rsa_verify(key["modulus"], key["exponent"], signature, covered, "sha1")
        self.assertTrue(check["ok"], check["detail"])

    def test_overlay_keeps_strong_name_but_breaks_authenticode(self):
        image = self.image("dual_overlay")
        self.assertTrue(verify.strong_name_check(image)["checks"]["rsa_signature_valid"])
        auth = verify.authenticode_check(image, anchors=[self.anchor])
        self.assertFalse(auth["digest_matches"])
        self.assertEqual(auth["verdict"]["signature"], "invalid")

    def test_checksum_edit_keeps_both_valid(self):
        image = self.image("dual_checksum_edit")
        self.assertTrue(verify.strong_name_check(image)["checks"]["rsa_signature_valid"])
        auth = verify.authenticode_check(image, anchors=[self.anchor])
        self.assertTrue(auth["digest_matches"])
        self.assertTrue(auth["signer_signature_valid"])

    def test_authenticode_valid_and_trusted(self):
        result = verify.authenticode_check(self.image("auth_full"), anchors=[self.anchor])
        self.assertTrue(result["digest_matches"])
        self.assertTrue(result["signer_signature_valid"])
        self.assertTrue(result["message_digest_attribute_matches"])
        self.assertTrue(result["certificate_chain"]["trusted"])

    def test_authenticode_valid_but_untrusted_chain(self):
        result = verify.authenticode_check(self.image("auth_untrusted_root"), anchors=[self.anchor])
        self.assertTrue(result["digest_matches"])
        self.assertTrue(result["signer_signature_valid"])
        self.assertFalse(result["certificate_chain"]["trusted"])
        self.assertEqual(result["verdict"]["signature"], "cryptographically valid")
        self.assertEqual(result["verdict"]["trust"], "not trusted")

    def test_authenticode_digest_mismatch(self):
        result = verify.authenticode_check(self.image("auth_wrong_digest"), anchors=[self.anchor])
        self.assertFalse(result["digest_matches"])
        self.assertTrue(result["signer_signature_valid"])  # signature over attrs is intact
        self.assertEqual(result["verdict"]["signature"], "invalid")

    def test_authenticode_body_tamper(self):
        result = verify.authenticode_check(self.image("auth_body_tampered"), anchors=[self.anchor])
        self.assertFalse(result["digest_matches"])
        self.assertEqual(result["verdict"]["signature"], "invalid")

    def test_strong_name_coverage_excludes_checksum_and_cert_entry(self):
        image = self.image("sn_full")
        ranges = verify.strong_name_covered_ranges(image, *self._slot(image))
        covered = set()
        for item in ranges:
            covered.update(range(item[0], item[1]))
        optional = verify._optional_header_offset(image)
        checksum = optional + 64
        cert_entry = verify._data_directory_offset(image, 4)
        self.assertNotIn(checksum, covered)
        self.assertNotIn(cert_entry, covered)
        self.assertIn(checksum - 1, covered)
        self.assertIn(cert_entry + 8, covered)

    def _slot(self, image):
        info = verify.parse_managed(image)
        return info["signature_offset"], info["strong_name_size"]

    def test_report_marks_not_executed(self):
        report_dir = self.tmp / "reports"
        result = report.build(self.tmp, report_dir)
        cases = result["cases"]
        self.assertEqual(set(cases), set(self.manifest))
        for case in cases.values():
            self.assertFalse(case["executed"])
        self.assertTrue((report_dir / "report.json").exists())
        payload = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["cases"]["sn_full"]["strong_name"]["verdict"]["signature_integrity"], "valid")
        self.assertEqual(
            payload["cases"]["sn_token_forgery"]["strong_name"]["verdict"]["signature_integrity"], "invalid",
        )


if __name__ == "__main__":
    unittest.main()
