import dataclasses
import json
import unittest
from datetime import datetime

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import univ, char

from pyasn1_modules import rfc5652
from pyasn1_modules import rfc6031

from mfa_import import (
    ErrorCode,
    HOTP_ALGORITHM,
    PIN_ALGORITHM,
    TOTP_ALGORITHM,
    InMemoryCredentialStore,
    ImportFailure,
    PlanError,
    build_import_plan,
    install_plan,
)
from mfa_import import builder
from mfa_import.builder import (
    HOTP_SEED,
    PIN_SEED,
    TOTP_SEED,
    build_conflict_package,
    build_cross_package_pin_reference,
    build_legal_package,
    build_pin_key,
    make_key,
    make_package,
)


def codes(plan):
    return {issue.code for issue in plan.issues}


def issue_for(plan, code):
    return plan.issues_by_code(code)


class LegalPackageTests(unittest.TestCase):
    def test_legal_two_key_package_is_importable(self):
        plan = build_import_plan(build_legal_package())
        self.assertTrue(plan.importable, plan.summary())
        self.assertEqual(plan.credential_count, 2)
        self.assertEqual(plan.version, 1)
        self.assertEqual(
            sorted(entry.key_id for entry in plan.entries),
            ["hotp-0001", "totp-0001"],
        )

    def test_package_and_key_attributes_are_separated(self):
        plan = build_import_plan(build_legal_package())
        self.assertEqual(plan.device.manufacturer, "Acme Token Corp")
        self.assertEqual(plan.device.serial_number, "SN-LEGAL-0001")
        hotp = next(e for e in plan.entries if e.key_id == "hotp-0001")
        self.assertEqual(hotp.otp.mode, "hotp")
        self.assertEqual(hotp.otp.counter, 42)
        self.assertIsNone(hotp.otp.time_interval)
        totp = next(e for e in plan.entries if e.key_id == "totp-0001")
        self.assertEqual(totp.otp.mode, "totp")
        self.assertEqual(totp.otp.time_interval, 30)
        self.assertIsNone(totp.otp.counter)
        self.assertEqual(hotp.pin_policy.usage_mode, "Local")
        self.assertEqual(hotp.pin_policy.min_length, 4)

    def test_plan_round_trips_through_der_and_content_info(self):
        package = build_legal_package()
        encoded = der_encode(package)
        decoded, rest = der_decode(encoded, asn1Spec=rfc6031.SymmetricKeyPackage())
        self.assertFalse(rest)
        plan_from_der = build_import_plan(decoded)
        self.assertTrue(plan_from_der.importable)

        content_info = rfc5652.ContentInfo()
        content_info["contentType"] = rfc6031.id_ct_KP_sKeyPackage
        content_info["content"] = univ.Any(encoded)
        plan_from_ci = build_import_plan(content_info)
        self.assertTrue(plan_from_ci.importable)
        self.assertEqual(
            plan_from_ci.summary()["credentials"],
            plan_from_der.summary()["credentials"],
        )

    def test_wrong_content_info_type_is_rejected(self):
        content_info = rfc5652.ContentInfo()
        content_info["contentType"] = rfc5652.id_data
        content_info["content"] = univ.Any(der_encode(build_legal_package()))
        with self.assertRaises(PlanError):
            build_import_plan(content_info)

    def test_unexpected_python_type_is_rejected(self):
        with self.assertRaises(PlanError):
            build_import_plan("not a package")


class OtpConstraintTests(unittest.TestCase):
    def test_hotp_requires_counter(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED),
        ])
        plan = build_import_plan(package)
        self.assertFalse(plan.importable)
        self.assertIn(ErrorCode.HOTP_REQUIRES_COUNTER, codes(plan))

    def test_hotp_forbids_time_parameters(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                     counter=1, time_interval=30),
        ])
        plan = build_import_plan(package)
        self.assertFalse(plan.importable)
        self.assertIn(ErrorCode.HOTP_FORBIDS_TIME_PARAMETERS, codes(plan))

    def test_totp_requires_interval_and_forbids_counter(self):
        no_interval = make_package([
            make_key(key_id="k", algorithm=TOTP_ALGORITHM, seed=TOTP_SEED,
                     time_start=0),
        ])
        plan = build_import_plan(no_interval)
        self.assertIn(ErrorCode.TOTP_REQUIRES_TIME_INTERVAL, codes(plan))

        with_counter = make_package([
            make_key(key_id="k2", algorithm=TOTP_ALGORITHM, seed=TOTP_SEED,
                     time_interval=30, counter=3),
        ])
        plan = build_import_plan(with_counter)
        self.assertIn(ErrorCode.TOTP_FORBIDS_COUNTER, codes(plan))
        self.assertFalse(plan.importable)

    def test_totp_zero_interval_is_invalid(self):
        package = make_package([
            make_key(key_id="k", algorithm=TOTP_ALGORITHM, seed=TOTP_SEED,
                     time_interval=0),
        ])
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.TIME_INTERVAL_NOT_POSITIVE, codes(plan))

    def test_check_digit_requires_decimal_encoding(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                     counter=1, response_format=("HEXADECIMAL", 8, True)),
        ])
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.CHECK_DIGIT_REQUIRES_DECIMAL, codes(plan))

    def test_challenge_format_check_digit_rule(self):
        attr = builder._challenge_format("BASE64", 4, 16, True)
        key = make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                       counter=1)
        key["sKeyAttrs"].setComponents(*(list(key["sKeyAttrs"]) + [attr]))
        plan = build_import_plan(make_package([key]))
        self.assertIn(ErrorCode.CHECK_DIGIT_REQUIRES_DECIMAL, codes(plan))

    def test_unknown_algorithm_is_unintelligible_and_blocks_import(self):
        package = make_package([
            make_key(key_id="k", algorithm="urn:example:unknown-otp",
                     seed=HOTP_SEED, counter=1),
        ])
        plan = build_import_plan(package)
        self.assertFalse(plan.importable)
        self.assertIn(ErrorCode.UNSUPPORTED_ALGORITHM, codes(plan))

    def test_usage_must_permit_otp(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                     counter=1, usages=("Encrypt",)),
        ])
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.KEY_USAGE_NOT_OTP, codes(plan))

    def test_pin_key_rejects_otp_transport_parameters(self):
        package = make_package([
            make_key(key_id="pin", algorithm=PIN_ALGORITHM, seed=PIN_SEED,
                     counter=5),
        ])
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.UNINTELLIGIBLE_PARAMETER, codes(plan))


class ValidityWindowTests(unittest.TestCase):
    def test_inverted_key_window(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                     counter=1, start_date="20300101000000Z",
                     expiry_date="20260101000000Z"),
        ])
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.KEY_WINDOW_INVERTED, codes(plan))

    def test_key_outside_device_window(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                     counter=1, start_date="20260101000000Z",
                     expiry_date="20320101000000Z"),
        ], device_start="20250101000000Z", device_expiry="20300101000000Z")
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.KEY_OUTSIDE_DEVICE_WINDOW, codes(plan))

    def test_inverted_device_window(self):
        package = make_package([
            make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                     counter=1),
        ], device_start="20300101000000Z", device_expiry="20250101000000Z")
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.DEVICE_WINDOW_INVERTED, codes(plan))


class PinReferenceTests(unittest.TestCase):
    def test_cross_package_pin_reference_is_rejected(self):
        plan = build_import_plan(build_cross_package_pin_reference())
        self.assertFalse(plan.importable)
        missing = issue_for(plan, ErrorCode.PIN_REFERENCE_MISSING)
        self.assertEqual(len(missing), 2)

    def test_pin_reference_to_non_pin_key_is_rejected(self):
        target = make_key(key_id="not-a-pin", algorithm=HOTP_ALGORITHM,
                          seed=HOTP_SEED, counter=1)
        protected = make_key(
            key_id="protected", algorithm=HOTP_ALGORITHM, seed=TOTP_SEED,
            counter=2,
            pin_policy=builder._pin_policy("Algorithmic", pin_key_id="not-a-pin"),
        )
        plan = build_import_plan(make_package([target, protected]))
        self.assertIn(ErrorCode.PIN_REFERENCES_NON_PIN_KEY, codes(plan))

    def test_pin_self_reference_is_rejected(self):
        pin_key = make_key(
            key_id="pin", algorithm=PIN_ALGORITHM, seed=PIN_SEED,
            pin_policy=builder._pin_policy("Local", pin_key_id="pin"),
        )
        plan = build_import_plan(make_package([pin_key]))
        self.assertIn(ErrorCode.PIN_REFERENCES_SELF, codes(plan))

    def test_resolved_reference_is_importable(self):
        pin_key = build_pin_key()
        package = make_package([
            pin_key,
            make_key(
                key_id="hotp", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                counter=1,
                pin_policy=builder._pin_policy("Algorithmic",
                                               pin_key_id="pin-root"),
            ),
        ])
        plan = build_import_plan(package)
        self.assertTrue(plan.importable, plan.summary())

    def test_inverted_pin_length_range_is_rejected(self):
        pin_key = make_key(
            key_id="pin", algorithm=PIN_ALGORITHM, seed=PIN_SEED,
            pin_policy=builder._pin_policy("Local", min_length=9,
                                           max_length=4, pin_encoding="DECIMAL"),
        )
        plan = build_import_plan(make_package([pin_key]))
        self.assertIn(ErrorCode.UNINTELLIGIBLE_PARAMETER, codes(plan))


class IdentityTests(unittest.TestCase):
    def test_duplicate_key_id_with_same_seed_is_ambiguous(self):
        first = make_key(key_id="dup", algorithm=HOTP_ALGORITHM,
                         seed=HOTP_SEED, counter=1)
        second = make_key(key_id="dup", algorithm=HOTP_ALGORITHM,
                          seed=HOTP_SEED, counter=2)
        plan = build_import_plan(make_package([first, second]))
        self.assertFalse(plan.importable)
        self.assertIn(ErrorCode.DUPLICATE_KEY_ID, codes(plan))
        self.assertNotIn(ErrorCode.SEED_MISMATCH_FOR_IDENTITY, codes(plan))

    def test_same_identity_with_different_seed_is_rejected(self):
        first = make_key(key_id="dup", algorithm=HOTP_ALGORITHM,
                         seed=HOTP_SEED, counter=1)
        second = make_key(key_id="dup", algorithm=HOTP_ALGORITHM,
                         seed=TOTP_SEED, counter=2)
        plan = build_import_plan(make_package([first, second]))
        self.assertIn(ErrorCode.DUPLICATE_KEY_ID, codes(plan))
        self.assertIn(ErrorCode.SEED_MISMATCH_FOR_IDENTITY, codes(plan))

    def test_missing_required_identity_and_algorithm(self):
        # Build a key with no keyId or algorithm by stripping them after build.
        key = make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                       counter=1)
        kept = [
            attr for attr in key["sKeyAttrs"]
            if attr["attrType"] not in (rfc6031.id_pskc_keyId,
                                        rfc6031.id_pskc_algorithm)
        ]
        key["sKeyAttrs"].setComponents(*kept)
        plan = build_import_plan(make_package([key]))
        self.assertIn(ErrorCode.MISSING_KEY_ID, codes(plan))
        self.assertIn(ErrorCode.MISSING_ALGORITHM, codes(plan))

    def test_missing_seed_blocks_import(self):
        source = make_key(key_id="k", algorithm=HOTP_ALGORITHM,
                          seed=HOTP_SEED, counter=1)
        attrs = (
            rfc6031.OneSymmetricKey().componentType["sKeyAttrs"]
            .asn1Object.clone())
        attrs.setComponents(*list(source["sKeyAttrs"]))
        empty_key = rfc6031.OneSymmetricKey()
        empty_key.setComponents(attrs)
        plan = build_import_plan(make_package([empty_key]))
        self.assertIn(ErrorCode.MISSING_SEED, codes(plan))


class AttributePlacementTests(unittest.TestCase):
    def test_package_level_attribute_on_key_is_wrong_scope(self):
        key = make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                       counter=1)
        misplaced = builder._key_attr(rfc6031.id_pskc_manufacturer,
                                      char.UTF8String("Acme"))
        key["sKeyAttrs"].setComponents(*(list(key["sKeyAttrs"]) + [misplaced]))
        plan = build_import_plan(make_package([key]))
        self.assertIn(ErrorCode.ATTRIBUTE_WRONG_SCOPE, codes(plan))

    def test_unknown_key_attribute_blocks_import(self):
        key = make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                       counter=1)
        unknown = builder._key_attr(univ.ObjectIdentifier("1.2.3.4.5"),
                                    univ.Integer(1))
        key["sKeyAttrs"].setComponents(*(list(key["sKeyAttrs"]) + [unknown]))
        plan = build_import_plan(make_package([key]))
        self.assertIn(ErrorCode.UNKNOWN_KEY_ATTRIBUTE, codes(plan))

    def test_unknown_package_attribute_blocks_import(self):
        package = build_legal_package()
        unknown = builder._package_attr(univ.ObjectIdentifier("1.2.3.4.6"),
                                        univ.Integer(1))
        package["sKeyPkgAttrs"].setComponents(
            *(list(package["sKeyPkgAttrs"]) + [unknown]))
        plan = build_import_plan(package)
        self.assertIn(ErrorCode.UNKNOWN_PACKAGE_ATTRIBUTE, codes(plan))

    def test_duplicate_attribute_is_rejected(self):
        key = make_key(key_id="k", algorithm=HOTP_ALGORITHM, seed=HOTP_SEED,
                       counter=1)
        duplicate_counter = builder._integer(rfc6031.id_pskc_counter, 2)
        key["sKeyAttrs"].setComponents(
            *(list(key["sKeyAttrs"]) + [duplicate_counter]))
        plan = build_import_plan(make_package([key]))
        self.assertIn(ErrorCode.DUPLICATE_ATTRIBUTE, codes(plan))


class ImmutabilityTests(unittest.TestCase):
    def test_plan_and_entries_are_frozen(self):
        plan = build_import_plan(build_legal_package())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.entries[0].key_id = "changed"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.importable = False

    def test_mutating_source_package_does_not_change_plan(self):
        package = build_legal_package()
        plan = build_import_plan(package)
        before = json.dumps(plan.summary(), sort_keys=True)
        package["sKeys"][0]["sKey"] = univ.OctetString(b"\x00" * 20)
        package["sKeys"][0]["sKeyAttrs"][0]["attrValues"][0] = univ.Any(
            der_encode(char.UTF8String("changed")))
        after = json.dumps(plan.summary(), sort_keys=True)
        self.assertEqual(before, after)
        hotp = next(e for e in plan.entries if e.key_id == "hotp-0001")
        self.assertEqual(hotp.seed_bytes(), HOTP_SEED)


class SecretHygieneTests(unittest.TestCase):
    def setUp(self):
        self.legal = build_import_plan(build_legal_package())
        self.conflict = build_import_plan(build_conflict_package())
        self.pin_ref = build_import_plan(build_cross_package_pin_reference())

    def _rendered_text(self):
        chunks = [
            json.dumps(self.legal.summary(), default=str),
            json.dumps(self.conflict.summary(), default=str),
            json.dumps(self.pin_ref.summary(), default=str),
            repr(self.legal),
            repr(self.conflict),
            repr(self.pin_ref),
        ]
        chunks.extend(repr(entry) for entry in self.legal.entries)
        chunks.extend(
            json.dumps(issue.public_dict())
            for plan in (self.legal, self.conflict, self.pin_ref)
            for issue in plan.issues
        )
        return "\n".join(chunks)

    def test_summaries_and_errors_contain_no_seed_material(self):
        text = self._rendered_text()
        for secret in (HOTP_SEED, TOTP_SEED, PIN_SEED):
            self.assertNotIn(secret.hex(), text)
            self.assertNotIn(repr(secret), text)
            self.assertNotIn("".join("%02x" % b for b in secret).upper(), text)

    def test_repr_redacts_seed_field(self):
        rendered = repr(self.legal.entries[0])
        self.assertNotIn("seed=", rendered)
        self.assertNotIn(HOTP_SEED.hex(), rendered)

    def test_seed_is_only_available_via_explicit_accessor(self):
        hotp = next(e for e in self.legal.entries if e.key_id == "hotp-0001")
        self.assertEqual(hotp.seed_bytes(), HOTP_SEED)
        self.assertNotIn("seed", hotp.public_summary())


class StoreTests(unittest.TestCase):
    def test_successful_plan_installs_all_credentials(self):
        store = InMemoryCredentialStore()
        plan = build_import_plan(build_legal_package())
        count = install_plan(plan, store)
        self.assertEqual(count, 2)
        self.assertEqual(store.installed_key_ids(),
                         ("hotp-0001", "totp-0001"))

    def test_failed_plan_installs_nothing(self):
        store = InMemoryCredentialStore()
        # Seed the store to prove pre-existing data is untouched.
        good = build_import_plan(build_legal_package())
        install_plan(good, store)
        before = store.installed_key_ids()

        bad = build_import_plan(build_conflict_package())
        with self.assertRaises(ImportFailure):
            install_plan(bad, store)
        self.assertEqual(store.installed_key_ids(), before)

    def test_stage_failure_rolls_back_partial_batch(self):
        class FailingStore(InMemoryCredentialStore):
            def __init__(self, fail_on):
                super().__init__()
                self.fail_on = fail_on

            def stage(self, entry):
                if entry.key_id == self.fail_on:
                    raise ImportFailure("simulated storage failure")
                super().stage(entry)

        plan = build_import_plan(build_legal_package())
        store = FailingStore(fail_on="totp-0001")
        with self.assertRaises(ImportFailure):
            install_plan(plan, store)
        self.assertEqual(store.installed_key_ids(), ())
        self.assertEqual(store.installed, {})

    def test_duplicate_identifier_is_rejected_and_rolled_back(self):
        store = InMemoryCredentialStore()
        first = build_import_plan(build_legal_package())
        install_plan(first, store)
        with self.assertRaises(ImportFailure):
            install_plan(first, store)
        self.assertEqual(store.installed_key_ids(),
                         ("hotp-0001", "totp-0001"))


if __name__ == "__main__":
    unittest.main()
