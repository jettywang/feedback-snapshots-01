#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2026, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
# Semantic fuzzing for RFC 6482 Route Origin Authorizations.
#
# The tests guard against treating "the ROA decodes" as "the route is
# authorized".  Structural validity, EE resource containment and concrete
# route authorization are checked independently, and every expected value
# is recomputed by an oracle that shares no logic with the checker.
#
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.roa_fuzz.adapter import LocalRoaAdapter
from tools.roa_fuzz.asn1_codec import StructuralError, decode_roa, encode_roa
from tools.roa_fuzz.fuzzer import RoaSemanticFuzzer
from tools.roa_fuzz.model import (
    AFI_IPV4,
    AFI_IPV6,
    EEResources,
    Prefix,
    RoaObject,
    RoaPrefix,
    Route,
)
from tools.roa_fuzz.oracle import ReferenceOracle


SEED = 20261114
SAMPLE_SIZE = 200


def make_roa(as_id, afi, network, length, max_length=None, version=0):
    prefix = Prefix(afi, network, length)
    return RoaObject(as_id, {afi: [RoaPrefix(prefix, max_length)]}, version)


class CodecRoundTripTestCase(unittest.TestCase):
    def test_round_trip_preserves_optional_maxlength_distinction(self):
        roa = make_roa(64496, AFI_IPV4, 0xC0000200, 24)
        der = encode_roa(roa)
        decoded = decode_roa(der)
        self.assertEqual(decoded.as_id, 64496)
        self.assertFalse(decoded.blocks[AFI_IPV4][0].has_max_length)

        roa_with_max = make_roa(64496, AFI_IPV4, 0xC0000200, 24, max_length=26)
        decoded_with_max = decode_roa(encode_roa(roa_with_max))
        self.assertTrue(decoded_with_max.blocks[AFI_IPV4][0].has_max_length)
        self.assertEqual(26, decoded_with_max.blocks[AFI_IPV4][0].max_length)

    def test_garbage_is_structural_error_not_authorization(self):
        adapter = LocalRoaAdapter()
        verdict = adapter.authorize(b"\x30\x03\x02\x01\x09", EEResources(),
                                    Route(64496, Prefix(AFI_IPV4, 0xC0000200, 24)))
        self.assertFalse(verdict.authorized)
        with self.assertRaises(StructuralError):
            decode_roa(b"not der at all")


class LayerSeparationTestCase(unittest.TestCase):
    def setUp(self):
        self.adapter = LocalRoaAdapter()
        self.oracle = ReferenceOracle()
        # EE cert is authoritative for 203.0.113.0/24 only.
        self.ee = EEResources()
        self.ee.add_prefix(Prefix(AFI_IPV4, 0xC0000200, 24))

    def test_decodable_roa_outside_ee_is_not_authorized(self):
        # 198.51.100.0/24 decodes fine but is not in the EE resources.
        roa = make_roa(64496, AFI_IPV4, 0xC6336400, 24, max_length=24)
        der = encode_roa(roa)
        self.assertTrue(self.adapter.check_structure(der).ok)
        self.assertFalse(self.adapter.check_ee_containment(decode_roa(der), self.ee))
        route = Route(64496, Prefix(AFI_IPV4, 0xC6336400, 24))
        verdict = self.adapter.authorize(der, self.ee, route)
        self.assertFalse(verdict.authorized)
        self.assertIn("EE resources", verdict.reason)
        self.assertFalse(self.oracle.is_resource_valid(roa, self.ee))

    def test_resource_valid_but_wrong_origin_as(self):
        roa = make_roa(64496, AFI_IPV4, 0xC0000200, 24, max_length=24)
        der = encode_roa(roa)
        route = Route(64497, Prefix(AFI_IPV4, 0xC0000200, 24))
        self.assertFalse(self.adapter.authorize(der, self.ee, route).authorized)


class SpecialSemanticsTestCase(unittest.TestCase):
    def setUp(self):
        self.adapter = LocalRoaAdapter()
        self.ee = EEResources()
        self.ee.add_prefix(Prefix(AFI_IPV4, 0xC0000200, 24))

    def test_as_zero_is_negative_attestation(self):
        roa = make_roa(0, AFI_IPV4, 0xC0000200, 24, max_length=24)
        self.assertTrue(self.adapter.is_negative_attestation(roa))
        der = encode_roa(roa)
        # Structurally fine and fully inside the EE resources ...
        self.assertTrue(self.adapter.check_structure(der).ok)
        self.assertTrue(self.adapter.check_ee_containment(decode_roa(der), self.ee))
        # ... but no route, not even one apparently "covered", is authorized.
        route = Route(0, Prefix(AFI_IPV4, 0xC0000200, 24))
        verdict = self.adapter.authorize(der, self.ee, route)
        self.assertFalse(verdict.authorized)
        self.assertIn("negative", verdict.reason)
        self.assertFalse(ReferenceOracle().is_route_authorized(roa, self.ee, route))

    def test_absent_maxlength_defaults_to_exact_prefix(self):
        exact = RoaPrefix(Prefix(AFI_IPV4, 0xC0000200, 24))
        self.assertFalse(exact.has_max_length)
        self.assertEqual(24, self.adapter.effective_max_length(exact))

        roa = make_roa(64496, AFI_IPV4, 0xC0000200, 24)
        der = encode_roa(roa)
        more_specific = Route(64496, Prefix(AFI_IPV4, 0xC0000200, 25))
        self.assertFalse(self.adapter.authorize(der, self.ee, more_specific).authorized)
        exact_route = Route(64496, Prefix(AFI_IPV4, 0xC0000200, 24))
        self.assertTrue(self.adapter.authorize(der, self.ee, exact_route).authorized)

    def test_present_maxlength_allows_more_specifics(self):
        roa = make_roa(64496, AFI_IPV4, 0xC0000200, 24, max_length=26)
        der = encode_roa(roa)
        allowed = Route(64496, Prefix(AFI_IPV4, 0xC0000200, 26))
        too_specific = Route(64496, Prefix(AFI_IPV4, 0xC0000200, 27))
        self.assertTrue(self.adapter.authorize(der, self.ee, allowed).authorized)
        self.assertFalse(self.adapter.authorize(der, self.ee, too_specific).authorized)

    def test_invalid_maxlength_is_structurally_rejected(self):
        roa = make_roa(64496, AFI_IPV4, 0xC0000200, 24, max_length=20)
        self.assertFalse(self.adapter.check_roa_object(roa).ok)
        roa_v6_bad = make_roa(64496, AFI_IPV6, 0x20010DB8000000000000000000000000, 32, max_length=129)
        self.assertFalse(self.adapter.check_roa_object(roa_v6_bad).ok)

    def test_unknown_address_family_is_structurally_rejected(self):
        roa = RoaObject(64496, {99: [RoaPrefix(Prefix(99, 0, 8))]})
        self.assertFalse(self.adapter.check_roa_object(roa).ok)

    def test_zero_length_prefix_round_trips_and_means_default_route(self):
        ee = EEResources()
        ee.add_range(AFI_IPV4, 0, (1 << 32) - 1)
        roa = RoaObject(64496, {AFI_IPV4: [RoaPrefix(Prefix(AFI_IPV4, 0, 0))]})
        decoded = decode_roa(encode_roa(roa))
        self.assertEqual(0, decoded.blocks[AFI_IPV4][0].prefix.length)
        self.assertTrue(self.adapter.check_ee_containment(decoded, ee))
        default_route = Route(64496, Prefix(AFI_IPV4, 0, 0))
        self.assertTrue(self.adapter.authorize(encode_roa(roa), ee, default_route).authorized)


class FuzzConsistencyTestCase(unittest.TestCase):
    def test_fixed_seed_small_sample_matches_oracle(self):
        fuzzer = RoaSemanticFuzzer(seed=SEED, sample_size=SAMPLE_SIZE)
        cases, findings = fuzzer.run()
        self.assertEqual(SAMPLE_SIZE, len(cases))

        # Every field the exercise asks to mutate must actually be exercised.
        mutated_fields = {case.field for case in cases if case.field != "baseline"}
        for required in ("address_family", "prefix_bits", "max_length",
                         "as_number", "resource_range"):
            self.assertIn(required, mutated_fields)

        # Cross-check the three layers separately on every generated case.
        for case in cases:
            self._assert_layers_agree(case)
        self.assertEqual([], findings, msg=self._format(findings))

    def _assert_layers_agree(self, case):
        oracle = ReferenceOracle()
        adapter = LocalRoaAdapter()
        expected_structure = oracle.is_structurally_valid_roa(case.roa)
        if case.der is None:
            self.assertFalse(expected_structure)
            return
        structure = adapter.check_structure(case.der)
        self.assertEqual(expected_structure, structure.ok, msg=case.index)
        if not expected_structure:
            return
        expected_resources = oracle.is_resource_valid(case.roa, case.ee)
        self.assertEqual(
            expected_resources,
            adapter.check_ee_containment(case.roa, case.ee),
            msg=case.index,
        )
        expected_route = oracle.is_route_authorized(case.roa, case.ee, case.route)
        verdict = adapter.authorize(case.der, case.ee, case.route)
        self.assertEqual(expected_route, verdict.authorized, msg=case.index)

    @staticmethod
    def _format(findings):
        return "; ".join(
            "case %d expected %s got %s (%s)" % (f.case.index, f.expected, f.actual, f.reason)
            for f in findings
        )

    def test_minimal_failure_artifact_is_persistable(self):
        fuzzer = RoaSemanticFuzzer(seed=SEED, sample_size=SAMPLE_SIZE)
        cases, _ = fuzzer.run()
        # Build a synthetic minimal failing artifact and confirm it carries
        # exactly the DER, EE resources and route triple needed to reproduce.
        case = cases[0]
        from tools.roa_fuzz.fuzzer import FuzzFinding
        finding = FuzzFinding(case, expected=True, actual=False, reason="synthetic")
        artifact = finding.to_dict()
        self.assertEqual(case.der.hex(), artifact["der_hex"])
        self.assertEqual(case.ee.to_dict(), artifact["ee_resources"])
        self.assertEqual(case.route.to_dict(), artifact["route"])
        # The persisted DER must still decode to the same ROA.
        self.assertEqual(case.roa.to_dict(), decode_roa(bytes.fromhex(artifact["der_hex"])).to_dict())


class FaultInjectionTestCase(unittest.TestCase):
    """If the checker is deliberately weakened, the fuzz corpus must expose
    a route that the weakened checker wrongly accepts."""

    def setUp(self):
        self.fuzzer = RoaSemanticFuzzer(seed=SEED, sample_size=SAMPLE_SIZE)
        self.cases, _ = self.fuzzer.run()

    def test_relaxed_maxlength_is_caught(self):
        relaxed = _RelaxedMaxLengthAdapter()
        escapes = []
        for case in self.cases:
            if case.der is None:
                continue
            expected = self.fuzzer._expected(case)
            verdict = relaxed.authorize(case.der, case.ee, case.route)
            if verdict.authorized and not expected:
                escapes.append(case)
        self.assertTrue(escapes, "relaxing maxLength must let an invalid route through")

    def test_ignored_ee_containment_is_caught(self):
        careless = _IgnoreEEContainmentAdapter()
        escapes = []
        for case in self.cases:
            if case.der is None:
                continue
            expected = self.fuzzer._expected(case)
            verdict = careless.authorize(case.der, case.ee, case.route)
            if verdict.authorized and not expected:
                escapes.append(case)
        self.assertTrue(escapes, "ignoring EE containment must let an invalid route through")


class _RelaxedMaxLengthAdapter(LocalRoaAdapter):
    """Pretend every maxLength is at least as wide as the full address."""

    def effective_max_length(self, entry):
        return entry.prefix.max_bit_length


class _IgnoreEEContainmentAdapter(LocalRoaAdapter):
    def check_ee_containment(self, roa, ee_resources):
        return True


class PersistenceTestCase(unittest.TestCase):
    def test_clean_run_writes_empty_findings_file(self):
        from tools.roa_fuzz.persist import run_and_persist

        with tempfile.TemporaryDirectory() as tmp:
            output = os.path.join(tmp, "nested", "findings.json")
            payload = run_and_persist(output, seed=SEED, sample_size=SAMPLE_SIZE)
            self.assertEqual(0, payload["finding_count"])
            self.assertTrue(os.path.isfile(output))

    def test_finding_artifact_round_trips_and_reproduces(self):
        import json

        from tools.roa_fuzz import fuzzer as fuzzer_module
        from tools.roa_fuzz.persist import run_and_persist

        original = fuzzer_module.LocalRoaAdapter
        fuzzer_module.LocalRoaAdapter = _RelaxedMaxLengthAdapter
        try:
            with tempfile.TemporaryDirectory() as tmp:
                output = os.path.join(tmp, "findings.json")
                payload = run_and_persist(output, seed=SEED, sample_size=SAMPLE_SIZE)
                self.assertGreater(payload["finding_count"], 0)
                with open(output, encoding="utf-8") as handle:
                    reloaded = json.load(handle)
                finding = reloaded["findings"][0]
                der = bytes.fromhex(finding["der_hex"])
                ee = EEResources.from_dict(finding["ee_resources"])
                route = Route.from_dict(finding["route"])
                # The weakened checker wrongly accepts what the oracle rejects.
                weak = _RelaxedMaxLengthAdapter()
                self.assertTrue(weak.authorize(der, ee, route).authorized)
                self.assertFalse(finding["expected_authorized"])
        finally:
            fuzzer_module.LocalRoaAdapter = original


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
