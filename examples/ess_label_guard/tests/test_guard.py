"""Tests for the ESS cross-policy label guard prototype.

They exercise real DER round-trips through pyasn1_modules.rfc2634 so that the
guard's assumptions about the ASN.1 structure stay honest.
"""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pyasn1.type import tag, univ
from pyasn1_modules import rfc2634, rfc5652

from ess_label_guard import (
    Attestations,
    LabelConsistencyError,
    collect_signed_labels,
    Clearance,
    Decision,
    Evidence,
    POLICY_A,
    POLICY_B,
    POLICIES,
    TRANSLATIONS,
    TRUSTED_ASSERTORS,
    build_equivalent_labels,
    build_label,
    category_syntax_table,
    check_access,
    combine_layer_results,
    naive_numeric_allows,
    parse_label,
)
from ess_label_guard.config import build_from_document, load_policy_document
from ess_label_guard.mapping import (
    ClearanceError,
    validate_configuration,
    Translation,
    CAT_A_CAVEAT,
    CAT_A_COMPARTMENT,
    CAT_B_DEPARTMENT,
    CAT_B_HANDLING,
)


def attested(translator="1.3.6.1.4.1.32473.100.9.1"):
    return Attestations(
        label_signature=Evidence(True, "cms-verifier"),
        translator=Evidence(True, translator),
        clearance=Evidence(True, "accreditation-authority"),
    )


A_ALPHA_11 = build_label(
    POLICY_A, 11, categories=[(CAT_A_COMPARTMENT, "ALPHA")])


class ConfigValidationTestCase(unittest.TestCase):
    def test_production_configuration_is_valid(self):
        self.assertTrue(validate_configuration())

    def test_incomplete_mapping_is_rejected_at_startup(self):
        broken = Translation(
            POLICY_A, 4, ((CAT_A_COMPARTMENT, "ALPHA"),),
            POLICY_B, 9, (), "1.3.6.1.4.1.32473.100.9.1")
        with self.assertRaises(ClearanceError):
            validate_configuration(translations=(broken,))

    def test_unknown_category_in_translation_is_rejected(self):
        broken = Translation(
            POLICY_A, 4, (("1.3.6.1.4.1.32473.999.9", "X"),),
            POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),),
            "1.3.6.1.4.1.32473.100.9.1")
        with self.assertRaises(ClearanceError):
            validate_configuration(translations=(broken,))

    def test_untrusted_assertor_is_rejected(self):
        broken = Translation(
            POLICY_A, 4, ((CAT_A_COMPARTMENT, "ALPHA"),),
            POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),),
            "1.3.6.1.4.1.32473.666.6")
        with self.assertRaises(ClearanceError):
            validate_configuration(translations=(broken,))

    def test_ambiguous_direction_owner_is_rejected(self):
        # Two roles claiming the same translation direction makes "who may
        # translate" ambiguous, even if both are globally trusted.
        first = Translation(
            POLICY_A, 4, ((CAT_A_COMPARTMENT, "ALPHA"),),
            POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),),
            "1.3.6.1.4.1.32473.100.9.1")
        second = Translation(
            POLICY_A, 4, ((CAT_A_COMPARTMENT, "BRAVO"),),
            POLICY_B, 9, ((CAT_B_DEPARTMENT, "ENG"),),
            "1.3.6.1.4.1.32473.200.9.1")
        with self.assertRaises(ClearanceError):
            validate_configuration(translations=(first, second))

    def test_ambiguous_source_key_is_rejected(self):
        first = Translation(
            POLICY_A, 4, ((CAT_A_COMPARTMENT, "ALPHA"),),
            POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),),
            "1.3.6.1.4.1.32473.100.9.1")
        second = Translation(
            POLICY_A, 4, ((CAT_A_COMPARTMENT, "ALPHA"),),
            POLICY_B, 7, ((CAT_B_DEPARTMENT, "FIN"),),
            "1.3.6.1.4.1.32473.100.9.1")
        with self.assertRaises(ClearanceError):
            validate_configuration(translations=(first, second))


def make_signer(label_der, equivalents_der=None):
    signer = rfc5652.SignerInfo()
    signer["version"] = 3
    sid = rfc5652.SignerIdentifier()
    sid["subjectKeyIdentifier"] = univ.OctetString(b"\x02" * 20).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    signer["sid"] = sid
    signer["digestAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
        "2.16.840.1.101.3.4.2.1")

    attrs = rfc5652.SignedAttributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    position = 0
    if label_der is not None:
        attr = rfc5652.Attribute()
        attr["attrType"] = rfc2634.id_aa_securityLabel
        attr["attrValues"].setComponentByPosition(0, label_der)
        attrs.setComponentByPosition(position, attr)
        position += 1
    if equivalents_der is not None:
        attr = rfc5652.Attribute()
        attr["attrType"] = rfc2634.id_aa_equivalentLabels
        attr["attrValues"].setComponentByPosition(0, equivalents_der)
        attrs.setComponentByPosition(position, attr)
    if position:
        signer["signedAttrs"] = attrs

    signer["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
        "1.2.840.113549.1.1.11")
    signer["signature"] = univ.OctetString(b"placeholder")
    return signer


def make_signed_data(signers):
    signed_data = rfc5652.SignedData()
    signed_data["version"] = 3
    signed_data["digestAlgorithms"].setComponentByPosition(
        0, signers[0]["digestAlgorithm"])
    signed_data["encapContentInfo"]["eContentType"] = rfc5652.id_data
    for position, signer in enumerate(signers):
        signed_data["signerInfos"].setComponentByPosition(position, signer)
    return signed_data


class SignerConsistencyTestCase(unittest.TestCase):
    def test_two_signers_with_identical_labels_are_accepted(self):
        signed_data = make_signed_data([make_signer(A_ALPHA_11),
                                         make_signer(A_ALPHA_11)])
        label, equivalents = collect_signed_labels(signed_data)
        self.assertEqual(label, A_ALPHA_11)
        self.assertEqual(equivalents, ())

    def test_two_signers_with_different_labels_are_rejected(self):
        other = build_label(POLICY_A, 2,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
        signed_data = make_signed_data([make_signer(A_ALPHA_11),
                                         make_signer(other)])
        with self.assertRaises(LabelConsistencyError):
            collect_signed_labels(signed_data)

    def test_one_signer_missing_label_is_rejected(self):
        signed_data = make_signed_data([make_signer(A_ALPHA_11),
                                         make_signer(None)])
        with self.assertRaises(LabelConsistencyError):
            collect_signed_labels(signed_data)

    def test_no_label_is_rejected(self):
        signed_data = make_signed_data([make_signer(None)])
        with self.assertRaises(Exception):
            collect_signed_labels(signed_data)

    def test_multi_valued_ess_attribute_is_rejected(self):
        signer = make_signer(A_ALPHA_11)
        attr = rfc5652.Attribute()
        attr["attrType"] = rfc2634.id_aa_securityLabel
        attr["attrValues"].setComponentByPosition(0, A_ALPHA_11)
        attr["attrValues"].setComponentByPosition(1, A_ALPHA_11)
        signer["signedAttrs"].setComponentByPosition(0, attr)
        signed_data = make_signed_data([signer])
        with self.assertRaises(LabelConsistencyError):
            collect_signed_labels(signed_data)

    def test_equivalent_attributes_are_collected_from_all_signers(self):
        eq = build_equivalent_labels([
            build_label(POLICY_B, 2, categories=[(CAT_B_DEPARTMENT, "FIN")])])
        signed_data = make_signed_data([make_signer(A_ALPHA_11, eq),
                                         make_signer(A_ALPHA_11, eq)])
        _, equivalents = collect_signed_labels(signed_data)
        self.assertEqual(len(equivalents), 2)


class LayerCombinationTestCase(unittest.TestCase):
    def test_inner_label_wins_when_outer_is_looser(self):
        outer = check_access(
            build_label(POLICY_A, 1,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")]),
            recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        # Inner label is stricter (A/2 -> B/7) and is denied for this reader.
        inner = check_access(
            build_label(POLICY_A, 2,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")]),
            recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(outer.decision, Decision.ALLOW)
        self.assertIs(inner.decision, Decision.DENY)
        self.assertIs(combine_layer_results(outer, inner), Decision.DENY)

    def test_review_layer_forces_review(self):
        allowed = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        review = check_access(
            build_label(POLICY_A, 4,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA"),
                                    (CAT_A_CAVEAT, "NOFORN")]),
            recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(combine_layer_results(allowed, review), Decision.REVIEW)


class JsonConfigurationTestCase(unittest.TestCase):
    def test_json_document_matches_builtin_tables(self):
        path = Path(__file__).resolve().parents[1] / "policies.example.json"
        policies, translations, trusted = load_policy_document(path)
        self.assertEqual(set(policies), {POLICY_A, POLICY_B})
        self.assertEqual(translations, TRANSLATIONS)
        self.assertEqual(trusted, TRUSTED_ASSERTORS)
        for policy_oid, policy in policies.items():
            self.assertEqual(policy.levels, POLICIES[policy_oid].levels)
            self.assertEqual(set(policy.categories),
                             set(POLICIES[policy_oid].categories))

    def test_new_category_in_json_is_decoded_without_code_change(self):
        path = Path(__file__).resolve().parents[1] / "policies.example.json"
        document = json.loads(path.read_text())
        new_oid = "1.3.6.1.4.1.32473.200.2.9"
        document["policies"][POLICY_B]["categories"][new_oid] = {
            "name": "need-to-share", "syntax": "ia5", "values": ["X"]}
        source_oid = new_oid
        document["translations"].append({
            "source_policy": POLICY_A, "source_classification": 0,
            "source_categories": [[CAT_A_COMPARTMENT, "ALPHA"]],
            "target_policy": POLICY_B, "target_classification": 0,
            "target_categories": [[CAT_B_DEPARTMENT, "FIN"],
                                   [source_oid, "X"]],
            "assertor": "1.3.6.1.4.1.32473.100.9.1",
        })
        policies, translations, trusted = build_from_document(document)
        syntax = category_syntax_table(policies)

        label = build_label(POLICY_A, 0,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")],
                            category_syntax=syntax)
        result = check_access(
            label, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 0, ((CAT_B_DEPARTMENT, "FIN"),
                                               (source_oid, "X"))),
            category_syntax=syntax,
            attestations=attested(),
            policies=policies, translations=translations,
            trusted_assertors=trusted)
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertIn(source_oid, result.to_text())

    def test_json_document_is_revalidated(self):
        path = Path(__file__).resolve().parents[1] / "policies.example.json"
        document = json.loads(path.read_text())
        document["translations"][0]["assertor"] = "1.3.6.1.4.1.32473.666.6"
        with self.assertRaises(ClearanceError):
            build_from_document(document)


class CustomPolicyTableTestCase(unittest.TestCase):
    def test_result_text_uses_the_supplied_table(self):
        path = Path(__file__).resolve().parents[1] / "policies.example.json"
        policies, translations, trusted = load_policy_document(path)
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2, ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            policies=policies, translations=translations,
            trusted_assertors=trusted)
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.source_level, "sensitive-but-unclassified")
        self.assertIn("(Agency-B)", result.to_text())
        self.assertIn("internal", result.to_text())


class PolicyTableTestCase(unittest.TestCase):
    def test_hierarchy_is_not_numeric_order(self):
        policy = POLICIES[POLICY_A]
        self.assertEqual(policy.level_name(11), "sensitive-but-unclassified")
        self.assertEqual(policy.level_name(2), "restricted")
        self.assertGreater(policy.rank(2), policy.rank(11))
        self.assertLess(policy.rank(1), policy.rank(11))

    def test_same_integer_means_different_level_in_other_domain(self):
        self.assertEqual(POLICIES[POLICY_A].level_name(2), "restricted")
        self.assertEqual(POLICIES[POLICY_B].level_name(2), "internal")


class RoundTripTestCase(unittest.TestCase):
    def test_build_and_parse_label(self):
        label = build_label(
            POLICY_A, 4,
            categories=[(CAT_A_COMPARTMENT, "BRAVO"),
                        (CAT_A_CAVEAT, "NOFORN")],
            privacy_mark="Agency-A // BRAVO // SECRET")
        parsed = parse_label(label)
        self.assertEqual(parsed.policy_oid, POLICY_A)
        self.assertEqual(parsed.classification, 4)
        self.assertEqual(parsed.privacy_mark, "Agency-A // BRAVO // SECRET")
        self.assertEqual(
            {cat.oid: cat.value for cat in parsed.categories},
            {CAT_A_COMPARTMENT: "BRAVO", CAT_A_CAVEAT: "NOFORN"})

    def test_parse_rejects_trailing_bytes(self):
        with self.assertRaises(Exception):
            parse_label(build_label(POLICY_A, 1) + b"\x00")

    def test_parse_unknown_category_keeps_raw_value(self):
        label = build_label(
            POLICY_A, 4,
            categories=[(CAT_A_COMPARTMENT, "ALPHA")],
            raw_categories=[("1.3.6.1.4.1.32473.999.9", b"\x0c\x07UNKNOWN")])
        parsed = parse_label(label)
        unknown = [c for c in parsed.categories if not c.known]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].value, None)
        self.assertEqual(unknown[0].raw, b"\x0c\x07UNKNOWN")


class CrossDomainAllowTestCase(unittest.TestCase):
    def test_a_11_alpha_maps_to_b_2_fin(self):
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2, ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.source_policy, POLICY_A)
        self.assertEqual(result.source_level, "sensitive-but-unclassified")
        self.assertEqual(result.effective_level, "internal")
        self.assertEqual(result.effective_categories,
                         ((CAT_B_DEPARTMENT, "FIN"),))

    def test_b_9_eng_maps_back_to_a_4_bravo(self):
        result = check_access(
            build_label(POLICY_B, 9,
                        categories=[(CAT_B_DEPARTMENT, "ENG")]),
            recipient_policy=POLICY_A,
            clearance=Clearance(POLICY_A, 4,
                                ((CAT_A_COMPARTMENT, "BRAVO"),)),
            attestations=attested("1.3.6.1.4.1.32473.200.9.1"))
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.effective_classification, 4)
        self.assertEqual(result.effective_level, "secret")

    def test_same_policy_uses_original_hierarchy(self):
        label = build_label(POLICY_A, 11,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
        clearance = Clearance(POLICY_A, 11,
                              ((CAT_A_COMPARTMENT, "ALPHA"),))
        result = check_access(
            label, recipient_policy=POLICY_A, clearance=clearance,
            attestations=attested())
        self.assertIs(result.decision, Decision.ALLOW)


class EscalationTestCase(unittest.TestCase):
    def test_numeric_comparison_would_grant_access_but_guard_denies(self):
        # A/2 is "restricted"; B/2 is "internal".  A/2+ALPHA maps to B/7+FIN.
        label = build_label(POLICY_A, 2,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
        clearance = Clearance(POLICY_B, 2, ((CAT_B_DEPARTMENT, "FIN"),))
        self.assertTrue(naive_numeric_allows(2, clearance.classification))
        result = check_access(
            label, recipient_policy=POLICY_B, clearance=clearance,
            attestations=attested())
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "clearance-below-label")
        self.assertEqual(result.effective_classification, 7)

    def test_numeric_order_inside_same_policy_would_grant_access(self):
        # A/11 (SBU) is numerically greater than A/2 (restricted), but ranks
        # lower.  A/11 clearance must not cover an A/2 label.
        label = build_label(POLICY_A, 2,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
        clearance = Clearance(POLICY_A, 11,
                              ((CAT_A_COMPARTMENT, "ALPHA"),))
        self.assertTrue(naive_numeric_allows(2, 11))
        result = check_access(
            label, recipient_policy=POLICY_A, clearance=clearance,
            attestations=attested())
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "clearance-below-label")

    def test_category_set_is_not_widened(self):
        # A/5+ALPHA maps to B/9+FIN+NEED-TO-KNOW.  A B/9+FIN clearance is
        # numerically high enough but lacks the handling category.
        label = build_label(POLICY_A, 5,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
        clearance = Clearance(POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),))
        result = check_access(
            label, recipient_policy=POLICY_B, clearance=clearance,
            attestations=attested())
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "clearance-missing-category")
        self.assertEqual(
            result.effective_categories,
            ((CAT_B_DEPARTMENT, "FIN"), (CAT_B_HANDLING, "NEED-TO-KNOW")))

    def test_extra_source_category_has_no_mapping(self):
        label = build_label(POLICY_A, 4,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA"),
                                        (CAT_A_CAVEAT, "NOFORN")])
        result = check_access(
            label, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "no-exact-local-mapping")


class UnknownAndContradictionTestCase(unittest.TestCase):
    def test_unknown_policy_is_review(self):
        result = check_access(
            build_label("1.3.6.1.4.1.32473.999.1", 5),
            recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9),
            attestations=attested())
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "unknown-source-policy")

    def test_unknown_category_is_review_not_loosened(self):
        label = build_label(
            POLICY_A, 5,
            categories=[(CAT_A_COMPARTMENT, "ALPHA")],
            raw_categories=[("1.3.6.1.4.1.32473.999.9", b"\x0c\x07UNKNOWN")])
        result = check_access(
            label, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),
                                 (CAT_B_HANDLING, "NEED-TO-KNOW"))),
            attestations=attested())
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertIn("not registered", result.detail)

    def test_missing_required_category_is_review(self):
        label = build_label(POLICY_A, 11)
        result = check_access(
            label, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertIn("required categories", result.detail)

    def test_unknown_category_value_is_review(self):
        label = build_label(POLICY_A, 11,
                            categories=[(CAT_A_COMPARTMENT, "CHARLIE")])
        result = check_access(
            label, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertIn("closed value set", result.detail)

    def test_absent_classification_has_no_local_meaning(self):
        label = build_label(POLICY_A)
        result = check_access(
            label, recipient_policy=POLICY_A,
            clearance=Clearance(POLICY_A, 0,
                                ((CAT_A_COMPARTMENT, "ALPHA"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertIn("classification is absent", result.detail)

    def test_authenticated_equivalent_contradiction_is_review(self):
        claimed = build_label(POLICY_B, 0,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        equivalent = build_equivalent_labels([claimed])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "authenticated-labels-contradict")
        self.assertEqual(result.equivalents[0].status, "contradicts")

    def test_equivalent_agreement_does_not_replace_local_mapping(self):
        claimed = build_label(POLICY_B, 2,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        equivalent = build_equivalent_labels([claimed])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.equivalents[0].status, "agrees")

    def test_duplicate_policy_oid_in_equivalents_is_review(self):
        duplicate = build_equivalent_labels([
            build_label(POLICY_B, 2,
                        categories=[(CAT_B_DEPARTMENT, "FIN")]),
            build_label(POLICY_B, 9,
                        categories=[(CAT_B_DEPARTMENT, "FIN")]),
        ])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            equivalent_attributes=[duplicate])
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "authenticated-labels-contradict")
        self.assertIn("occurs more than once", result.detail)

    def test_translator_trust_is_direction_specific(self):
        # The B-side role is a trusted translator, but only for B -> A.  It
        # must not be able to translate A -> B just because it is on a global
        # allowlist.
        claimed = build_label(POLICY_B, 0,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        equivalent = build_equivalent_labels([claimed])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested("1.3.6.1.4.1.32473.200.9.1"),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.equivalents[0].status, "ignored")
        self.assertFalse(result.equivalents[0].translator_trusted)

    def test_third_policy_claim_is_ignored_without_direction_trust(self):
        # No local A -> third translation exists, so no role is authorised to
        # translate into the third policy.  RFC 2634 says not to act on such
        # an attribute; it is ignored rather than used to loosen the decision.
        third = build_label("1.3.6.1.4.1.32473.300.1", 1)
        equivalent = build_equivalent_labels([third])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.equivalents[0].status, "ignored")
        self.assertFalse(result.equivalents[0].translator_trusted)

    def test_recipient_policy_claim_without_local_mapping_is_review(self):
        # A low label that has no A -> B mapping, plus an authenticated claim
        # under B.  The claim must not be used to invent a mapping.
        label = build_label(POLICY_A, 0,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
        claimed = build_label(POLICY_B, 0,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        equivalent = build_equivalent_labels([claimed])
        result = check_access(
            label, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 0,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "equivalent-labels-unverifiable")

    def test_same_policy_ignores_equivalents_but_reports_them(self):
        # A legitimate foreign-policy EquivalentLabels claim is ignored, per
        # RFC 2634, when the original policy is understood locally.
        claimed = build_label(POLICY_B, 2,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        equivalent = build_equivalent_labels([claimed])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_A,
            clearance=Clearance(POLICY_A, 11,
                                ((CAT_A_COMPARTMENT, "ALPHA"),)),
            attestations=attested(),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.equivalents[0].status,
                         "ignored-policy-understood")

    def test_same_policy_duplicate_authenticated_label_is_review(self):
        duplicate = build_equivalent_labels([
            build_label(POLICY_A, 4,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")])])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_A,
            clearance=Clearance(POLICY_A, 11,
                                ((CAT_A_COMPARTMENT, "ALPHA"),)),
            attestations=attested(),
            equivalent_attributes=[duplicate])
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "authenticated-labels-contradict")
        self.assertIn("repeated", result.detail)

    def test_multiple_equivalent_attributes_are_review(self):
        claimed = build_label(POLICY_B, 2,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        other = build_label(POLICY_B, 9,
                            categories=[(CAT_B_DEPARTMENT, "FIN")])
        first = build_equivalent_labels([claimed])
        second = build_equivalent_labels([other])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(),
            equivalent_attributes=[first, second])
        self.assertIs(result.decision, Decision.REVIEW)
        self.assertEqual(result.reason, "multiple-equivalent-labels-attributes")

    def test_unverified_translator_is_ignored_not_trusted(self):
        claimed = build_label(POLICY_B, 0,
                              categories=[(CAT_B_DEPARTMENT, "FIN")])
        equivalent = build_equivalent_labels([claimed])
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested(translator="rogue-translator"),
            equivalent_attributes=[equivalent])
        self.assertIs(result.decision, Decision.ALLOW)
        self.assertEqual(result.equivalents[0].status, "ignored")
        self.assertFalse(result.equivalents[0].translator_trusted)

    def test_missing_original_label_denies(self):
        result = check_access(
            b"", recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "missing-original-label")

    def test_signature_not_verified_denies(self):
        attestations = Attestations(
            label_signature=Evidence(False),
            translator=Evidence(False),
            clearance=Evidence(True, "accreditation-authority"))
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 2,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attestations)
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "label-signature-not-verified")

    def test_clearance_not_verified_denies(self):
        attestations = Attestations(
            label_signature=Evidence(True, "cms-verifier"),
            clearance=Evidence(False))
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_B, 9,
                                ((CAT_B_DEPARTMENT, "FIN"),)),
            attestations=attestations)
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "recipient-clearance-not-attested")

    def test_clearance_in_other_policy_denies(self):
        result = check_access(
            A_ALPHA_11, recipient_policy=POLICY_B,
            clearance=Clearance(POLICY_A, 5,
                                ((CAT_A_COMPARTMENT, "ALPHA"),)),
            attestations=attested())
        self.assertIs(result.decision, Decision.DENY)
        self.assertEqual(result.reason, "clearance-policy-mismatch")


if __name__ == "__main__":
    unittest.main()
