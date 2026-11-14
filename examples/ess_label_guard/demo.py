#!/usr/bin/env python3
"""Executable prototype: cross-policy receiving check for ESS security labels.

Run directly from the repository root:

    python examples/ess_label_guard/demo.py

It prints:

  1. the two finite policies and their bilateral translation tables;
  2. a legitimate cross-domain delivery (ALLOW);
  3. a numeric-comparison escalation (DENY) and its corrected result;
  4. an authenticated EquivalentLabels contradiction (REVIEW);
  5. an unknown-category and an incomplete-mapping case (REVIEW).

Nothing here signs, encrypts or contacts a network.  Signature verification,
envelope decryption and clearance issuance are represented by explicit
attestations; see README.md for who must provide each one.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pyasn1.type import tag, univ

from pyasn1_modules import rfc2634, rfc5652

from ess_label_guard import (
    Attestations,
    Clearance,
    Evidence,
    POLICY_A,
    POLICY_B,
    POLICIES,
    TRANSLATIONS,
    build_equivalent_labels,
    build_label,
    check_access,
    collect_signed_labels,
    naive_numeric_allows,
)
from ess_label_guard.mapping import CAT_A_COMPARTMENT, CAT_B_DEPARTMENT


ATTESTED = Attestations(
    label_signature=Evidence(True, "CMS verifier at gateway-b"),
    translator=Evidence(True, "1.3.6.1.4.1.32473.100.9.1"),
    clearance=Evidence(True, "Agency-B accreditation authority"),
)


def rule(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def show(result):
    print(result.to_text())
    print()


def print_policies():
    rule("1. Two finite policy domains (no other policy is accepted)")
    for policy in POLICIES.values():
        levels = " < ".join(
            f"{number}:{name}" for number, name in policy.levels)
        cats = ", ".join(
            f"{cat.name}({cat.oid})"
            + (f"={{{','.join(sorted(cat.values))}}}"
               if cat.values is not None else "")
            for cat in policy.categories.values())
        print(f"{policy.name}  oid={policy.oid}")
        print(f"  hierarchy (ascending rank): {levels}")
        print(f"  categories: {cats}")
        print(f"  required: {sorted(policy.required_categories)}")
    print()
    print(f"bilateral translations: {len(TRANSLATIONS)} entries, all explicit")
    print("the same document can be loaded from policies.example.json; "
          "see config.load_policy_document")
    for trans in TRANSLATIONS:
        print(f"  {trans.source_policy} [{trans.source_classification}] "
              f"{_show_cats(trans.source_categories)} -> "
              f"{trans.target_policy} [{trans.target_classification}] "
              f"{_show_cats(trans.target_categories)}  assertor={trans.assertor}")


def _show_cats(categories):
    return "{" + ", ".join(f"{oid.split('.')[-1]}={value}"
                           for oid, value in categories) + "}"


def legitimate_delivery():
    rule("2. Legitimate cross-domain delivery: A/11 + ALPHA -> B/2 + FIN")
    label = build_label(POLICY_A, 11,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")],
                        privacy_mark="Agency-A // ALPHA // SBU")
    clearance = Clearance(POLICY_B, 2, ((CAT_B_DEPARTMENT, "FIN"),))
    result = check_access(
        label, recipient_policy=POLICY_B, clearance=clearance,
        attestations=ATTESTED)
    show(result)


def numeric_escalation():
    rule("3. Numeric comparison escalates access: A/2 + ALPHA vs clearance B/2")

    label = build_label(POLICY_A, 2,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")],
                        privacy_mark="Agency-A // ALPHA // RESTRICTED")
    clearance = Clearance(POLICY_B, 2, ((CAT_B_DEPARTMENT, "FIN"),))

    print("naive comparator (ignores policy OID and hierarchy):")
    print(f"  source classification=2 <= clearance classification=2 "
          f"-> allows={naive_numeric_allows(2, 2)}")
    print("  but A/2 is 'restricted' and B/2 is 'internal'; "
          "A/2 maps to B/7 'confidential'.")
    print("  A/11 is 'sensitive-but-unclassified' and is lower than A/2, "
          "so the integer 11 > 2 is not a safe ordering either.")
    print()

    result = check_access(
        label, recipient_policy=POLICY_B, clearance=clearance,
        attestations=ATTESTED)
    show(result)
    print("corrected result: the exact local mapping A/2+ALPHA -> B/7+FIN is "
          "used, and B/2 clearance is below B/7 -> DENY.")


def equivalent_contradiction():
    rule("4. Authenticated EquivalentLabels contradicts the local mapping")
    label = build_label(POLICY_A, 11,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")])
    # Local mapping says B/2+FIN.  A trusted translator claims B/0+FIN.
    # The loosest possible B label.  If a gateway "chose the most permissive
    # equivalent label", this would grant access; the guard instead reviews it.
    claimed = build_label(POLICY_B, 0,
                          categories=[(CAT_B_DEPARTMENT, "FIN")])
    equivalent = build_equivalent_labels([claimed])
    clearance = Clearance(POLICY_B, 2, ((CAT_B_DEPARTMENT, "FIN"),))
    result = check_access(
        label, recipient_policy=POLICY_B, clearance=clearance,
        attestations=ATTESTED, equivalent_attributes=[equivalent])
    show(result)


def unknown_and_incomplete():
    rule("5. Unknown category and incomplete mapping never pick a looser label")

    label = build_label(
        POLICY_A, 5,
        categories=[(CAT_A_COMPARTMENT, "ALPHA")],
        raw_categories=[("1.3.6.1.4.1.32473.999.9", b"\x0c\x07UNKNOWN")])
    clearance = Clearance(POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),))
    unknown = check_access(
        label, recipient_policy=POLICY_B, clearance=clearance,
        attestations=ATTESTED)
    print("unknown category ->", unknown.decision.value, unknown.reason)
    print(unknown.detail)
    print()

    # A/5+ALPHA has a configured mapping, but it includes an extra handling
    # category that a B/9+FIN-only clearance does not carry.
    label = build_label(POLICY_A, 5,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA")])
    clearance = Clearance(POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),))
    missing = check_access(
        label, recipient_policy=POLICY_B, clearance=clearance,
        attestations=ATTESTED)
    print("mapped label with missing category clearance ->",
          missing.decision.value, missing.reason)
    print(missing.detail)
    print()

    label = build_label(POLICY_A, 4,
                        categories=[(CAT_A_COMPARTMENT, "ALPHA"),
                                    ("1.3.6.1.4.1.32473.100.2.2", "NOFORN")])
    clearance = Clearance(POLICY_B, 9, ((CAT_B_DEPARTMENT, "FIN"),))
    unmatched = check_access(
        label, recipient_policy=POLICY_B, clearance=clearance,
        attestations=ATTESTED)
    print("no exact mapping (extra caveat) ->",
          unmatched.decision.value, unmatched.reason)
    print(unmatched.detail)
    print(unmatched.notes[-1] if unmatched.notes else "")


def signed_attribute_extraction():
    rule("6. Extraction from a real-looking SignerInfo signedAttrs set")
    label_der = build_label(POLICY_A, 11,
                            categories=[(CAT_A_COMPARTMENT, "ALPHA")])
    eq_der = build_equivalent_labels([
        build_label(POLICY_B, 2, categories=[(CAT_B_DEPARTMENT, "FIN")])])

    attr1 = rfc5652.Attribute()
    attr1["attrType"] = rfc2634.id_aa_securityLabel
    attr1["attrValues"].setComponentByPosition(0, label_der)
    attr2 = rfc5652.Attribute()
    attr2["attrType"] = rfc2634.id_aa_equivalentLabels
    attr2["attrValues"].setComponentByPosition(0, eq_der)

    signer = rfc5652.SignerInfo()
    signer["version"] = 3
    sid = rfc5652.SignerIdentifier()
    sid["subjectKeyIdentifier"] = univ.OctetString(b"\x01" * 20).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    signer["sid"] = sid
    signer["digestAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
        "2.16.840.1.101.3.4.2.1")
    signed_attrs = rfc5652.SignedAttributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    signed_attrs.setComponentByPosition(0, attr1)
    signed_attrs.setComponentByPosition(1, attr2)
    signer["signedAttrs"] = signed_attrs
    signer["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
        "1.2.840.113549.1.1.11")
    signer["signature"] = univ.OctetString(b"placeholder")

    signed_data = rfc5652.SignedData()
    signed_data["version"] = 3
    signed_data["digestAlgorithms"].setComponentByPosition(
        0, signer["digestAlgorithm"])
    signed_data["encapContentInfo"]["eContentType"] = rfc5652.id_data
    signed_data["signerInfos"].setComponentByPosition(0, signer)

    label, equivalents = collect_signed_labels(signed_data)
    print(f"consistent label across signerInfos: {len(label)} bytes of DER")
    print(f"equivalent-labels attributes across signerInfos: "
          f"{len(equivalents)}")
    print("unsigned attrs are not inspected; the CMS verifier must confirm "
          "the signature over signedAttrs before these values are trusted.")
    print("if signerInfos disagreed, collect_signed_labels() would raise "
          "instead of choosing one label.")


def main():
    print_policies()
    legitimate_delivery()
    numeric_escalation()
    equivalent_contradiction()
    unknown_and_incomplete()
    signed_attribute_extraction()


if __name__ == "__main__":
    main()
