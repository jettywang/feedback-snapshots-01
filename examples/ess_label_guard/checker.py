"""Cross-policy receiving check for S/MIME ESS security labels.

Security model (deliberately small):

* The *label signer* proves only that this label is bound to this content.
  Signature verification and certificate-path validation are done by the
  receiving CMS layer, not by this module.
* A *trusted translator* proves that the label in a foreign policy means what
  the EquivalentLabels attribute says it means.  Who is trusted is a local
  configuration decision; it is never inferred from the message.
* The *recipient's accreditation authority* proves the recipient's clearance.
  The message sender and the mail gateway never grant it.

This module compares labels only inside explicitly configured finite policy
tables.  It never computes a "maximum", "minimum" or "most permissive" label.
Every unverifiable case escalates to REVIEW and therefore does not grant access.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Optional, Sequence, Tuple

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.error import PyAsn1Error

from pyasn1_modules import rfc2634

from .mapping import (
    POLICIES,
    category_syntax_table,
    TRANSLATIONS,
    TRUSTED_ASSERTORS,
    Clearance,
    Policy,
)
from .label import LabelParseError, ParsedLabel, parse_label


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"


@dataclass(frozen=True)
class Evidence:
    """One proof and the party accountable for it.

    ``authority`` is who asserts the fact, not who benefits from it.  An empty
    authority with ``verified=False`` is the normal "no proof supplied" state.
    """

    verified: bool
    authority: str = ""
    note: str = ""


@dataclass(frozen=True)
class Attestations:
    """The three independent proofs a receiving gateway needs.

    ``label_signature``: the CMS verifier checked the signerInfo signature over
    signedAttrs (which include the label) and validated the signer certificate
    path.  This proves integrity and origin, not the truth of the label.

    ``translator``: the EquivalentLabels attribute signature was verified and
    its signer is in the local translator allowlist.  This proves authority to
    translate, not that the translation is semantically right; local policy
    owns that judgement.

    ``clearance``: a trusted source (accreditation authority, signed clearance
    attribute, directory) asserted the recipient's clearance.  This proves
    eligibility, not message authenticity.
    """

    label_signature: Evidence = Evidence(False)
    translator: Evidence = Evidence(False)
    clearance: Evidence = Evidence(False)


@dataclass(frozen=True)
class EquivalentObservation:
    policy_oid: str
    classification: Optional[int]
    level_name: Optional[str]
    categories: Tuple[Tuple[str, str], ...]
    signature_verified: bool
    translator_trusted: bool
    status: str
    detail: str = ""


@dataclass(frozen=True)
class AccessResult:
    decision: Decision
    reason: str
    detail: str
    source_policy: str
    source_classification: Optional[int]
    source_level: Optional[str]
    source_categories: Tuple[Tuple[str, str], ...]
    source_privacy_mark: Optional[str]
    effective_policy: Optional[str]
    effective_classification: Optional[int]
    effective_level: Optional[str]
    effective_categories: Tuple[Tuple[str, str], ...]
    clearance: Clearance
    equivalents: Tuple[EquivalentObservation, ...] = ()
    authorities: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    # The closed configuration actually used for this decision.  Carried so
    # that rendering and audit text never silently fall back to another table.
    policy_table: Mapping[str, Policy] = field(
        default_factory=dict, repr=False, compare=False)

    def allows(self) -> bool:
        return self.decision is Decision.ALLOW

    def to_text(self) -> str:
        lines = [
            f"decision: {self.decision.value} ({self.reason})",
            f"why: {self.detail}",
            "original label: "
            + _render_label(self.policy_table, self.source_policy,
                            self.source_classification, self.source_level,
                            self.source_categories)
            + _render_privacy_mark(self.source_privacy_mark),
        ]
        if self.effective_policy is not None:
            lines.append(
                "effective label: "
                + _render_label(self.policy_table, self.effective_policy,
                                self.effective_classification,
                                self.effective_level,
                                self.effective_categories))
        clearance_policy = self.policy_table.get(self.clearance.policy_oid)
        clearance_level = None
        if clearance_policy is not None and self.clearance.classification is not None:
            clearance_level = clearance_policy.level_name(
                self.clearance.classification)
        lines.append(
            "recipient clearance: "
            + _render_label(self.policy_table, self.clearance.policy_oid,
                            self.clearance.classification, clearance_level,
                            self.clearance.categories))
        for obs in self.equivalents:
            lines.append(
                "equivalent label: "
                + _render_label(self.policy_table, obs.policy_oid,
                                obs.classification, obs.level_name,
                                obs.categories)
                + f"; signature={'ok' if obs.signature_verified else 'no'}"
                + f"; translator={'trusted' if obs.translator_trusted else 'no'}"
                + f"; status={obs.status}"
                + (f" ({obs.detail})" if obs.detail else ""))
        for authority in self.authorities:
            lines.append(f"proved by: {authority}")
        for note in self.notes:
            lines.append(f"note: {note}")
        return "\n".join(lines)


def _policy_text(policy_table, policy_oid) -> str:
    policy = policy_table.get(policy_oid)
    if policy is None:
        return f"{policy_oid} (policy not configured locally)"
    return f"{policy_oid} ({policy.name})"


def _render_label(policy_table, policy_oid, classification, level,
                  categories) -> str:
    return (
        f"policy={_policy_text(policy_table, policy_oid)} "
        f"classification={classification} "
        f"level={level or '<undefined>'} "
        "categories="
        + (_render_categories(policy_table, policy_oid, categories)
           or "(none)"))


def _render_categories(policy_table, policy_oid, categories) -> str:
    policy = policy_table.get(policy_oid)
    parts = []
    for oid, value in categories:
        name = None
        if policy is not None:
            spec = policy.categories.get(oid)
            name = None if spec is None else spec.name
        parts.append(f"{oid}{f' ({name})' if name else ''}={value}")
    return ", ".join(parts)


def _render_privacy_mark(mark: Optional[str]) -> str:
    if mark is None:
        return ""
    return f" privacy-mark={mark!r} (display only; not used for access control)"


def _label_categories(label: ParsedLabel) -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted(
        (cat.oid, cat.value if cat.value is not None
         else f"<raw {cat.raw.hex()}>")
        for cat in label.categories))


def _normalize(label: ParsedLabel, policy: Policy):
    """Validate a label under its own policy.

    Returns ``(classification, categories, problems)``.  A missing optional
    field is not invented here; only ``policy.absent_classification`` can give
    absence a local meaning.
    """

    problems = []

    if label.classification is None:
        classification = policy.absent_classification
        if classification is None:
            problems.append(
                f"{policy.oid}: classification is absent and this policy "
                "defines no explicit meaning for absence")
    else:
        classification = label.classification
        if policy.rank(classification) is None:
            problems.append(
                f"{policy.oid}: classification integer {classification} is "
                "not defined by this policy")
            classification = None

    seen = set()
    categories = []
    for cat in label.categories:
        spec = policy.categories.get(cat.oid)
        if spec is None:
            problems.append(
                f"{policy.oid}: category type {cat.oid} is not registered in "
                "this policy; its syntax and meaning are unknown")
            continue
        if cat.oid in seen:
            problems.append(f"{policy.oid}: duplicate category type {cat.oid}")
            continue
        seen.add(cat.oid)
        if cat.value is None:
            problems.append(
                f"{policy.oid}: category {cat.oid} value cannot be decoded "
                f"with the locally configured {spec.syntax!r} syntax")
            continue
        if spec.values is not None and cat.value not in spec.values:
            problems.append(
                f"{policy.oid}: category {cat.oid} value {cat.value!r} is not "
                "in the locally closed value set")
            continue
        categories.append((cat.oid, cat.value))

    missing = {oid for oid in policy.required_categories if oid not in seen}
    if missing:
        problems.append(
            f"{policy.oid}: required categories missing {sorted(missing)}")

    return classification, tuple(sorted(categories)), problems


def _load_equivalent_payloads(attribute_payloads: Sequence[bytes],
                              category_syntax=None):
    """Decode every EquivalentLabels attribute into parsed labels."""

    labels = []
    errors = []
    for index, payload in enumerate(attribute_payloads):
        try:
            seq, rest = der_decoder(payload, asn1Spec=rfc2634.EquivalentLabels())
        except PyAsn1Error as exc:
            errors.append(f"EquivalentLabels[{index}] DER decode failed: {exc}")
            continue
        if rest:
            errors.append(
                f"EquivalentLabels[{index}] has {len(rest)} trailing bytes")
            continue
        if len(seq) == 0:
            errors.append(f"EquivalentLabels[{index}] is empty")
            continue
        for position, label in enumerate(seq):
            try:
                labels.append(parse_label(der_encoder(label),
                                          category_syntax=category_syntax))
            except (PyAsn1Error, LabelParseError) as exc:
                errors.append(
                    f"EquivalentLabels[{index}][{position}] invalid: {exc}")
    return labels, errors


def check_access(
    original_label_der: bytes,
    *,
    recipient_policy: str,
    clearance: Clearance,
    attestations: Attestations,
    equivalent_attributes: Sequence[bytes] = (),
    policies=POLICIES,
    translations=TRANSLATIONS,
    trusted_assertors=TRUSTED_ASSERTORS,
    category_syntax=None,
) -> AccessResult:
    """Return ALLOW / DENY / REVIEW for one receiving decision."""

    if category_syntax is None:
        category_syntax = category_syntax_table(policies)

    authorities = (
        "label signature: "
        + _evidence_text(attestations.label_signature),
        "conversion authority: "
        + _evidence_text(attestations.translator,
                         applicable=bool(equivalent_attributes)),
        "recipient eligibility: "
        + _evidence_text(attestations.clearance),
    )

    if not original_label_der:
        return _result(
            decision=Decision.DENY, reason="missing-original-label",
            detail="no ESSSecurityLabel signed attribute is present; access "
                   "control cannot be based on an absent label",
            source=None, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    try:
        source = parse_label(bytes(original_label_der),
                             category_syntax=category_syntax)
    except (LabelParseError, PyAsn1Error) as exc:
        return _result(
            decision=Decision.DENY, reason="malformed-original-label",
            detail=str(exc), source=None, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    if not attestations.label_signature.verified:
        return _result(
            decision=Decision.DENY, reason="label-signature-not-verified",
            detail="no CMS verifier proved that this label is bound to the "
                   "signed content; its semantics must not be used",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    recipient = policies.get(recipient_policy)
    if recipient is None:
        return _result(
            decision=Decision.REVIEW, reason="unknown-recipient-policy",
            detail=f"recipient policy {recipient_policy} is not in the local "
                   "configuration",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    source_policy = policies.get(source.policy_oid)
    if source_policy is None:
        return _result(
            decision=Decision.REVIEW, reason="unknown-source-policy",
            detail=f"source policy {source.policy_oid} is not in the local "
                   "configuration; its classification integers and category "
                   "types have no local meaning",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    source_classification, source_categories, problems = _normalize(
        source, source_policy)
    if problems:
        return _result(
            decision=Decision.REVIEW,
            reason="source-label-incomplete-or-unknown",
            detail="; ".join(problems), source=source,
            recipient_policy=recipient_policy, clearance=clearance,
            authorities=authorities, policies=policies)

    if not attestations.clearance.verified:
        return _result(
            decision=Decision.DENY, reason="recipient-clearance-not-attested",
            detail="no trusted accreditation authority proved the recipient's "
                   "clearance",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    if clearance.policy_oid != recipient_policy:
        return _result(
            decision=Decision.DENY, reason="clearance-policy-mismatch",
            detail=f"clearance is under {clearance.policy_oid}, recipient "
                   f"policy is {recipient_policy}",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities, policies=policies)

    clearance_problems = _check_clearance(clearance, recipient)
    if clearance_problems:
        return _result(
            decision=Decision.DENY,
            reason="clearance-malformed-or-unknown",
            detail="; ".join(clearance_problems), source=source,
            recipient_policy=recipient_policy, clearance=clearance,
            authorities=authorities, policies=policies)

    notes = []
    observations = []

    if source.policy_oid == recipient_policy:
        # RFC 2634 section 3.4.2: if the policy in ESSSecurityLabel is
        # understood, it MUST be processed and all EquivalentLabels ignored.
        # This is the one case where equivalents cannot force REVIEW; they are
        # still reported as "ignored" so the operator sees they were present.
        effective_policy = recipient_policy
        effective_classification = source_classification
        effective_level = recipient.level_name(source_classification)
        effective_categories = source_categories
        notes.append("source policy is understood locally; per RFC 2634 the "
                     "original label governs and EquivalentLabels are ignored")
        if equivalent_attributes:
            # RFC 2634 requires ignoring these for the decision.  They are
            # still parsed for the audit trail, and a malformed one cannot
            # loosen anything because it contributes no observation.
            ignored_labels, ignored_errors = _load_equivalent_payloads(
                equivalent_attributes, category_syntax)
            for label in ignored_labels:
                observation = _observe(
                    label, attestations, source.policy_oid,
                    trusted_assertors, translations, policies)
                observations.append(_replace_status(
                    observation, "ignored-policy-understood",
                    "source policy is understood locally; RFC 2634 says to "
                    "ignore this attribute"))
            if ignored_errors:
                notes.append("ignored malformed EquivalentLabels: "
                             + "; ".join(ignored_errors))
            notes.append(
                f"{len(equivalent_attributes)} EquivalentLabels attribute(s) "
                "present but not used")

            # RFC 2634 requires every policy OID to be unique across the
            # original label and EquivalentLabels.  An authenticated duplicate
            # of the source policy is a contradiction even when the original
            # policy is understood locally, so it goes to manual review rather
            # than being silently ignored.
            if attestations.translator.verified:
                duplicates = [
                    label for label in ignored_labels
                    if label.policy_oid == source.policy_oid]
                if duplicates:
                    return _result(
                        decision=Decision.REVIEW,
                        reason="authenticated-labels-contradict",
                        detail="security-policy OID "
                               f"{source.policy_oid} is repeated in an "
                               "authenticated EquivalentLabels attribute; "
                               "RFC 2634 requires policy OIDs to be unique",
                        source=source, recipient_policy=recipient_policy,
                        clearance=clearance, authorities=authorities,
                        equivalents=observations, notes=notes,
                        policies=policies)
    else:
        if len(equivalent_attributes) > 1:
            return _result(
                decision=Decision.REVIEW,
                reason="multiple-equivalent-labels-attributes",
                detail="more than one EquivalentLabels attribute is present; "
                       "a local gateway will not merge or choose among "
                       "translator claims",
                source=source, recipient_policy=recipient_policy,
                clearance=clearance, authorities=authorities, policies=policies)
        equivalent_labels, equivalent_errors = _load_equivalent_payloads(
            equivalent_attributes, category_syntax)
        if equivalent_errors:
            return _result(
                decision=Decision.REVIEW,
                reason="equivalent-labels-unparseable",
                detail="; ".join(equivalent_errors), source=source,
                recipient_policy=recipient_policy, clearance=clearance,
                authorities=authorities, policies=policies)

        observations, contradiction, equivalent_notes = _cross_check_equivalents(
            equivalent_labels, source, source_classification, source_categories,
            recipient_policy, attestations, trusted_assertors, translations,
            policies)
        notes.extend(equivalent_notes)

        if contradiction:
            return _result(
                decision=Decision.REVIEW,
                reason="authenticated-labels-contradict",
                detail=contradiction, source=source,
                recipient_policy=recipient_policy, clearance=clearance,
                authorities=authorities, equivalents=observations,
                notes=notes, policies=policies)

        unverifiable = [obs for obs in observations
                        if obs.status == "unverifiable"]
        if unverifiable:
            return _result(
                decision=Decision.REVIEW,
                reason="equivalent-labels-unverifiable",
                detail="; ".join(
                    f"{obs.policy_oid}: {obs.detail}" for obs in unverifiable),
                source=source, recipient_policy=recipient_policy,
                clearance=clearance, authorities=authorities,
                equivalents=observations, notes=notes, policies=policies)
        matches = [
            trans for trans in translations
            if trans.source_policy == source.policy_oid
            and trans.target_policy == recipient_policy
            and trans.source_classification == source_classification
            and trans.source_categories == source_categories
        ]
        if not matches:
            return _result(
                decision=Decision.REVIEW, reason="no-exact-local-mapping",
                detail="no complete bilateral mapping matches this "
                       "classification and exactly these category values; "
                       "partial, nearest or default matches are not used",
                source=source, recipient_policy=recipient_policy,
                clearance=clearance, authorities=authorities,
                equivalents=observations, notes=notes, policies=policies,
                extra_notes=(_mapping_gap_note(
                    source_policy, source_classification, source_categories,
                    recipient_policy, translations, policies),))
        if len(matches) > 1:
            return _result(
                decision=Decision.REVIEW, reason="ambiguous-local-mapping",
                detail="more than one configured translation matches; refusing "
                       "to choose the more permissive one",
                source=source, recipient_policy=recipient_policy,
                clearance=clearance, authorities=authorities,
                equivalents=observations, notes=notes, policies=policies)
        translation = matches[0]
        authorities = authorities + (
            "local mapping: provisioned by role "
            f"{translation.assertor} (configuration, not message-borne)",)
        effective_policy = translation.target_policy
        effective_classification = translation.target_classification
        effective_level = recipient.level_name(effective_classification)
        effective_categories = translation.target_categories
        notes.append("translated by local mapping asserted by role "
                     f"{translation.assertor}")
        if equivalent_labels:
            notes.append("EquivalentLabels were cross-checked for consistency "
                         "only; they did not select a label")

    missing_categories = _missing_categories(
        effective_categories, clearance.categories)
    effective = (effective_policy, effective_classification, effective_level,
                 effective_categories)
    if missing_categories:
        return _result(
            decision=Decision.DENY, reason="clearance-missing-category",
            detail="recipient clearance lacks the effective category values: "
                   + _render_categories(policies, effective_policy, missing_categories),
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities,
            equivalents=observations, notes=notes, effective=effective,
            policies=policies)

    effective_rank = recipient.rank(effective_classification)
    clearance_rank = recipient.rank(clearance.classification)
    if effective_rank is None or clearance_rank is None:
        return _result(
            decision=Decision.REVIEW, reason="classification-not-comparable",
            detail="classification is not in the recipient hierarchy",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities,
            equivalents=observations, notes=notes, effective=effective,
            policies=policies)

    if clearance_rank < effective_rank:
        return _result(
            decision=Decision.DENY, reason="clearance-below-label",
            detail=f"effective rank {effective_rank} ({effective_level}) "
                   f"exceeds clearance rank {clearance_rank} "
                   f"({recipient.level_name(clearance.classification)})",
            source=source, recipient_policy=recipient_policy,
            clearance=clearance, authorities=authorities,
            equivalents=observations, notes=notes, effective=effective,
            policies=policies)

    return _result(
        decision=Decision.ALLOW, reason="eligible",
        detail="clearance covers the effective classification and every "
               "effective category",
        source=source, recipient_policy=recipient_policy,
        clearance=clearance, authorities=authorities,
        equivalents=observations, notes=notes, effective=effective,
        policies=policies)


def _cross_check_equivalents(equivalent_labels, source, source_classification,
                             source_categories, recipient_policy, attestations,
                             trusted_assertors, translations, policies):
    observations = []
    notes = []
    contradiction = None
    seen_policies = set()

    for label in equivalent_labels:
        observation = _observe(label, attestations, source.policy_oid,
                               trusted_assertors, translations, policies)

        if not observation.signature_verified:
            observation = _replace_status(
                observation, "ignored",
                "attribute signature not verified")
            observations.append(observation)
            notes.append(f"policy {label.policy_oid}: unverified claim ignored")
            continue

        if not observation.translator_trusted:
            observation = _replace_status(
                observation, "ignored",
                "signer is not a locally trusted translator")
            observations.append(observation)
            notes.append(
                f"policy {label.policy_oid}: translator "
                f"{attestations.translator.authority or '<none>'} is not trusted")
            continue

        if label.policy_oid in seen_policies:
            contradiction = (
                f"security-policy OID {label.policy_oid} occurs more than once "
                "across EquivalentLabels; RFC 2634 requires every policy OID "
                "to be unique")
            observations.append(
                _replace_status(observation, "contradicts", contradiction))
            continue
        seen_policies.add(label.policy_oid)

        policy = policies.get(label.policy_oid)
        if policy is None:
            observation = _replace_status(
                observation, "unverifiable",
                "policy is not configured locally")
            observations.append(observation)
            notes.append(
                f"policy {label.policy_oid}: claim cannot be interpreted "
                "locally and is not needed for this decision")
            continue

        eq_classification, eq_categories, eq_problems = _normalize(label, policy)
        if eq_problems:
            contradiction = (
                f"EquivalentLabels under {label.policy_oid} is not fully "
                "interpretable: " + "; ".join(eq_problems))
            observations.append(
                _replace_status(observation, "contradicts", contradiction))
            continue

        if label.policy_oid == source.policy_oid:
            contradiction = (
                "EquivalentLabels repeats the source policy OID "
                f"{label.policy_oid}; RFC 2634 requires it to be distinct")
            observations.append(
                _replace_status(observation, "contradicts", contradiction))
            continue

        if label.policy_oid == recipient_policy:
            local = [
                trans for trans in translations
                if trans.source_policy == source.policy_oid
                and trans.target_policy == recipient_policy
                and trans.source_classification == source_classification
                and trans.source_categories == source_categories
            ]
            if not local:
                observation = _replace_status(
                    observation, "unverifiable",
                    "no local mapping exists to confirm the claim")
                observations.append(observation)
                notes.append(
                    f"policy {label.policy_oid}: authenticated claim has no "
                    "local translation to check it against")
            elif (len(local) == 1
                  and local[0].target_classification == eq_classification
                  and local[0].target_categories == eq_categories):
                observation = _replace_status(observation, "agrees")
                observations.append(observation)
            else:
                contradiction = (
                    "authenticated EquivalentLabels under "
                    f"{label.policy_oid} disagrees with the local mapping: "
                    f"claimed classification={eq_classification} "
                    "categories="
                    + _render_categories(policies, label.policy_oid,
                                         eq_categories))
                observations.append(
                    _replace_status(observation, "contradicts", contradiction))
            continue

        observation = _replace_status(
            observation, "unverifiable",
            "third policy has no configured relation to the recipient")
        observations.append(observation)
        notes.append(
            f"policy {label.policy_oid}: no local relation to "
            f"{recipient_policy}; claim is not used")

    return observations, contradiction, notes


def _observe(label: ParsedLabel, attestations: Attestations,
             source_policy: str, trusted_assertors,
             translations, policies) -> EquivalentObservation:
    policy = policies.get(label.policy_oid)
    level = None
    if policy is not None and label.classification is not None:
        level = policy.level_name(label.classification)
    return EquivalentObservation(
        policy_oid=label.policy_oid,
        classification=label.classification,
        level_name=level,
        categories=_label_categories(label),
        signature_verified=attestations.translator.verified,
        translator_trusted=_trusted_for_direction(
            attestations, source_policy, label.policy_oid, trusted_assertors,
            translations),
        status="unverified",
    )


def _trusted_for_direction(attestations, source_policy, target_policy,
                            trusted_assertors, translations) -> bool:
    """A role may translate only the direction configured for that role."""

    authority = attestations.translator.authority
    if not attestations.translator.verified or authority not in trusted_assertors:
        return False
    return any(
        trans.source_policy == source_policy
        and trans.target_policy == target_policy
        and trans.assertor == authority
        for trans in translations)



def _replace_status(observation, status, detail=""):
    return EquivalentObservation(
        policy_oid=observation.policy_oid,
        classification=observation.classification,
        level_name=observation.level_name,
        categories=observation.categories,
        signature_verified=observation.signature_verified,
        translator_trusted=observation.translator_trusted,
        status=status,
        detail=detail,
    )


def _check_clearance(clearance: Clearance, policy: Policy):
    problems = []
    if clearance.classification is None:
        problems.append(f"{policy.oid}: clearance has no classification")
    elif policy.rank(clearance.classification) is None:
        problems.append(
            f"{policy.oid}: clearance classification "
            f"{clearance.classification} is undefined")
    seen = set()
    for cat_oid, value in clearance.categories:
        if cat_oid in seen:
            problems.append(f"{policy.oid}: duplicate clearance category {cat_oid}")
        seen.add(cat_oid)
        spec = policy.categories.get(cat_oid)
        if spec is None:
            problems.append(
                f"{policy.oid}: clearance category {cat_oid} is unknown")
        elif spec.values is not None and value not in spec.values:
            problems.append(
                f"{policy.oid}: clearance value {value!r} for {cat_oid} is "
                "not in the closed value set")
    return problems


def _missing_categories(required, available):
    available_map = {}
    for oid, value in available:
        available_map.setdefault(oid, set()).add(value)
    return tuple(sorted(
        (oid, value) for oid, value in required
        if value not in available_map.get(oid, set())))


def _mapping_gap_note(source_policy, classification, categories,
                      recipient_policy, translations, policies=POLICIES):
    available = sorted(
        f"{t.source_classification}+"
        f"{_render_categories(policies, source_policy.oid, t.source_categories)}"
        for t in translations
        if t.source_policy == source_policy.oid
        and t.target_policy == recipient_policy)
    return (f"configured {source_policy.oid}->{recipient_policy} entries: "
            f"{available or 'none'}; looked for classification={classification} "
            "categories="
            + (_render_categories(policies, source_policy.oid, categories)
               or "(none)"))


def _evidence_text(evidence: Evidence, applicable: bool = True) -> str:
    if not applicable:
        return "<not applicable: no EquivalentLabels attribute present>"
    state = "verified" if evidence.verified else "NOT verified"
    authority = evidence.authority or "<none>"
    return f"{authority} ({state})" + (
        f" [{evidence.note}]" if evidence.note else "")


def _result(*, decision, reason, detail, source: Optional[ParsedLabel],
            recipient_policy, clearance, authorities, equivalents=(),
            notes=(), extra_notes=(), effective=None, policies=POLICIES):
    if source is None:
        source_policy = "<unparsed>"
        source_classification = None
        source_level = None
        source_categories = ()
        source_privacy_mark = None
    else:
        source_policy = source.policy_oid
        source_classification = source.classification
        source_level = None
        if source.policy_oid in policies:
            source_level = policies[source.policy_oid].level_name(
                source.classification)
        source_categories = _label_categories(source)
        source_privacy_mark = source.privacy_mark

    if effective is None:
        effective_policy = None
        effective_classification = None
        effective_level = None
        effective_categories = ()
    else:
        (effective_policy, effective_classification, effective_level,
         effective_categories) = effective

    return AccessResult(
        decision=decision,
        reason=reason,
        detail=detail,
        source_policy=source_policy,
        source_classification=source_classification,
        source_level=source_level,
        source_categories=source_categories,
        source_privacy_mark=source_privacy_mark,
        effective_policy=effective_policy,
        effective_classification=effective_classification,
        effective_level=effective_level,
        effective_categories=effective_categories,
        clearance=clearance,
        equivalents=tuple(equivalents),
        authorities=tuple(authorities),
        notes=tuple(notes) + tuple(extra_notes),
        policy_table=policies,
    )


def combine_layer_results(*results: AccessResult) -> Decision:
    """AND the verdicts of the CMS layers; labels are never merged.

    RFC 2634 allows a label in the inner signature, the outer signature, or
    both.  The outer label protects the encrypted body and is available to a
    gateway before decryption; the inner label protects the plaintext and is
    only available to the recipient after decryption.  Each layer is checked
    separately against the same recipient policy and clearance.  Access is
    granted only if every available layer is ALLOW: a stricter inner label can
    never be relaxed by a looser outer label, and vice versa.
    """

    decisions = [result.decision for result in results]
    if not decisions:
        raise ValueError("at least one layer result is required")
    if Decision.DENY in decisions:
        return Decision.DENY
    if Decision.REVIEW in decisions:
        return Decision.REVIEW
    return Decision.ALLOW


def naive_numeric_allows(source_classification: int,
                         clearance_classification: int) -> bool:
    """The flawed comparator, used only in the demo/tests to show escalation.

    It ignores the policy OID, the hierarchy order and the category set.  Never
    use it for a real decision.
    """

    return source_classification <= clearance_classification
