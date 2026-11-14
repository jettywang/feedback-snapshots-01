# This file is being contributed to pyasn1-modules software.
#
# Trust Anchor Format (RFC 5914) -- minimal path-validation consumer
#
# Copyright (c) 2024, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
# This is deliberately tiny: it shows how a path validator consumes the
# immutable TrustAnchorConstraints produced by rfc5914_import.  It evaluates
# two concrete controls -- dNSName name constraints and the required policy
# set -- so that the same leaf certificate yields different verdicts under two
# anchors that share a public key but carry different constraints.

from dataclasses import dataclass

from pyasn1.codec.der.decoder import decode as der_decoder

from pyasn1_modules import rfc5280
from pyasn1_modules.rfc5914_import import TrustAnchorConstraints


@dataclass(frozen=True)
class ValidationDecision:
    accepted: bool
    reason: str


def _dns_in_subtree(dns_name, subtree_dns):
    """RFC 5280 section 4.2.1.10 dNSName matching.

    A constraint starting with "." matches only sub-domains.  A constraint
    without a leading dot matches the exact name and any of its sub-domains.
    """
    name = dns_name.lower()
    base = subtree_dns.lower()
    if base.startswith('.'):
        return name == base[1:] or name.endswith(base)
    return name == base or name.endswith('.' + base)


def _constraint_dns_names(name_constraints_der, field_name):
    if name_constraints_der is None:
        return ()
    nc, rest = der_decoder(name_constraints_der, rfc5280.NameConstraints())
    if rest or not nc[field_name].hasValue():
        return ()
    names = []
    for subtree in nc[field_name]:
        base = subtree['base']
        if base.getName() == 'dNSName':
            names.append(str(base.getComponent()))
    return tuple(names)


def _leaf_dns_names(leaf_san_der):
    if leaf_san_der is None:
        return ()
    sans, rest = der_decoder(leaf_san_der, rfc5280.SubjectAltName())
    if rest:
        return ()
    return tuple(str(name.getComponent()) for name in sans
                 if name.getName() == 'dNSName')


def _leaf_policy_ids(leaf_policies_der):
    if leaf_policies_der is None:
        return frozenset()
    policies, rest = der_decoder(leaf_policies_der,
                                 rfc5280.CertificatePolicies())
    if rest:
        return frozenset()
    return frozenset(str(p['policyIdentifier']) for p in policies)


def _required_policy_ids(certificate_policies_der):
    if certificate_policies_der is None:
        return frozenset()
    policies, rest = der_decoder(certificate_policies_der,
                                 rfc5280.CertificatePolicies())
    if rest:
        return frozenset()
    return frozenset(str(p['policyIdentifier']) for p in policies)


def evaluate_leaf(anchor, leaf_san_der, leaf_policies_der):
    """Evaluate one leaf against one anchor's immutable constraints.

    Returns a ValidationDecision; the anchor's controls are never mutated.
    """
    if not isinstance(anchor, TrustAnchorConstraints):
        raise TypeError('anchor must be a TrustAnchorConstraints object')

    leaf_names = _leaf_dns_names(leaf_san_der)

    permitted = _constraint_dns_names(
        anchor.name_constraints_der, 'permittedSubtrees'
    )
    if permitted:
        if not any(_dns_in_subtree(name, base)
                   for name in leaf_names for base in permitted):
            return ValidationDecision(
                False, 'leaf dNSName %r is outside permittedSubtrees'
                % (leaf_names,))

    excluded = _constraint_dns_names(
        anchor.name_constraints_der, 'excludedSubtrees'
    )
    for name in leaf_names:
        for base in excluded:
            if _dns_in_subtree(name, base):
                return ValidationDecision(
                    False, 'leaf dNSName %r matches excludedSubtrees %r'
                    % (name, base))

    required = _required_policy_ids(anchor.certificate_policies_der)
    if required:
        present = _leaf_policy_ids(leaf_policies_der)
        missing = required - present
        if missing:
            return ValidationDecision(
                False, 'leaf is missing required policy %s'
                % (sorted(missing),))

    return ValidationDecision(True, 'all anchor controls satisfied')
