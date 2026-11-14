#!/usr/bin/env python
#
# Minimal end-to-end demonstration of the RFC 5914 trust anchor import adapter
# and its path-validation consumer.  It builds two trust anchors that share a
# public key but carry different name constraints, imports them, and shows that
# the same leaf certificate gets a different verdict under each anchor.
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import rfc5914_import
from pyasn1_modules import rfc5914_pathcheck

from tests import test_rfc5914_import as fixtures


def main():
    # Same public key, two distinct name-constraint policies.
    strict = fixtures._cert_path(
        fixtures._name('strict-anchor'),
        name_constr=fixtures._dns_constraints(permitted=('example.com',)))
    loose = fixtures._cert_path(
        fixtures._name('loose-anchor'),
        name_constr=fixtures._dns_constraints(permitted=('other.example.net',)))

    trust_list = fixtures._list(
        fixtures._ta_info(fixtures.TEST_KEY_DER_A, fixtures.KEY_ID_A,
                          cert_path=strict),
        fixtures._ta_info(fixtures.TEST_KEY_DER_A, fixtures.KEY_ID_A,
                          cert_path=loose),
    )

    # Trust in the source must be stated explicitly by the caller.
    anchors = rfc5914_import.import_trust_anchor_list(
        trust_list, source_trusted=True)

    same_key = anchors[0].has_same_key(anchors[1])
    distinct = anchors[0].fingerprint != anchors[1].fingerprint
    print('anchors share a public key : %s' % same_key)
    print('anchors kept distinct      : %s' % distinct)

    leaf = fixtures._leaf_san(('host.example.com',))
    labels = ('strict (example.com)', 'loose (other.example.net)')
    for label, anchor in zip(labels, anchors):
        decision = rfc5914_pathcheck.evaluate_leaf(anchor, leaf, None)
        verdict = 'ACCEPT' if decision.accepted else 'REJECT'
        print('%-24s -> %s (%s)' % (label, verdict, decision.reason))

    # Export then re-import: the authorisation scope must not widen.
    exported = rfc5914_import.export_trust_anchor_list_der(anchors)
    within = rfc5914_import.authorisation_is_within(
        exported, der_encoder(trust_list))
    print('export stays within scope  : %s' % within)


if __name__ == '__main__':
    main()
