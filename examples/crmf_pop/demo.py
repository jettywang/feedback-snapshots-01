#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Runnable CRMF POP validation example.

Usage::

    python -m examples.crmf_pop.demo

The demo decorates the verifier with test callbacks, then feeds it the
legitimate requests and the one-field attack copies.  It prints the signed
octets length for each case and whether the request was accepted.

The callbacks below are the only test-specific part.  A real integration
replaces ``verify_signature`` with a public-key signature check and
``verify_public_key_mac`` with the same RFC 4211 password-based MAC the
server already computes from its own shared secret.  Everything else --
recomputing the signed octets, comparing the two public-key copies, and
requiring a trusted-RA context -- is what a registration service has to do
regardless of the crypto library.
"""

import sys

from pyasn1_modules import rfc4211

from examples.crmf_pop import der
from examples.crmf_pop import fixtures
from examples.crmf_pop import verifier

PRINCIPALS = (fixtures.LEGITIMATE, fixtures.ATTACKER)


def test_signature_check(public_key_der, signed_bytes, signature,
                         algorithm_der):
    """Fixed test signature check, keyed by the public key in the request.

    It really compares the key and the bytes: the public key selects which
    test secret to use, and the signature must equal HMAC(secret,
    signed_bytes).  Returning ``True`` unconditionally would let every
    attack through, which the regression tests assert against.
    """
    for principal in PRINCIPALS:
        if public_key_der == der.subject_public_key_info(
                der.public_key(principal)):
            return signature == der.sign(principal, signed_bytes)
    return False


def test_public_key_mac_check(pbm, public_key_der, mac_value):
    """Check the MAC with the one shared secret the server holds for alice."""
    expected = der.pbm_mac(
        der.password(fixtures.LEGITIMATE), bytes(pbm['salt']),
        int(pbm['iterationCount']), public_key_der)
    return mac_value == expected


def make_policy(allow_ra_verified=False):
    return verifier.VerificationPolicy(allow_ra_verified=allow_ra_verified)


def run():
    issuer = verifier.IssuerContext(**fixtures.issuer_context())

    print('Bounded CRMF POP validation demo (RFC 4211 section 4.1)\n')
    print('Legitimate requests')
    print('-------------------')
    for name, example in fixtures.legitimate_cases().items():
        policy = make_policy(allow_ra_verified=(name == 'ra_verified'))
        ra_context = verifier.TrustedRA(
            'demo-ra', example.cert_request_der) \
            if name == 'ra_verified' else None
        try:
            result = verifier.verify_cert_request(
                example.message, test_signature_check,
                policy=policy, issuer=issuer, ra_context=ra_context,
                verify_public_key_mac=test_public_key_mac_check)
        except verifier.PopError as exc:
            print('  %-28s REJECTED: %s' % (name, exc))
            continue
        print('  %-28s accepted  signed=%s bytes  '
              'subject_bound=%s  subject_authenticated=%s  auth=%s'
              % (name,
                 '-' if result.signed_bytes is None
                 else len(result.signed_bytes),
                 result.subject_bound, result.subject_authenticated,
                 result.auth_method or 'none'))

    print('\nAttack copies '
          '(each differs from a legitimate request in one place)')
    print('------------------------------------------------------------------')
    # The RA context approved the *legitimate* raVerified request.  The
    # replay attack reuses it, so binding has to catch the difference.
    legitimate_ra = fixtures.build_ra_verified()
    ra_context = verifier.TrustedRA(
        'demo-ra', legitimate_ra.cert_request_der)
    all_rejected = True
    for name, example in fixtures.attack_cases().items():
        policy = make_policy(allow_ra_verified=True)
        try:
            verifier.verify_cert_request(
                example.message, test_signature_check,
                policy=policy, issuer=issuer, ra_context=ra_context,
                verify_public_key_mac=test_public_key_mac_check)
        except verifier.PopError as exc:
            print('  %-40s rejected: %s' % (name, exc))
        else:
            all_rejected = False
            print('  %-40s ACCEPTED -- regression' % name)

    if not all_rejected:
        print('\nFAILED: at least one attack copy was accepted')
        return 1

    print('\nAll attack copies were rejected.')
    return 0


def main(argv=None):
    del argv
    return run()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
