#!/usr/bin/env python
# coding: utf-8
#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Offline RFC 3820 proxy-chain admission demo.

Builds synthetic EEC -> proxy -> proxy chains (no private keys, no network),
runs the admission engine and prints one line per scenario.  This is an
inspection prototype: signature verification is out of scope and is stated as
such in the output.

Run with the project virtualenv:

    .venv/bin/python tools/proxychain-admission.py
    .venv/bin/python tools/proxychain-admission.py --emit docs/fixtures
"""

import argparse
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import proxychain
from pyasn1_modules import rfc3820
from pyasn1_modules.proxychain import Decision
from pyasn1_modules.proxychain import PolicyError
from pyasn1_modules.proxychain import PolicyInterpreter
from pyasn1_modules.proxychain import Rights
from tests.proxy_fixtures import CN, LOCAL_POLICY, NOW, O, READ, US, WRITE
from tests.proxy_fixtures import make_eec, make_proxy, name


class TokenInterpreter(PolicyInterpreter):
    """Example application interpreter for LOCAL_POLICY.

    Policy syntax: comma-separated ``read`` / ``write`` tokens.  Only rights
    already delegated by the issuer may be granted.
    """

    language = LOCAL_POLICY

    def interpret(self, policy_octets, delegated_rights):
        if policy_octets is None:
            raise PolicyError('explicit policy expression required')
        granted = set()
        for token in policy_octets.decode('ascii').split(','):
            token = token.strip()
            if token == 'read':
                granted.add(READ)
            elif token == 'write':
                granted.add(WRITE)
            else:
                raise PolicyError('unknown token %r' % token)
        return Rights(granted)


def legal_chain():
    eec = make_eec()
    first = make_proxy(eec, 'alice-proxy-1', rfc3820.id_ppl_inheritAll,
                       path_len=1, serial=2)
    second = make_proxy(first, 'alice-proxy-2', rfc3820.id_ppl_inheritAll,
                        path_len=0, serial=3)
    return eec, [first, second]


def scenarios():
    interpreter = TokenInterpreter()

    eec, chain = legal_chain()
    yield ('legal two-level inheritAll', eec, chain, {})

    eec, chain = legal_chain()
    broken = make_proxy(eec, 'alice-proxy-1', rfc3820.id_ppl_inheritAll,
                        path_len=0, serial=2)
    yield ('path length 0 still signs a proxy', eec, [broken, chain[1]], {})

    eec, chain = legal_chain()
    wrong_subject = make_proxy(eec, 'alice-proxy-1',
                               rfc3820.id_ppl_inheritAll,
                               path_len=1, serial=2)
    wrong_subject['tbsCertificate']['subject'] = name(
        (US, 'US'), (O, 'Example Corp'), (CN, 'Alice'),
        (O, 'Attacker Corp')
    )
    yield ('subject adds an O instead of one CN', eec,
           [wrong_subject, chain[1]], {})

    eec, chain = legal_chain()
    non_critical = make_proxy(eec, 'alice-proxy-1',
                              rfc3820.id_ppl_inheritAll,
                              path_len=1, critical=False, serial=2)
    yield ('ProxyCertInfo not critical', eec, [non_critical, chain[1]], {})

    eec = make_eec()
    unknown = make_proxy(eec, 'alice-proxy-1', LOCAL_POLICY,
                         policy=b'read', path_len=0, serial=2)
    yield ('restricted language, no interpreter', eec, [unknown], {})

    eec, chain = legal_chain()
    restricted = make_proxy(eec, 'alice-proxy-1', LOCAL_POLICY,
                            policy=b'read', path_len=1, serial=2)
    restricted_leaf = make_proxy(restricted, 'alice-proxy-2', LOCAL_POLICY,
                                 policy=b'write', path_len=0, serial=3)
    yield ('interpreter tries to widen read-only delegation', eec,
           [restricted, restricted_leaf],
           {'policy_interpreters': [interpreter]})

    eec = make_eec()
    independent = make_proxy(eec, 'alice-proxy-1',
                             rfc3820.id_ppl_independent, path_len=1,
                             serial=2)
    inherited = make_proxy(independent, 'alice-proxy-2',
                           rfc3820.id_ppl_inheritAll, path_len=0, serial=3)
    yield ('inheritAll below independent stays empty', eec,
           [independent, inherited], {})


def solve(scenarios, now=NOW):
    """Yield ``(label, eec, chain, kwargs, result)`` for each scenario."""
    for label, eec, chain, kwargs in scenarios:
        yield label, eec, chain, kwargs, proxychain.check_chain(
            eec, chain, now=now, **kwargs
        )


def _pem(cert):
    body = base64.b64encode(der_encoder(cert)).decode('ascii')
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % (
        '\n'.join(lines)
    )


def emit(directory):
    """Write the synthetic certificates as PEM bundles for external review."""
    os.makedirs(directory, exist_ok=True)
    for label, eec, chain, kwargs, result in solve(scenarios()):
        slug = (label.replace(' ', '-').replace(',', '')
                .replace(':', '').lower())
        path = os.path.join(directory, slug + '.pem')
        with open(path, 'w') as stream:
            stream.write(_pem(eec))
            for cert in chain:
                stream.write(_pem(cert))
        print('wrote %s (%s)' % (path, result.code))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit', metavar='DIR',
                        help='write synthetic PEM chains for external review')
    args = parser.parse_args(argv)

    if args.emit:
        return emit(args.emit)

    print('RFC 3820 proxy-chain admission prototype')
    print('signatures: NOT verified (input chain assumed externally checked)')
    print('now=%s' % NOW.isoformat())
    print('')
    failures = 0
    for label, eec, chain, kwargs, result in solve(scenarios()):
        rights = 'n/a'
        if result.rights is not None:
            rights = ('unrestricted' if result.rights.unrestricted
                      else sorted(result.rights.items))
        print('%-48s %-14s %-38s rights=%s'
              % (label, result.code, result.reason or '-', rights))
        if result.detail:
            print('    detail: %s' % result.detail)
        if result.code != Decision.ACCEPT:
            failures += 1
    print('')
    print('%d scenario(s) denied or indeterminate as designed.' % failures)
    return 0


if __name__ == '__main__':
    sys.exit(main())
