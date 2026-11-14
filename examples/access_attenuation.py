"""Demonstrate progressive attenuation with structured access caveats.

Run with: .venv/bin/python examples/access_attenuation.py
"""
from __future__ import print_function, unicode_literals

import datetime

from pymacaroons import Macaroon, Verifier
from pymacaroons.exceptions import (
    MacaroonAccessException,
    MacaroonVerificationFailedException,
)


KEY = b'issuer secret used only for this demo'
UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)
EARLY = datetime.datetime(2026, 11, 14, 12, 30, 0, tzinfo=UTC)
LATE = datetime.datetime(2026, 11, 14, 13, 0, 0, tzinfo=UTC)


def issue():
    return Macaroon(
        location='https://api.example.test/',
        identifier='demo-key',
        key=KEY,
    )


def attempt(token, method, path, now=NOW):
    try:
        verifier = Verifier()
        verifier.satisfy_access(method=method, path=path, now=now)
        verifier.verify(token, KEY)
        return 'ALLOW'
    except (MacaroonAccessException, MacaroonVerificationFailedException):
        return 'DENY '


def show(label, token):
    checks = [
        ('GET', '/v1/documents', NOW),
        ('GET', '/v1/documents/42', NOW),
        ('DELETE', '/v1/documents/42', NOW),
        ('GET', '/v1/secrets', NOW),
        ('GET', '/v1/documents%2F..%2Fsecrets', NOW),
        ('GET', '/v1/documents/hello%20world', NOW),
        ('GET', '/v1/documents/42', EARLY),
        ('GET', '/v1/documents/42', datetime.datetime(
            2026, 11, 14, 12, 30, 0, 1, tzinfo=UTC)),
    ]
    print('\n== {0} =='.format(label))
    print(token.inspect())
    for method, path, now in checks:
        label_time = now.strftime('%H:%M:%S.%f')
        print('  {0:6} {1:34} {2:15} {3}'.format(
            method, path, label_time, attempt(token, method, path, now)))


def main():
    root = issue()
    root.add_access_caveat(
        resource='/v1/documents', method='GET', expires=LATE
    )
    show('root: GET under /v1/documents until 13:00Z', root)

    delegated = root.copy()
    delegated.add_access_caveat(resource='/v1/documents/42')
    delegated.add_access_caveat(expires=EARLY)
    show('delegated: /v1/documents/42 only, until 12:30Z', delegated)

    conflicting = root.copy()
    conflicting.add_access_caveat(method='POST')
    show('conflicting: GET + POST intersection is empty', conflicting)

    encoded = issue()
    encoded.add_access_caveat(resource='/v1/documents/hello world')
    show('encoded: canonical path contains a literal space', encoded)

    permissive = root.copy()
    verifier = Verifier()
    verifier.satisfy_general(lambda predicate: True)
    verifier.satisfy_access(method='GET', path='/v1/secrets', now=NOW)
    try:
        verifier.verify(permissive, KEY)
        print('\npermissive callback: ALLOW (BUG)')
    except MacaroonVerificationFailedException:
        print('\npermissive callback: DENY (structured caveat still enforced)')

    print('\nDeadline boundary for the delegated token:')
    print('  at 12:30:00.000000Z :', attempt(
        delegated, 'GET', '/v1/documents/42', EARLY))
    print('  at 12:30:00.000001Z :', attempt(
        delegated, 'GET', '/v1/documents/42',
        EARLY + datetime.timedelta(microseconds=1)))


if __name__ == '__main__':
    main()
