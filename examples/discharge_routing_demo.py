"""Offline demonstration of safe third-party discharge routing.

Run with:  python examples/discharge_routing_demo.py

There is no network access.  ``InMemoryTransport`` is a small stand-in that
records the exact JSON body that would have been sent to each configured
endpoint and returns a locally issued discharge macaroon.
"""
from __future__ import unicode_literals

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymacaroons import Macaroon, Verifier  # noqa: E402
from pymacaroons.discharge_routing import (  # noqa: E402
    DischargeClient,
    DischargeRegistry,
    DischargeService,
    Endpoint,
    build_report,
)
from pymacaroons.exceptions import (  # noqa: E402
    AmbiguousDischargeCaveat,
    DischargeRedirectRefused,
    MacaroonInvalidSignatureException,
)


class Response(object):
    def __init__(self, status=200, body='', headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}


class InMemoryTransport(object):
    def __init__(self):
        self.handlers = {}
        self.requests = []

    def on(self, url, handler):
        self.handlers[url] = handler

    def send(self, request):
        self.requests.append(request)
        return self.handlers[request.url](request)


def discharge_handler(caveat_key):
    def handler(request):
        payload = json.loads(request.body.decode('utf-8'))
        macaroon = Macaroon(
            location=request.url,
            identifier=payload['caveat_id'],
            key=caveat_key,
        )
        macaroon.add_first_party_caveat('service = checked')
        return Response(200, json.dumps({'discharge': macaroon.serialize()}))
    return handler


def show(title, report):
    print('\n=== {} ==='.format(title))
    print('destination : {} {}'.format(
        report['destination']['request_method'],
        report['destination']['request_url'],
    ))
    print('payload     : {}'.format(report['destination']['request_body']))
    print('location    : {!r} (trusted={}, status={})'.format(
        report['destination']['location_hint'],
        report['destination']['location_hint_is_trusted'],
        report['destination']['location_hint_status'],
    ))
    print('authenticated by: {}'.format(
        report['authentication']['discharge_authenticated_by']
    ))
    print('https proves    : {}'.format(
        report['authentication']['https_proves']
    ))
    print('target verified : {}'.format(
        report['authentication']['target_verification']
    ))
    print('root bound to   : identifier={!r} signature={}'.format(
        report['root_binding']['root_identifier'],
        report['root_binding']['root_signature'],
    ))
    print('binding checked : {}'.format(
        report['root_binding']['structural_binding_verified']
    ))


def main():
    root_key = 'root-key-only-the-target-knows'
    transport = InMemoryTransport()
    transport.on(
        'https://org-a.example/discharge',
        discharge_handler('key-a'),
    )
    transport.on(
        'https://org-b.example/discharge',
        discharge_handler('key-b'),
    )
    client = DischargeClient(
        DischargeRegistry([
            DischargeService(
                'org-a', Endpoint('https://org-a.example/discharge'),
                location_hints=['org-a'], caveat_ids=['shared-id', 'photo-id'],
            ),
            DischargeService(
                'org-b', Endpoint('https://org-b.example/discharge'),
                location_hints=['org-b'], caveat_ids=['shared-id'],
            ),
        ]),
        transport,
    )

    root = Macaroon(
        location='https://target.example/resource',
        identifier='root-request-7',
        key=root_key,
    )
    root.add_third_party_caveat('org-a', 'key-a', 'shared-id')
    root.add_third_party_caveat('org-b', 'key-b', 'shared-id')

    print('root signature:', root.signature)

    # 1. Location changed only.  Signature, identifier, and routing stay put.
    #    This caveat id is claimed by exactly one locally configured service.
    unique = Macaroon(
        location='https://target.example/resource',
        identifier='root-request-8',
        key=root_key,
    )
    unique.add_third_party_caveat('org-a', 'key-a', 'photo-id')
    tampered = unique.copy()
    tampered.caveats[0].location = 'https://attacker.example/discharge'
    assert tampered.signature == unique.signature
    result = client.fetch(tampered.caveats[0])
    show('location changed only', build_report(result))

    # 2. Same short caveat id at two organizations, both issued locally.
    first = client.fetch(root.caveats[0])
    second = client.fetch(root.caveats[1])
    verifier = Verifier(discharge_macaroons=[
        root.prepare_for_request(second.discharge),
        root.prepare_for_request(first.discharge),
    ])
    verifier.satisfy_exact('service = checked')
    show(
        'two organizations, one short id',
        build_report(
            first,
            result.bind(root),
            target_verified=verifier.verify(root, root_key),
        ),
    )

    # 3. A forged location reaches another organization, but its discharge
    #    is not authenticated by the root's caveat key.
    forged = root.copy()
    forged.caveats[0].location = 'org-b'
    wrong = client.fetch(forged.caveats[0])
    print('\n=== forged location to org-b ===')
    print('request went to :', wrong.request.url)
    print('payload         :', wrong.request.body.decode('utf-8'))
    try:
        Verifier(
            discharge_macaroons=[root.prepare_for_request(wrong.discharge)]
        ).verify(root, root_key)
    except MacaroonInvalidSignatureException:
        print('target verdict  : invalid signature (org-b cannot '
              'authenticate the root caveat)')

    # 4. Explicit refusals.
    print('\n=== explicit refusals ===')
    ambiguous = root.copy()
    ambiguous.caveats[0].location = 'unknown-org'
    try:
        client.fetch(ambiguous.caveats[0])
    except AmbiguousDischargeCaveat as error:
        print('ambiguous id    :', error)

    redirect_transport = InMemoryTransport()
    redirect_transport.on(
        'https://org-a.example/discharge',
        lambda request: Response(
            302, '', {'Location': 'https://attacker.example/discharge'}
        ),
    )
    redirect_client = DischargeClient(client.registry, redirect_transport)
    try:
        redirect_client.fetch(root.caveats[0])
    except DischargeRedirectRefused as error:
        print('redirect        :', error)

    print('\nrecorded requests:')
    for request in transport.requests:
        print(' ', request.url, request.body.decode('utf-8'))


if __name__ == '__main__':
    main()
