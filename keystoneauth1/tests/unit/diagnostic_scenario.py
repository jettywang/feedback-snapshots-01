# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Reproduce the diagnostic hand-off against local substitutes.

Run this module to regenerate the project-lead record::

    .venv/bin/python -m keystoneauth1.tests.unit.diagnostic_scenario \
        --output diagnostic-record

It writes two files:

``diagnostic-record/public.json``
    The shareable export.  It reconstructs the stage order (catalog,
    request, response, re-authentication, request, response, error) and
    keeps the correlation identifier, but none of the three fictional
    private markers and no unapproved address or service name.

``diagnostic-record/internal.json``
    The controlled debugging record.  Same identifier, but it still
    contains the actual causes so an on-call engineer can match a public
    digest back to the real value.

The substitutes are entirely local:

* a fake catalog token whose compute entry is named with a private marker;
* a business endpoint that answers 401 once (the re-authentication) and
  then 500 with a synthetic error body.

The three fictional private markers live, respectively, in the catalog
entry's service name, the re-authentication response body, and the final
error body.
"""

import argparse
import json
import os
import sys
import uuid

import requests

from keystoneauth1 import diagnostics
from keystoneauth1 import exceptions
from keystoneauth1 import fixture
from keystoneauth1 import identity
from keystoneauth1 import session


CATALOG_MARKER = 'fictional-catalog-name-Zx81'
REAUTH_MARKER = 'fictional-reauth-token-Qw77'
ERROR_MARKER = 'fictional-error-detail-Rt42'

ENDPOINT = 'https://compute.substitute.invalid'
PUBLIC_MARKERS = (CATALOG_MARKER, REAUTH_MARKER, ERROR_MARKER)


class _SubstituteAdapter(requests.adapters.BaseAdapter):
    """A tiny transport that serves the two fake endpoints in memory."""

    def __init__(self, auth_payload, business_responses):
        super().__init__()
        self.auth_payload = auth_payload
        self.business_responses = list(business_responses)
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append(request.url)
        response = requests.Response()
        response.request = request
        response.url = request.url
        if '/auth/tokens' in request.url:
            response.status_code = 201
            response.headers['X-Subject-Token'] = uuid.uuid4().hex
            response._content = json.dumps(self.auth_payload).encode()
            response.headers['Content-Type'] = 'application/json'
            return response

        status, body = self.business_responses.pop(0)
        response.status_code = status
        response.headers['Content-Type'] = 'application/json'
        response._content = json.dumps(body).encode()
        return response

    def close(self):
        pass


def build_session(policy):
    token = fixture.V3Token()
    token.set_project_scope()
    service = token.add_service('compute', name=CATALOG_MARKER)
    service.add_standard_endpoints(public=ENDPOINT)

    payload = dict(token)
    auth = identity.V3Password(
        auth_url='https://identity.substitute.invalid/v3',
        user_id=uuid.uuid4().hex,
        password=REAUTH_MARKER,
        project_id=uuid.uuid4().hex,
    )
    business = [
        (
            401,
            {
                'error': {
                    'message': 're-authentication required',
                    'details': REAUTH_MARKER,
                }
            },
        ),
        (
            500,
            {
                'error': {
                    'message': 'synthetic backend failure',
                    'details': ERROR_MARKER,
                }
            },
        ),
    ]
    adapter = _SubstituteAdapter(payload, business)
    sess = session.Session(auth=auth, diagnostic_policy=policy)
    sess.mount('https://', adapter)
    return sess, adapter


def run(output_dir):
    policy = diagnostics.DiagnosticPolicy(
        service_name=False,
        endpoint=False,
        user_token=False,
        service_token=False,
        private_markers=PUBLIC_MARKERS,
    )
    sess, adapter = build_session(policy)
    diagnostic = diagnostics.RequestDiagnostic(policy=policy)
    exc = None
    try:
        sess.get(
            '/v2/resource',
            diagnostic=diagnostic,
            endpoint_filter={
                'service_type': 'compute',
                'service_name': CATALOG_MARKER,
            },
        )
    except exceptions.InternalServerError as caught:
        exc = caught

    if exc is None:
        raise SystemExit('expected the synthetic backend failure to raise')

    public = exc.diagnostic.public_view()
    internal = exc.diagnostic.internal_view()

    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, 'public.json'), 'w') as fh:
        json.dump(public, fh, indent=2, sort_keys=True)
        fh.write('\n')
    with open(os.path.join(output_dir, 'internal.json'), 'w') as fh:
        json.dump(internal, fh, indent=2, sort_keys=True)
        fh.write('\n')

    return public, internal


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--output',
        default='diagnostic-record',
        help='directory for public.json and internal.json',
    )
    args = parser.parse_args(argv)
    public, internal = run(args.output)

    marker_leak = any(
        marker in json.dumps(public, sort_keys=True)
        for marker in PUBLIC_MARKERS
    )
    if marker_leak:
        raise SystemExit('public record leaked a private marker')

    stages = [stage['stage'] for stage in public['stages']]
    print(f'request_id={public["request_id"]}')
    print(f'stages={",".join(stages)}')
    print(f'wrote {args.output}/public.json and {args.output}/internal.json')
    return 0


if __name__ == '__main__':
    sys.exit(main())
