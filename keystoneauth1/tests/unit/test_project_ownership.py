"""In-memory ownership scenario for project-constrained adapters."""

import json

import requests

from keystoneauth1 import adapter as adapter_mod
from keystoneauth1 import exceptions
from keystoneauth1 import plugin
from keystoneauth1.discover import EndpointData
from keystoneauth1.session import Session


CATALOG = 'http://shared.example/'
VERSION = 'http://shared.example/v1/'


class ProjectAuth(plugin.BaseAuthPlugin):
    def __init__(self, project_id):
        super().__init__()
        self.project_id = project_id
        self.revision = 0
        self.token = f'token-{project_id}-0'
        self.catalog_available = True

    def get_project_id(self, session):
        return self.project_id

    def get_token(self, session):
        return self.token

    def invalidate(self):
        self.revision += 1
        self.token = f'token-{self.project_id}-{self.revision}'
        return True

    def get_endpoint_data(self, session, **kwargs):
        if not self.catalog_available:
            raise exceptions.EndpointNotFound('catalog unavailable')
        data = EndpointData(
            catalog_url=CATALOG,
            service_url=CATALOG,
            service_type='shared',
            interface='public',
            region_name='RegionOne',
            project_id=self.project_id,
        )
        return data.get_versioned_data(
            session,
            project_id=self.project_id,
            cache=self._discovery_cache,
            allow_version_hack=True,
            min_version=(1, 0),
            max_version=(1, 0),
        )


class InMemoryHttp:
    def __init__(self):
        self.business_requests = []

    def request(self, method, url, **kwargs):
        if url.rstrip('/') == CATALOG.rstrip('/'):
            payload = {
                'versions': [
                    {
                        'id': 'v1.0',
                        'status': 'CURRENT',
                        'version': '1.0',
                        'min_version': '1.0',
                        'max_version': '1.0',
                        'links': [{'rel': 'self', 'href': VERSION}],
                    }
                ]
            }
        else:
            token = kwargs['headers']['X-Auth-Token']
            project_id = '-'.join(token.split('-')[1:-1])
            record = {
                'method': method,
                'url': url,
                'token': token,
                'project_id': project_id,
            }
            self.business_requests.append(record)
            payload = {'ok': True, 'request': record}

        response = requests.Response()
        response.status_code = 200
        response.url = url
        response._content = json.dumps(payload).encode()
        response.headers['Content-Type'] = 'application/json'
        response.encoding = 'utf-8'
        prepared = requests.PreparedRequest()
        prepared.method = method
        prepared.url = url
        response.request = prepared
        response.history = []
        return response


def make_adapter(http, project_id, auth=None):
    auth = auth or ProjectAuth(project_id)
    session = Session(session=http, discovery_cache={})
    adapter = adapter_mod.Adapter(
        session,
        auth=auth,
        project_id=project_id,
        service_type='shared',
        interface='public',
        region_name='RegionOne',
        version='1.0',
    )
    return adapter, auth


def test_project_ownership_is_isolated_during_refresh_and_outage():
    http = InMemoryHttp()
    adapter_a, auth_a = make_adapter(http, 'project-a')
    adapter_b, _ = make_adapter(http, 'project-b')

    discovered = adapter_a.get_endpoint_data()
    assert discovered.project_id == 'project-a'
    assert discovered.api_version == (1, 0)
    assert discovered.url == VERSION
    assert adapter_a.project_state == 'verified'

    response_b = adapter_b.get('things')
    assert response_b.status_code == 200
    assert len(http.business_requests) == 1
    assert http.business_requests[0]['project_id'] == 'project-b'
    send_b = adapter_b.project_send_records[-1]
    assert send_b['project_id'] == 'project-b'
    assert send_b['api_version'] == (1, 0)

    adapter_a.invalidate()
    auth_a.catalog_available = False
    try:
        adapter_a.get('things')
    except exceptions.StaleProjectEndpoint as exc:
        assert exc.project_id == 'project-a'
        assert exc.state == 'stale'
        assert exc.reason_code == 'stale_endpoint'
    else:
        raise AssertionError('stale project endpoint was sent')

    assert adapter_a.project_state == 'stale'
    assert len(http.business_requests) == 1

    auth_a.catalog_available = True
    response_a = adapter_a.get('things')
    assert response_a.status_code == 200
    assert len(http.business_requests) == 2
    assert http.business_requests[1]['project_id'] == 'project-a'
    assert http.business_requests[1]['token'] == auth_a.token
    send_a = adapter_a.project_send_records[-1]
    assert send_a['project_id'] == 'project-a'
    assert send_a['api_version'] == (1, 0)
    assert send_a['auth_generation'] == 2


def test_changed_project_evidence_blocks_send():
    http = InMemoryHttp()
    adapter_a, auth_a = make_adapter(http, 'project-a')
    adapter_a.get_endpoint_data()

    auth_a.project_id = 'project-c'
    auth_a.token = 'token-project-c-9'

    try:
        adapter_a.get('things')
    except exceptions.ProjectMismatch as exc:
        assert exc.project_id == 'project-c'
        assert exc.reason_code == 'project_mismatch'
    else:
        raise AssertionError('cross-project send was allowed')

    assert adapter_a.project_state == 'mismatch'
    assert http.business_requests == []
