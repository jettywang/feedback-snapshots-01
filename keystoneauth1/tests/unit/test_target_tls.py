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

from __future__ import annotations

import itertools
import threading
import time
from typing import Any

import requests

from keystoneauth1 import discover
from keystoneauth1 import session as ksa_session
from keystoneauth1 import tls as ksa_tls


class FakeConnection:
    next_id = itertools.count(1)

    def __init__(self) -> None:
        self.id = next(self.next_id)
        self.closed = False


class FakePool:
    def __init__(self, generation: int) -> None:
        self.generation = generation
        self.lock = threading.RLock()
        self.idle: list[FakeConnection] = []
        self.closed_connections: list[int] = []
        self.next_id = 0
        self.closed = False
        self.active = 0

    def checkout(self) -> tuple[FakeConnection, bool]:
        with self.lock:
            if self.closed:
                raise RuntimeError(f'pool generation {self.generation} closed')
            if self.idle:
                connection = self.idle.pop()
                self.active += 1
                return connection, True
            self.next_id += 1
            connection = FakeConnection()
            self.active += 1
            return connection, False

    def checkin(
        self, connection: FakeConnection, adapter_closed: bool
    ) -> None:
        with self.lock:
            self.active -= 1
            if self.closed or adapter_closed or connection.closed:
                connection.closed = True
                self.closed_connections.append(connection.id)
                return
            self.idle.append(connection)

    def close(self) -> None:
        with self.lock:
            self.closed = True
            for connection in self.idle:
                connection.closed = True
                self.closed_connections.append(connection.id)
            self.idle.clear()


class FakeTransportAdapter(requests.adapters.BaseAdapter):
    def __init__(
        self,
        service: 'FakeService',
        binding: ksa_tls.TLSBinding,
        ledger: ksa_tls.TLSConnectionLedger | None = None,
    ):
        super().__init__()
        self.service = service
        self.binding = binding
        self.ledger = ledger
        self.tls_generation: ksa_tls.TLSGeneration | None = None
        self.pool = FakePool(binding.generation)
        self.closed = False

    def send(  # type: ignore[override]
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        generation = self.tls_generation
        if generation is not None:
            generation.begin_send()
        connection, reused = self.pool.checkout()
        record = {
            'service': self.service.name,
            'url': request.url,
            'method': request.method,
            'cert': cert,
            'verify': verify,
            'generation': self.binding.generation,
            'fingerprint': self.binding.fingerprint,
            'connection': connection.id,
            'reused': reused,
            'adapter_closed': self.closed,
        }
        self.service.transport.append(record)
        self.service.reuse.append(
            {
                'service': self.service.name,
                'generation': self.binding.generation,
                'connection': connection.id,
                'reused': reused,
            }
        )
        if generation is not None:
            generation.checkouts += 1
            if reused:
                generation.reuses += 1
        if self.ledger is not None:
            self.ledger.record(
                'checkout',
                target=self.binding.target.origin,
                generation=self.binding.generation,
                connection_id=connection.id,
                reused=reused,
            )

        status = 200
        body: dict[str, Any] | list[Any] = {'ok': True}
        path = request.path_url or '/'
        try:
            status, body = self.service.handle(request.method, path)
        except Exception:
            self.pool.checkin(connection, self.closed)
            if generation is not None:
                generation.end_send()
            raise

        response = requests.Response()
        response.status_code = status
        response._content = (
            b'{"versions":{"values":['
            b'{"id":"v1","status":"stable",'
            b'"links":[{"rel":"self","href":"https://'
            + self.service.name.encode()
            + b'/v1/"}]'
            b'}]}}'
            if path == '/'
            else b'{"ok": true}'
        )
        response.encoding = 'utf-8'
        response.url = request.url or ''
        response.request = request
        response.headers['Content-Type'] = 'application/json'

        self.pool.checkin(connection, self.closed)
        if generation is not None:
            generation.end_send()
            generation.close_if_allowed()
        return response

    def close(self) -> None:
        self.closed = True
        self.pool.close()
        self.service.closed_adapters.append(self.binding.generation)


class FakeService:
    def __init__(self, name: str, block_path: str | None = None) -> None:
        self.name = name
        self.block_path = block_path
        self.entered = threading.Event()
        self.release = threading.Event()
        self.transport: list[dict[str, Any]] = []
        self.reuse: list[dict[str, Any]] = []
        self.requested_paths: list[str] = []
        self.closed_adapters: list[int] = []

    def handle(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
        self.requested_paths.append(path)
        if self.block_path and path.startswith(self.block_path):
            self.entered.set()
            if not self.release.wait(timeout=5):
                raise RuntimeError(f'{self.name} blocker was not released')
        return 200, {'ok': True}


def _build_session(
    services: dict[str, FakeService], *, cert: str | None = None
) -> ksa_session.Session:
    def factory(binding: ksa_tls.TLSBinding) -> FakeTransportAdapter:
        service = services[binding.target.host]
        return FakeTransportAdapter(
            service, binding, ledger=registry.ledger
        )

    registry = ksa_tls.TargetTLSRegistry(adapter_factory=factory)
    return ksa_session.Session(cert=cert, tls_registry=registry)


def test_target_tls_used_by_discovery_and_application_requests() -> None:
    service_a = FakeService('a.example')
    services = {'a.example': service_a}
    session = _build_session(services)
    session.configure_tls(
        'https://a.example',
        cert=('a-old.crt', 'a.key'),
        verify='ca-a.pem',
    )

    discovery = discover.Discover(session, 'https://a.example/')
    versions = discovery.raw_version_data()
    session.get('https://a.example/things')

    assert [version['id'] for version in versions] == ['v1']
    assert [record['url'] for record in service_a.transport] == [
        'https://a.example/',
        'https://a.example/things',
    ]
    assert all(
        record['cert'] == ('a-old.crt', 'a.key')
        and record['verify'] == 'ca-a.pem'
        for record in service_a.transport
    )


def test_two_services_share_session_and_rotation_retires_old_pool() -> None:
    service_a = FakeService('a.example', block_path='/block')
    service_b = FakeService('b.example')
    service_c = FakeService('c.example')
    services = {
        'a.example': service_a,
        'b.example': service_b,
        'c.example': service_c,
    }
    session = _build_session(services, cert='session-global.crt')
    session.configure_tls(
        'https://a.example', cert=('a.crt', 'a.key'), verify='ca.pem'
    )
    session.configure_tls(
        'https://b.example', cert=('b-v1.crt', 'b.key'), verify='ca.pem'
    )
    session.configure_tls('https://c.example', None)

    # Establish and reuse B's first-generation connection.
    session.get('https://b.example/one')
    session.get('https://b.example/two')
    assert service_b.reuse[0]['reused'] is False
    assert service_b.reuse[1]['reused'] is True
    old_b_connection = service_b.transport[0]['connection']

    # The no-certificate target explicitly gets cert=None, not B's or A's.
    session.get('https://c.example/')
    assert service_c.transport[-1]['cert'] is None

    result: dict[str, Any] = {}

    def in_flight_a() -> None:
        try:
            result['response'] = session.get('https://a.example/block')
        except Exception as exc:  # pragma: no cover - failure diagnostic
            result['error'] = exc

    worker = threading.Thread(target=in_flight_a)
    worker.start()
    assert service_a.entered.wait(timeout=2)

    # Rotate B while A is blocked inside its request.
    transition = session.rotate_tls(
        'https://b.example',
        cert=('b-v2.crt', 'b.key'),
        verify='ca.pem',
        exit_condition='idle',
        approved=True,
    )
    assert transition.old is not None
    assert transition.old.closed is True
    assert service_b.closed_adapters == [1]

    # A's in-flight transport record was already fixed to generation 1.
    in_flight_record = service_a.transport[-1]
    assert in_flight_record['generation'] == 1
    assert in_flight_record['cert'] == ('a.crt', 'a.key')

    service_a.release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert 'error' not in result

    # New B requests use generation 2 and do not reuse the old connection.
    session.get('https://b.example/three')
    session.get('https://b.example/four')
    b_after = [
        record
        for record in service_b.transport
        if record['url'].endswith(('/three', '/four'))
    ]
    assert [record['generation'] for record in b_after] == [2, 2]
    assert all(
        record['cert'] == ('b-v2.crt', 'b.key') for record in b_after
    )
    assert b_after[0]['reused'] is False
    assert b_after[0]['connection'] != old_b_connection
    assert b_after[1]['reused'] is True

    # The retired generation's connection was closed; the new pool survives.
    assert transition.old is not None
    old_adapter = transition.old.adapter
    assert isinstance(old_adapter, FakeTransportAdapter)
    assert old_adapter.pool.closed is True
    assert old_b_connection in old_adapter.pool.closed_connections

    report = session.check_tls('https://b.example')
    assert report['matched'] is True
    assert report['current']['generation'] == 2
    assert report['retired'][0]['closed'] is True
    assert report['retired'][0]['generation'] == 1

    # Give ledger timing-sensitive cleanup a moment if a future async hook is
    # introduced; the synchronous contract is already asserted above.
    time.sleep(0)


def test_retired_generation_waits_until_in_flight_send_returns() -> None:
    service = FakeService('slow.example', block_path='/slow')
    session = _build_session({'slow.example': service})
    session.configure_tls('https://slow.example', cert='v1.crt')

    session.get('https://slow.example/warm')
    old_connection = service.transport[-1]['connection']

    result: dict[str, Any] = {}
    worker = threading.Thread(
        target=lambda: result.setdefault(
            'response', session.get('https://slow.example/slow')
        )
    )
    worker.start()
    assert service.entered.wait(timeout=2)

    transition = session.rotate_tls(
        'https://slow.example',
        cert='v2.crt',
        exit_condition='idle',
        approved=True,
    )
    assert transition.old is not None
    assert transition.old.active_sends == 1
    assert transition.old.closed is False

    service.release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert 'error' not in result
    assert transition.old.closed is True
    old_adapter = transition.old.adapter
    assert isinstance(old_adapter, FakeTransportAdapter)
    assert old_connection in old_adapter.pool.closed_connections

    session.get('https://slow.example/after')
    after = service.transport[-1]
    assert after['generation'] == 2
    assert after['cert'] == 'v2.crt'
    assert after['reused'] is False
    assert after['connection'] != old_connection
