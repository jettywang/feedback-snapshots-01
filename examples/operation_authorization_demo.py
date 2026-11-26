#!/usr/bin/env python3
"""Demonstrate request-scoped operation authorization with local doubles.

The HTTP transport is an in-memory requests adapter; no network or local
socket is required. Two operations run concurrently:

* a user-only query, which must never send ``X-Service-Token``;
* a dual-identity operation, whose 401 retry waits until both replacement
  credentials exist and the service scope matches.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
import types

import requests

from keystoneauth1 import operation_authorization as op_auth
from keystoneauth1 import plugin
from keystoneauth1 import service_token
from keystoneauth1 import session as ks_session


QUERY_URL = 'http://double.example/v1/query'
OPERATION_URL = 'http://double.example/v1/privileged-operation'
SERVICE_SCOPE = 'service-project-scope'


class ControlledAuth(plugin.BaseAuthPlugin):
    def __init__(self, identity, token, scope=None):
        super().__init__()
        self.identity = identity
        self.token = token
        self.scope = scope
        self.waiting = threading.Event()
        self.invalidations = 0
        self._condition = threading.Condition()

    def get_token(self, session):
        deadline = time.monotonic() + 5
        with self._condition:
            while self.token is None:
                self.waiting.set()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        f'timed out waiting for {self.identity} credential'
                    )
                self._condition.wait(timeout=min(0.05, remaining))
            self.waiting.clear()
            return self.token

    def restore(self, token, scope=None):
        with self._condition:
            self.token = token
            if scope is not None:
                self.scope = scope
            self._condition.notify_all()

    def invalidate(self):
        with self._condition:
            had_token = self.token is not None
            self.token = None
            self.invalidations += 1
            self._condition.notify_all()
            return had_token


class InMemoryDoubleAdapter:
    def __init__(self, handler):
        self.handler = handler

    def send(self, request, **kwargs):
        context = types.SimpleNamespace(
            status_code=200, headers={'Content-Type': 'application/json'}
        )
        body = self.handler(request, context)
        response = requests.Response()
        response.status_code = context.status_code
        response.headers.update(context.headers)
        response._content = json.dumps(body).encode()
        response.encoding = 'utf-8'
        response.request = request
        response.url = request.url
        response.connection = self
        return response

    def close(self):
        pass


def wait_for(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError('timed out waiting for demonstration condition')


def main():
    user_auth = ControlledAuth('user', 'user-old')
    service_auth = ControlledAuth('service', 'service-old', SERVICE_SCOPE)
    auth = service_token.ServiceTokenAuthWrapper(user_auth, service_auth)

    records = []
    records_lock = threading.Lock()
    query_arrived = threading.Event()
    dual_first_arrived = threading.Event()
    release_query = threading.Event()

    def record(request, operation):
        entry = {
            'operation': operation,
            'request_number': len(
                [item for item in records if item['operation'] == operation]
            )
            + 1,
            'X-Auth-Token': request.headers.get('X-Auth-Token'),
            'X-Service-Token': request.headers.get('X-Service-Token'),
            'result': None,
        }
        with records_lock:
            records.append(entry)
        return entry

    def query_handler(request, context):
        entry = record(request, 'query')
        query_arrived.set()
        if not release_query.wait(5):
            raise RuntimeError('query was not released')
        entry['result'] = 200
        return {'result': 'query-ok'}

    def operation_handler(request, context):
        entry = record(request, 'dual-operation')
        if entry['request_number'] == 1:
            entry['result'] = 401
            context.status_code = 401
            dual_first_arrived.set()
            return {'error': 'reauthenticate'}
        entry['result'] = 200
        return {'result': 'dual-operation-ok'}

    def handler(request, context):
        if request.url == QUERY_URL:
            return query_handler(request, context)
        return operation_handler(request, context)

    http_session = requests.Session()
    http_session.mount(
        'http://double.example/', InMemoryDoubleAdapter(handler)
    )
    client = ks_session.Session(auth=auth, session=http_session)

    query_approval = op_auth.OperationAuthorization.user_only(
        operation_id='query-001'
    )
    operation_approval = op_auth.OperationAuthorization.dual_identity(
        SERVICE_SCOPE, operation_id='dual-001'
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        query_future = executor.submit(
            client.get, QUERY_URL, operation_authorization=query_approval
        )
        operation_future = executor.submit(
            client.get,
            OPERATION_URL,
            operation_authorization=operation_approval,
        )

        if not query_arrived.wait(5):
            raise RuntimeError('query did not start')
        if not dual_first_arrived.wait(5):
            raise RuntimeError('dual operation did not receive 401')

        wait_for(user_auth.waiting.is_set)
        user_auth.restore('user-new')

        wait_for(service_auth.waiting.is_set)
        if service_auth.token is not None:
            raise RuntimeError('service credential restored too early')
        service_auth.restore('service-new', SERVICE_SCOPE)

        wait_for(
            lambda: len(
                [
                    item
                    for item in records
                    if item['operation'] == 'dual-operation'
                ]
            )
            == 2
        )
        release_query.set()

        query_response = query_future.result(5)
        operation_response = operation_future.result(5)

    output = {
        'records': records,
        'query_status': query_response.status_code,
        'operation_status': operation_response.status_code,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

    if query_response.status_code != 200:
        raise SystemExit('query did not complete')
    if operation_response.status_code != 200:
        raise SystemExit('dual operation did not complete')


if __name__ == '__main__':
    main()
