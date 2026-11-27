"""Tests for shareable Pushgateway receipts.

These tests never open a socket: every HTTP interaction is driven by a
scripted in-process handler so they run in environments where local port
binding is unavailable.
"""

import json

import pytest

from prometheus_client import (
    CollectorRegistry, delete_from_gateway, Gauge, PushReceipt,
    push_to_gateway, pushadd_to_gateway, ReceiptBook,
)
from prometheus_client.receipts import (
    current_receipt_id, extract_status_code, fingerprint_grouping_key,
    gateway_designator, PHASE_ACCEPTED, PHASE_CONSTRUCTED, PHASE_FAILED,
    PHASE_UNKNOWN, TransferResult,
)


class FakeResponse:
    """Mimics the status attributes of an http.client.HTTPResponse."""

    def __init__(self, code, url=None):
        self.code = code
        self.url = url


class ScriptedHandler:
    """Handler factory whose senders follow a per-call script.

    Each script entry is a value returned by the sender, or an exception
    instance the sender raises.  ``transfers`` records one entry per sender
    invocation, including the receipt id visible on the execution context,
    which proves transmissions and receipts correlate one-to-one.
    """

    def __init__(self, script):
        self.script = list(script)
        self.transfers = []

    def __call__(self, url, method, timeout, headers, data):
        entry = self.script[len(self.transfers)]
        captured_headers = list(headers)

        def sender():
            self.transfers.append({
                'receipt_id': current_receipt_id.get(),
                'url': url,
                'method': method,
                'timeout': timeout,
                'headers': captured_headers,
                'body': data,
            })
            if isinstance(entry, BaseException):
                raise entry
            return entry

        return sender


def make_registry():
    registry = CollectorRegistry()
    Gauge('g', 'help', registry=registry).set(7)
    return registry


RESTRICTED_GROUP = {'instance': 'secret/value with space'}


def test_receipt_distinct_ids_and_one_to_one_transfers():
    book = ReceiptBook()
    handler = ScriptedHandler([FakeResponse(202), FakeResponse(200), None])
    registry = make_registry()

    r1 = push_to_gateway('gw.example:9091', 'job', registry,
                         handler=handler, receipt_book=book)
    r2 = pushadd_to_gateway('gw.example:9091', 'job', registry,
                            handler=handler, receipt_book=book)
    r3 = delete_from_gateway('gw.example:9091', 'job',
                             handler=handler, receipt_book=book)

    # Three transmissions, three receipts, distinct ids, exact correlation.
    assert len(book) == 3
    assert len(handler.transfers) == 3
    receipt_ids = {r1.receipt_id, r2.receipt_id, r3.receipt_id}
    assert len(receipt_ids) == 3
    assert [t['receipt_id'] for t in handler.transfers] == [
        r1.receipt_id, r2.receipt_id, r3.receipt_id,
    ]
    assert [t['method'] for t in handler.transfers] == ['PUT', 'POST', 'DELETE']


def test_three_phases_are_distinguished_on_success():
    book = ReceiptBook()
    receipt = push_to_gateway(
        'gw.example', 'job', make_registry(),
        handler=ScriptedHandler([FakeResponse(202)]), receipt_book=book,
    )
    assert receipt.phase == PHASE_ACCEPTED
    assert receipt.outcome == 'accepted'
    assert receipt.status_code == 202
    assert receipt.supports_status is True
    assert receipt.constructed_at <= receipt.attempted_at <= receipt.completed_at


def test_interleaved_pushadd_failure_after_redirect_and_delete_accepted():
    book = ReceiptBook()
    redirect_log = []

    def redirect_then_fail(url, method, timeout, headers, data):
        def sender():
            # Simulate following a 301 inside the handler, then failing.
            redirect_log.append(('301', url))
            raise OSError('redirected target refused the connection')
        return sender

    with pytest.raises(OSError):
        pushadd_receipt = pushadd_to_gateway(
            'gw.example', 'job', make_registry(), RESTRICTED_GROUP,
            handler=redirect_then_fail, receipt_book=book,
        )
    pushadd_receipt = book.all()[0]
    delete_receipt = delete_from_gateway(
        'gw.example', 'job', RESTRICTED_GROUP,
        handler=ScriptedHandler([FakeResponse(202)]), receipt_book=book,
    )

    assert len(redirect_log) == 1
    assert pushadd_receipt.phase == PHASE_FAILED
    assert pushadd_receipt.outcome == 'handler_error'
    assert pushadd_receipt.attempted_at is not None  # transport was tried
    assert pushadd_receipt.status_code is None

    assert delete_receipt.phase == PHASE_ACCEPTED
    assert delete_receipt.status_code == 202

    # Same group: fingerprints match even though outcomes differ.
    assert (pushadd_receipt.grouping_fingerprint
            == delete_receipt.grouping_fingerprint)
    assert pushadd_receipt.receipt_id != delete_receipt.receipt_id

    # A late-arriving failure must not overwrite the accepted delete.
    late_error = OSError('late transport failure from an earlier hop')
    delete_receipt.record_error(late_error, 999999.0)
    delete_receipt.record_result(FakeResponse(500), 999999.0)
    assert delete_receipt.phase == PHASE_ACCEPTED
    assert delete_receipt.status_code == 202
    assert delete_receipt.completed_at != 999999.0

    # The pushadd receipt remains the failed one, untouched by the delete.
    assert pushadd_receipt.phase == PHASE_FAILED
    assert book.get(delete_receipt.receipt_id) is delete_receipt


def test_custom_sender_returning_only_a_result_object():
    book = ReceiptBook()
    handler = ScriptedHandler([
        TransferResult(status_code=200, final_url='https://gw/metrics/job/job',
                       redirect_count=1),
        None,  # sender reports nothing provable
    ])

    accepted = push_to_gateway(
        'gw.example', 'job', make_registry(),
        handler=handler, receipt_book=book,
    )
    unknown = push_to_gateway(
        'gw.example', 'job', make_registry(),
        handler=handler, receipt_book=book,
    )

    assert accepted.phase == PHASE_ACCEPTED
    assert accepted.status_code == 200
    assert accepted.redirect_count == 1

    assert unknown.phase == PHASE_UNKNOWN
    assert unknown.outcome == 'unproven'
    assert unknown.status_code is None
    assert unknown.supports_status is False


def test_non_2xx_result_is_failed_http_error():
    book = ReceiptBook()
    receipt = delete_from_gateway(
        'gw.example', 'job',
        handler=ScriptedHandler([TransferResult(status_code=503)]),
        receipt_book=book,
    )
    assert receipt.phase == PHASE_FAILED
    assert receipt.outcome == 'http_error'
    assert receipt.status_code == 503


def test_handler_factory_exception_is_construction_failure():
    book = ReceiptBook()

    def broken_factory(url, method, timeout, headers, data):
        raise ValueError('cannot build a sender')

    with pytest.raises(ValueError):
        push_to_gateway('gw.example', 'job', make_registry(),
                        handler=broken_factory, receipt_book=book)

    receipt = book.all()[0]
    assert receipt.phase == PHASE_FAILED
    assert receipt.attempted_at is None  # never reached transport
    assert receipt.constructed_at is not None


def test_unsupported_compression_is_construction_failure():
    book = ReceiptBook()
    handler = ScriptedHandler([FakeResponse(200)])
    with pytest.raises(ValueError):
        push_to_gateway('gw.example', 'job', make_registry(),
                        handler=handler, compression='brotli', receipt_book=book)
    assert handler.transfers == []  # nothing was transmitted
    receipt = book.all()[0]
    assert receipt.phase == PHASE_FAILED
    assert receipt.attempted_at is None


def test_shareable_view_redacts_sensitive_fields():
    book = ReceiptBook()

    def auth_handler(url, method, timeout, headers, data):
        headers.append(('Authorization', 'Basic cm9vdDpzdXBlcnNlY3JldA=='))
        return ScriptedHandler([OSError('boom: supers3cret password')])(
            url, method, timeout, headers, data,
        )

    with pytest.raises(OSError):
        pushadd_to_gateway(
            'gw.example', 'job', make_registry(), RESTRICTED_GROUP,
            handler=auth_handler, receipt_book=book,
        )
    receipt = book.all()[0]

    shared = receipt.shareable()
    shared_json = json.dumps(shared)
    # Restricted grouping value, credentials and raw error text stay local.
    assert 'secret/value with space' not in shared_json
    assert 'supers3cret' not in shared_json
    assert 'Basic' not in shared_json
    assert 'url' not in shared
    assert 'grouping_key' not in shared
    assert 'error_message' not in shared
    assert shared['auth_configured'] is True
    assert shared['error_type'] == 'OSError'
    assert shared['grouping_label_names'] == ['instance']
    assert shared['phase'] == PHASE_FAILED

    local = receipt.local()
    assert local['url'].startswith('http://gw.example/metrics/job/job/')
    assert local['grouping_key'] == RESTRICTED_GROUP
    assert local['auth_header_names'] == ['Authorization']
    assert 'supers3cret' in local['error_message']

    # The book-level shareable export is equally redacted and JSON-safe.
    book_json = book.to_json()
    assert 'supers3cret' not in book_json
    assert 'secret/value with space' not in book_json
    assert len(json.loads(book_json)) == 1


def test_gateway_userinfo_is_stripped_from_shareable_view():
    book = ReceiptBook()
    receipt = delete_from_gateway(
        'http://admin:hunter2@gw.example:9091', 'job',
        handler=ScriptedHandler([FakeResponse(202)]), receipt_book=book,
    )
    shared = json.dumps(receipt.shareable())
    assert 'hunter2' not in shared
    assert 'admin' not in shared
    assert receipt.gateway == 'http://gw.example:9091'
    assert gateway_designator('http://admin:hunter2@gw.example:9091') == \
        'http://gw.example:9091'


def test_grouping_fingerprints_group_same_operations_together():
    same_a = fingerprint_grouping_key({'a': 1, 'b': 'x'})
    same_b = fingerprint_grouping_key({'b': 'x', 'a': 1})  # order-independent
    different = fingerprint_grouping_key({'a': 2})
    assert same_a == same_b
    assert same_a != different


def test_operation_without_book_returns_none_and_still_runs():
    handler = ScriptedHandler([FakeResponse(202)])
    result = push_to_gateway('gw.example', 'job', make_registry(),
                             handler=handler)
    assert result is None
    assert len(handler.transfers) == 1


def test_extract_status_code_handles_shapes():
    assert extract_status_code(FakeResponse(201)) == 201
    assert extract_status_code(204) == 204
    assert extract_status_code(TransferResult(status_code=202)) == 202
    assert extract_status_code({'status_code': 500}) == 500
    assert extract_status_code(None) is None
    assert extract_status_code(True) is None
    assert extract_status_code(object()) is None


def test_unknown_phase_when_sender_returns_none():
    book = ReceiptBook()
    receipt = delete_from_gateway('gw.example', 'job',
                                  handler=ScriptedHandler([None]),
                                  receipt_book=book)
    assert receipt.phase == PHASE_UNKNOWN
    assert receipt.outcome == 'unproven'
    assert receipt.frozen is True


def test_final_url_from_geturl_is_kept_local_only():
    class UrlResponse:
        code = 200

        def geturl(self):
            return 'http://gw.example/redirected/job/job'

    book = ReceiptBook()
    receipt = push_to_gateway('gw.example', 'job', make_registry(),
                              handler=ScriptedHandler([UrlResponse()]),
                              receipt_book=book)
    assert receipt.local()['final_url'] == \
        'http://gw.example/redirected/job/job'
    assert 'final_url' not in receipt.shareable()
    assert 'redirected' not in receipt.to_json()


def test_receipt_book_lookup_helpers():
    book = ReceiptBook()
    one = push_to_gateway('gw.example', 'job', make_registry(),
                          {'g': 1}, handler=ScriptedHandler([FakeResponse(200)]),
                          receipt_book=book)
    two = delete_from_gateway('gw.example', 'job', {'g': 1},
                              handler=ScriptedHandler([FakeResponse(200)]),
                              receipt_book=book)
    other = delete_from_gateway('gw.example', 'job', {'g': 2},
                                handler=ScriptedHandler([FakeResponse(200)]),
                                receipt_book=book)
    assert book.get(one.receipt_id) is one
    assert one.receipt_id in book
    assert {r.receipt_id for r in book.for_group(one.grouping_fingerprint)} == {
        one.receipt_id, two.receipt_id,
    }
    assert other.grouping_fingerprint != one.grouping_fingerprint
    assert [r['receipt_id'] for r in book.shareable()] == [
        one.receipt_id, two.receipt_id, other.receipt_id,
    ]


def test_phase_constants_are_ordered_distinctly():
    # Construction and the transport attempt must never be confused.
    assert PHASE_CONSTRUCTED != 'attempted'
    constructed = PushReceipt('push', 'PUT', 'gw', 'http://gw/x')
    assert constructed.phase == PHASE_CONSTRUCTED
    assert constructed.attempted_at is None
