# Tests for the HTTP/2 -> HTTP/1.1 boundary adapter. These exercise the
# translation rules and, crucially, prove with an independent h11 SERVER that
# every upstream stream produces exactly one downstream request and that a
# rejected stream never leaves a partial request on a reusable connection.

import pytest

import h11

from .._h2_adapter import H2DownstreamConnection, H2StreamAdapter
from .helpers import normalize_data_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def translate(events):
    adapter = H2StreamAdapter()
    for event in events:
        adapter.handle_event(event)
    return adapter.h11_events


def origin_headers(
    method=b"GET",
    scheme=b"https",
    authority=b"example.com",
    path=b"/",
    extra=(),
    end_stream=False,
):
    headers = [
        (b":method", method),
        (b":scheme", scheme),
        (b":authority", authority),
        (b":path", path),
    ]
    headers.extend(extra)
    return h11.H2Headers(headers, end_stream=end_stream)


def consume_one_request(server):
    # Drive an independent h11 SERVER over one full request cycle and return
    # the normalized request events it parsed. CONNECT switches the server
    # into tunnel (SWITCHED_PROTOCOL) state and so has no EndOfMessage.
    seen = []
    while True:
        event = server.next_event()
        if event in (h11.NEED_DATA, h11.PAUSED):
            break
        seen.append(event)
        if type(event) is h11.Request and event.method == b"CONNECT":
            # The request ends at its header block. A 2xx response then moves
            # the server into tunnel (SWITCHED_PROTOCOL) state.
            assert server.their_state is h11.SEND_BODY
            server.send(
                h11.Response(
                    status_code=200,
                    headers=[],
                )
            )
            assert server.our_state is h11.SWITCHED_PROTOCOL
            break
        if type(event) is h11.EndOfMessage:
            server.send(h11.Response(status_code=204, headers=[]))
            server.send(h11.EndOfMessage())
            server.start_next_cycle()
            break
    return normalize_data_events(seen)


# ---------------------------------------------------------------------------
# Happy-path translation
# ---------------------------------------------------------------------------


def test_simple_get_becomes_one_request():
    events = translate([origin_headers(path=b"/a", end_stream=True)])
    assert [type(event) for event in events] == [h11.Request, h11.EndOfMessage]
    request = events[0]
    assert request.method == b"GET"
    assert request.target == b"/a"
    assert request.http_version == b"1.1"
    # :authority is synthesized into a single Host header.
    assert request.headers == [(b"host", b"example.com")]


def test_host_header_used_when_authority_absent():
    events = translate(
        [
            h11.H2Headers(
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":path", b"/x"),
                    (b"host", b"only-host.example"),
                ],
                end_stream=True,
            )
        ]
    )
    assert events[0].headers == [(b"host", b"only-host.example")]


def test_matching_authority_and_host_accepted():
    events = translate(
        [
            origin_headers(
                authority=b"example.com",
                extra=((b"host", b"example.com"),),
                end_stream=True,
            )
        ]
    )
    # Host is not duplicated.
    assert events[0].headers == [(b"host", b"example.com")]


def test_unknown_end_to_end_headers_preserved():
    events = translate(
        [
            origin_headers(
                extra=(
                    (b"x-custom", b"value"),
                    (b"accept", b"*/*"),
                ),
                end_stream=True,
            )
        ]
    )
    request = events[0]
    assert (b"x-custom", b"value") in request.headers
    assert (b"accept", b"*/*") in request.headers
    # Host stays first (h11 writer also places it first on the wire).
    assert request.headers[0] == (b"host", b"example.com")


def test_body_without_content_length_uses_chunked():
    events = translate(
        [
            origin_headers(method=b"POST"),
            h11.H2Data(b"hello"),
            h11.H2Data(b" world", end_stream=True),
        ]
    )
    request = events[0]
    assert (b"transfer-encoding", b"chunked") in request.headers
    data_events = [event for event in events if type(event) is h11.Data]
    assert b"".join(event.data for event in data_events) == b"hello world"
    assert type(events[-1]) is h11.EndOfMessage


def test_body_with_content_length_keeps_length():
    events = translate(
        [
            origin_headers(
                method=b"POST", extra=((b"content-length", b"3"),)
            ),
            h11.H2Data(b"abc", end_stream=True),
        ]
    )
    request = events[0]
    assert (b"content-length", b"3") in request.headers
    assert not any(name == b"transfer-encoding" for name, _ in request.headers)
    assert [type(event) for event in events] == [
        h11.Request,
        h11.Data,
        h11.EndOfMessage,
    ]


def test_empty_body_request_has_no_framing_header():
    events = translate([origin_headers(method=b"POST", end_stream=True)])
    request = events[0]
    assert not any(
        name in (b"content-length", b"transfer-encoding")
        for name, _ in request.headers
    )


def test_te_trailers_allowed_other_te_rejected():
    events = translate(
        [origin_headers(extra=((b"te", b"trailers"),), end_stream=True)]
    )
    assert (b"te", b"trailers") in events[0].headers

    with pytest.raises(h11.H2AdapterError):
        translate(
            [origin_headers(extra=((b"te", b"gzip"),), end_stream=True)]
        )


def test_asterisk_form_only_for_options():
    events = translate(
        [
            h11.H2Headers(
                [
                    (b":method", b"OPTIONS"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                    (b":path", b"*"),
                ],
                end_stream=True,
            )
        ]
    )
    assert events[0].target == b"*"

    with pytest.raises(h11.H2AdapterError):
        translate([origin_headers(method=b"GET", path=b"*", end_stream=True)])


def test_trailers_require_chunked_and_are_emitted():
    events = translate(
        [
            origin_headers(method=b"POST"),
            h11.H2Data(b"payload"),
            h11.H2EndOfStream(trailers=((b"x-trailer", b"t"),)),
        ]
    )
    request = events[0]
    assert (b"transfer-encoding", b"chunked") in request.headers
    assert events[-1].headers == [(b"x-trailer", b"t")]


# ---------------------------------------------------------------------------
# CONNECT tunnel handling
# ---------------------------------------------------------------------------


def test_connect_uses_authority_form_target():
    events = translate(
        [
            h11.H2Headers(
                [(b":method", b"CONNECT"), (b":authority", b"tunnel.example:443")],
                end_stream=True,
            )
        ]
    )
    request = events[0]
    assert request.method == b"CONNECT"
    assert request.target == b"tunnel.example:443"
    assert request.headers == [(b"host", b"tunnel.example:443")]
    assert [type(event) for event in events] == [h11.Request, h11.EndOfMessage]


@pytest.mark.parametrize(
    "headers",
    [
        # scheme/path must be absent
        [
            (b":method", b"CONNECT"),
            (b":authority", b"h:443"),
            (b":scheme", b"https"),
        ],
        [
            (b":method", b"CONNECT"),
            (b":authority", b"h:443"),
            (b":path", b"/"),
        ],
        # missing / bad authority
        [(b":method", b"CONNECT")],
        [(b":method", b"CONNECT"), (b":authority", b"h:")],
        [(b":method", b"CONNECT"), (b":authority", b"h:noport")],
        [(b":method", b"CONNECT"), (b":authority", b"no-port")],
        [(b":method", b"CONNECT"), (b":authority", b"h/evil:443")],
    ],
)
def test_connect_malformed_rejected(headers):
    with pytest.raises(h11.H2AdapterError):
        translate([h11.H2Headers(headers, end_stream=True)])


def test_connect_rejects_body_and_host_conflict():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                h11.H2Headers(
                    [(b":method", b"CONNECT"), (b":authority", b"h:443")]
                ),
                h11.H2Data(b"x", end_stream=True),
            ]
        )
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                h11.H2Headers(
                    [
                        (b":method", b"CONNECT"),
                        (b":authority", b"h:443"),
                        (b"host", b"other:443"),
                    ],
                    end_stream=True,
                )
            ]
        )


# ---------------------------------------------------------------------------
# Pseudo-header / authority / target validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        # missing mandatory pseudo-headers
        [
            (b":scheme", b"https"),
            (b":authority", b"x"),
            (b":path", b"/"),
        ],
        [
            (b":method", b"GET"),
            (b":authority", b"x"),
            (b":path", b"/"),
        ],
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"x"),
        ],
        # unknown pseudo-header
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"x"),
            (b":path", b"/"),
            (b":unknown", b"1"),
        ],
        # duplicate pseudo-header
        [
            (b":method", b"GET"),
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"x"),
            (b":path", b"/"),
        ],
        # pseudo-header after a regular header
        [
            (b":method", b"GET"),
            (b"x-regular", b"1"),
            (b":scheme", b"https"),
            (b":authority", b"x"),
            (b":path", b"/"),
        ],
    ],
)
def test_bad_pseudo_headers_rejected(headers):
    with pytest.raises(h11.H2AdapterError):
        translate([h11.H2Headers(headers, end_stream=True)])


def test_authority_host_conflict_rejected():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                origin_headers(
                    authority=b"a.example",
                    extra=((b"host", b"b.example"),),
                    end_stream=True,
                )
            ]
        )


def test_neither_authority_nor_host_rejected():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                h11.H2Headers(
                    [
                        (b":method", b"GET"),
                        (b":scheme", b"https"),
                        (b":path", b"/"),
                    ],
                    end_stream=True,
                )
            ]
        )


def test_multiple_host_rejected():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                origin_headers(
                    extra=((b"host", b"a"), (b"host", b"b")),
                    end_stream=True,
                )
            ]
        )


@pytest.mark.parametrize(
    "path",
    [
        b"http://evil.example/path",  # absolute-form
        b"evil.example/path",         # not origin/asterisk form
        b"",                          # empty
    ],
)
def test_illegal_target_forms_rejected(path):
    with pytest.raises(h11.H2AdapterError):
        translate([origin_headers(path=path, end_stream=True)])


# ---------------------------------------------------------------------------
# Connection-level headers and control-character hardening
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
        b"trailer",
    ],
)
def test_connection_level_headers_rejected(name):
    with pytest.raises(h11.H2AdapterError):
        translate(
            [origin_headers(extra=((name, b"x"),), end_stream=True)]
        )


@pytest.mark.parametrize(
    "value",
    [
        b"good\r\nEvil: 1",   # raw CR/LF
        b"good\nEvil: 1",     # raw LF
        b"good\x00null",      # NUL
        b"good\x07bel",       # other C0 control
        b"good\x7fdel",       # DEL
    ],
)
def test_raw_control_characters_rejected(value):
    with pytest.raises(h11.H2AdapterError):
        translate(
            [origin_headers(extra=((b"x-inject", value),), end_stream=True)]
        )


@pytest.mark.parametrize(
    "path",
    [
        b"/%0d%0aEvil:1",
        b"/%0D%0A",
        b"/%00",
        b"/a%0ab",
    ],
)
def test_encoded_control_characters_in_target_rejected(path):
    with pytest.raises(h11.H2AdapterError):
        translate([origin_headers(path=path, end_stream=True)])


def test_encoded_control_character_in_header_rejected():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                origin_headers(
                    extra=((b"x-smuggle", b"%0d%0aEvil: 1"),),
                    end_stream=True,
                )
            ]
        )


def test_benign_percent_encoding_preserved():
    # Percent-encoding that does not decode to a control char is opaque data
    # and must survive untouched.
    events = translate([origin_headers(path=b"/q=100%20ok", end_stream=True)])
    assert events[0].target == b"/q=100%20ok"


def test_uppercase_header_name_rejected():
    # HTTP/2 requires lower-cased field names.
    with pytest.raises(h11.H2AdapterError):
        translate(
            [origin_headers(extra=((b"X-Custom", b"v"),), end_stream=True)]
        )


# ---------------------------------------------------------------------------
# Body length / end-of-stream consistency
# ---------------------------------------------------------------------------


def test_content_length_short_body_rejected():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                origin_headers(extra=((b"content-length", b"9"),)),
                h11.H2Data(b"abc", end_stream=True),
            ]
        )


def test_content_length_overrun_rejected():
    adapter = H2StreamAdapter()
    adapter.handle_event(
        origin_headers(method=b"POST", extra=((b"content-length", b"2"),))
    )
    with pytest.raises(h11.H2AdapterError):
        adapter.handle_event(h11.H2Data(b"abcdef", end_stream=True))


def test_declared_length_cannot_swallow_next_stream():
    # A body that overran the declared length must be rejected, and the
    # downstream connection must not carry any bytes from the bad stream.
    downstream = H2DownstreamConnection()
    good = translate([origin_headers(path=b"/first", end_stream=True)])
    downstream.submit(good)
    snapshot = downstream.outbound

    adapter = H2StreamAdapter()
    adapter.handle_event(
        origin_headers(
            method=b"POST",
            path=b"/second",
            extra=((b"content-length", b"3"),),
        )
    )
    with pytest.raises(h11.H2AdapterError):
        adapter.handle_event(h11.H2Data(b"way-too-much", end_stream=True))

    assert downstream.outbound == snapshot
    assert downstream.request_count == 1


def test_trailers_with_content_length_rejected():
    with pytest.raises(h11.H2AdapterError):
        translate(
            [
                origin_headers(extra=((b"content-length", b"7"),)),
                h11.H2Data(b"payload"),
                h11.H2EndOfStream(trailers=((b"x-trailer", b"t"),)),
            ]
        )


# ---------------------------------------------------------------------------
# End-to-end: independent h11 SERVER proves a strict one-to-one mapping
# ---------------------------------------------------------------------------


def test_each_upstream_stream_is_one_downstream_request():
    downstream = H2DownstreamConnection()

    streams = [
        [origin_headers(path=b"/one", end_stream=True)],
        [
            origin_headers(method=b"POST", path=b"/two"),
            h11.H2Data(b"chunk", end_stream=True),
        ],
        [
            origin_headers(
                method=b"POST",
                path=b"/three",
                extra=((b"content-length", b"2"),),
            ),
            h11.H2Data(b"ok", end_stream=True),
        ],
        [
            origin_headers(
                method=b"OPTIONS", path=b"*", end_stream=True
            )
        ],
    ]
    for stream in streams:
        downstream.submit(translate(stream))

    assert downstream.request_count == 4

    server = h11.Connection(h11.SERVER)
    server.receive_data(downstream.outbound)

    first = consume_one_request(server)
    assert type(first[0]) is h11.Request and first[0].target == b"/one"
    assert type(first[-1]) is h11.EndOfMessage

    second = consume_one_request(server)
    assert second[0].target == b"/two"
    body = b"".join(
        event.data for event in second if type(event) is h11.Data
    )
    assert body == b"chunk"

    third = consume_one_request(server)
    assert third[0].target == b"/three"
    assert (b"content-length", b"2") in third[0].headers

    fourth = consume_one_request(server)
    assert fourth[0].method == b"OPTIONS"
    assert fourth[0].target == b"*"

    # No trailing bytes: exactly four requests, nothing pipelined behind them.
    assert server.next_event() is h11.NEED_DATA
    assert server.trailing_data == (b"", False)


def test_connect_is_one_request_on_independent_server():
    downstream = H2DownstreamConnection()
    downstream.submit(
        translate(
            [
                h11.H2Headers(
                    [(b":method", b"CONNECT"), (b":authority", b"tunnel:443")],
                    end_stream=True,
                )
            ]
        )
    )
    server = h11.Connection(h11.SERVER)
    server.receive_data(downstream.outbound)
    parsed = consume_one_request(server)
    assert len(parsed) == 1
    assert parsed[0].method == b"CONNECT"
    assert parsed[0].target == b"tunnel:443"
    assert server.our_state is h11.SWITCHED_PROTOCOL


def test_failed_stream_leaves_no_partial_request_on_reusable_connection():
    downstream = H2DownstreamConnection()
    downstream.submit(translate([origin_headers(path=b"/good", end_stream=True)]))
    clean_snapshot = downstream.outbound
    assert downstream.request_count == 1

    bad_streams = [
        # authority conflict
        [
            origin_headers(
                authority=b"a", extra=((b"host", b"b"),), end_stream=True
            )
        ],
        # encoded control character
        [origin_headers(path=b"/%0d%0a", end_stream=True)],
        # length mismatch
        [
            origin_headers(extra=((b"content-length", b"9"),)),
            h11.H2Data(b"abc", end_stream=True),
        ],
    ]
    for stream in bad_streams:
        with pytest.raises(h11.H2AdapterError):
            downstream.submit(translate(stream))
        # The reusable connection is byte-for-byte unchanged.
        assert downstream.outbound == clean_snapshot
        assert downstream.request_count == 1

    # The single good request still parses as exactly one complete request.
    server = h11.Connection(h11.SERVER)
    server.receive_data(downstream.outbound)
    request_events = consume_one_request(server)
    assert request_events[0].target == b"/good"
    assert server.next_event() is h11.NEED_DATA


def test_downstream_poisons_on_wire_level_violation():
    # If a request reaches the scratch h11 client with a framing violation
    # that only the writer detects, submit must poison the connection rather
    # than emit partial bytes. Here the Content-Length writer refuses a body
    # that is longer than the declared length.
    downstream = H2DownstreamConnection()
    invalid_events = [
        h11.Request(
            method=b"POST",
            target=b"/",
            headers=[
                (b"host", b"example.com"),
                (b"content-length", b"2"),
            ],
        ),
        h11.Data(b"too-long"),
        h11.EndOfMessage(),
    ]
    with pytest.raises(h11.H2AdapterError):
        downstream.submit(invalid_events)
    assert downstream.poisoned is True
    assert downstream.outbound == b""
    assert downstream.request_count == 0
    # A poisoned connection refuses further reuse entirely.
    with pytest.raises(h11.H2AdapterError):
        downstream.submit(translate([origin_headers(end_stream=True)]))


def test_events_unavailable_until_stream_complete():
    adapter = H2StreamAdapter()
    adapter.handle_event(origin_headers(method=b"POST"))
    with pytest.raises(h11.H2AdapterError):
        adapter.h11_events  # noqa: B018
    adapter.handle_event(h11.H2Data(b"x", end_stream=True))
    events = adapter.h11_events
    assert type(events[-1]) is h11.EndOfMessage


def test_events_before_headers_are_rejected():
    adapter = H2StreamAdapter()
    with pytest.raises(h11.H2AdapterError):
        adapter.handle_event(h11.H2Data(b"x"))
    other = H2StreamAdapter()
    with pytest.raises(h11.H2AdapterError):
        other.handle_event(h11.H2EndOfStream())


def test_event_after_end_of_stream_rejected():
    adapter = H2StreamAdapter()
    adapter.handle_event(origin_headers(end_stream=True))
    with pytest.raises(h11.H2AdapterError):
        adapter.handle_event(h11.H2Data(b"late"))
