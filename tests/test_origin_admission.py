"""Tests for the per-stream origin admission adapter."""
from __future__ import annotations

import h2.config
import h2.connection
import h2.events
import pytest
from h2.origin_admission import (
    AdmissionError,
    Origin,
    OriginAdmissionAdapter,
    RejectionReason,
    TLSCertificateInfo,
    TrailerDecision,
)

CERTIFICATE = TLSCertificateInfo.create(
    dns_names=["api.example.com", "cdn.example.com", "*.wild.example.com", "shared-cert.example.net"],
    ip_addresses=["203.0.113.7", "2001:db8::1"],
)

ALLOWED_ORIGINS = frozenset(
    {
        Origin("https", "api.example.com", 443),
        Origin("https", "cdn.example.com", 443),
        Origin("https", "img.wild.example.com", 443),
        Origin("http", "plain.example.com", 80),
        Origin("https", "203.0.113.7", 443),
        Origin("https", "[2001:db8::1]", 443),
    },
)


def make_adapter(
    certificate: TLSCertificateInfo | None = CERTIFICATE,
    allowed: frozenset[Origin] = ALLOWED_ORIGINS,
) -> OriginAdmissionAdapter:
    """Build an adapter backed by the shared test certificate and allow set."""
    return OriginAdmissionAdapter(certificate, allowed)


def request_headers(
    authority: str,
    *,
    scheme: str = "https",
    path: str = "/",
    extra: list[tuple[str, str]] | None = None,
) -> list[tuple[bytes, bytes]]:
    """Build minimal request headers with a configurable authority."""
    headers = [
        (b":method", b"GET"),
        (b":path", path.encode()),
        (b":scheme", scheme.encode()),
        (b":authority", authority.encode()),
    ]
    if extra:
        headers.extend((name.encode(), value.encode()) for name, value in extra)
    return headers


class TestOriginModel:
    def test_equality_and_default_ports(self) -> None:
        assert Origin("https", "api.example.com", 443) == Origin("https", "api.example.com", 443)
        assert Origin("https", "api.example.com", 443) != Origin("https", "api.example.com", 8443)
        assert Origin("https", "api.example.com", 443) != Origin("http", "api.example.com", 443)
        assert hash(Origin("https", "a.example", 443)) == hash(Origin("https", "a.example", 443))

    def test_ip_literal_detection_and_rendering(self) -> None:
        origin = Origin("https", "[2001:db8::1]", 443)
        assert origin.is_ip_literal is True
        assert Origin("https", "api.example.com", 443).is_ip_literal is False
        assert str(origin) == "https://[2001:db8::1]:443"
        assert str(Origin("https", "api.example.com", 443)) == "https://api.example.com:443"


class TestTLSCertificateInfo:
    def test_default_collections_are_empty(self) -> None:
        info = TLSCertificateInfo()
        assert info.dns_names == frozenset()
        assert info.ip_addresses == frozenset()

    def test_create_normalizes_iterables_to_frozensets(self) -> None:
        info = TLSCertificateInfo.create(["a.example", "b.example"], ["203.0.113.7"])
        assert info.dns_names == frozenset({"a.example", "b.example"})
        assert info.ip_addresses == frozenset({"203.0.113.7"})


class TestAdapterSurface:
    def test_allowed_origins_are_exposed_as_frozenset(self) -> None:
        adapter = make_adapter()
        assert adapter.allowed_origins == ALLOWED_ORIGINS
        assert isinstance(adapter.allowed_origins, frozenset)

    def test_rejection_reason_property_mirrors_reason(self) -> None:
        adapter = make_adapter()
        rejected = adapter.admit_request_headers(1, request_headers("shared-cert.example.net"))
        allowed = adapter.admit_request_headers(3, request_headers("api.example.com"))
        assert rejected.rejection_reason is RejectionReason.ORIGIN_NOT_ALLOWED
        assert allowed.rejection_reason is None
        assert adapter.decision_for_stream(99) is None
        assert adapter.origin_for_stream(99) is None


class TestOriginParsing:
    @pytest.mark.parametrize(
        ("authority", "scheme", "host", "port"),
        [
            ("api.example.com", "https", "api.example.com", 443),
            ("api.example.com:443", "https", "api.example.com", 443),
            ("plain.example.com", "http", "plain.example.com", 80),
            ("plain.example.com:8080", "http", "plain.example.com", 8080),
            ("API.Example.COM", "https", "api.example.com", 443),
            ("203.0.113.7:8443", "https", "203.0.113.7", 8443),
            ("[2001:db8::1]", "https", "[2001:db8::1]", 443),
            ("[2001:DB8::1]:8443", "https", "[2001:db8::1]", 8443),
            ("api.example.com.", "https", "api.example.com.", 443),
        ],
    )
    def test_valid_authorities(self, authority: str, scheme: str, host: str, port: int) -> None:
        expected = Origin(scheme, host, port)
        allowed = set(ALLOWED_ORIGINS)
        allowed.add(expected)
        if host.endswith("."):
            allowed.add(Origin(scheme, host[:-1], port))
        adapter = OriginAdmissionAdapter(CERTIFICATE, allowed)
        decision = adapter.admit_request_headers(1, request_headers(authority, scheme=scheme))
        assert decision.allowed is True
        assert decision.origin == expected

    @pytest.mark.parametrize(
        "authority",
        [
            "[::1",
            "[v9.zone]",
            "203.0.113.7:abc",
            "api.example.com:0",
            "api.example.com:65536",
            "api.example.com:443:8443",
            "bad label.example.com",
            "api..example.com",
            "-leading.example.com",
            "trailing-.example.com",
            ":443",
            "api.example.com:",
            "a" * 254 + ".example.com",
            "[2001:db8::1]extra",
            "[2001:db8::1]:",
        ],
    )
    def test_malformed_authorities_are_rejected(self, authority: str) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers(authority))
        assert decision.allowed is False
        assert decision.reason in (RejectionReason.MALFORMED_AUTHORITY, RejectionReason.CERTIFICATE_NAME_MISMATCH)
        assert decision.status_code == 400 if decision.reason is RejectionReason.MALFORMED_AUTHORITY else decision.status_code == 421

    def test_unknown_scheme_requires_explicit_port(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("api.example.com", scheme="grpc"))
        assert decision.reason is RejectionReason.MALFORMED_AUTHORITY
        assert decision.status_code == 400

    @pytest.mark.parametrize("scheme", ["HTTPS", "1https", "ht tps", "ht!tps"])
    def test_invalid_scheme_tokens(self, scheme: str) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("api.example.com", scheme=scheme))
        assert decision.reason is RejectionReason.INVALID_SCHEME
        assert decision.status_code == 400

    def test_missing_pseudo_headers(self) -> None:
        adapter = make_adapter()
        decision = adapter.admit_request_headers(
            1, [(b":method", b"GET"), (b":path", b"/"), (b":authority", b"api.example.com")],
        )
        assert decision.reason is RejectionReason.MISSING_PSEUDO_HEADER
        assert decision.status_code == 400

    def test_duplicate_pseudo_headers_are_rejected(self) -> None:
        decision = make_adapter().admit_request_headers(
            1,
            [
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"https"),
                (b":authority", b"api.example.com"),
                (b":authority", b"cdn.example.com"),
            ],
        )
        assert decision.reason is RejectionReason.MISSING_PSEUDO_HEADER

    def test_host_header_used_when_authority_absent(self) -> None:
        decision = make_adapter().admit_request_headers(
            1,
            [
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"https"),
                (b"host", b"api.example.com"),
            ],
        )
        assert decision.allowed is True
        assert decision.origin == Origin("https", "api.example.com", 443)

    def test_conflicting_host_and_authority(self) -> None:
        decision = make_adapter().admit_request_headers(
            1,
            request_headers(
                "api.example.com",
                extra=[("host", "other.example.com")],
            ),
        )
        assert decision.allowed is False
        assert decision.reason is RejectionReason.HOST_CONFLICT
        assert decision.status_code == 400
        assert decision.origin is None

    def test_matching_host_and_authority_is_accepted(self) -> None:
        decision = make_adapter().admit_request_headers(
            1,
            request_headers("api.example.com", extra=[("host", "api.example.com")]),
        )
        assert decision.allowed is True

    def test_duplicate_host_headers_are_rejected(self) -> None:
        decision = make_adapter().admit_request_headers(
            1,
            [
                (b":method", b"GET"),
                (b":path", b"/"),
                (b":scheme", b"https"),
                (b"host", b"api.example.com"),
                (b"host", b"cdn.example.com"),
            ],
        )
        assert decision.reason is RejectionReason.MISSING_PSEUDO_HEADER
        assert decision.status_code == 400


class TestCertificateCoverage:
    def test_exact_dns_match(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("cdn.example.com"))
        assert decision.allowed is True
        assert decision.certificate_covered is True

    def test_wildcard_matches_single_label_only(self) -> None:
        accepted = make_adapter().admit_request_headers(1, request_headers("img.wild.example.com"))
        assert accepted.allowed is True
        rejected = make_adapter().admit_request_headers(
            3, request_headers("deep.img.wild.example.com"),
        )
        assert rejected.reason is RejectionReason.CERTIFICATE_NAME_MISMATCH
        assert rejected.status_code == 421
        assert rejected.certificate_covered is False

    def test_wildcard_does_not_match_base_domain(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("wild.example.com"))
        assert decision.reason is RejectionReason.CERTIFICATE_NAME_MISMATCH

    def test_name_not_on_certificate(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("evil.example.org"))
        assert decision.reason is RejectionReason.CERTIFICATE_NAME_MISMATCH
        assert decision.status_code == 421

    def test_ip_literal_covered_by_ip_san(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("203.0.113.7"))
        assert decision.allowed is True
        v6 = make_adapter().admit_request_headers(3, request_headers("[2001:db8::1]"))
        assert v6.allowed is True

    def test_ip_literal_absent_from_certificate(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("198.51.100.9"))
        assert decision.reason is RejectionReason.CERTIFICATE_NAME_MISMATCH

    def test_wildcard_dns_name_never_covers_ip_literal(self) -> None:
        certificate = TLSCertificateInfo.create(dns_names=["*.example.com"])
        adapter = OriginAdmissionAdapter(
            certificate, {Origin("https", "203.0.113.7", 443)},
        )
        decision = adapter.admit_request_headers(1, request_headers("203.0.113.7"))
        assert decision.reason is RejectionReason.CERTIFICATE_NAME_MISMATCH

    def test_without_tls_information_every_https_origin_is_uncovered(self) -> None:
        adapter = OriginAdmissionAdapter(None, ALLOWED_ORIGINS)
        decision = adapter.admit_request_headers(1, request_headers("api.example.com"))
        assert decision.reason is RejectionReason.CERTIFICATE_NAME_MISMATCH

    def test_plain_http_does_not_require_certificate_coverage(self) -> None:
        adapter = OriginAdmissionAdapter(None, {Origin("http", "plain.example.com", 80)})
        decision = adapter.admit_request_headers(
            1, request_headers("plain.example.com", scheme="http"),
        )
        assert decision.allowed is True
        assert decision.certificate_covered is False
        assert decision.origin == Origin("http", "plain.example.com", 80)


class TestAllowSet:
    def test_certificate_covered_but_unauthorized_origin_is_rejected(self) -> None:
        decision = make_adapter().admit_request_headers(1, request_headers("shared-cert.example.net"))
        assert decision.allowed is False
        assert decision.reason is RejectionReason.ORIGIN_NOT_ALLOWED
        assert decision.certificate_covered is True
        assert decision.status_code == 403

    def test_allow_set_is_scheme_and_port_sensitive(self) -> None:
        adapter = make_adapter()
        different_port = adapter.admit_request_headers(1, request_headers("api.example.com:8443"))
        assert different_port.reason is RejectionReason.ORIGIN_NOT_ALLOWED
        different_scheme = adapter.admit_request_headers(
            3, request_headers("api.example.com", scheme="http"),
        )
        assert different_scheme.reason is RejectionReason.ORIGIN_NOT_ALLOWED
        assert different_scheme.origin == Origin("http", "api.example.com", 80)

    def test_plain_http_allowed_origin(self) -> None:
        decision = make_adapter().admit_request_headers(
            1, request_headers("plain.example.com", scheme="http"),
        )
        assert decision.allowed is True
        assert decision.origin == Origin("http", "plain.example.com", 80)


class TestStreamIsolation:
    def _three_interleaved_streams(self) -> OriginAdmissionAdapter:
        adapter = make_adapter()
        first = adapter.admit_request_headers(1, request_headers("api.example.com"))
        second = adapter.admit_request_headers(3, request_headers("cdn.example.com"))
        third = adapter.admit_request_headers(5, request_headers("shared-cert.example.net"))
        assert first.allowed
        assert second.allowed
        assert third.reason is RejectionReason.ORIGIN_NOT_ALLOWED
        return adapter

    def test_rejecting_one_stream_preserves_other_identities(self) -> None:
        adapter = self._three_interleaved_streams()
        assert adapter.admitted_streams() == (1, 3)
        assert adapter.origin_for_stream(1) == Origin("https", "api.example.com", 443)
        assert adapter.origin_for_stream(3) == Origin("https", "cdn.example.com", 443)
        assert adapter.origin_for_stream(5) is None
        rejected = adapter.decision_for_stream(5)
        assert rejected is not None
        assert rejected.reason is RejectionReason.ORIGIN_NOT_ALLOWED

    def test_audit_trail_records_every_independent_decision(self) -> None:
        adapter = self._three_interleaved_streams()
        entries = adapter.audit_trail
        assert [entry.stream_id for entry in entries] == [1, 3, 5]
        assert [entry.allowed for entry in entries] == [True, True, False]
        allowed_entries = [entry for entry in entries if entry.allowed]
        for entry in allowed_entries:
            assert entry.phase == "request"
            assert entry.origin in ALLOWED_ORIGINS
            assert entry.certificate_covered is True

    def test_admitting_same_stream_twice_is_a_programming_error(self) -> None:
        adapter = make_adapter()
        adapter.admit_request_headers(1, request_headers("api.example.com"))
        with pytest.raises(AdmissionError, match="already admitted"):
            adapter.admit_request_headers(1, request_headers("cdn.example.com"))
        assert adapter.origin_for_stream(1) == Origin("https", "api.example.com", 443)

    def test_string_headers_are_accepted(self) -> None:
        decision = make_adapter().admit_request_headers(
            1,
            [(":method", "GET"), (":path", "/"), (":scheme", "https"), (":authority", "api.example.com")],
        )
        assert decision.allowed is True


class TestTrailers:
    def test_ordinary_trailers_keep_fixed_origin(self) -> None:
        adapter = make_adapter()
        adapter.admit_request_headers(1, request_headers("api.example.com"))
        decision = adapter.inspect_trailers(1, [(b"x-trace-id", b"abc")])
        assert isinstance(decision, TrailerDecision)
        assert decision.allowed is True
        assert decision.origin == Origin("https", "api.example.com", 443)

    @pytest.mark.parametrize("forbidden", [b":authority", b"host", b":scheme", b":path", b":method"])
    def test_trailers_cannot_rewrite_origin(self, forbidden: bytes) -> None:
        adapter = make_adapter()
        adapter.admit_request_headers(1, request_headers("api.example.com"))
        decision = adapter.inspect_trailers(1, [(forbidden, b"evil.example.org"), (b"x", b"y")])
        assert decision.allowed is False
        assert decision.reason is RejectionReason.TRAILER_PSEUDO_HEADER
        assert decision.status_code == 400
        assert adapter.origin_for_stream(1) == Origin("https", "api.example.com", 443)

    def test_trailers_on_unknown_stream_are_rejected(self) -> None:
        decision = make_adapter().inspect_trailers(99, [(b"x", b"y")])
        assert decision.reason is RejectionReason.UNKNOWN_STREAM
        assert decision.status_code == 400

    def test_trailer_audit_entries_reference_the_fixed_origin(self) -> None:
        adapter = make_adapter()
        adapter.admit_request_headers(1, request_headers("api.example.com"))
        adapter.inspect_trailers(1, [(b"x-trace-id", b"abc")])
        adapter.inspect_trailers(1, [(b":authority", b"evil.example.org")])
        trailer_entries = [entry for entry in adapter.audit_trail if entry.phase == "trailer"]
        assert [entry.allowed for entry in trailer_entries] == [True, False]
        assert {entry.origin for entry in trailer_entries} == {Origin("https", "api.example.com", 443)}


class TestH2Integration:
    def _server_and_client(self) -> tuple[h2.connection.H2Connection, h2.connection.H2Connection]:
        client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
        server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        client.initiate_connection()
        server.receive_data(client.data_to_send())
        client.receive_data(server.data_to_send())
        return client, server

    def test_request_events_feed_directly_into_adapter(self) -> None:
        client, server = self._server_and_client()
        adapter = make_adapter()
        dispatch: dict[int, Origin] = {}
        stream_requests = [
            (1, "api.example.com"),
            (3, "cdn.example.com"),
            (5, "shared-cert.example.net"),
        ]
        for stream_id, authority in stream_requests:
            client.send_headers(stream_id, request_headers(authority), end_stream=True)
        for event in server.receive_data(client.data_to_send()):
            if isinstance(event, h2.events.RequestReceived):
                decision = adapter.admit_request_event(event)
                if decision.allowed:
                    assert decision.origin is not None
                    dispatch[event.stream_id] = decision.origin
                server.send_headers(
                    event.stream_id,
                    [(b":status", b"204" if decision.allowed else str(decision.status_code).encode())],
                    end_stream=True,
                )
        assert dispatch == {
            1: Origin("https", "api.example.com", 443),
            3: Origin("https", "cdn.example.com", 443),
        }
        assert adapter.admitted_streams() == (1, 3)
        responses = client.receive_data(server.data_to_send())
        statuses = {
            event.stream_id: dict(event.headers)[b":status"]
            for event in responses
            if isinstance(event, h2.events.ResponseReceived)
        }
        assert statuses == {1: b"204", 3: b"204", 5: b"403"}

    def test_trailer_events_cannot_change_dispatched_origin(self) -> None:
        client, server = self._server_and_client()
        adapter = make_adapter()
        client.send_headers(1, request_headers("api.example.com"))
        client.send_data(1, b"payload")
        client.send_headers(1, [(b"x-trace", b"abc")], end_stream=True)
        origins: list[Origin] = []
        for event in server.receive_data(client.data_to_send()):
            if isinstance(event, h2.events.RequestReceived):
                decision = adapter.admit_request_event(event)
                assert decision.allowed
            elif isinstance(event, h2.events.TrailersReceived):
                trailer_decision = adapter.inspect_trailer_event(event)
                assert trailer_decision.allowed
                fixed_origin = adapter.origin_for_stream(event.stream_id)
                assert fixed_origin is not None
                origins.append(fixed_origin)
        assert origins == [Origin("https", "api.example.com", 443)]

    def test_h2_rejects_conflicting_host_before_adapter_runs(self) -> None:
        from tests.helpers import FrameFactory

        _client, server = self._server_and_client()
        raw_headers = request_headers("api.example.com", extra=[("host", "other.example.com")])
        frame = FrameFactory().build_headers_frame(raw_headers, stream_id=1)  # type: ignore[no-untyped-call]
        with pytest.raises(h2.exceptions.ProtocolError):
            server.receive_data(frame.serialize())
