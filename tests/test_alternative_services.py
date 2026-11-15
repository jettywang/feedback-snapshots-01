"""
Tests for the restricted RFC 7838 alternative service cache.
"""

from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.events

import h2.alternative_services


class FakeClock:
    """
    A deterministic clock for cache freshness tests.
    """

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_event(
    *,
    stream_id: int = 0,
    origin: bytes | str | None = b"https://example.com",
    field: bytes | None = b'h2=":8000"; ma=60',
) -> h2.events.AlternativeServiceAvailable:
    """
    Build an AlternativeServiceAvailable event like h2 would emit.
    """
    event = h2.events.AlternativeServiceAvailable()
    event.stream_id = stream_id
    event.origin = origin
    event.field_value = field
    return event


def identity_for(
    origin: str = "https://example.com",
    *,
    verified: bool = True,
    peer_names: tuple[str, ...] = ("example.com",),
) -> h2.alternative_services.TlsIdentity:
    return h2.alternative_services.TlsIdentity(
        origin,
        verified=verified,
        peer_names=peer_names,
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def cache(clock: FakeClock) -> h2.alternative_services.AlternativeServiceCache:
    return h2.alternative_services.AlternativeServiceCache(
        ["https://example.com"],
        clock=clock,
    )


class TestConnectionLevelAdvertisements:
    """
    Stream 0 ALTSVC frames carry an explicit origin.
    """

    def test_connection_event_is_accepted_as_inert_candidate(self, cache: FakeClock, clock: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"https://example.com"),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.ACCEPTED
        assert update.source is h2.alternative_services.AdvertisementSource.CONNECTION
        assert len(update.added) == 1

        candidate = update.added[0]
        assert candidate.origin.host == "example.com"
        assert candidate.protocol_id == "h2"
        assert candidate.host == "example.com"
        assert candidate.port == 8000
        assert candidate.stream_id == 0
        assert candidate.source is h2.alternative_services.AdvertisementSource.CONNECTION
        assert candidate.advertised_at == clock.now
        assert candidate.expires_at == clock.now + 60
        assert candidate.persist is False
        assert cache.candidates("https://example.com") == (candidate,)

    def test_connection_event_origin_may_be_written_as_origin(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"https://example.com:443"),
            tls_identity=identity_for(),
        )

        assert update.accepted
        assert update.origin == h2.alternative_services.parse_origin("https://example.com")

    def test_connection_event_without_origin_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b""),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNTRUSTED_ORIGIN
        assert cache.candidates("https://example.com") == ()

    def test_connection_event_accepts_bare_authority_as_origin(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"example.com"),
            tls_identity=identity_for(),
        )

        # h2 passes the frame's origin through verbatim, and existing peers
        # commonly send a bare authority.  It is canonicalized with the
        # cache's default scheme but still must match a trusted origin.
        assert update.accepted
        assert update.origin == h2.alternative_services.parse_origin("https://example.com")

    def test_stream_event_is_not_a_connection_event(self, cache: FakeClock) -> None:
        event = make_event(stream_id=1, origin=b"example.com")

        update = cache.offer_connection(event, tls_identity=identity_for())

        assert update.status is h2.alternative_services.AdmissionStatus.WRONG_STREAM
        assert cache.candidates("https://example.com") == ()


class TestStreamLevelAdvertisements:
    """
    Stream-level ALTSVC frames take their origin from the request authority.
    """

    example_request_headers = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def receive_stream_event(self, frame_factory, stream_id: int = 1) -> h2.events.AlternativeServiceAvailable:
        connection = h2.connection.H2Connection()
        connection.initiate_connection()
        connection.send_headers(stream_id=1, headers=self.example_request_headers)
        connection.clear_outbound_data_buffer()

        frame = frame_factory.build_alt_svc_frame(
            stream_id=stream_id,
            origin=b"",
            field=b'h2=":8000"; ma=60',
        )
        events = connection.receive_data(frame.serialize())
        assert len(events) == 1
        assert isinstance(events[0], h2.events.AlternativeServiceAvailable)
        return events[0]

    def test_h2_reports_stream_id_on_event(self, frame_factory, cache: FakeClock) -> None:
        event = self.receive_stream_event(frame_factory)

        assert event.stream_id == 1
        assert event.origin == b"example.com"

        update = cache.offer_stream(event, tls_identity=identity_for())
        assert update.accepted
        assert update.source is h2.alternative_services.AdvertisementSource.STREAM
        assert update.added[0].stream_id == 1

    def test_pushed_stream_uses_pushed_authority(self, frame_factory, cache: FakeClock) -> None:
        connection = h2.connection.H2Connection()
        connection.initiate_connection()
        connection.send_headers(stream_id=1, headers=self.example_request_headers)

        pushed_headers = [
            (":authority", "example.com"),
            (":path", "/pushed"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        push = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=pushed_headers,
        )
        connection.receive_data(push.serialize())
        connection.clear_outbound_data_buffer()

        frame = frame_factory.build_alt_svc_frame(
            stream_id=2,
            origin=b"",
            field=b'h2=":8000"; ma=60',
        )
        events = connection.receive_data(frame.serialize())
        assert len(events) == 1
        assert events[0].stream_id == 2
        assert events[0].origin == b"example.com"

        update = cache.offer_stream(events[0], tls_identity=identity_for())
        assert update.accepted
        assert update.added[0].stream_id == 2

    def test_connection_event_is_not_a_stream_event(self, cache: FakeClock) -> None:
        update = cache.offer_stream(
            make_event(stream_id=0, origin=b"https://example.com"),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.WRONG_STREAM
        assert cache.candidates("https://example.com") == ()

    def test_stream_event_with_scheme_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer_stream(
            make_event(stream_id=1, origin=b"https://example.com"),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.WRONG_STREAM
        assert cache.candidates("https://example.com") == ()

    def test_stream_event_without_inferred_origin_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer_stream(
            make_event(stream_id=1, origin=None),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.WRONG_STREAM
        assert cache.candidates("https://example.com") == ()

    def test_stream_event_with_bad_stream_id_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer(
            make_event(stream_id=-1, origin=b"example.com"),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.WRONG_STREAM
        assert cache.candidates("https://example.com") == ()


class TestOriginAndIdentityVerification:
    """
    Advertisements cannot establish trust or transfer it to another origin.
    """

    def test_untrusted_origin_is_not_stored(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"https://other.example"),
            tls_identity=identity_for("https://other.example", peer_names=("other.example",)),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNTRUSTED_ORIGIN
        assert cache.candidates("https://other.example") == ()
        assert cache.candidates("https://example.com") == ()

    def test_identity_for_another_origin_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"https://example.com"),
            tls_identity=identity_for("https://other.example", peer_names=("other.example",)),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNVERIFIED_CONNECTION
        assert cache.candidates("https://example.com") == ()

    def test_unverified_identity_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"https://example.com"),
            tls_identity=identity_for(verified=False, peer_names=()),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNVERIFIED_CONNECTION
        assert cache.candidates("https://example.com") == ()

    def test_verified_identity_without_peer_names_is_refused(self) -> None:
        with pytest.raises(ValueError):
            h2.alternative_services.TlsIdentity(
                "https://example.com",
                verified=True,
                peer_names=(),
            )

    def test_identity_peer_names_must_cover_origin_host(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(stream_id=0, origin=b"https://example.com"),
            tls_identity=identity_for(peer_names=("other.example",)),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNVERIFIED_CONNECTION

    def test_wildcard_peer_name_covers_origin(self) -> None:
        identity = h2.alternative_services.TlsIdentity(
            "https://api.example.com",
            verified=True,
            peer_names=("*.example.com",),
        )

        assert identity.authorizes("https://api.example.com")

    def test_wildcard_peer_name_does_not_cross_labels(self) -> None:
        identity = identity_for(peer_names=("*.example.com",))

        assert identity.covers_host("a.example.com")
        assert not identity.covers_host("example.com")
        assert not identity.covers_host("a.b.example.com")


class TestMaxAgeUpdatesAndClearing:
    """
    ``ma`` controls expiry; updates and clear operations are well-scoped.
    """

    def test_update_replaces_candidate_for_same_protocol(self, cache: FakeClock, clock: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        old = first.added[0]
        clock.advance(10)

        second = cache.offer_connection(
            make_event(field=b'h2=":8001"; ma=30'),
            tls_identity=identity_for(),
        )

        assert second.accepted
        assert second.removed == (old,)
        assert [candidate.port for candidate in cache.candidates("https://example.com")] == [8001]
        assert second.added[0].expires_at == clock.now + 30

    def test_multiple_alternatives_for_one_protocol_are_kept(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60, h2="alt.example.com:443"; ma=60'),
            tls_identity=identity_for(),
        )

        assert update.accepted
        assert len(update.added) == 2
        assert {candidate.authority for candidate in update.added} == {"example.com:8000", "alt.example.com:443"}

    def test_unsupported_protocol_does_not_replace_candidate(self, cache: FakeClock) -> None:
        cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        old = cache.candidates("https://example.com")

        update = cache.offer_connection(
            make_event(field=b'h3=":443"; ma=60'),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNSUPPORTED_PROTOCOL
        assert cache.candidates("https://example.com") == old

    def test_protocol_identifier_is_case_sensitive(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'H2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )

        # Protocol identifiers are ALPN identifiers and are case-sensitive.
        assert update.status is h2.alternative_services.AdmissionStatus.UNSUPPORTED_PROTOCOL

    def test_ma_zero_removes_candidate_for_protocol(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=0'),
            tls_identity=identity_for(),
        )

        assert update.accepted
        assert update.added == ()
        assert update.removed == first.added
        assert cache.candidates("https://example.com") == ()

    def test_default_ma_is_one_day(self, cache: FakeClock, clock: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"'),
            tls_identity=identity_for(),
        )

        assert update.added[0].expires_at == clock.now + 86400

    def test_persist_parameter_is_recorded(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60; persist=1'),
            tls_identity=identity_for(),
        )

        assert update.added[0].persist is True

    def test_header_clear_removes_candidates(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.apply_header(
            "https://example.com",
            b"clear",
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.CLEARED
        assert update.removed == first.added
        assert cache.candidates("https://example.com") == ()

    def test_altsvc_frame_cannot_clear(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.offer_connection(
            make_event(field=b"clear"),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.CLEAR_NOT_ALLOWED
        assert cache.candidates("https://example.com") == first.added

    def test_clear_without_matching_identity_does_nothing(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.clear(
            "https://example.com",
            tls_identity=identity_for(verified=False, peer_names=()),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNVERIFIED_CONNECTION
        assert cache.candidates("https://example.com") == first.added

    def test_clear_from_untrusted_origin_does_nothing(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.clear(
            "https://other.example",
            tls_identity=identity_for("https://other.example", peer_names=("other.example",)),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.UNTRUSTED_ORIGIN
        assert cache.candidates("https://example.com") == first.added


class TestMalformedAdvertisements:
    """
    Bad advertisements are rejected atomically and never displace good state.
    """

    @pytest.mark.parametrize(
        "field",
        [
            b'h2=":0"; ma=60',
            b'h2=":65536"; ma=60',
            b'h2=":8000"; ma=abc',
            b'h2=":8000"; ma=60; ma=30',
            b'h2=":8000"; persist=2',
            b'h2=":8000" junk',
            b'h2=":8000; ma=60',
            b'h2=":8000"; ma=60,',
            b"clear",
            b'h2=":8000"; ma=60\xff',
        ],
    )
    def test_malformed_field_does_not_replace_valid_candidate(
        self,
        cache: FakeClock,
        field: bytes,
    ) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.offer_connection(
            make_event(field=field),
            tls_identity=identity_for(),
        )

        assert not update.accepted
        assert cache.candidates("https://example.com") == first.added

    def test_quoted_ma_is_rejected(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma="60"'),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.MALFORMED

    def test_one_bad_alternative_rejects_whole_field(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60, h3="not-a-port"; ma=30'),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.MALFORMED
        assert cache.candidates("https://example.com") == ()

    def test_field_can_be_bounded(self, clock: FakeClock) -> None:
        cache = h2.alternative_services.AlternativeServiceCache(
            ["https://example.com"],
            clock=clock,
            max_field_length=16,
        )

        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.MALFORMED

    def test_candidate_count_is_bounded(self, clock: FakeClock) -> None:
        cache = h2.alternative_services.AlternativeServiceCache(
            ["https://example.com"],
            clock=clock,
            max_candidates_per_origin=2,
        )

        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60, h2=":8001"; ma=60, h2=":8002"; ma=60'),
            tls_identity=identity_for(),
        )

        assert update.status is h2.alternative_services.AdmissionStatus.TOO_MANY_CANDIDATES
        assert cache.candidates("https://example.com") == ()


class TestExpiry:
    """
    Candidates stop being usable at their advertised freshness lifetime.
    """

    def test_candidate_expires_at_ma_boundary(self, cache: FakeClock, clock: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        candidate = update.added[0]
        identity = identity_for()

        clock.advance(59)
        assert cache.candidates("https://example.com") == (candidate,)
        assert cache.authorize("https://example.com", candidate, tls_identity=identity)

        clock.advance(1)
        assert cache.candidates("https://example.com") == ()
        assert cache.authorize("https://example.com", candidate, tls_identity=identity) is False
        assert cache.select("https://example.com", tls_identity=identity) is None

    def test_expired_records_are_purged(self, cache: FakeClock, clock: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        clock.advance(61)

        removed = cache.purge_expired()

        assert removed == first.added
        assert cache.candidates("https://example.com") == ()


class TestTargetSelection:
    """
    A candidate is never a target until the original origin is re-authorized.
    """

    def test_select_requires_a_verified_identity(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert update.accepted

        assert cache.select("https://example.com", tls_identity=None) is None
        assert cache.select("https://example.com", tls_identity=identity_for(verified=False, peer_names=())) is None

    def test_select_rejects_identity_for_another_origin(self, cache: FakeClock) -> None:
        cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )

        assert (
            cache.select(
                "https://example.com",
                tls_identity=identity_for("https://other.example", peer_names=("other.example",)),
            )
            is None
        )

    def test_select_returns_candidate_after_identity_verification(self, cache: FakeClock) -> None:
        candidate = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        ).added[0]

        selected = cache.select("https://example.com", tls_identity=identity_for())

        assert selected == candidate
        assert cache.authorize("https://example.com", candidate, tls_identity=identity_for())

    def test_stale_candidate_after_update_is_not_authorized(self, cache: FakeClock) -> None:
        old = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        ).added[0]
        cache.offer_connection(
            make_event(field=b'h2=":8001"; ma=60'),
            tls_identity=identity_for(),
        )

        assert cache.authorize("https://example.com", old, tls_identity=identity_for()) is False

    def test_rejected_advertisement_does_not_affect_authorized_candidate(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        candidate = first.added[0]

        rejected = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(verified=False, peer_names=()),
        )

        assert rejected.status is h2.alternative_services.AdmissionStatus.UNVERIFIED_CONNECTION
        assert cache.authorize("https://example.com", candidate, tls_identity=identity_for())

    def test_unknown_origin_never_has_candidates(self, cache: FakeClock) -> None:
        cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )

        assert cache.candidates("https://unknown.example") == ()
        assert (
            cache.select(
                "https://unknown.example",
                tls_identity=identity_for("https://unknown.example", peer_names=("unknown.example",)),
            )
            is None
        )


class SelectionDouble:
    """
    Stands in for the connection layer that would use a selected candidate.

    It records connection attempts and refuses to emit a request or credentials
    unless the cache authorizes a specific live candidate for the original
    origin with an identity verified on the new connection.
    """

    def __init__(self, cache: h2.alternative_services.AlternativeServiceCache) -> None:
        self.cache = cache
        self.connection_attempts: list[h2.alternative_services.AlternativeServiceCandidate] = []
        self.requests: list[tuple[str, bytes]] = []
        self.credentials: list[bytes] = []

    def connect_and_request(
        self,
        origin: str,
        candidate: h2.alternative_services.AlternativeServiceCandidate,
        *,
        tls_identity: h2.alternative_services.TlsIdentity | None,
        request: bytes = b"",
        credential: bytes = b"secret",
    ) -> bool:
        self.connection_attempts.append(candidate)
        if tls_identity is None:
            return False
        if not self.cache.authorize(origin, candidate, tls_identity=tls_identity):
            return False

        self.requests.append((origin, request))
        self.credentials.append(credential)
        return True


class TestNoRequestBeforeVerification:
    """
    An advertisement cannot itself cause a request or credential to be sent.
    """

    def test_advertisement_alone_sends_nothing(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        candidate = update.added[0]
        selection = SelectionDouble(cache)

        assert (
            selection.connect_and_request(
                "https://example.com",
                candidate,
                tls_identity=None,
            )
            is False
        )
        assert selection.connection_attempts == [candidate]
        assert selection.requests == []
        assert selection.credentials == []

    def test_unverified_identity_sends_nothing(self, cache: FakeClock) -> None:
        candidate = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        ).added[0]
        selection = SelectionDouble(cache)

        assert (
            selection.connect_and_request(
                "https://example.com",
                candidate,
                tls_identity=identity_for(verified=False, peer_names=()),
            )
            is False
        )
        assert selection.requests == []
        assert selection.credentials == []

    def test_identity_for_advertised_address_alone_is_not_authority(self, cache: FakeClock) -> None:
        candidate = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        ).added[0]
        elsewhere = h2.alternative_services.TlsIdentity(
            "https://example.com",
            verified=False,
            peer_names=("example.com",),
        )
        selection = SelectionDouble(cache)

        assert (
            selection.connect_and_request(
                "https://example.com",
                candidate,
                tls_identity=elsewhere,
            )
            is False
        )
        assert selection.requests == []
        assert selection.credentials == []

    def test_verified_origin_identity_allows_request(self, cache: FakeClock) -> None:
        candidate = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        ).added[0]
        selection = SelectionDouble(cache)

        assert (
            selection.connect_and_request(
                "https://example.com",
                candidate,
                tls_identity=identity_for(),
                request=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            )
            is True
        )
        assert selection.requests == [
            ("https://example.com", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ]
        assert selection.credentials == [b"secret"]

    def test_expired_candidate_cannot_be_used(self, cache: FakeClock, clock: FakeClock) -> None:
        candidate = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        ).added[0]
        selection = SelectionDouble(cache)
        clock.advance(60)

        assert (
            selection.connect_and_request(
                "https://example.com",
                candidate,
                tls_identity=identity_for(),
            )
            is False
        )
        assert selection.requests == []
        assert selection.credentials == []

    def test_h2_altsvc_event_does_not_write_to_connection(self, frame_factory, cache: FakeClock) -> None:
        connection = h2.connection.H2Connection()
        connection.initiate_connection()
        connection.send_headers(
            stream_id=1,
            headers=[
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
        )
        connection.clear_outbound_data_buffer()

        frame = frame_factory.build_alt_svc_frame(
            stream_id=1,
            origin=b"",
            field=b'h2=":8000"; ma=60',
        )
        events = connection.receive_data(frame.serialize())
        update = cache.offer_stream(events[0], tls_identity=identity_for())
        assert update.accepted

        # Neither receiving the frame nor caching the candidate produces
        # outbound request data on the existing connection.
        assert connection.data_to_send() == b""

        selection = SelectionDouble(cache)
        candidate = update.added[0]
        assert selection.connect_and_request("https://example.com", candidate, tls_identity=None) is False
        assert selection.requests == []
        assert selection.credentials == []


class TestOriginParsingEdges:
    """
    Origin values from peers and configuration are canonicalized, not trusted.
    """

    @pytest.mark.parametrize(
        "origin",
        [
            "https://example.com",
            "https://example.com:443",
            "https://example.com/",
            "HTTPS://EXAMPLE.COM",
            b"https://example.com",
        ],
    )
    def test_equivalent_https_origins_canonicalize(self, origin) -> None:
        parsed = h2.alternative_services.parse_origin(origin)

        assert parsed == h2.alternative_services.Origin("https", "example.com", 443)
        assert str(parsed) == "https://example.com"

    @pytest.mark.parametrize(
        "origin",
        [
            "https://example.com/path",
            "https://example.com?query",
            "https://example.com#fragment",
            "https://user@example.com",
            "https://example.com:0",
            "https://example.com:70000",
            "https://[::1",
            "https://exa mple.com",
            "https://example.com\x00",
        ],
    )
    def test_invalid_origins_are_rejected(self, origin) -> None:
        with pytest.raises(ValueError):
            h2.alternative_services.parse_origin(origin)

    def test_stream_origin_uses_default_scheme(self) -> None:
        assert h2.alternative_services.parse_origin("example.com") == h2.alternative_services.Origin(
            "https",
            "example.com",
            443,
        )

    def test_origin_with_nondefault_port_is_kept(self) -> None:
        assert str(h2.alternative_services.parse_origin("https://example.com:8443")) == ("https://example.com:8443")

    def test_ipv6_origin_round_trips(self) -> None:
        parsed = h2.alternative_services.parse_origin("https://[::1]:8443")

        assert parsed == h2.alternative_services.Origin("https", "::1", 8443)
        assert str(parsed) == "https://[::1]:8443"

    def test_alternative_for_other_host_is_stored_but_not_selected_implicitly(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(field=b'h2="alt.example.com:443"; ma=60'),
            tls_identity=identity_for(),
        )

        assert update.accepted
        assert update.added[0].host == "alt.example.com"

    def test_alternative_host_need_not_match_origin_host(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )

        assert first.accepted
        assert cache.candidates("https://example.com")[0].host == "example.com"

    def test_empty_alternative_host_means_origin_host(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )

        assert first.accepted
        assert first.added[0].authority == "example.com:8000"

    def test_origin_event_origin_field_is_reported(self, cache: FakeClock) -> None:
        update = cache.offer_connection(
            make_event(origin=b"https://example.com"),
            tls_identity=identity_for(),
        )

        assert update.origin == h2.alternative_services.Origin("https", "example.com", 443)
        assert update.source is h2.alternative_services.AdvertisementSource.CONNECTION

    def test_clear_is_case_insensitive_but_only_for_headers(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.apply_header("https://example.com", b"CLEAR", tls_identity=identity_for())

        assert update.status is h2.alternative_services.AdmissionStatus.CLEARED
        assert cache.candidates("https://example.com") == ()

    def test_clear_with_whitespace_is_accepted_for_headers(self, cache: FakeClock) -> None:
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert first.accepted

        update = cache.apply_header("https://example.com", b"  clear \t", tls_identity=identity_for())

        assert update.status is h2.alternative_services.AdmissionStatus.CLEARED

    def test_clear_alone_does_not_affect_other_origins(self, clock: FakeClock) -> None:
        cache = h2.alternative_services.AlternativeServiceCache(
            ["https://example.com", "https://other.example"],
            clock=clock,
        )
        first = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        other = cache.offer_connection(
            make_event(origin=b"https://other.example", field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for("https://other.example", peer_names=("other.example",)),
        )
        assert first.accepted and other.accepted

        cache.apply_header("https://example.com", b"clear", tls_identity=identity_for())

        assert cache.candidates("https://example.com") == ()
        assert cache.candidates("https://other.example") == other.added


class TestBatchAndHostileSequence:
    """
    Ordered advertisement sequences cannot launder an untrusted origin.
    """

    def test_offer_events_reports_each_result(self, cache: FakeClock) -> None:
        events = [
            make_event(stream_id=0, origin=b"https://example.com"),
            make_event(stream_id=0, origin=b"https://unknown.example"),
            make_event(stream_id=1, origin=b"https://example.com"),
        ]
        updates = cache.offer_events(events, tls_identity=identity_for())

        assert updates[0].accepted
        assert updates[1].status is h2.alternative_services.AdmissionStatus.UNTRUSTED_ORIGIN
        assert updates[2].status is h2.alternative_services.AdmissionStatus.WRONG_STREAM
        assert len(cache.candidates("https://example.com")) == 1

    def test_hostile_sequence_does_not_replace_trusted_candidate(self, cache: FakeClock, clock: FakeClock) -> None:
        trusted = cache.offer_connection(
            make_event(field=b'h2=":8000"; ma=60'),
            tls_identity=identity_for(),
        )
        assert trusted.accepted

        clock.advance(1)
        attempts = [
            make_event(field=b'h2=":9000"; ma=60\xff'),
            make_event(field=b'h2=":9001"; ma=60; ma=5'),
            make_event(field=b'h2=":9002"; ma="60"'),
            make_event(field=b'h2=":9003"; ma=60, h3="bad-port"; ma=60'),
            make_event(field=b"clear"),
        ]
        for event in attempts:
            update = cache.offer_connection(event, tls_identity=identity_for())
            assert not update.accepted

        assert cache.candidates("https://example.com") == trusted.added
