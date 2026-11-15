"""
Tests for the restricted Early Hints consumer example.

Every test drives real :class:`H2Connection` peers and passes the resulting
``InformationalResponseReceived``/``ResponseReceived``/``StreamReset`` events
to the consumer.  No events are hand-constructed.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import pytest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes

from examples.early_hints.restricted_early_hints import (
    IgnoredLink,
    PrefetchPolicy,
    PrefetchRule,
    RecordingPrefetcher,
    RestrictedEarlyHintsConsumer,
    UserCache,
    parse_link_header,
)


class H2Fixture:
    """Two real h2 peers plus a consumer fed from the client's events."""

    def __init__(self, consumer: RestrictedEarlyHintsConsumer) -> None:
        self.consumer = consumer
        self.client = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        self.server = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        self.client.initiate_connection()
        self.server.initiate_connection()
        self.server.receive_data(self.client.data_to_send())
        self.client.receive_data(self.server.data_to_send())

    def _client_events(self) -> Iterable[object]:
        return self.client.receive_data(self.server.data_to_send())

    def open_request(self, stream_id: int, owner: str, url: str) -> None:
        self.consumer.begin_request(stream_id, owner, url)
        path = url.split("://", 1)[1].split("/", 1)
        authority = path[0]
        request_path = "/" + path[1] if len(path) > 1 else "/"
        self.client.send_headers(
            stream_id,
            [
                (":method", "GET"),
                (":scheme", url.split("://", 1)[0]),
                (":authority", authority),
                (":path", request_path),
            ],
        )
        self.server.receive_data(self.client.data_to_send())

    def hints(
        self,
        stream_id: int,
        links: Sequence[str],
        extra: Sequence[tuple[str, str]] = (),
    ) -> None:
        headers: list[tuple[str, str]] = [(":status", "103")]
        headers.extend(("link", link) for link in links)
        headers.extend(extra)
        self.server.send_headers(stream_id, headers)
        self.consumer.feed(self._client_events())

    def final_headers(
        self,
        stream_id: int,
        status: int,
        headers: Sequence[tuple[str, str]] = (),
    ) -> None:
        self.server.send_headers(
            stream_id,
            [(":status", str(status)), *headers],
        )
        self.consumer.feed(self._client_events())

    def end_stream(self, stream_id: int) -> None:
        self.server.send_data(stream_id, b"", end_stream=True)
        self.consumer.feed(self._client_events())

    def final(
        self,
        stream_id: int,
        status: int,
        headers: Sequence[tuple[str, str]] = (),
    ) -> None:
        self.server.send_headers(
            stream_id,
            [(":status", str(status)), *headers],
            end_stream=True,
        )
        self.consumer.feed(self._client_events())

    def reset(self, stream_id: int) -> None:
        self.server.reset_stream(stream_id, error_code=ErrorCodes.CANCEL)
        self.consumer.feed(self._client_events())


def build_consumer(
    rules: Sequence[PrefetchRule] | None = None,
) -> tuple[RestrictedEarlyHintsConsumer, RecordingPrefetcher, UserCache]:
    prefetcher = RecordingPrefetcher()
    cache = UserCache()
    policy = PrefetchPolicy(
        rules
        or [
            PrefetchRule("https://up.example", "/assets/"),
            PrefetchRule("https://cdn.example", "/theme.css"),
        ],
    )
    return RestrictedEarlyHintsConsumer(policy, prefetcher, cache), prefetcher, cache


class TestLinkParsing:
    def test_quoted_comma_and_semicolon_stay_inside_parameters(self) -> None:
        links = parse_link_header(
            '</assets/a.css>; rel=preload; as=style; title="a, b; c", ' "<https://cdn.example/theme.css>; rel=preload; as=style",
        )

        assert links is not None
        assert [link.target for link in links] == [
            "/assets/a.css",
            "https://cdn.example/theme.css",
        ]
        assert links[0].params["title"] == "a, b; c"

    def test_angle_brackets_inside_quoted_parameter_are_data(self) -> None:
        links = parse_link_header('</assets/a.css>; rel=preload; title="a <b> c"')

        assert links is not None
        assert links[0].params["title"] == "a <b> c"

    @pytest.mark.parametrize(
        "value",
        [
            '</assets/a.css>; rel=preload; title="unterminated',
            "</assets/a.css; rel=preload",
            "</assets/a.css>; rel=preload; rel=prefetch",
            '</assets/a.css>; rel="preload; as=style',
            "</assets/a.css>; bad param=value",
            "",
        ],
    )
    def test_unreliable_field_is_rejected_as_a_whole(self, value: str) -> None:
        assert parse_link_header(value) is None


class TestRestrictedPrefetch:
    def test_approved_hint_prefetches_without_credentials_then_commits(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(
            1,
            ["</assets/app.css>; rel=preload; as=style"],
            extra=[
                ("cache-control", "public, max-age=86400"),
                ("www-authenticate", 'Basic realm="asset"'),
            ],
        )

        assert [call.url for call in prefetcher.calls] == ["https://up.example/assets/app.css"]
        assert prefetcher.calls[0].credentials_sent is False
        assert cache.get("alice", "https://up.example/assets/app.css") is None

        h2.final(1, 200, [("cache-control", "public, max-age=60")])

        assert cache.get("alice", "https://up.example/assets/app.css") == (b"prefetched:https://up.example/assets/app.css")

    def test_200_headers_alone_do_not_commit_before_stream_end(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.hints(1, ["</assets/app.css>; rel=preload; as=style"])

        h2.final_headers(1, 200)
        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []

        h2.end_stream(1)
        assert cache.keys_for("alice") == ["https://up.example/assets/app.css"]

    def test_final_401_discards_prefetch_despite_103_cache_headers(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(
            1,
            ["</assets/app.css>; rel=preload; as=style"],
            extra=[("cache-control", "public, max-age=86400")],
        )
        h2.final(1, 401, [("cache-control", "no-store")])

        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []
        assert consumer.rejected_final_responses == [(1, "alice", 401, "final-status-not-authorized")]

    def test_103_cache_fields_are_not_final_policy(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        # A hint claiming no-store must not override a later allowed response.
        h2.hints(
            1,
            ["</assets/app.css>; rel=preload; as=style"],
            extra=[("cache-control", "no-store")],
        )
        h2.final(1, 200)
        assert cache.keys_for("alice") == ["https://up.example/assets/app.css"]

    @pytest.mark.parametrize("status", [206, 204, 304])
    def test_partial_and_bodyless_final_statuses_do_not_commit(self, status: int) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.hints(1, ["</assets/app.css>; rel=preload; as=style"])

        h2.final(1, status)

        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []
        assert consumer.rejected_final_responses == [(1, "alice", status, "final-status-not-authorized")]

    def test_unreadable_final_cache_policy_fails_closed(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.hints(1, ["</assets/app.css>; rel=preload; as=style"])

        h2.final(1, 200, [("cache-control", "public, \u00fc")])

        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []
        assert consumer.rejected_final_responses == [(1, "alice", 200, "unreadable-final-cache-policy")]

    def test_vary_star_cannot_authorize_a_shared_cache_entry(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.hints(1, ["</assets/app.css>; rel=preload; as=style"])

        h2.final(1, 200, [("vary", "*")])

        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []
        assert consumer.rejected_final_responses == [(1, "alice", 200, "final-cache-policy")]

    @pytest.mark.parametrize("directive", ["no-store", "private", "no-cache"])
    def test_final_response_cache_policy_can_still_block_commit(self, directive: str) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.hints(1, ["</assets/app.css>; rel=preload; as=style"])

        h2.final(1, 200, [("cache-control", f"public, {directive}")])

        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []
        assert consumer.rejected_final_responses == [(1, "alice", 200, "final-cache-policy")]

    def test_multiple_hints_fetch_each_approved_url_once(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(1, ["</assets/a.css>; rel=preload; as=style"])
        h2.hints(
            1,
            [
                "</assets/a.css>; rel=preload; as=style",
                "</assets/b.css>; rel=preload; as=style",
            ],
        )
        h2.final(1, 200)

        assert [call.url for call in prefetcher.calls] == [
            "https://up.example/assets/a.css",
            "https://up.example/assets/b.css",
        ]
        assert cache.keys_for("alice") == [
            "https://up.example/assets/a.css",
            "https://up.example/assets/b.css",
        ]


class TestUntrustedHints:
    def test_cross_origin_unapproved_and_unsafe_links_are_not_fetched(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(
            1,
            [
                "<https://evil.example/assets/app.css>; rel=preload; as=style",
                "<//evil.example/assets/app.css>; rel=preload; as=style",
                "<https://up.example@evil.example/assets/app.css>; rel=preload; as=style",
                "</private/secret.css>; rel=preload; as=style",
                "</assets/%2e%2e/private/secret.css>; rel=preload; as=style",
                "</assets/%252e%252e/private/secret.css>; rel=preload; as=style",
                "</assets/a%5c..%5csecret.css>; rel=preload; as=style",
                "</assets/%C2%A0traversal.css>; rel=preload; as=style",
                '<https://cdn.example/theme.css>; rel=preload; as=style; anchor="https://elsewhere.example/"',
            ],
        )
        h2.final(1, 200)

        assert prefetcher.calls == []
        assert cache.keys_for("alice") == []
        reasons = {link.reason for link in consumer.ignored_links}
        assert reasons == {"not-approved", "invalid-origin", "unsafe-path", "unsupported-anchor"}

    def test_non_ascii_link_field_is_recorded_as_ignored(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(1, ["/assets/caf\u00e9.css; rel=preload"])
        h2.final(1, 200)

        assert prefetcher.calls == []
        assert consumer.ignored_links[-1].reason == "non-ascii-link"

    def test_non_preload_relations_are_ignored(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(
            1,
            [
                "</assets/app.css>; rel=prefetch",
                "</assets/app.css>; rel=modulepreload",
                "</assets/app.css>",
            ],
        )
        h2.final(1, 200)

        assert prefetcher.calls == []
        assert cache.keys_for("alice") == []
        assert all(link.reason == "unsupported-relation" for link in consumer.ignored_links)

    def test_malformed_field_is_ignored_without_blocking_valid_field(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(
            1,
            [
                '</assets/bad.css>; rel=preload; title="unterminated',
                "</assets/good.css>; rel=preload; as=style",
            ],
        )
        h2.final(1, 200)

        assert [call.url for call in prefetcher.calls] == ["https://up.example/assets/good.css"]
        assert any(isinstance(link, IgnoredLink) and link.reason == "malformed-link" for link in consumer.ignored_links)

    def test_100_and_101_are_not_treated_as_early_hints(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")

        h2.hints(1, ["</assets/continue.css>; rel=preload; as=style"])
        # Replace the Link on a 101 response: it must not be fetched either.
        h2.server.send_headers(
            1,
            [(":status", "101"), ("link", "</assets/switch.css>; rel=preload")],
        )
        consumer.feed(h2.client.receive_data(h2.server.data_to_send()))
        h2.final(1, 200)

        assert [call.url for call in prefetcher.calls] == ["https://up.example/assets/continue.css"]
        assert cache.keys_for("alice") == ["https://up.example/assets/continue.css"]


class TestInterleavingAndResets:
    def test_interleaved_streams_never_share_staging_or_cache_entries(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)

        h2.open_request(1, "alice", "https://up.example/account")
        h2.open_request(3, "bob", "https://up.example/account")

        # Both users are told about the same asset URL.  The fetches are
        # distinct and both stay quarantined.
        h2.hints(1, ["</assets/shared.css>; rel=preload; as=style"])
        h2.hints(3, ["</assets/shared.css>; rel=preload; as=style"])

        assert [(call.owner, call.stream_id, call.url) for call in prefetcher.calls] == [
            ("alice", 1, "https://up.example/assets/shared.css"),
            ("bob", 3, "https://up.example/assets/shared.css"),
        ]
        assert cache.keys_for("alice") == []
        assert cache.keys_for("bob") == []

        # Alice is denied.  Only Bob's result may become readable.
        h2.final(1, 401)
        assert cache.keys_for("alice") == []
        assert cache.keys_for("bob") == []

        h2.final(3, 200)
        assert cache.keys_for("alice") == []
        assert cache.keys_for("bob") == ["https://up.example/assets/shared.css"]

    def test_hints_on_denied_stream_do_not_authorize_another_stream(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)

        h2.open_request(1, "alice", "https://up.example/account")
        h2.open_request(3, "bob", "https://up.example/account")

        # Alice's hint arrives while both streams are open.  Bob has not asked
        # for anything, so nothing may be fetched for him.
        h2.hints(1, ["</assets/secret.css>; rel=preload; as=style"])
        h2.final(1, 401)
        h2.final(3, 200)

        assert [(call.owner, call.stream_id) for call in prefetcher.calls] == [("alice", 1)]
        assert cache.keys_for("alice") == []
        assert cache.keys_for("bob") == []

    def test_stream_reset_discards_staged_results_even_after_200(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.hints(1, ["</assets/app.css>; rel=preload; as=style"])

        h2.final_headers(1, 200)
        assert cache.keys_for("alice") == []

        h2.reset(1)

        assert len(prefetcher.calls) == 1
        assert cache.keys_for("alice") == []
        assert consumer.rejected_final_responses == [(1, "alice", 200, "stream-reset")]

    def test_stream_reset_on_other_stream_does_not_discard_this_one(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.open_request(3, "bob", "https://up.example/account")
        h2.hints(1, ["</assets/a.css>; rel=preload; as=style"])
        h2.hints(3, ["</assets/b.css>; rel=preload; as=style"])

        h2.reset(1)
        h2.final(3, 200)

        assert cache.keys_for("alice") == []
        assert cache.keys_for("bob") == ["https://up.example/assets/b.css"]

    def test_connection_termination_discards_all_quarantines(self) -> None:
        consumer, prefetcher, cache = build_consumer()
        h2 = H2Fixture(consumer)
        h2.open_request(1, "alice", "https://up.example/account")
        h2.open_request(3, "bob", "https://up.example/account")
        h2.hints(1, ["</assets/a.css>; rel=preload; as=style"])
        h2.hints(3, ["</assets/b.css>; rel=preload; as=style"])

        h2.server.close_connection(error_code=ErrorCodes.NO_ERROR)
        events = h2.client.receive_data(h2.server.data_to_send())
        consumer.feed(events)

        assert cache.keys_for("alice") == []
        assert cache.keys_for("bob") == []
        assert {item[3] for item in consumer.rejected_final_responses} == {"connection-terminated"}
