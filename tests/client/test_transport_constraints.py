from __future__ import annotations

import typing

import pytest

import httpx


class RecordingTransport(httpx.BaseTransport):
    """
    A transport that only records the requests it is asked to handle.

    It never opens a socket - responses are synthesised, including optional
    redirects. A flag records whether the transport was ever invoked, which
    lets tests prove that a refused request never reaches a disallowed
    transport.
    """

    def __init__(
        self,
        name: str,
        *,
        redirect_to: str | None = None,
        respond_with: int = 200,
    ) -> None:
        self.name = name
        self.redirect_to = redirect_to
        self.respond_with = httpx.codes.SEE_OTHER if redirect_to else respond_with
        self.requests: list[httpx.Request] = []
        self.invoked = False
        self.closed = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.invoked = True
        self.requests.append(request)
        headers = (
            {"location": self.redirect_to} if self.redirect_to is not None else {}
        )
        return httpx.Response(self.respond_with, headers=headers, text=self.name)

    def close(self) -> None:
        self.closed += 1


def build_constraints() -> tuple[
    RecordingTransport, RecordingTransport, RecordingTransport
]:
    exact_port = RecordingTransport("exact-port")
    wildcard = RecordingTransport("wildcard")
    safe_default = RecordingTransport("safe-default")
    return exact_port, wildcard, safe_default


def build_client() -> tuple[
    httpx.Client, RecordingTransport, RecordingTransport, RecordingTransport
]:
    exact_port, wildcard, safe_default = build_constraints()
    client = httpx.Client(
        transport=safe_default,
        transport_constraints={
            "https://secure.example.com:8443": exact_port,
            "https://*.example.com": wildcard,
        },
    )
    return client, exact_port, wildcard, safe_default


# ---------------------------------------------------------------------------
# Exact port and wildcard routing
# ---------------------------------------------------------------------------


def test_exact_port_uses_dedicated_managed_transport() -> None:
    client, exact_port, wildcard, safe_default = build_client()
    try:
        response = client.get("https://secure.example.com:8443/secret")
    finally:
        client.close()

    assert response.status_code == 200
    assert len(exact_port.requests) == 1
    assert exact_port.requests[0].url == httpx.URL(
        "https://secure.example.com:8443/secret"
    )
    # The more specific port mount must not be shadowed by the wildcard.
    assert wildcard.requests == []
    assert safe_default.requests == []


def test_wildcard_pattern_uses_wildcard_managed_transport() -> None:
    client, exact_port, wildcard, safe_default = build_client()
    try:
        response = client.get("https://api.example.com/v1/widgets")
    finally:
        client.close()

    assert response.status_code == 200
    assert [request.url for request in wildcard.requests] == [
        httpx.URL("https://api.example.com/v1/widgets")
    ]
    assert exact_port.requests == []
    assert safe_default.requests == []


def test_unmatched_url_is_refused_before_any_transport_runs() -> None:
    client, exact_port, wildcard, safe_default = build_client()
    try:
        with pytest.raises(httpx.TransportConstraintError) as exc_info:
            client.get("https://evil.example.net/steal")
    finally:
        client.close()

    assert exc_info.value.request.url == httpx.URL("https://evil.example.net/steal")
    # Refusal happens before the disallowed transport would be called.
    assert exact_port.invoked is False
    assert wildcard.invoked is False
    assert safe_default.invoked is False


def test_non_http_scheme_is_refused_without_touching_a_transport() -> None:
    client, exact_port, wildcard, safe_default = build_client()
    try:
        with pytest.raises(httpx.TransportConstraintError):
            client.get("custom://www.example.com/resource")
    finally:
        client.close()

    assert exact_port.invoked is False
    assert wildcard.invoked is False
    assert safe_default.invoked is False


def test_specific_mount_takes_priority_over_broad_safe_default() -> None:
    exact_port = RecordingTransport("exact-port")
    safe_default = RecordingTransport("safe-default")
    client = httpx.Client(
        transport=safe_default,
        transport_constraints={
            "all://": safe_default,
            "https://secure.example.com:8443": exact_port,
        },
    )
    try:
        client.get("https://secure.example.com:8443/secret")
    finally:
        client.close()

    assert len(exact_port.requests) == 1
    assert safe_default.requests == []


def test_transport_constraints_are_optional_and_default_routing_is_kept() -> None:
    safe_default = RecordingTransport("safe-default")
    with httpx.Client(transport=safe_default) as client:
        response = client.get("https://www.example.com/")
    assert response.status_code == 200
    assert len(safe_default.requests) == 1


def test_none_constraint_value_is_rejected() -> None:
    safe_default = RecordingTransport("safe-default")
    with pytest.raises(TypeError):
        httpx.Client(
            transport=safe_default,
            transport_constraints={"https://*.example.com": None},
        )


# ---------------------------------------------------------------------------
# Redirects: routing is re-confirmed for every hop
# ---------------------------------------------------------------------------


def test_redirect_to_another_managed_transport_is_rerouted() -> None:
    wildcard = RecordingTransport(
        "wildcard", redirect_to="https://secure.example.com:8443/target"
    )
    exact_port = RecordingTransport("exact-port")
    safe_default = RecordingTransport("safe-default")
    client = httpx.Client(
        transport=safe_default,
        transport_constraints={
            "https://secure.example.com:8443": exact_port,
            "https://*.example.com": wildcard,
        },
        follow_redirects=True,
    )
    try:
        response = client.get("https://api.example.com/start")
    finally:
        client.close()

    assert response.status_code == 200
    assert [request.url for request in wildcard.requests] == [
        httpx.URL("https://api.example.com/start")
    ]
    assert [request.url for request in exact_port.requests] == [
        httpx.URL("https://secure.example.com:8443/target")
    ]
    assert safe_default.invoked is False


def test_redirect_outside_constraints_is_refused_before_dispatch() -> None:
    wildcard = RecordingTransport(
        "wildcard", redirect_to="https://evil.example.net/outside"
    )
    safe_default = RecordingTransport("safe-default")
    client = httpx.Client(
        transport=safe_default,
        transport_constraints={"https://*.example.com": wildcard},
        follow_redirects=True,
    )
    try:
        with pytest.raises(httpx.TransportConstraintError) as exc_info:
            client.get("https://api.example.com/start")
    finally:
        client.close()

    assert exc_info.value.request.url == httpx.URL(
        "https://evil.example.net/outside"
    )
    # Only the first, permitted hop ran. The redirected request was refused.
    assert len(wildcard.requests) == 1
    assert safe_default.invoked is False


# ---------------------------------------------------------------------------
# Authentication follow-ups: routing is re-confirmed when the auth flow
# issues another request.
# ---------------------------------------------------------------------------


class TwoStepAuth(httpx.Auth):
    challenge_url = "https://secure.example.com:8443/challenge"

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> typing.Generator[httpx.Request, httpx.Response, None]:
        challenge = httpx.Request("GET", self.challenge_url)
        challenge_response = yield challenge
        request.headers["X-Auth-Token"] = challenge_response.text
        yield request

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> typing.AsyncGenerator[httpx.Request, httpx.Response]:
        challenge = httpx.Request("GET", self.challenge_url)
        challenge_response = yield challenge
        request.headers["X-Auth-Token"] = challenge_response.text
        yield request


class ExternalChallengeAuth(TwoStepAuth):
    challenge_url = "https://challenge.example.net/token"


def test_authentication_follow_up_is_rerouted_through_managed_transport() -> None:
    exact_port = RecordingTransport("exact-port")
    safe_default = RecordingTransport("safe-default")
    client = httpx.Client(
        transport=safe_default,
        transport_constraints={"https://secure.example.com:8443": exact_port},
        auth=TwoStepAuth(),
    )
    try:
        response = client.get("https://secure.example.com:8443/login")
    finally:
        client.close()

    assert response.status_code == 200
    assert [request.url.path for request in exact_port.requests] == [
        "/challenge",
        "/login",
    ]
    login_request = exact_port.requests[1]
    assert login_request.headers["X-Auth-Token"] == "exact-port"
    assert safe_default.invoked is False


def test_authentication_follow_up_outside_constraints_is_refused() -> None:
    exact_port = RecordingTransport("exact-port")
    safe_default = RecordingTransport("safe-default")
    client = httpx.Client(
        transport=safe_default,
        transport_constraints={"https://secure.example.com:8443": exact_port},
        auth=ExternalChallengeAuth(),
    )
    try:
        with pytest.raises(httpx.TransportConstraintError) as exc_info:
            client.get("https://secure.example.com:8443/login")
    finally:
        client.close()

    # The auth flow's resend targets an unmanaged URL and is refused...
    assert exc_info.value.request.url == httpx.URL(
        "https://challenge.example.net/token"
    )
    # ...before any transport (including the managed one) is invoked.
    assert exact_port.invoked is False
    assert safe_default.invoked is False


# ---------------------------------------------------------------------------
# Resource release follows the existing client contract
# ---------------------------------------------------------------------------


def test_constrained_transports_are_closed_with_the_client() -> None:
    exact_port, wildcard, safe_default = build_constraints()
    with httpx.Client(
        transport=safe_default,
        transport_constraints={
            "https://secure.example.com:8443": exact_port,
            "https://*.example.com": wildcard,
        },
    ):
        pass

    assert exact_port.closed == 1
    assert wildcard.closed == 1
    assert safe_default.closed == 1


def test_shared_constraint_transport_is_closed_exactly_once() -> None:
    managed = RecordingTransport("managed")
    with httpx.Client(
        transport=managed,
        transport_constraints={"all://": managed},
    ):
        pass

    assert managed.closed == 1


# ---------------------------------------------------------------------------
# Async parity
# ---------------------------------------------------------------------------


class AsyncRecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, name: str, *, redirect_to: str | None = None) -> None:
        self.name = name
        self.redirect_to = redirect_to
        self.respond_with = httpx.codes.SEE_OTHER if redirect_to else 200
        self.requests: list[httpx.Request] = []
        self.invoked = False
        self.closed = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.invoked = True
        self.requests.append(request)
        headers = (
            {"location": self.redirect_to} if self.redirect_to is not None else {}
        )
        return httpx.Response(self.respond_with, headers=headers, text=self.name)

    async def aclose(self) -> None:
        self.closed += 1


@pytest.mark.anyio
async def test_async_exact_port_and_wildcard_routing() -> None:
    exact_port = AsyncRecordingTransport("exact-port")
    wildcard = AsyncRecordingTransport("wildcard")
    safe_default = AsyncRecordingTransport("safe-default")
    async with httpx.AsyncClient(
        transport=safe_default,
        transport_constraints={
            "https://secure.example.com:8443": exact_port,
            "https://*.example.com": wildcard,
        },
    ) as client:
        await client.get("https://secure.example.com:8443/secret")
        await client.get("https://api.example.com/widgets")

    assert [request.url for request in exact_port.requests] == [
        httpx.URL("https://secure.example.com:8443/secret")
    ]
    assert [request.url for request in wildcard.requests] == [
        httpx.URL("https://api.example.com/widgets")
    ]
    assert safe_default.invoked is False


@pytest.mark.anyio
async def test_async_unmatched_url_is_refused_before_dispatch() -> None:
    wildcard = AsyncRecordingTransport("wildcard")
    safe_default = AsyncRecordingTransport("safe-default")
    async with httpx.AsyncClient(
        transport=safe_default,
        transport_constraints={"https://*.example.com": wildcard},
    ) as client:
        with pytest.raises(httpx.TransportConstraintError) as exc_info:
            await client.get("https://evil.example.net/steal")

    assert exc_info.value.request.url == httpx.URL("https://evil.example.net/steal")
    assert wildcard.invoked is False
    assert safe_default.invoked is False


@pytest.mark.anyio
async def test_async_redirect_is_rerouted_and_reconfirmed() -> None:
    wildcard = AsyncRecordingTransport(
        "wildcard", redirect_to="https://secure.example.com:8443/target"
    )
    exact_port = AsyncRecordingTransport("exact-port")
    safe_default = AsyncRecordingTransport("safe-default")
    async with httpx.AsyncClient(
        transport=safe_default,
        transport_constraints={
            "https://secure.example.com:8443": exact_port,
            "https://*.example.com": wildcard,
        },
        follow_redirects=True,
    ) as client:
        await client.get("https://api.example.com/start")

    assert [request.url for request in wildcard.requests] == [
        httpx.URL("https://api.example.com/start")
    ]
    assert [request.url for request in exact_port.requests] == [
        httpx.URL("https://secure.example.com:8443/target")
    ]
    assert safe_default.invoked is False


@pytest.mark.anyio
async def test_async_authentication_follow_up_uses_managed_transport() -> None:
    exact_port = AsyncRecordingTransport("exact-port")
    safe_default = AsyncRecordingTransport("safe-default")
    async with httpx.AsyncClient(
        transport=safe_default,
        transport_constraints={"https://secure.example.com:8443": exact_port},
        auth=TwoStepAuth(),
    ) as client:
        response = await client.get("https://secure.example.com:8443/login")

    assert response.status_code == 200
    assert [request.url.path for request in exact_port.requests] == [
        "/challenge",
        "/login",
    ]
    assert safe_default.invoked is False
    assert exact_port.closed == 1
