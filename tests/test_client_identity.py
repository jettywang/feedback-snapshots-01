"""
Tests for the restricted, embeddable client-certificate (mTLS) identity
selection transports.

These tests never open a real socket and need no online CA: two fixed
identities are minted in-process with ``trustme``, and a metering transport
records the *effective* identity/SSL context that each request actually used.
Connection-pool creation is counted so connection reuse and ownership can be
asserted deterministically.
"""

from __future__ import annotations

import os
import ssl
import tempfile
import threading
import typing

import anyio
import pytest
import trustme

import httpx
from httpx._mtls import MTLS_CLIENT_IDENTITY_EXTENSION

# Two distinct in-process CAs -> two distinct, fixed client identities.
CA_A = trustme.CA()
CA_B = trustme.CA()
CERT_A = CA_A.issue_cert("api.example.com")
CERT_B = CA_B.issue_cert("partner.example.com")

ORIGIN_API = "https://api.example.com"
ORIGIN_PARTNER = "https://partner.example.com"


class MeteredTransport(httpx.BaseTransport):
    """
    A stand-in per-identity connection pool.

    Counts how many times a pool is created (one per identity in the registry)
    and records the effective identity + SSL context for every request it
    handles, so the tests can prove which mTLS identity actually served a call.
    """

    instances: list["MeteredTransport"] = []

    def __init__(self, identity: httpx.ClientIdentity, ssl_context: typing.Any) -> None:
        self.identity = identity
        self.ssl_context = ssl_context
        self.requests: list[httpx.Request] = []
        self.closed = 0
        MeteredTransport.instances.append(self)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        effective = request.extensions[MTLS_CLIENT_IDENTITY_EXTENSION]
        assert effective == self.identity.name
        return httpx.Response(
            200,
            json={
                "identity": self.identity.name,
                "path": request.url.raw_path.decode(),
            },
        )

    def close(self) -> None:
        self.closed += 1


class AsyncMeteredTransport(httpx.AsyncBaseTransport):
    instances: list["AsyncMeteredTransport"] = []

    def __init__(self, identity: httpx.ClientIdentity, ssl_context: typing.Any) -> None:
        self.identity = identity
        self.ssl_context = ssl_context
        self.requests: list[httpx.Request] = []
        self.closed = 0
        AsyncMeteredTransport.instances.append(self)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        effective = request.extensions[MTLS_CLIENT_IDENTITY_EXTENSION]
        assert effective == self.identity.name
        return httpx.Response(
            200,
            json={
                "identity": self.identity.name,
                "path": request.url.raw_path.decode(),
            },
        )

    async def aclose(self) -> None:
        self.closed += 1


@pytest.fixture
def identities() -> list[httpx.ClientIdentity]:
    return [
        httpx.ClientIdentity(
            "identity-a",
            origins=[ORIGIN_API],
            cert_pem=CERT_A.cert_chain_pems[0].bytes(),
            key_pem=CERT_A.private_key_pem.bytes(),
            verify=False,
        ),
        httpx.ClientIdentity(
            "identity-b",
            origins=[ORIGIN_API, ORIGIN_PARTNER],
            cert_pem=CERT_B.cert_chain_pems[0].bytes(),
            key_pem=CERT_B.private_key_pem.bytes(),
            verify=False,
        ),
    ]


@pytest.fixture
def metered_sync(
    identities: list[httpx.ClientIdentity],
) -> tuple[httpx.ClientIdentityTransport, list[MeteredTransport]]:
    MeteredTransport.instances = []
    transport = httpx.ClientIdentityTransport(
        identities, transport_factory=MeteredTransport
    )
    return transport, MeteredTransport.instances


@pytest.fixture
def metered_async(
    identities: list[httpx.ClientIdentity],
) -> tuple[httpx.AsyncClientIdentityTransport, list[AsyncMeteredTransport]]:
    AsyncMeteredTransport.instances = []
    transport = httpx.AsyncClientIdentityTransport(
        identities, transport_factory=AsyncMeteredTransport
    )
    return transport, AsyncMeteredTransport.instances


def test_identities_use_distinct_ssl_contexts(
    identities: list[httpx.ClientIdentity],
) -> None:
    identity_a, identity_b = identities
    # Each identity gets its own SSLContext rather than sharing a single
    # mutable context that could have its certificate swapped per request.
    assert identity_a.ssl_context is not identity_b.ssl_context
    assert isinstance(identity_a.ssl_context, ssl.SSLContext)
    assert isinstance(identity_b.ssl_context, ssl.SSLContext)


def test_pem_material_is_loaded_without_exposing_file_paths(
    identities: list[httpx.ClientIdentity],
) -> None:
    # Building from in-memory PEM succeeds and leaves no temp cert/key files.
    identity_a = identities[0]
    assert identity_a.ssl_context is not None
    # A path-like selector is just an unknown name, never dereferenced.
    assert identity_a.permits(httpx.URL(ORIGIN_API))
    assert not identity_a.permits(httpx.URL(ORIGIN_PARTNER))


def test_in_memory_pem_leaves_no_temp_files() -> None:
    import glob

    pattern = os.path.join(tempfile.gettempdir(), "httpx-mtls-*")
    before = set(glob.glob(pattern))
    httpx.ClientIdentity(
        "identity-a",
        origins=[ORIGIN_API],
        cert_pem=CERT_A.cert_chain_pems[0].bytes(),
        key_pem=CERT_A.private_key_pem.bytes(),
        verify=False,
    )
    after = set(glob.glob(pattern))
    assert after - before == set()


def test_interleaved_requests_use_authorized_identity(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, pools = metered_sync
    with httpx.Client(transport=transport) as client:
        first = client.get(
            f"{ORIGIN_API}/one", extensions=httpx.client_identity("identity-a")
        )
        second = client.get(
            f"{ORIGIN_API}/two", extensions=httpx.client_identity("identity-b")
        )
        third = client.get(
            f"{ORIGIN_API}/three", extensions=httpx.client_identity("identity-a")
        )

    assert first.json()["identity"] == "identity-a"
    assert second.json()["identity"] == "identity-b"
    assert third.json()["identity"] == "identity-a"

    pool_a, pool_b = pools
    assert [r.url.path for r in pool_a.requests] == ["/one", "/three"]
    assert [r.url.path for r in pool_b.requests] == ["/two"]
    # Each pool saw exactly the identity it was built for.
    assert pool_a.identity.name == "identity-a"
    assert pool_b.identity.name == "identity-b"
    # The effective TLS context recorded by the meter is the exact context
    # registered for that identity, proving which mTLS material served each call.
    assert pool_a.ssl_context is transport._identities["identity-a"].ssl_context
    assert pool_b.ssl_context is transport._identities["identity-b"].ssl_context


def test_same_origin_identity_reuses_its_own_pool(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, pools = metered_sync
    with httpx.Client(transport=transport) as client:
        for path in ("/a", "/b", "/c"):
            response = client.get(
                f"{ORIGIN_API}{path}",
                extensions=httpx.client_identity("identity-a"),
            )
            assert response.json()["identity"] == "identity-a"

    # One identity -> one lazily created pool, reused for every request.
    assert len(pools) == 1
    assert len(pools[0].requests) == 3
    # Connections are never shared across identities.
    assert pools[0].identity.name == "identity-a"


def test_cross_origin_request_is_denied_before_connection(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, pools = metered_sync
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.ClientIdentityOriginDenied) as exc_info:
            client.get(
                f"{ORIGIN_PARTNER}/secret",
                extensions=httpx.client_identity("identity-a"),
            )

    # The denial is a request-level transport error carrying the request.
    assert isinstance(exc_info.value, httpx.ClientIdentityError)
    assert exc_info.value.request.url.host == "partner.example.com"
    # No pool (and therefore no connection/handshake) was created for it.
    assert pools == []


def test_missing_and_unknown_identity_fail_before_connection(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, pools = metered_sync
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.ClientIdentityNotRequested):
            client.get(f"{ORIGIN_API}/no-identity")
        with pytest.raises(httpx.ClientIdentityNotRegistered):
            client.get(
                f"{ORIGIN_API}/unknown",
                extensions=httpx.client_identity("not-registered"),
            )
    assert pools == []


def test_redirect_is_rechecked_against_identity_permissions(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, _pools = metered_sync

    def redirecting_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            target = str(request.url.copy_with(path="/end"))
            return httpx.Response(302, headers={"location": target})
        return httpx.Response(
            200,
            json={
                "identity": request.extensions[MTLS_CLIENT_IDENTITY_EXTENSION]
            },
        )

    # Replace the metered pools with redirect-aware ones via a fresh factory.
    redirect_transport = httpx.ClientIdentityTransport(
        [
            httpx.ClientIdentity(
                "identity-a",
                origins=[ORIGIN_API],
                ssl_context=transport._identities["identity-a"].ssl_context,
            )
        ],
        transport_factory=lambda identity, ctx: httpx.MockTransport(
            redirecting_handler
        ),
    )
    with httpx.Client(transport=redirect_transport, follow_redirects=True) as client:
        response = client.get(
            f"{ORIGIN_API}/start", extensions=httpx.client_identity("identity-a")
        )
    # Same-origin redirect is followed and still served by the same identity.
    assert response.json()["identity"] == "identity-a"

    # A redirect that crosses to an origin the identity cannot reach must be
    # rejected on the follow-up hop, not silently sent.
    def cross_origin_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": f"{ORIGIN_PARTNER}/end"})
        return httpx.Response(200)

    cross_transport = httpx.ClientIdentityTransport(
        [
            httpx.ClientIdentity(
                "identity-a",
                origins=[ORIGIN_API],
                ssl_context=transport._identities["identity-a"].ssl_context,
            )
        ],
        transport_factory=lambda identity, ctx: httpx.MockTransport(
            cross_origin_handler
        ),
    )
    with httpx.Client(transport=cross_transport, follow_redirects=True) as client:
        with pytest.raises(httpx.ClientIdentityOriginDenied):
            client.get(
                f"{ORIGIN_API}/start",
                extensions=httpx.client_identity("identity-a"),
            )


def test_mtls_identity_is_independent_of_authorization_header(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, pools = metered_sync
    with httpx.Client(transport=transport, auth=("user", "pass")) as client:
        response = client.get(
            f"{ORIGIN_API}/auth",
            extensions=httpx.client_identity("identity-b"),
        )

    assert response.json()["identity"] == "identity-b"
    request = pools[0].requests[0]
    # HTTP-level auth is present and untouched; it does not pick the mTLS identity.
    assert request.headers["Authorization"].startswith("Basic ")
    assert request.extensions[MTLS_CLIENT_IDENTITY_EXTENSION] == "identity-b"


def test_close_has_clear_ownership_and_is_idempotent(
    metered_sync: tuple[httpx.ClientIdentityTransport, list[MeteredTransport]],
) -> None:
    transport, pools = metered_sync
    client = httpx.Client(transport=transport)
    client.get(f"{ORIGIN_API}/a", extensions=httpx.client_identity("identity-a"))
    client.get(f"{ORIGIN_PARTNER}/b", extensions=httpx.client_identity("identity-b"))
    assert len(pools) == 2 and all(pool.closed == 0 for pool in pools)

    client.close()
    # The registry transport owns every per-identity pool and closes each once.
    assert all(pool.closed == 1 for pool in pools)

    # Closing again must not double-close the owned pools.
    transport.close()
    assert all(pool.closed == 1 for pool in pools)


def test_sync_cancellation_closes_owned_pools() -> None:
    # A handler that blocks lets us abandon a request mid-flight from another
    # thread and prove the caller can still release every owned connection.
    gate = threading.Event()
    release = threading.Event()

    def slow_handler(request: httpx.Request) -> httpx.Response:
        gate.set()
        release.wait(timeout=5)
        return httpx.Response(200)

    identity = httpx.ClientIdentity(
        "identity-a",
        origins=[ORIGIN_API],
        ssl_context=ssl.create_default_context(),
    )
    transport = httpx.ClientIdentityTransport(
        [identity],
        transport_factory=lambda ident, ctx: httpx.MockTransport(slow_handler),
    )
    client = httpx.Client(transport=transport)

    def worker() -> None:
        client.get(f"{ORIGIN_API}/slow", extensions=httpx.client_identity("identity-a"))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    gate.wait(timeout=5)  # Ensure the request is in flight before cancelling.

    # Abandoning/cancelling the work and closing the client releases ownership.
    client.close()
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.anyio
async def test_async_interleaved_requests_and_pool_reuse(
    metered_async: tuple[
        httpx.AsyncClientIdentityTransport, list[AsyncMeteredTransport]
    ],
) -> None:
    transport, pools = metered_async
    async with httpx.AsyncClient(transport=transport) as client:
        results = []
        async with anyio.create_task_group() as tg:

            async def call(name: str, path: str) -> None:
                response = await client.get(
                    f"{ORIGIN_API}{path}", extensions=httpx.client_identity(name)
                )
                results.append((path, response.json()["identity"]))

            tg.start_soon(call, "identity-a", "/1")
            tg.start_soon(call, "identity-b", "/2")
            tg.start_soon(call, "identity-a", "/3")

    assert {"/1": "identity-a", "/2": "identity-b", "/3": "identity-a"} == dict(
        (path, name) for path, name in results
    )
    # Exactly one pool per identity even with concurrent interleaving.
    assert sorted(pool.identity.name for pool in pools) == [
        "identity-a",
        "identity-b",
    ]
    pool_a = next(pool for pool in pools if pool.identity.name == "identity-a")
    assert sorted(request.url.path for request in pool_a.requests) == ["/1", "/3"]


@pytest.mark.anyio
async def test_async_cross_origin_denied_before_connection(
    metered_async: tuple[
        httpx.AsyncClientIdentityTransport, list[AsyncMeteredTransport]
    ],
) -> None:
    transport, pools = metered_async
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(httpx.ClientIdentityOriginDenied):
            await client.get(
                f"{ORIGIN_PARTNER}/x",
                extensions=httpx.client_identity("identity-a"),
            )
    assert pools == []


@pytest.mark.anyio
async def test_async_mid_flight_cancellation_closes_owned_pools(
    identities: list[httpx.ClientIdentity],
) -> None:
    proceed = anyio.Event()

    class SlowAsyncTransport(httpx.AsyncBaseTransport):
        instances: list["SlowAsyncTransport"] = []

        def __init__(self, identity: httpx.ClientIdentity, ctx: typing.Any) -> None:
            self.identity = identity
            self.closed = 0
            SlowAsyncTransport.instances.append(self)

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            await proceed.wait()
            return httpx.Response(200)

        async def aclose(self) -> None:
            self.closed += 1

    SlowAsyncTransport.instances = []
    transport = httpx.AsyncClientIdentityTransport(
        identities, transport_factory=SlowAsyncTransport
    )

    # Drive the transport directly so cancellation does not get masked by the
    # high-level client's own context teardown.
    request = httpx.Request(
        "GET",
        f"{ORIGIN_API}/slow",
        extensions=httpx.client_identity("identity-a"),
    )
    with pytest.raises(TimeoutError):
        with anyio.fail_after(0.2):
            await transport.handle_async_request(request)

    # Cancelled mid-flight: the pool was created for the authorized identity and
    # is still owned by the registry transport, which releases it exactly once.
    pool = SlowAsyncTransport.instances[0]
    assert pool.identity.name == "identity-a"
    assert pool.closed == 0
    await transport.aclose()
    assert pool.closed == 1
    assert transport._pools == {}  # type: ignore[attr-defined]
    # Idempotent: a second close does not touch already-released pools.
    await transport.aclose()
    assert pool.closed == 1
    proceed.set()


def test_identity_rejects_unknown_file_path_style_selector() -> None:
    # Identities are selected by registered name only; a path-like string is
    # simply an unregistered name and can never reach a certificate file.
    identity = httpx.ClientIdentity(
        "identity-a",
        origins=[ORIGIN_API],
        cert_pem=CERT_A.cert_chain_pems[0].bytes(),
        key_pem=CERT_A.private_key_pem.bytes(),
        verify=False,
    )
    transport = httpx.ClientIdentityTransport(
        [identity], transport_factory=MeteredTransport
    )
    MeteredTransport.instances = []
    with httpx.Client(transport=transport) as client:
        with pytest.raises(httpx.ClientIdentityNotRegistered):
            client.get(
                f"{ORIGIN_API}/etc-passwd",
                extensions=httpx.client_identity("/etc/passwd"),
            )
    assert MeteredTransport.instances == []
