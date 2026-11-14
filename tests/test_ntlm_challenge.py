# -*- coding: utf-8 -*-
# Copyright: (c) 2026, pyspnego contributors
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import concurrent.futures
import datetime
import json
import os
import threading
import typing

import pytest

import spnego
import spnego._ntlm as ntlm
from spnego._ntlm_challenge import (
    FixedClock,
    InMemoryNTLMChallengeStore,
    NTLMChallengeStatus,
)
from spnego._ntlm_raw.messages import (
    Authenticate,
    AvId,
    Challenge,
    FileTime,
    NegotiateFlags,
)
from spnego.exceptions import (
    InvalidTokenError,
    NTLMChallengeBusyError,
    NTLMChallengeExpiredError,
    NTLMChallengeMismatchError,
    NTLMChallengeNotFoundError,
    NTLMChallengeReplayError,
)

ORIGIN = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
LIFETIME = datetime.timedelta(seconds=30)


@pytest.fixture()
def challenge_setup(tmp_path, monkeypatch):
    username = "D\\user"
    password = "Passw0rd!"
    cred_file = tmp_path / "ntlm.cred"
    cred_file.write_text("D:user:%s" % password, encoding="utf-8")
    monkeypatch.setenv("NTLM_USER_FILE", str(cred_file))

    def make_client(pw: str = password) -> spnego.ContextProxy:
        return spnego.client(
            username,
            pw,
            hostname="server",
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
        )

    def make_acceptor(
        store: typing.Optional[spnego.NTLMChallengeStore] = None,
        clock: typing.Optional[spnego.NTLMClock] = None,
        lifetime: typing.Union[datetime.timedelta, float] = LIFETIME,
    ) -> spnego.ContextProxy:
        return spnego.server(
            hostname="server",
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
            challenge_store=store,
            challenge_lifetime=lifetime,
            clock=clock or FixedClock(ORIGIN),
        )

    def start(
        store: typing.Optional[spnego.NTLMChallengeStore] = None,
        clock: typing.Optional[spnego.NTLMClock] = None,
        password: str = password,
        own_handler: bool = False,
    ) -> typing.Tuple[spnego.ContextProxy, bytes, bytes, bytes, typing.Optional[spnego.ContextProxy]]:
        client = make_client(password)
        negotiate = client.step()
        assert negotiate is not None
        handler = make_acceptor(store=store, clock=clock)
        challenge = handler.step(negotiate)
        assert challenge is not None
        authenticate = client.step(challenge)
        assert authenticate is not None
        return client, negotiate, challenge, authenticate, handler if own_handler else None

    return make_client, make_acceptor, start


def get_challenge_id(challenge: bytes) -> str:
    target_info = Challenge.unpack(challenge).target_info
    assert target_info is not None
    value = target_info[AvId(ntlm.CHALLENGE_ID_AV_ID)]
    assert isinstance(value, bytes)
    return value.decode("ascii")


def get_nt_response(authenticate: bytes) -> bytes:
    auth = Authenticate.unpack(authenticate)
    assert auth.nt_challenge_response is not None
    return auth.nt_challenge_response


def replace_nt_response(authenticate: bytes, nt_response: bytes) -> bytes:
    """Return a copy of the Authenticate token with the NT response replaced."""
    auth = Authenticate.unpack(authenticate)
    old_response = auth.nt_challenge_response
    assert old_response is not None
    assert len(old_response) == len(nt_response)

    raw = bytearray(authenticate)
    offset = int.from_bytes(raw[24:28], "little")
    raw[offset : offset + len(nt_response)] = nt_response
    return bytes(raw)


def test_fixed_clock_is_deterministic():
    clock = FixedClock(ORIGIN)
    assert clock.now() == ORIGIN
    assert clock.now() == clock.now()

    assert clock.advance(10) == ORIGIN + datetime.timedelta(seconds=10)
    assert clock.advance(datetime.timedelta(minutes=1)) == ORIGIN + datetime.timedelta(seconds=70)

    clock.set(datetime.datetime(2026, 1, 1, 0, 0, 0))  # naive is UTC
    assert clock.now() == ORIGIN.replace(hour=0)


def test_store_lifecycle_and_transitions():
    store = InMemoryNTLMChallengeStore()
    state = ntlm.NTLMChallengeState(
        challenge_id="abc",
        server_challenge=b"12345678",
        negotiate_message=b"negotiate",
        challenge_message=b"challenge",
        flags=int(NegotiateFlags.unicode),
        target_info=b"info",
        issued_at=ORIGIN,
        expires_at=ORIGIN + LIFETIME,
    )
    store.issue(state)

    assert [t.action for t in store.transitions] == ["issued"]
    assert store.get("abc") == state

    reserved = store.reserve("abc", now=ORIGIN)
    assert reserved.status == NTLMChallengeStatus.in_progress
    assert reserved.attempts == 1

    released = store.release("abc", now=ORIGIN + datetime.timedelta(seconds=1), reason="bad password")
    assert released.status == NTLMChallengeStatus.pending

    reserved_again = store.reserve("abc", now=ORIGIN + datetime.timedelta(seconds=2))
    assert reserved_again.attempts == 2

    completed = store.complete("abc", principal="D\\user", now=ORIGIN + datetime.timedelta(seconds=3))
    assert completed.status == NTLMChallengeStatus.completed
    assert completed.principal == "D\\user"
    assert completed is not None

    actions = [(t.action, t.status) for t in store.transitions]
    assert actions == [
        ("issued", NTLMChallengeStatus.pending),
        ("reserved", NTLMChallengeStatus.in_progress),
        ("released", NTLMChallengeStatus.pending),
        ("reserved", NTLMChallengeStatus.in_progress),
        ("completed", NTLMChallengeStatus.completed),
    ]

    with pytest.raises(NTLMChallengeReplayError):
        store.reserve("abc", now=ORIGIN + datetime.timedelta(seconds=4))

    with pytest.raises(NTLMChallengeReplayError):
        store.complete("abc", principal="D\\user", now=ORIGIN + datetime.timedelta(seconds=4))


def test_store_issue_duplicate():
    store = InMemoryNTLMChallengeStore()
    state = ntlm.NTLMChallengeState(
        challenge_id="abc",
        server_challenge=b"12345678",
        negotiate_message=b"negotiate",
        challenge_message=b"challenge",
        flags=0,
        target_info=b"info",
        issued_at=ORIGIN,
        expires_at=ORIGIN + LIFETIME,
    )
    store.issue(state)
    with pytest.raises(ValueError, match="already been issued"):
        store.issue(state)


def test_store_unknown_challenge():
    store = InMemoryNTLMChallengeStore()
    with pytest.raises(NTLMChallengeNotFoundError):
        store.reserve("missing", now=ORIGIN)


def test_store_expiry_is_from_issue_time():
    store = InMemoryNTLMChallengeStore()
    state = ntlm.NTLMChallengeState(
        challenge_id="abc",
        server_challenge=b"12345678",
        negotiate_message=b"negotiate",
        challenge_message=b"challenge",
        flags=0,
        target_info=b"info",
        issued_at=ORIGIN,
        expires_at=ORIGIN + LIFETIME,
    )
    store.issue(state)

    with pytest.raises(NTLMChallengeExpiredError):
        store.reserve("abc", now=ORIGIN + LIFETIME)

    assert store.get("abc") is not None
    assert store.get("abc").status == NTLMChallengeStatus.expired  # type: ignore[union-attr]

    with pytest.raises(NTLMChallengeExpiredError):
        store.reserve("abc", now=ORIGIN + LIFETIME - datetime.timedelta(seconds=1))


def test_store_active_filters_expired():
    store = InMemoryNTLMChallengeStore()
    for index in range(2):
        store.issue(
            ntlm.NTLMChallengeState(
                challenge_id="c%d" % index,
                server_challenge=b"12345678",
                negotiate_message=b"negotiate",
                challenge_message=b"challenge",
                flags=0,
                target_info=b"info",
                issued_at=ORIGIN + datetime.timedelta(seconds=index),
                expires_at=ORIGIN + LIFETIME + datetime.timedelta(seconds=index),
            )
        )

    assert len(store.active(now=ORIGIN)) == 2
    active = store.active(now=ORIGIN + LIFETIME)
    assert len(active) == 1
    assert active[0].challenge_id == "c1"


def test_store_concurrent_reserve_only_one_wins():
    store = InMemoryNTLMChallengeStore()
    store.issue(
        ntlm.NTLMChallengeState(
            challenge_id="abc",
            server_challenge=b"12345678",
            negotiate_message=b"negotiate",
            challenge_message=b"challenge",
            flags=0,
            target_info=b"info",
            issued_at=ORIGIN,
            expires_at=ORIGIN + LIFETIME,
        )
    )

    barrier = threading.Barrier(2)
    results: typing.List[str] = []
    lock = threading.Lock()

    def reserve() -> None:
        barrier.wait()
        try:
            store.reserve("abc", now=ORIGIN)
            outcome = "reserved"

        except NTLMChallengeBusyError:
            outcome = "busy"

        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=reserve) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(results) == ["busy", "reserved"]
    assert store.get("abc") is not None
    assert store.get("abc").attempts == 1  # type: ignore[union-attr]


def test_acceptor_completes_on_second_instance(challenge_setup):
    _, _, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge, authenticate, _handler = start(store=store)

    # A completely different acceptor has no local state from the CHALLENGE.
    acceptor = challenge_setup[1](store=store)
    assert acceptor.step(authenticate) is None
    assert acceptor.complete
    assert acceptor.client_principal == "D\\user"

    state = store.get(get_challenge_id(challenge))
    assert state is not None
    assert state.status == NTLMChallengeStatus.completed
    assert state.principal == "D\\user"


def test_acceptor_missing_challenge_id(challenge_setup):
    make_client, make_acceptor, _ = challenge_setup
    acceptor = make_acceptor()
    # A raw Authenticate with no matching server state cannot be correlated.
    auth = Authenticate(
        flags=int(NegotiateFlags.unicode),
        nt_challenge_response=b"\x00" * 24,
        username="user",
        domain_name="D",
    ).pack()

    with pytest.raises(NTLMChallengeMismatchError):
        acceptor.step(auth)


def test_acceptor_second_response_rejected(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, _challenge, authenticate, _handler = start(store=store)

    first = make_acceptor(store=store)
    first.step(authenticate)
    assert first.complete

    second = make_acceptor(store=store)
    with pytest.raises(NTLMChallengeReplayError):
        second.step(authenticate)


def test_acceptor_same_instance_after_completion_rejected(challenge_setup):
    _, _, start = challenge_setup
    _client, _negotiate, _challenge, authenticate, handler = start(own_handler=True)
    assert handler is not None
    handler.step(authenticate)
    assert handler.complete

    with pytest.raises(InvalidTokenError, match="already complete"):
        handler.step(authenticate)


def test_acceptor_challenge_flags_must_match(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, _challenge, authenticate, _handler = start(store=store)

    tampered = Authenticate.unpack(authenticate)
    tampered.flags = tampered.flags & ~int(NegotiateFlags.unicode)
    with pytest.raises(NTLMChallengeMismatchError, match="flags do not match"):
        make_acceptor(store=store).step(tampered.pack())

    # The failed attempt did not consume the challenge.
    assert store.get(get_challenge_id(_challenge)).status == NTLMChallengeStatus.pending  # type: ignore[union-attr]


def test_acceptor_client_timestamp_cannot_renew(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    clock = FixedClock(ORIGIN)
    _client, _negotiate, challenge, authenticate, _handler = start(store=store, clock=clock)

    # Rewrite the client time inside the NTLMv2 response to the far future.
    nt_response = bytearray(get_nt_response(authenticate))
    nt_response[24:32] = FileTime.from_datetime(
        datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)
    ).pack()
    tampered = replace_nt_response(authenticate, bytes(nt_response))

    clock.set(ORIGIN + LIFETIME)
    with pytest.raises(NTLMChallengeExpiredError):
        make_acceptor(store=store, clock=clock).step(tampered)

    # Retrying with the original token does not extend or reset the window.
    with pytest.raises(NTLMChallengeExpiredError):
        make_acceptor(store=store, clock=clock).step(authenticate)

    assert clock.now() == ORIGIN + LIFETIME


def test_acceptor_expiry_before_lifetime_is_still_valid(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    clock = FixedClock(ORIGIN)
    _client, _negotiate, _challenge, authenticate, _handler = start(store=store, clock=clock)

    clock.set(ORIGIN + LIFETIME - datetime.timedelta(microseconds=1))
    acceptor = make_acceptor(store=store, clock=clock)
    acceptor.step(authenticate)
    assert acceptor.complete


def test_acceptor_wrong_password_keeps_own_challenge(challenge_setup):
    make_client, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge, _authenticate, _handler = start(store=store)

    wrong_client = make_client("WrongPassword")
    wrong_client.step()
    wrong_auth = wrong_client.step(challenge)
    assert wrong_auth is not None

    with pytest.raises(InvalidTokenError, match="Invalid NTLM response"):
        make_acceptor(store=store).step(wrong_auth)

    state = store.get(get_challenge_id(challenge))
    assert state is not None
    assert state.status == NTLMChallengeStatus.pending
    assert state.attempts == 1

    # A correct response on the same challenge still completes after the failure.
    good_client = make_client()
    good_client.step()
    good_auth = good_client.step(challenge)
    assert good_auth is not None
    acceptor = make_acceptor(store=store)
    acceptor.step(good_auth)
    assert acceptor.complete
    assert acceptor.client_principal == "D\\user"


def test_acceptor_password_failure_does_not_consume_other_challenge(challenge_setup):
    make_client, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge1, _auth1, _handler1 = start(store=store)
    _client2, _negotiate2, challenge2, auth2, _handler2 = start(store=store)

    wrong_client = make_client("WrongPassword")
    wrong_client.step()
    wrong_auth = wrong_client.step(challenge1)
    assert wrong_auth is not None

    with pytest.raises(InvalidTokenError):
        make_acceptor(store=store).step(wrong_auth)

    assert store.get(get_challenge_id(challenge1)).status == NTLMChallengeStatus.pending  # type: ignore[union-attr]
    assert store.get(get_challenge_id(challenge2)).status == NTLMChallengeStatus.pending  # type: ignore[union-attr]

    acceptor = make_acceptor(store=store)
    acceptor.step(auth2)
    assert acceptor.complete and acceptor.client_principal == "D\\user"


def test_acceptor_cross_challenge_response_rejected_locally(challenge_setup):
    _, _, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client1, _negotiate1, challenge1, _auth1, handler1 = start(store=store, own_handler=True)
    _client2, _negotiate2, challenge2, auth2, _handler2 = start(store=store)

    assert handler1 is not None
    with pytest.raises(NTLMChallengeMismatchError, match="different challenge"):
        handler1.step(auth2)

    assert store.get(get_challenge_id(challenge1)).status == NTLMChallengeStatus.pending  # type: ignore[union-attr]
    assert store.get(get_challenge_id(challenge2)).status == NTLMChallengeStatus.pending  # type: ignore[union-attr]

    # Challenge 2 is untouched and completes with its own response.
    acceptor = challenge_setup[1](store=store)
    acceptor.step(auth2)
    assert acceptor.complete


def test_acceptor_cross_challenge_response_rejected_fresh_instance(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client1, _negotiate1, challenge1, auth1, _handler1 = start(store=store)
    _client2, _negotiate2, challenge2, _auth2, _handler2 = start(store=store)

    # Rewrite the echoed identifier of the response for challenge 1 so a fresh
    # acceptor looks up challenge 2.  The response hash covers the identifier.
    nt_response = get_nt_response(auth1)
    old_id = get_challenge_id(challenge1).encode("ascii")
    new_id = get_challenge_id(challenge2).encode("ascii")
    assert old_id in nt_response
    tampered = replace_nt_response(auth1, nt_response.replace(old_id, new_id))

    # The rewritten identifier changes the hashed AV pairs so the proof no
    # longer validates for the substituted challenge.
    acceptor = make_acceptor(store=store)
    with pytest.raises(InvalidTokenError, match="Invalid NTLM response"):
        acceptor.step(tampered)

    assert store.get(get_challenge_id(challenge2)).status == NTLMChallengeStatus.pending  # type: ignore[union-attr]


def test_store_concurrent_completion_end_to_end(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge, authenticate, _handler = start(store=store)

    barrier = threading.Barrier(2)
    results: typing.List[str] = []
    lock = threading.Lock()

    def accept() -> None:
        acceptor = make_acceptor(store=store)
        barrier.wait()
        try:
            acceptor.step(authenticate)
            outcome = "completed:%s" % acceptor.client_principal

        except NTLMChallengeBusyError:
            outcome = "busy"

        except NTLMChallengeReplayError:
            outcome = "replay"

        with lock:
            results.append(outcome)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(accept) for _ in range(2)]
        for future in futures:
            future.result()

    assert sorted(results) == ["busy", "completed:D\\user"]
    assert store.get(get_challenge_id(challenge)).status == NTLMChallengeStatus.completed  # type: ignore[union-attr]


def test_store_snapshot_restore_pending_challenge(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge, authenticate, _handler = start(store=store)

    snapshot = store.snapshot()
    assert json.loads(json.dumps(snapshot)) == snapshot

    restored = InMemoryNTLMChallengeStore.restore(snapshot, now=ORIGIN)
    assert restored.get(get_challenge_id(challenge)) is not None

    acceptor = make_acceptor(store=restored)
    acceptor.step(authenticate)
    assert acceptor.complete
    assert acceptor.client_principal == "D\\user"

    actions = [t.action for t in restored.transitions]
    assert "restored" in actions
    assert actions[-2:] == ["reserved", "completed"]


def test_store_snapshot_restore_keeps_consumed_challenge(challenge_setup):
    _, make_acceptor, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge, authenticate, _handler = start(store=store)

    make_acceptor(store=store).step(authenticate)
    restored = InMemoryNTLMChallengeStore.restore(store.snapshot(), now=ORIGIN)

    assert restored.get(get_challenge_id(challenge)).status == NTLMChallengeStatus.completed  # type: ignore[union-attr]

    with pytest.raises(NTLMChallengeReplayError):
        make_acceptor(store=restored).step(authenticate)


def test_store_snapshot_restore_releases_in_progress(challenge_setup):
    _, _, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, challenge, authenticate, _handler = start(store=store)
    challenge_id = get_challenge_id(challenge)

    # Simulate a process stopping after reserving but before completing.
    store.reserve(challenge_id, now=ORIGIN)
    assert store.get(challenge_id).status == NTLMChallengeStatus.in_progress  # type: ignore[union-attr]

    restored = InMemoryNTLMChallengeStore.restore(store.snapshot(), now=ORIGIN)
    state = restored.get(challenge_id)
    assert state is not None
    assert state.status == NTLMChallengeStatus.pending

    # The recovered store can still complete the original response.
    acceptor = challenge_setup[1](store=restored)
    acceptor.step(authenticate)
    assert acceptor.complete


def test_store_restore_rejects_unknown_schema():
    with pytest.raises(ValueError, match="snapshot version"):
        InMemoryNTLMChallengeStore.restore({"schema_version": 999})


def test_acceptor_invalid_lifetime(challenge_setup):
    make_client, _, _ = challenge_setup
    with pytest.raises(ValueError, match="greater than zero"):
        spnego._ntlm.NTLMProxy(
            spnego.CredentialCache(),
            usage="accept",
            challenge_lifetime=datetime.timedelta(0),
        )


def test_acceptor_accepts_datetime_clock(challenge_setup):
    _, _, start = challenge_setup
    store = InMemoryNTLMChallengeStore()
    _client, _negotiate, _challenge, authenticate, _handler = start(store=store)

    acceptor = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
        challenge_store=store,
        clock=ORIGIN,
    )
    acceptor.step(authenticate)
    assert acceptor.complete
