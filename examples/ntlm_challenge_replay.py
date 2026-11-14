#!/usr/bin/env python3
"""Demonstrate replay-safe NTLMv2 challenges across acceptor requests.

Run from the repository root with::

    .venv/bin/python examples/ntlm_challenge_replay.py

The script uses a fixed clock and an in-memory credential file, so it never
sleeps and never touches real system accounts.  It exercises a shared
in-memory store with request-scoped acceptor instances and records every state
transition together with the authenticated identity.
"""

import concurrent.futures
import datetime
import os
import socket
import tempfile
import typing

import spnego
from spnego._ntlm import CHALLENGE_ID_AV_ID
from spnego._ntlm_raw.messages import (
    AvId,
    Challenge,
)
from spnego.exceptions import (
    NTLMChallengeBusyError,
    NTLMChallengeExpiredError,
    NTLMChallengeMismatchError,
    NTLMChallengeReplayError,
)

ORIGIN = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
LIFETIME = datetime.timedelta(seconds=30)
DOMAIN = "D"
USERNAME = "user"
PASSWORD = "Passw0rd!"
PRINCIPAL = "%s\\%s" % (DOMAIN, USERNAME)


def _write_credential_file() -> str:
    fd, path = tempfile.mkstemp(suffix=".creds")
    os.write(fd, ("%s:%s:%s" % (DOMAIN, USERNAME, PASSWORD)).encode())
    os.close(fd)
    return path


def _get_nt_response_offset(token: bytes) -> int:
    return int.from_bytes(token[24:28], "little")


class Harness:
    """Builds clients and request-scoped acceptors around one shared store."""

    def __init__(self) -> None:
        self.credentials_file = _write_credential_file()
        os.environ["NTLM_USER_FILE"] = self.credentials_file
        self.store = spnego.InMemoryNTLMChallengeStore()
        self.clock = spnego.FixedClock(ORIGIN)
        self.hostname = socket.gethostname()

    def close(self) -> None:
        try:
            os.unlink(self.credentials_file)
        except FileNotFoundError:
            pass

    def client(self, password: str = PASSWORD) -> spnego.ContextProxy:
        return spnego.client(
            "%s\\%s" % (DOMAIN, USERNAME),
            password,
            hostname=self.hostname,
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
        )

    def acceptor(self, store: typing.Optional[spnego.NTLMChallengeStore] = None) -> spnego.ContextProxy:
        return spnego.server(
            hostname=self.hostname,
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
            challenge_store=store or self.store,
            challenge_lifetime=LIFETIME,
            clock=self.clock,
        )

    def start(self, password: str = PASSWORD) -> typing.Tuple[bytes, bytes, bytes]:
        """Run NEGOTIATE and CHALLENGE as two independent request handlers."""
        client = self.client(password)
        negotiate = client.step()
        assert negotiate is not None
        challenge = self.acceptor().step(negotiate)
        assert challenge is not None
        authenticate = client.step(challenge)
        assert authenticate is not None
        return negotiate, challenge, authenticate

    def start_with_handler(self, password: str = PASSWORD) -> typing.Tuple[bytes, bytes, bytes, spnego.ContextProxy]:
        """Like start(), but returns the handler that issued the CHALLENGE."""
        client = self.client(password)
        negotiate = client.step()
        assert negotiate is not None
        handler = self.acceptor()
        challenge = handler.step(negotiate)
        assert challenge is not None
        authenticate = client.step(challenge)
        assert authenticate is not None
        return negotiate, challenge, authenticate, handler

    @staticmethod
    def challenge_id(challenge: bytes) -> str:
        target_info = Challenge.unpack(challenge).target_info
        assert target_info is not None
        return typing.cast(bytes, target_info[AvId(CHALLENGE_ID_AV_ID)]).decode("ascii")


def show_transitions(store: spnego.NTLMChallengeStore, title: str, start: int = 0) -> None:
    print("\n%s" % title)
    for t in store.transitions[start:]:
        print(
            "  {at} {prev:>11} -> {status:<11} action={action:<10} principal={principal!r} detail={detail!r}".format(
                at=t.at.strftime("%H:%M:%S"),
                prev=t.previous_status.value if t.previous_status else "-",
                status=t.status.value,
                action=t.action,
                principal=t.principal,
                detail=t.detail,
            )
        )


def scenario_concurrent_completion(harness: Harness) -> None:
    """Two handlers submit the same valid response; only one may complete."""
    _negotiate, challenge, authenticate = harness.start()
    challenge_id = harness.challenge_id(challenge)
    start = len(harness.store.transitions)

    def submit() -> str:
        acceptor = harness.acceptor()
        try:
            acceptor.step(authenticate)
            return "completed as %s" % acceptor.client_principal
        except NTLMChallengeBusyError:
            return "busy (another handler held the reservation)"
        except NTLMChallengeReplayError:
            return "replay (challenge already consumed)"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: submit(), range(2)))

    completions = [r for r in results if r.startswith("completed")]
    print("\nConcurrent completion of challenge %s" % challenge_id)
    print("  submitter results: %s" % sorted(results))
    assert completions == ["completed as %s" % PRINCIPAL], results

    late = harness.acceptor()
    try:
        late.step(authenticate)
        raise AssertionError("a consumed challenge was accepted again")
    except NTLMChallengeReplayError:
        print("  a later duplicate response: rejected (NTLMChallengeReplayError)")

    show_transitions(harness.store, "Transitions for concurrent completion", start)


def scenario_expiry(harness: Harness) -> None:
    """Expiry uses the server issue time; a future client time cannot extend it."""
    _negotiate, challenge, authenticate = harness.start()
    challenge_id = harness.challenge_id(challenge)
    start = len(harness.store.transitions)

    # Move the client supplied NTLMv2 timestamp far into the future.  The token
    # is no longer valid, but expiry is decided before the response is checked.
    future_auth = bytearray(authenticate)
    nt_offset = _get_nt_response_offset(authenticate)
    future = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    future_auth[nt_offset + 24 : nt_offset + 32] = spnego._ntlm_raw.messages.FileTime.from_datetime(future).pack()

    harness.clock.set(ORIGIN + LIFETIME)
    expired = harness.acceptor()
    try:
        expired.step(bytes(future_auth))
        raise AssertionError("an expired challenge was accepted")
    except NTLMChallengeExpiredError:
        print("\nExpiry of challenge %s" % challenge_id)
        print("  issued at %s, lifetime %s" % (ORIGIN.isoformat(), LIFETIME))
        print("  clock is %s and client timestamp is %s" % (harness.clock.now().isoformat(), future.isoformat()))
        print("  result: NTLMChallengeExpiredError; the client time did not renew the challenge")

    # A retry after expiry is also rejected rather than restarting the clock.
    retry = harness.acceptor()
    try:
        retry.step(authenticate)
        raise AssertionError("a retry renewed an expired challenge")
    except NTLMChallengeExpiredError:
        print("  retry at the same time: NTLMChallengeExpiredError")

    show_transitions(harness.store, "Transitions for expiry", start)


def scenario_cross_challenge(harness: Harness) -> None:
    """A response created for one challenge is not valid for another."""
    harness.clock.set(ORIGIN + datetime.timedelta(minutes=5))
    _neg_a, challenge_a, _auth_a, handler_a = harness.start_with_handler()

    client_b = harness.client()
    negotiate_b = client_b.step()
    assert negotiate_b is not None
    challenge_b = harness.acceptor().step(negotiate_b)
    assert challenge_b is not None
    auth_for_b = client_b.step(challenge_b)
    assert auth_for_b is not None

    start = len(harness.store.transitions)

    # The handler that issued challenge A receives the response to challenge B.
    try:
        handler_a.step(auth_for_b)
        raise AssertionError("a response for another challenge was accepted")
    except NTLMChallengeMismatchError:
        print("\nCross-challenge substitution")
        print("  response is bound to %s" % harness.challenge_id(challenge_b))
        print("  presented to the handler that issued %s" % harness.challenge_id(challenge_a))
        print("  result: NTLMChallengeMismatchError")

    # Rewriting only the echoed identifier does not help: the response hash
    # covers the identifier as part of the AV pairs.
    old_id = harness.challenge_id(challenge_b).encode("ascii")
    new_id = harness.challenge_id(challenge_a).encode("ascii")
    tampered_auth = auth_for_b.replace(old_id, new_id)
    tampered = harness.acceptor()
    try:
        tampered.step(tampered_auth)
        raise AssertionError("a tampered challenge identifier was accepted")
    except Exception as e:
        print("  rewriting the challenge identifier: %s" % type(e).__name__)

    # The untouched response for B still completes challenge B normally.
    handler_b = harness.acceptor()
    handler_b.step(auth_for_b)
    assert handler_b.complete and handler_b.client_principal == PRINCIPAL
    print("  the correctly bound response still completed as %s" % handler_b.client_principal)

    show_transitions(harness.store, "Transitions for cross-challenge substitution", start)


def scenario_password_failure(harness: Harness) -> None:
    """A wrong password releases only its own challenge; a retry is still usable."""
    harness.clock.set(ORIGIN + datetime.timedelta(minutes=10))
    client = harness.client(PASSWORD)
    negotiate = client.step()
    assert negotiate is not None
    challenge = harness.acceptor().step(negotiate)
    assert challenge is not None
    challenge_id = harness.challenge_id(challenge)
    start = len(harness.store.transitions)

    wrong_client = harness.client("WrongPassword")
    wrong_client.step()
    wrong_auth = wrong_client.step(challenge)
    assert wrong_auth is not None

    failed = harness.acceptor()
    try:
        failed.step(wrong_auth)
        raise AssertionError("a wrong password was accepted")
    except Exception as e:
        print("\nPassword failure on challenge %s" % challenge_id)
        print("  result: %s; challenge remains pending" % type(e).__name__)

    state = harness.store.get(challenge_id)
    assert state is not None and state.status == spnego.NTLMChallengeStatus.pending
    print("  state after failure: %s (attempts=%d)" % (state.status.value, state.attempts))

    # A fresh client response to the same challenge can still complete.
    retry_client = harness.client()
    retry_client.step()
    retry_auth = retry_client.step(challenge)
    assert retry_auth is not None
    retry_acceptor = harness.acceptor()
    retry_acceptor.step(retry_auth)
    assert retry_acceptor.complete and retry_acceptor.client_principal == PRINCIPAL
    print("  retry after failure: completed as %s" % retry_acceptor.client_principal)

    show_transitions(harness.store, "Transitions for password failure and retry", start)


def scenario_process_restore(harness: Harness) -> None:
    """Snapshot a pending challenge, rebuild the store in a new process, finish."""
    harness.clock.set(ORIGIN + datetime.timedelta(minutes=15))
    _negotiate, challenge, authenticate = harness.start()
    challenge_id = harness.challenge_id(challenge)
    start = len(harness.store.transitions)

    snapshot = harness.store.snapshot()
    restored = spnego.InMemoryNTLMChallengeStore.restore(snapshot, now=harness.clock.now())
    print("\nProcess recovery for challenge %s" % challenge_id)
    print("  snapshot: %d state(s), %d transition(s)" % (len(snapshot["states"]), len(snapshot["transitions"])))

    recovered = harness.acceptor(store=restored)
    recovered.step(authenticate)
    assert recovered.complete and recovered.client_principal == PRINCIPAL
    print("  recovered acceptor: completed as %s" % recovered.client_principal)

    # The recovered store keeps the replay protection: the same response is done.
    duplicate = harness.acceptor(store=restored)
    try:
        duplicate.step(authenticate)
        raise AssertionError("the restored store lost replay protection")
    except NTLMChallengeReplayError:
        print("  duplicate after recovery: rejected (NTLMChallengeReplayError)")

    show_transitions(restored, "Transitions in the restored store", start)


def main() -> None:
    harness = Harness()
    try:
        scenario_concurrent_completion(harness)
        scenario_expiry(harness)
        scenario_cross_challenge(harness)
        scenario_password_failure(harness)
        scenario_process_restore(harness)
    finally:
        harness.close()


if __name__ == "__main__":
    main()
