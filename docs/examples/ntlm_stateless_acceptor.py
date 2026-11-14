#!/usr/bin/python
"""Accept NTLMv2 across separate HTTP style requests with replay protection."""

import datetime

import spnego
from spnego._ntlm import CHALLENGE_ID_AV_ID
from spnego._ntlm_raw.messages import AvId, Challenge


def challenge_id(token: bytes) -> str:
    target_info = Challenge.unpack(token).target_info
    assert target_info is not None
    return target_info[AvId(CHALLENGE_ID_AV_ID)].decode("ascii")


def main() -> None:
    clock = spnego.FixedClock(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
    store = spnego.InMemoryNTLMChallengeStore()

    def new_acceptor() -> spnego.ContextProxy:
        # Each request creates a fresh context; the store carries the state.
        return spnego.server(
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
            challenge_store=store,
            challenge_lifetime=datetime.timedelta(seconds=60),
            clock=clock,
        )

    client = spnego.client(
        "username",
        "password",
        hostname="server",
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )

    # Request 1: the NEGOTIATE + CHALLENGE exchange.
    negotiate = client.step()
    challenge = new_acceptor().step(negotiate)
    print("Issued challenge %s" % challenge_id(challenge))

    # Request 2: a different request handler validates the AUTHENTICATE.
    authenticate = client.step(challenge)
    acceptor = new_acceptor()
    acceptor.step(authenticate)
    print("Authenticated %s" % acceptor.client_principal)
    print("Session key %r" % acceptor.session_key)

    # Any later replay of the same response is rejected by the store.
    try:
        new_acceptor().step(authenticate)
    except spnego.exceptions.NTLMChallengeReplayError:
        print("Replay rejected")

    # The same applies in a new process, which only shares the store snapshot.
    restored = spnego.InMemoryNTLMChallengeStore.restore(store.snapshot())
    recovered = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
        challenge_store=restored,
    )
    try:
        recovered.step(authenticate)
    except spnego.exceptions.NTLMChallengeReplayError:
        print("Replay rejected after restore")


def restore_demo() -> None:
    """A fresh process picks up a challenge that was issued before the restart."""
    clock = spnego.FixedClock(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
    store = spnego.InMemoryNTLMChallengeStore()
    client = spnego.client(
        "username",
        "password",
        hostname="server",
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    challenge = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
        challenge_store=store,
        clock=clock,
    ).step(client.step())
    authenticate = client.step(challenge)

    restored = spnego.InMemoryNTLMChallengeStore.restore(store.snapshot(), now=clock.now())
    recovered = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
        challenge_store=restored,
        clock=clock,
    )
    recovered.step(authenticate)
    print("Recovered process authenticated %s" % recovered.client_principal)


if __name__ == "__main__":
    main()
    restore_demo()
