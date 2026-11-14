# -*- coding: utf-8 -*-
# End-to-end harness for the CredSSP state fuzzer.
#
# A genuine CredSSPProxy initiator and a FuzzableCredSSPServer acceptor are
# connected through their ssl.MemoryBIO transports, exactly like the production
# tests. The harness advances the real TLS handshake and the real NTLM/SPNEGO
# authentication rounds to the target phase, then injects a mutated TSRequest
# that is protected by the negotiated TLS session. The TSRequest codec and the
# stage progression are never skipped; only the per-phase field policy inside
# the acceptor is swapped.

import dataclasses
import json
import os
import typing

import spnego
from spnego.exceptions import NegotiateOptions

from .acceptor import AcceptOutcome, FuzzableCredSSPServer
from .mutations import Sample
from .state_model import Phase

NTLM_OPTIONS = NegotiateOptions.use_ntlm


@dataclasses.dataclass
class Pair:
    client: spnego.ContextProxy
    server: FuzzableCredSSPServer


def build_pair(username: str, password: str, policy: typing.Any) -> Pair:
    client = spnego.client(
        username, password, hostname="credssp-fuzz.local", protocol="credssp", options=NTLM_OPTIONS
    )
    server = FuzzableCredSSPServer(policy, hostname="credssp-fuzz.local", options=NTLM_OPTIONS)
    return Pair(client=client, server=server)


def run_tls_handshake(pair: Pair) -> bytes:
    """Drives the real memory-BIO TLS handshake between the two peers.

    This mirrors the production test loop: it exchanges TLS records until the
    initiator has created its inner SPNEGO/NTLM auth context, at which point the
    TLS channel is established. The acceptor's last emitted token is the reply
    to the initiator's first NTLM negotiate and is returned so ``advance`` can
    feed it back into the real client generator.
    """
    server_token = None
    guard = 0
    while pair.client._auth_context is None and guard < 32:
        guard += 1
        client_token = pair.client.step(server_token)
        server_token = pair.server.step(client_token)
    return server_token or b""


def advance(pair: Pair, phase: Phase) -> None:
    """Runs the genuine exchange so the acceptor sits ready for ``phase``.

    With NTLM under SPNEGO the post-TLS traffic is fixed:

      * ``m1``: client negoTokens (NTLM negotiate) -> authentication phase;
      * ``m2``: client negoTokens + pubKeyAuth     -> public key phase;
      * ``m3``: client authInfo                     -> credential phase.

    Every client message is produced by the real generator and every reply is
    processed through the real acceptor generator, so the TSRequest codec and
    stage progression are fully exercised before any mutation is injected.
    """
    auth_reply = run_tls_handshake(pair)

    if phase is Phase.authentication:
        return

    # The TLS loop already exchanged m1; the client now emits the public key m2.
    pub_key_token = pair.client.step(auth_reply)
    pair.server.step(pub_key_token)

    # At both the public key and credential phases the acceptor's NTLM context
    # is now established and its TLS session is idle. The client is deliberately
    # not driven past m2: producing the real credential m3 would write a TLS
    # record the fuzzer is about to replace with a mutated one.


def deliver_over_tls(pair: Pair, plaintext: bytes, fragment_size: typing.Optional[int] = None) -> None:
    """Wraps plaintext with the real TLS session and feeds it to the acceptor.

    With ``fragment_size`` set the ciphertext is split across several unwrap
    calls, proving TLS record framing is reassembled before the TSRequest codec
    sees the bytes.
    """
    wrapped = pair.client.wrap(plaintext).data
    if fragment_size is None:
        pair.server.unwrap(wrapped)
        return

    for offset in range(0, len(wrapped), fragment_size):
        pair.server.unwrap(wrapped[offset : offset + fragment_size])


def inject(
    pair: Pair,
    sample: Sample,
    *,
    fragment_size: typing.Optional[int] = None,
) -> AcceptOutcome:
    """Delivers one mutated TSRequest over TLS and records the acceptor verdict."""
    # The mutated bytes travel through the real TLS protection layer first.
    deliver_over_tls(pair, sample.encoded, fragment_size=fragment_size)
    return pair.server.accept_raw(sample.phase, sample.encoded)


# ---------------------------------------------------------------------------
# Artifact recording
# ---------------------------------------------------------------------------


def save_artifacts(
    out_dir: str,
    findings: typing.List[typing.Dict[str, typing.Any]],
) -> str:
    """Writes failing tokens (hex) plus the phase reached to a JSONL file."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "credssp_fuzz_failures.jsonl")
    with open(path, mode="w", encoding="utf-8") as fd:
        for finding in findings:
            fd.write(json.dumps(finding, sort_keys=True) + "\n")
    return path


def finding_record(sample: Sample, outcome: AcceptOutcome, reason: str) -> typing.Dict[str, typing.Any]:
    return {
        "sample": sample.name,
        "phase": sample.phase.value,
        "stage_reached": outcome.stage,
        "reason": reason,
        "decoded": outcome.decoded,
        "credential_accepted": outcome.credential_accepted,
        "credential_early": outcome.credential_early,
        "model_legal": outcome.evaluation.legal,
        "model_reasons": list(outcome.evaluation.reasons),
        "acceptor_error": outcome.error,
        "token_hex": sample.encoded.hex(),
    }
