# -*- coding: utf-8 -*-
# Stateful structure fuzzing of the CredSSP TSRequest (MS-CSSP 2.2.1).
#
# These tests drive a real in-memory TLS CredSSP exchange and inject mutated
# TSRequest messages at each handshake phase. An independent state model judges
# whether the field combination is legal for the phase; the security oracle
# asserts that delegated credentials (authInfo) are never consumed early.

import os

import pytest

import spnego
from spnego._credssp_structures import NegoData, TSRequest
from spnego.exceptions import NegotiateOptions

from ._credssp_fuzz.acceptor import (
    FuzzableCredSSPServer,
    PermissiveAcceptPolicy,
    StrictAcceptPolicy,
)
from ._credssp_fuzz.harness import advance, build_pair, inject, save_artifacts
from ._credssp_fuzz.mutations import generate_samples
from ._credssp_fuzz.runner import run_campaign, run_strict
from ._credssp_fuzz.state_model import Phase, evaluate

SEED = 20261115
PER_PHASE = 12


@pytest.fixture(scope="module")
def samples():
    return generate_samples(SEED, PER_PHASE)


def test_corpus_is_deterministic():
    first = generate_samples(SEED, PER_PHASE)
    second = generate_samples(SEED, PER_PHASE)
    assert [s.encoded for s in first] == [s.encoded for s in second]
    assert len(first) == PER_PHASE * len(Phase)
    # Every requested mutation class is represented in the corpus.
    names = " ".join(s.name for s in first)
    for marker in [
        "dup_version",
        "multi_nego_tokens",
        "early_auth_info",
        "early_pub_key_auth",
        "error_with_credentials",
        "truncated",
        "concat_second_object",
        "broken_length",
        "shuffled_fields",
    ]:
        assert marker in names


def test_state_model_marks_early_credentials_illegal():
    legal = TSRequest(6, nego_tokens=NegoData(b"\x01")).pack()
    assert evaluate(legal, Phase.authentication).legal

    early = TSRequest(6, nego_tokens=NegoData(b"\x01"), auth_info=b"secret").pack()
    verdict = evaluate(early, Phase.authentication)
    assert not verdict.legal
    assert verdict.premature_credential

    final = TSRequest(6, auth_info=b"secret").pack()
    assert evaluate(final, Phase.credential).legal


def test_strict_acceptor_never_consumes_early_credentials(ntlm_cred, samples, tmp_path):
    result = run_strict(ntlm_cred[0], ntlm_cred[1], samples)

    if not result.ok:
        path = save_artifacts(str(tmp_path), result.findings)
        pytest.fail("strict acceptor violated the state oracle (%d findings): %s" % (len(result.findings), path))

    assert result.premature_accepts == 0
    # Malformed length blobs must be rejected at decode time and never reach the
    # credential sink, while out-of-phase blobs are rejected by the state model.
    assert result.decode_rejections > 0
    assert result.structural_rejections > 0


def test_fragmented_tls_does_not_change_verdict(ntlm_cred, samples):
    fragmented = run_campaign(
        ntlm_cred[0], ntlm_cred[1], samples, StrictAcceptPolicy(), fragment_size=7
    )
    whole = run_strict(ntlm_cred[0], ntlm_cred[1], samples)
    assert fragmented.ok
    # Splitting the TLS records must not alter which requests are rejected.
    assert [f["sample"] for f in fragmented.findings] == [f["sample"] for f in whole.findings]


def test_permissive_double_is_caught(ntlm_cred, samples, tmp_path):
    # The deliberately vulnerable acceptor must accept an early authInfo; the
    # oracle has to flag it, proving the criterion can actually catch the bug.
    early = next(s for s in samples if "early_auth_info" in s.name and s.phase is Phase.authentication)

    pair = build_pair(ntlm_cred[0], ntlm_cred[1], PermissiveAcceptPolicy())
    advance(pair, early.phase)
    outcome = inject(pair, early)

    assert outcome.decoded
    assert outcome.credential_accepted
    assert outcome.credential_early
    assert pair.server.credential_accepted_early
    assert not outcome.evaluation.legal

    result = run_campaign(ntlm_cred[0], ntlm_cred[1], samples, PermissiveAcceptPolicy())
    assert not result.ok, "oracle failed to catch the permissive acceptor"
    assert result.premature_accepts > 0
    save_artifacts(str(tmp_path), result.findings)


def test_legitimate_final_token_is_not_rejected(ntlm_cred):
    # A complete, genuine CredSSP exchange must finish successfully; the strict
    # policy and state model must not false-positive on the real final token.
    client = spnego.client(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname="credssp-fuzz.local",
        protocol="credssp",
        options=NegotiateOptions.use_ntlm,
    )
    server = FuzzableCredSSPServer(
        StrictAcceptPolicy(), hostname="credssp-fuzz.local", options=NegotiateOptions.use_ntlm
    )

    token = client.step(None)
    guard = 0
    while token is not None and guard < 32:
        guard += 1
        token = server.step(token)
        if token is None:
            break
        token = client.step(token)

    assert client.complete
    assert server.complete
    credential = server.get_extra_info("client_credential")
    assert credential is not None
    assert not server.credential_accepted_early


def test_legal_requests_pass_state_model_each_phase():
    authentication = TSRequest(6, nego_tokens=NegoData(b"\x01\x02")).pack()
    public_key = TSRequest(
        6, nego_tokens=NegoData(b"\x03"), pub_key_auth=b"pk", client_nonce=os.urandom(32)
    ).pack()
    credential = TSRequest(6, auth_info=b"cred").pack()

    assert evaluate(authentication, Phase.authentication).legal
    assert evaluate(public_key, Phase.public_key).legal
    assert evaluate(credential, Phase.credential).legal


def test_trailing_object_is_flagged():
    first = TSRequest(6, nego_tokens=NegoData(b"\x01")).pack()
    trailing = first + TSRequest(6, auth_info=b"x").pack()
    verdict = evaluate(trailing, Phase.authentication)
    assert not verdict.legal
    assert verdict.has_trailing_object
