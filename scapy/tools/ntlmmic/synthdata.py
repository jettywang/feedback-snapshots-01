"""Synthetic, credential-free NTLM handshakes for diagnostic validation.

All identities here are fabricated: user names, domains, passwords and the
NT hash are generated locally and never correspond to real accounts. The
module builds complete NTLMv2 handshakes with scapy's NTLMSSP implementation,
then derives controlled tampered / truncated variants so the analyser can be
exercised against known-good and known-bad evidence.

Nothing in this module contacts a server or performs authentication.
"""

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.gssapi import (
    GSS_C_FLAGS,
    GSS_C_NO_CHANNEL_BINDINGS,
    GssChannelBindings,
)
from scapy.layers.ntlm import (
    HMAC_MD5,
    NTLM_AUTHENTICATE_V2,
    NTLM_CHALLENGE,
    NTLMSSP,
)

from scapy.tools.ntlmmic.evidence import (
    NTLM_AUTH_MIC_LENGTH,
    NTLM_AUTH_MIC_OFFSET,
    NTLM_AV_CHANNEL_BINDINGS,
)


@dataclass
class HandshakeArtifacts:
    context_id: str
    description: str
    records: List[Dict[str, str]]
    exported_key: Optional[bytes]
    outer_binding_hash: Optional[bytes]
    ssp_audit: Optional[Dict[str, Any]]


def _fake_identity(tag: str) -> Tuple[str, str, bytes]:
    """Return a fabricated UPN, password and NT hash for a test identity."""
    upn = "labuser_%s@example.invalid" % tag
    password = "synthetic-only-%s" % os.urandom(6).hex()
    nt_hash = NTLMSSP(UPN=upn, PASSWORD=password).HASHNT
    return upn, password, nt_hash


def _build_handshake(
    context_id: str,
    tag: str,
    use_mic: bool,
    channel_bindings: GssChannelBindings,
    server_challenge: Optional[bytes] = None,
    extra_negotiate_flag: Optional[str] = None,
) -> Tuple[
    List[Dict[str, str]],
    bytes,
    Optional[bytes],
    GssChannelBindings,
    Dict[str, Any],
]:
    upn, _password, nt_hash = _fake_identity(tag)
    client = NTLMSSP(UPN=upn, HASHNT=nt_hash, USE_MIC=use_mic)
    server = NTLMSSP(
        IDENTITIES={upn.split("@")[0]: nt_hash},
        SERVER_CHALLENGE=server_challenge,
    )

    client_ctx, negotiate, _ = client.GSS_Init_sec_context(
        None,
        req_flags=GSS_C_FLAGS.GSS_C_INTEG_FLAG | GSS_C_FLAGS.GSS_C_CONF_FLAG,
    )
    if extra_negotiate_flag is not None:
        negotiate.NegotiateFlags = negotiate.NegotiateFlags | extra_negotiate_flag
    server_ctx, challenge, _ = server.GSS_Accept_sec_context(None, negotiate)
    client_ctx, authenticate, _ = client.GSS_Init_sec_context(
        client_ctx,
        challenge,
        chan_bindings=channel_bindings,
    )

    records = [
        _record(context_id, "nego", negotiate, "NEGOTIATE"),
        _record(context_id, "chal", challenge, "CHALLENGE"),
        _record(context_id, "auth", authenticate, "AUTHENTICATE"),
    ]
    outer_hash = (
        channel_bindings.digestMD5()
        if channel_bindings != GSS_C_NO_CHANNEL_BINDINGS
        else None
    )
    tokens = {"nego": negotiate, "chal": challenge, "auth": authenticate}
    return records, client_ctx.ExportedSessionKey, outer_hash, channel_bindings, tokens


def _record(context_id: str, suffix: str, packet: Any, note: str) -> Dict[str, str]:
    return {
        "record_id": "%s-%s" % (context_id, suffix),
        "context_id": context_id,
        "token_b64": base64.b64encode(bytes(packet)).decode("ascii"),
        "note": note,
    }


def _tls_server_endpoint_binding(label: bytes) -> GssChannelBindings:
    """Build a tls-server-end-point style GSS channel binding struct."""
    application_data = b"tls-server-end-point:" + label
    return GssChannelBindings(application_data=application_data)


def _auth_record(records: List[Dict[str, str]]) -> Dict[str, str]:
    return next(r for r in records if "AUTHENTICATE" in r["note"])


def _challenge_record(records: List[Dict[str, str]]) -> Dict[str, str]:
    return next(r for r in records if "CHALLENGE" in r["note"])


def _locate_cbt_value(raw_token: bytes) -> Tuple[int, int]:
    """Return the absolute (start, end) offset of the CBT hash in raw bytes."""
    packet = NTLM_AUTHENTICATE_V2(raw_token)
    nt_raw = bytes(packet.NtChallengeResponse)
    nt_start = raw_token.find(nt_raw)
    cbt_pair = next(
        pair
        for pair in packet.NtChallengeResponse.AvPairs
        if pair.AvId == NTLM_AV_CHANNEL_BINDINGS
    )
    value_start = nt_raw.find(cbt_pair.Value)
    return nt_start + value_start, nt_start + value_start + len(cbt_pair.Value)


def _tamper_mic(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Flip one byte of the carried MIC without updating any other field."""
    auth_record = _auth_record(records)
    raw = bytearray(base64.b64decode(auth_record["token_b64"]))
    raw[NTLM_AUTH_MIC_OFFSET] ^= 0xFF
    auth_record["token_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    auth_record["note"] = "AUTHENTICATE (MIC byte tampered)"
    return records


def _tamper_username(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Flip a byte inside the UTF-16 user name, leaving the MIC intact."""
    auth_record = _auth_record(records)
    raw = bytearray(base64.b64decode(auth_record["token_b64"]))
    packet = NTLM_AUTHENTICATE_V2(bytes(raw))
    user_raw = packet.UserName.encode("utf-16le")
    user_offset = raw.find(user_raw)
    raw[user_offset] ^= 0x01
    auth_record["token_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    auth_record["note"] = "AUTHENTICATE (username byte tampered, MIC stale)"
    return records


def _tamper_challenge(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Flip a server-challenge byte while keeping the original AUTHENTICATE."""
    challenge_record = _challenge_record(records)
    raw = bytearray(base64.b64decode(challenge_record["token_b64"]))
    packet = NTLM_CHALLENGE(bytes(raw))
    challenge_offset = raw.find(packet.ServerChallenge)
    raw[challenge_offset] ^= 0x01
    challenge_record["token_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    challenge_record["note"] = "CHALLENGE (server challenge tampered)"
    return records


def _cbt_tamper_records(
    context_id: str,
) -> Tuple[List[Dict[str, str]], bytes, bytes]:
    """Build a handshake whose CBT is corrupted but MIC stays self-consistent.

    The CBT byte is flipped first, then a fresh MIC is recomputed with a
    distinct attacker-chosen key. This isolates channel-binding failure from
    MIC failure: the MIC verifies only with that alternate key, while the
    carried CBT hash no longer matches the real outer channel.
    """
    binding = _tls_server_endpoint_binding(b"endpoint-cbt")
    records, _real_key, outer_hash, _channel, tokens = _build_handshake(
        context_id, context_id, use_mic=True, channel_bindings=binding
    )
    auth_record = _auth_record(records)
    raw = bytearray(base64.b64decode(auth_record["token_b64"]))
    start, _end = _locate_cbt_value(bytes(raw))
    raw[start] ^= 0xAA

    alternate_key = b"\xcc" * 16
    raw[NTLM_AUTH_MIC_OFFSET:NTLM_AUTH_MIC_OFFSET + NTLM_AUTH_MIC_LENGTH] = (
        b"\x00" * NTLM_AUTH_MIC_LENGTH
    )
    to_sign = (
        bytes(tokens["nego"]) + bytes(tokens["chal"]) + bytes(raw)
    )
    forged_mic = HMAC_MD5(alternate_key, to_sign)
    raw[NTLM_AUTH_MIC_OFFSET:NTLM_AUTH_MIC_OFFSET + NTLM_AUTH_MIC_LENGTH] = (
        forged_mic
    )
    auth_record["token_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    auth_record["note"] = "AUTHENTICATE (CBT tampered, MIC recomputed with alt key)"
    return records, alternate_key, outer_hash


def _drop_negotiate(records: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [r for r in records if r["note"] != "NEGOTIATE"]


def _ssp_audit(context_id: str, status: str, reason: str) -> Dict[str, Any]:
    """Simulate the SSP-side view, which a passive capture cannot provide."""
    return {
        "context_id": context_id,
        "source": "simulated-ssp-audit (not derived from wire bytes)",
        "mic_verification": status,
        "reason": reason,
    }


def build_dataset() -> Tuple[List[HandshakeArtifacts], List[Dict[str, str]]]:
    """Build the full validation dataset and an interleaved capture stream.

    The first two contexts are independent, fully captured handshakes. One of
    them deliberately reuses the same 8-byte server challenge to prove that
    challenge equality never causes context splicing.
    """
    artifacts: List[HandshakeArtifacts] = []
    shared_challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"

    binding_a = _tls_server_endpoint_binding(b"endpoint-A")
    records_a, key_a, outer_a, _, tokens_a = _build_handshake(
        "ctx_alpha", "alpha", use_mic=True, channel_bindings=binding_a,
        server_challenge=shared_challenge,
        extra_negotiate_flag="NEGOTIATE_IDENTIFY",
    )
    artifacts.append(
        HandshakeArtifacts(
            "ctx_alpha",
            "Complete NTLMv2 handshake with MIC and matching channel binding.",
            records_a,
            key_a,
            outer_a,
            _ssp_audit("ctx_alpha", "verified", "SSP recomputed MIC and accepted CBT"),
        )
    )

    binding_b = _tls_server_endpoint_binding(b"endpoint-B")
    records_b, key_b, outer_b, _, tokens_b = _build_handshake(
        "ctx_beta", "beta", use_mic=True, channel_bindings=binding_b,
        server_challenge=shared_challenge,
    )
    artifacts.append(
        HandshakeArtifacts(
            "ctx_beta",
            "Complete handshake reusing the same server challenge as ctx_alpha.",
            records_b,
            key_b,
            outer_b,
            _ssp_audit("ctx_beta", "verified", "SSP recomputed MIC and accepted CBT"),
        )
    )

    # Controlled tampering, each derived from a fresh valid handshake.
    tamper_specs = [
        (
            "ctx_mic_flip",
            "MIC present but one byte corrupted; recomputation must fail.",
            _tamper_mic,
            "fail",
            "SSP rejected the token: bad MIC",
        ),
        (
            "ctx_user_tamper",
            "User name byte modified after MIC generation; stale MIC must fail.",
            _tamper_username,
            "fail",
            "SSP rejected the token: bad MIC over modified AUTHENTICATE",
        ),
        (
            "ctx_chal_tamper",
            "CHALLENGE modified while AUTHENTICATE is unchanged; MIC must fail.",
            _tamper_challenge,
            "fail",
            "SSP rejected the token: bad MIC over modified CHALLENGE",
        ),
    ]
    for index, (ctx_id, description, tamper_fn, mic_status, reason) in enumerate(
        tamper_specs
    ):
        binding = _tls_server_endpoint_binding(b"endpoint-%d" % index)
        records, key, outer_hash, _, _ = _build_handshake(
            ctx_id, ctx_id, use_mic=True, channel_bindings=binding
        )
        records = tamper_fn(records)
        artifacts.append(
            HandshakeArtifacts(
                ctx_id,
                description,
                records,
                key,
                outer_hash,
                _ssp_audit(ctx_id, mic_status, reason),
            )
        )

    # Isolated CBT failure: MIC stays verifiable under the alternate key while
    # the channel-binding hash no longer matches the outer channel.
    cbt_records, cbt_key, cbt_outer = _cbt_tamper_records("ctx_cbt_tamper")
    artifacts.append(
        HandshakeArtifacts(
            "ctx_cbt_tamper",
            "CBT hash corrupted and MIC recomputed with an alternate key; MIC "
            "can pass only with that key, channel binding must mismatch.",
            cbt_records,
            cbt_key,
            cbt_outer,
            _ssp_audit(
                "ctx_cbt_tamper",
                "verified",
                "SSP accepted the MIC under its negotiated key then rejected "
                "channel binding (bad bindings)",
            ),
        )
    )

    # No MIC at all: presence must read absent, not failed or passed.
    records_nomic, key_nomic, _outer_nomic, _, _ = _build_handshake(
        "ctx_no_mic",
        "nomic",
        use_mic=False,
        channel_bindings=GSS_C_NO_CHANNEL_BINDINGS,
    )
    artifacts.append(
        HandshakeArtifacts(
            "ctx_no_mic",
            "NTLMv2 handshake generated without a MIC.",
            records_nomic,
            key_nomic,
            None,
            _ssp_audit(
                "ctx_no_mic",
                "not_requested",
                "SSP saw no MIC claim and applied no MIC verification",
            ),
        )
    )

    # Half capture: only CHALLENGE + AUTHENTICATE survive.
    records_half, _key_half, _outer_half, _, _ = _build_handshake(
        "ctx_half",
        "half",
        use_mic=True,
        channel_bindings=GSS_C_NO_CHANNEL_BINDINGS,
    )
    artifacts.append(
        HandshakeArtifacts(
            "ctx_half",
            "Rear-only capture: NEGOTIATE missing, MIC present but uncheckable.",
            _drop_negotiate(records_half),
            None,
            None,
            None,
        )
    )

    # Deliberate splice using all three legs from two different conversations.
    # Both share a server challenge by construction, which is exactly the
    # situation where matching on challenge would wrongly merge them.
    alpha = next(a for a in artifacts if a.context_id == "ctx_alpha")
    beta = next(a for a in artifacts if a.context_id == "ctx_beta")
    spliced = [
        _spliced_record(tokens_a["nego"], "ctx_spliced", "nego", "ctx_alpha"),
        _spliced_record(tokens_b["chal"], "ctx_spliced", "chal", "ctx_beta"),
        _spliced_record(tokens_b["auth"], "ctx_spliced", "auth", "ctx_beta"),
    ]
    artifacts.append(
        HandshakeArtifacts(
            "ctx_spliced",
            "Three-leg splice of two conversations; MIC recomputation must fail "
            "instead of silently passing on a shared challenge.",
            spliced,
            beta.exported_key,
            beta.outer_binding_hash,
            _ssp_audit(
                "ctx_spliced",
                "fail",
                "SSP rejected: tokens do not belong to one conversation",
            ),
        )
    )

    interleaved = _interleave(
        alpha.records,
        beta.records,
    )
    return artifacts, interleaved


def _spliced_record(
    packet: Any, context_id: str, suffix: str, origin: str
) -> Dict[str, str]:
    record = _record(context_id, suffix, packet, "NEGOTIATE" if suffix == "nego" else (
        "CHALLENGE" if suffix == "chal" else "AUTHENTICATE"
    ))
    record["origin_context"] = origin
    record["note"] = record["note"] + " (spliced from %s)" % origin
    return record


def _interleave(
    first: List[Dict[str, str]],
    second: List[Dict[str, str]],
) -> List[Dict[str, str]]:
    """Merge two ordered handshakes into one interleaved on-the-wire stream."""
    stream = []
    for left, right in zip(first, second):
        stream.append(left)
        stream.append(right)
    return stream


def write_dataset(output_dir: str) -> Dict[str, str]:
    """Persist the capture, per-context keys and an SSP audit sidecar."""
    os.makedirs(output_dir, exist_ok=True)
    artifacts, interleaved = build_dataset()

    capture_path = os.path.join(output_dir, "capture.jsonl")
    with open(capture_path, "w", encoding="utf-8") as handle:
        for record in interleaved:
            handle.write(json.dumps(record) + "\n")
        for item in artifacts[2:]:
            for record in item.records:
                handle.write(json.dumps(record) + "\n")

    keys_path = os.path.join(output_dir, "session_keys.json")
    with open(keys_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                item.context_id: item.exported_key.hex()
                for item in artifacts
                if item.exported_key is not None
            },
            handle,
            indent=2,
        )

    bindings_path = os.path.join(output_dir, "outer_bindings.json")
    with open(bindings_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                item.context_id: item.outer_binding_hash.hex()
                for item in artifacts
                if item.outer_binding_hash is not None
            },
            handle,
            indent=2,
        )

    audit_path = os.path.join(output_dir, "ssp_audit.json")
    with open(audit_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                item.context_id: item.ssp_audit
                for item in artifacts
                if item.ssp_audit is not None
            },
            handle,
            indent=2,
        )

    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "contexts": [
                    {
                        "context_id": item.context_id,
                        "description": item.description,
                        "record_count": len(item.records),
                    }
                    for item in artifacts
                ],
                "synthetic_only": True,
                "real_accounts": False,
            },
            handle,
            indent=2,
        )
    return {
        "capture": capture_path,
        "keys": keys_path,
        "outer_bindings": bindings_path,
        "ssp_audit": audit_path,
        "manifest": manifest_path,
    }
