"""State machine that turns NTLM token facts into integrity diagnostics.

The key discipline is that *presence*, *verifiability* and *verdict* are
distinct outputs:

- a MIC or channel-binding value can be present yet never verified;
- verification can be impossible because the exported session key or part of
  the handshake is missing;
- only an explicit recomputation (or an SSP audit record) can produce a pass or
  fail verdict.

Nothing here authenticates a user or opens a network connection.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.ntlm import HMAC_MD5

from scapy.tools.ntlmmic.evidence import (
    NTLM_AUTH_MIC_LENGTH,
    NTLM_AUTH_MIC_OFFSET,
    NTLM_AV_FLAGS,
    NTLM_AV_TIMESTAMP,
    NTLM_AVFLAG_MIC_INTEGRITY,
    NTLM_MSG_AUTHENTICATE,
    NTLM_MSG_CHALLENGE,
    NTLM_MSG_NEGOTIATE,
    TokenEvidence,
)


class Presence(str, Enum):
    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class Verifiability(str, Enum):
    VERIFIABLE = "verifiable"
    NOT_VERIFIABLE = "not_verifiable"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class MatchStatus(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


@dataclass
class Reason:
    """A single conclusion with the evidence it rests on."""

    code: str
    detail: str

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass
class MicDiagnosis:
    presence: Presence
    presence_reasons: List[Reason] = field(default_factory=list)
    verifiability: Verifiability = Verifiability.NOT_VERIFIABLE
    verifiability_reasons: List[Reason] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    verdict_reasons: List[Reason] = field(default_factory=list)
    expected_mic: Optional[str] = None
    observed_mic: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "presence": self.presence.value,
            "presence_reasons": [r.as_dict() for r in self.presence_reasons],
            "verifiability": self.verifiability.value,
            "verifiability_reasons": [
                r.as_dict() for r in self.verifiability_reasons
            ],
            "verdict": self.verdict.value,
            "verdict_reasons": [r.as_dict() for r in self.verdict_reasons],
            "expected_mic": self.expected_mic,
            "observed_mic": self.observed_mic,
        }


@dataclass
class ChannelBindingDiagnosis:
    presence: Presence
    presence_reasons: List[Reason] = field(default_factory=list)
    outer_context: str = "unknown"
    outer_context_reasons: List[Reason] = field(default_factory=list)
    match: MatchStatus = MatchStatus.UNKNOWN
    match_reasons: List[Reason] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "presence": self.presence.value,
            "presence_reasons": [r.as_dict() for r in self.presence_reasons],
            "outer_context": self.outer_context,
            "outer_context_reasons": [
                r.as_dict() for r in self.outer_context_reasons
            ],
            "match": self.match.value,
            "match_reasons": [r.as_dict() for r in self.match_reasons],
        }


@dataclass
class ContextReport:
    context_id: str
    messages_seen: List[int]
    complete: bool
    mic: MicDiagnosis
    channel_binding: ChannelBindingDiagnosis
    consistency: List[Reason] = field(default_factory=list)
    anomalies: List[Reason] = field(default_factory=list)
    ssp: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "context_id": self.context_id,
            "messages_seen": sorted(self.messages_seen),
            "complete": self.complete,
            "mic": self.mic.as_dict(),
            "channel_binding": self.channel_binding.as_dict(),
            "consistency": [r.as_dict() for r in self.consistency],
            "anomalies": [r.as_dict() for r in self.anomalies],
            "ssp_context": self.ssp,
        }


def _first(tokens: List[TokenEvidence], message_type: int) -> Optional[TokenEvidence]:
    for token in tokens:
        if token.message_type == message_type:
            return token
    return None


def _mic_presence(
    challenge: Optional[TokenEvidence],
    authenticate: Optional[TokenEvidence],
) -> Tuple[Presence, List[Reason]]:
    reasons = []
    if authenticate is None:
        reasons.append(
            Reason(
                "no_authenticate",
                "No AUTHENTICATE token in this context; MIC presence cannot be "
                "observed from the wire.",
            )
        )
        return Presence.UNKNOWN, reasons

    slot = authenticate.mic_slot_present
    av_flags = authenticate.client_challenge_av.get(NTLM_AV_FLAGS)
    client_claims_mic = bool(av_flags and av_flags & NTLM_AVFLAG_MIC_INTEGRITY)
    server_flags = (
        challenge.target_info_av.get(NTLM_AV_FLAGS) if challenge is not None else None
    )
    server_signals_mic = bool(
        server_flags and server_flags & NTLM_AVFLAG_MIC_INTEGRITY
    )

    reasons.append(
        Reason(
            "mic_slot",
            "AUTHENTICATE MIC 16-byte slot is %s."
            % ("populated" if slot else "not populated"),
        )
    )
    reasons.append(
        Reason(
            "client_avflag",
            "Client MsvAvFlags bit 0x2 (MIC integrity) is %s."
            % ("set" if client_claims_mic else "not set"),
        )
    )
    reasons.append(
        Reason(
            "server_avflag",
            "Server CHALLENGE MsvAvFlags bit 0x2 is %s."
            % ("set" if server_signals_mic else "not set"),
        )
    )

    if slot == client_claims_mic:
        if slot:
            return Presence.PRESENT, reasons
        return Presence.ABSENT, reasons
    reasons.append(
        Reason(
            "mic_indicator_conflict",
            "MIC slot and client MsvAvFlags disagree; presence is ambiguous "
            "rather than asserted.",
        )
    )
    return Presence.UNKNOWN, reasons


def _check_flag_echo(
    challenge: Optional[TokenEvidence],
    authenticate: Optional[TokenEvidence],
    anomalies: List[Reason],
) -> None:
    if challenge is None or authenticate is None:
        return
    challenge_flags = set(challenge.flags)
    authenticate_flags = set(authenticate.flags)
    dropped = challenge_flags - authenticate_flags
    extra = authenticate_flags - challenge_flags
    if dropped:
        anomalies.append(
            Reason(
                "flags_dropped",
                "AUTHENTICATE does not echo negotiated flags: %s."
                % ", ".join(sorted(dropped)),
            )
        )
    if extra:
        anomalies.append(
            Reason(
                "flags_added",
                "AUTHENTICATE advertises flags not in CHALLENGE: %s."
                % ", ".join(sorted(extra)),
            )
        )


def _check_av_echo(
    challenge: Optional[TokenEvidence],
    authenticate: Optional[TokenEvidence],
    anomalies: List[Reason],
) -> None:
    if challenge is None or authenticate is None:
        return
    server_pairs = set(challenge.target_info_av.keys())
    client_pairs = set(authenticate.client_challenge_av.keys())
    missing = server_pairs - client_pairs
    if missing:
        anomalies.append(
            Reason(
                "target_info_not_echoed",
                "Client NTLMv2 response omits server AV ids: %s."
                % ", ".join("0x%04x" % av_id for av_id in sorted(missing)),
            )
        )


def _verify_mic(
    tokens_by_type: Dict[int, TokenEvidence],
    authenticate: TokenEvidence,
    exported_key: Optional[bytes],
    complete: bool,
) -> MicDiagnosis:
    diagnosis = MicDiagnosis(presence=Presence.UNKNOWN)
    challenge = tokens_by_type.get(NTLM_MSG_CHALLENGE)
    negotiate = tokens_by_type.get(NTLM_MSG_NEGOTIATE)

    diagnosis.presence, diagnosis.presence_reasons = _mic_presence(
        challenge, authenticate
    )

    if diagnosis.presence == Presence.ABSENT:
        diagnosis.verifiability = Verifiability.NOT_VERIFIABLE
        diagnosis.verifiability_reasons.append(
            Reason(
                "mic_not_negotiated",
                "The client did not claim a MIC; there is no value to verify "
                "and no handshake-integrity guarantee is provided.",
            )
        )
        diagnosis.verdict = Verdict.UNKNOWN
        diagnosis.verdict_reasons.append(
            Reason(
                "absence_is_not_failure",
                "Missing MIC is reported as absent/unknown, not as a failed "
                "verification, because no MIC was ever produced.",
            )
        )
        return diagnosis

    missing_legs = [
        name
        for message_type, name in (
            (NTLM_MSG_NEGOTIATE, "NEGOTIATE"),
            (NTLM_MSG_CHALLENGE, "CHALLENGE"),
            (NTLM_MSG_AUTHENTICATE, "AUTHENTICATE"),
        )
        if message_type not in tokens_by_type
    ]
    if missing_legs:
        diagnosis.verifiability_reasons.append(
            Reason(
                "incomplete_handshake",
                "Missing leg(s) %s; the MIC covers all three tokens and cannot "
                "be recomputed from a partial capture."
                % ", ".join(missing_legs),
            )
        )
    if exported_key is None:
        diagnosis.verifiability_reasons.append(
            Reason(
                "no_exported_session_key",
                "No defender-supplied exported session key for this context; "
                "the HMAC-MD5 key is unavailable offline.",
            )
        )
    if missing_legs or exported_key is None:
        diagnosis.verifiability = Verifiability.NOT_VERIFIABLE
        diagnosis.verdict = Verdict.UNKNOWN
        diagnosis.verdict_reasons.append(
            Reason(
                "verdict_held_unknown",
                "Presence of the MIC field is not a verification result; the "
                "verdict stays unknown until the material above is provided.",
            )
        )
        diagnosis.observed_mic = (
            authenticate.mic_value.hex()
            if authenticate.mic_value is not None
            else None
        )
        return diagnosis

    diagnosis.verifiability = Verifiability.VERIFIABLE
    diagnosis.verifiability_reasons.append(
        Reason(
            "material_complete",
            "All three tokens and the exported session key are available; MIC "
            "recomputation is possible offline.",
        )
    )

    auth_with_zero_mic = bytearray(authenticate.raw)
    mic_end = NTLM_AUTH_MIC_OFFSET + NTLM_AUTH_MIC_LENGTH
    if len(authenticate.raw) < mic_end:
        diagnosis.verdict = Verdict.UNKNOWN
        diagnosis.verdict_reasons.append(
            Reason(
                "mic_locate_failed",
                "AUTHENTICATE is too short to contain the fixed-offset MIC slot.",
            )
        )
        return diagnosis
    auth_with_zero_mic[NTLM_AUTH_MIC_OFFSET:mic_end] = b"\x00" * NTLM_AUTH_MIC_LENGTH
    expected = HMAC_MD5(
        exported_key,
        negotiate.raw + challenge.raw + bytes(auth_with_zero_mic),
    )
    diagnosis.expected_mic = expected.hex()
    diagnosis.observed_mic = authenticate.mic_value.hex()
    if expected == authenticate.mic_value:
        diagnosis.verdict = Verdict.PASS
        diagnosis.verdict_reasons.append(
            Reason(
                "mic_recomputed_match",
                "HMAC-MD5 over NEGOTIATE+CHALLENGE+AUTH(MIC zeroed) matches the "
                "carried MIC.",
            )
        )
    else:
        diagnosis.verdict = Verdict.FAIL
        diagnosis.verdict_reasons.append(
            Reason(
                "mic_recomputed_mismatch",
                "Recomputed HMAC-MD5 differs from the carried MIC; at least one "
                "token was modified after MIC generation or the key is wrong.",
            )
        )
    return diagnosis


def _diagnose_channel_binding(
    challenge: Optional[TokenEvidence],
    authenticate: Optional[TokenEvidence],
    outer_binding_hash: Optional[bytes],
) -> ChannelBindingDiagnosis:
    diagnosis = ChannelBindingDiagnosis(presence=Presence.UNKNOWN)
    if authenticate is None:
        diagnosis.presence = Presence.UNKNOWN
        diagnosis.presence_reasons.append(
            Reason(
                "no_authenticate",
                "No AUTHENTICATE token; channel-binding AV pair presence is "
                "unobservable.",
            )
        )
        return diagnosis

    if authenticate.channel_binding_present:
        diagnosis.presence = Presence.PRESENT
        diagnosis.presence_reasons.append(
            Reason(
                "cbt_av_present",
                "MsvAvChannelBindings (AV id 0x000A) is present in the NTLMv2 "
                "client challenge with value %s."
                % authenticate.channel_binding_value.hex(),
            )
        )
    else:
        diagnosis.presence = Presence.ABSENT
        diagnosis.presence_reasons.append(
            Reason(
                "cbt_av_absent",
                "No MsvAvChannelBindings AV pair in the NTLMv2 client challenge.",
            )
        )

    if challenge is not None and NTLM_AV_TIMESTAMP in challenge.target_info_av:
        diagnosis.outer_context_reasons.append(
            Reason(
                "server_timestamp_present",
                "CHALLENGE carries MsvAvTimestamp; modern SSPs use it alongside "
                "EPA, but it does not by itself prove channel binding is "
                "required.",
            )
        )

    if outer_binding_hash is None:
        diagnosis.outer_context = "unknown"
        diagnosis.outer_context_reasons.append(
            Reason(
                "no_outer_binding",
                "No outer-channel binding (for example TLS server end-point "
                "hash) supplied; the CBT value cannot be compared offline.",
            )
        )
        diagnosis.match = MatchStatus.UNKNOWN
        diagnosis.match_reasons.append(
            Reason(
                "match_held_unknown",
                "A carried CBT value is only a claim; matching against the real "
                "channel is undecided without outer-channel material.",
            )
        )
        return diagnosis

    diagnosis.outer_context = "provided"
    if not authenticate.channel_binding_present:
        diagnosis.match = MatchStatus.MISMATCH
        diagnosis.match_reasons.append(
            Reason(
                "binding_required_but_absent",
                "Outer channel binding exists but the client omitted "
                "MsvAvChannelBindings; an SSP enforcing EPA would reject this.",
            )
        )
    elif authenticate.channel_binding_value == outer_binding_hash:
        diagnosis.match = MatchStatus.MATCH
        diagnosis.match_reasons.append(
            Reason(
                "cbt_hash_match",
                "Carried MsvAvChannelBindings equals the supplied outer-channel "
                "MD5 hash.",
            )
        )
    else:
        diagnosis.match = MatchStatus.MISMATCH
        diagnosis.match_reasons.append(
            Reason(
                "cbt_hash_mismatch",
                "Carried MsvAvChannelBindings differs from the supplied "
                "outer-channel MD5 hash.",
            )
        )
    return diagnosis


def analyze_context(
    context_id: str,
    evidences: List[TokenEvidence],
    exported_key: Optional[bytes] = None,
    outer_binding_hash: Optional[bytes] = None,
    ssp_audit: Optional[Dict[str, Any]] = None,
    records: Optional[List[Any]] = None,
) -> ContextReport:
    """Produce the full integrity report for one handshake context."""
    tokens_by_type = {}
    for evidence in evidences:
        if evidence.parse_error:
            continue
        tokens_by_type.setdefault(evidence.message_type, evidence)

    messages_seen = list(tokens_by_type.keys())
    complete = all(
        message_type in tokens_by_type
        for message_type in (
            NTLM_MSG_NEGOTIATE,
            NTLM_MSG_CHALLENGE,
            NTLM_MSG_AUTHENTICATE,
        )
    )
    challenge = tokens_by_type.get(NTLM_MSG_CHALLENGE)
    authenticate = tokens_by_type.get(NTLM_MSG_AUTHENTICATE)

    anomalies: List[Reason] = []
    for evidence in evidences:
        if evidence.parse_error:
            anomalies.append(
                Reason(
                    "parse_error",
                    "%s: %s" % (evidence.record_id, evidence.parse_error),
                )
            )
    _check_flag_echo(challenge, authenticate, anomalies)
    _check_av_echo(challenge, authenticate, anomalies)

    if authenticate is None:
        mic = MicDiagnosis(presence=Presence.UNKNOWN)
        mic.presence_reasons.append(
            Reason(
                "no_authenticate",
                "No AUTHENTICATE token in context; nothing to verify and no "
                "integrity protection can be claimed.",
            )
        )
        mic.verifiability = Verifiability.NOT_VERIFIABLE
        mic.verifiability_reasons.append(
            Reason("partial_capture", "Only the first leg(s) of the handshake exist.")
        )
        mic.verdict = Verdict.UNKNOWN
        mic.verdict_reasons.append(
            Reason(
                "not_a_pass",
                "A partial handshake must never be recorded as integrity "
                "verified; verdict remains unknown.",
            )
        )
    else:
        mic = _verify_mic(tokens_by_type, authenticate, exported_key, complete)

    channel_binding = _diagnose_channel_binding(
        challenge, authenticate, outer_binding_hash
    )

    consistency = []
    if complete:
        consistency.append(
            Reason(
                "three_legs_grouped",
                "NEGOTIATE, CHALLENGE and AUTHENTICATE share the explicit "
                "context id and were analysed as one handshake.",
            )
        )
    else:
        consistency.append(
            Reason(
                "context_incomplete",
                "Context has %d of 3 message types; no cross-leg integrity "
                "conclusion is drawn." % len(tokens_by_type),
            )
        )
    if records is not None:
        anomalies.extend(detect_lineage_mismatch(context_id, records))

    return ContextReport(
        context_id=context_id,
        messages_seen=messages_seen,
        complete=complete,
        mic=mic,
        channel_binding=channel_binding,
        consistency=consistency,
        anomalies=anomalies,
        ssp=ssp_audit,
    )


def detect_lineage_mismatch(
    context_id: str,
    records: List[Any],
) -> List[Reason]:
    """Report tokens whose explicit origin context differs from their group.

    This only reads an explicit ``origin_context`` annotation supplied with the
    capture. It never infers lineage from user names, challenges or payload
    similarity.
    """
    origins = {
        record.origin_context
        for record in records
        if getattr(record, "origin_context", None) is not None
    }
    if not origins:
        return []
    reasons = []
    if origins != {context_id}:
        reasons.append(
            Reason(
                "mixed_origin_context",
                "Tokens in %s carry explicit origins %s; the group is a splice "
                "of distinct conversations and must not be treated as one "
                "verified handshake."
                % (context_id, ", ".join(sorted(origins))),
            )
        )
    return reasons


def detect_reused_challenge(
    all_reports_input: List[Tuple[str, List[TokenEvidence]]],
) -> List[Reason]:
    """Flag identical server challenges across distinct contexts.

    Reuse is informational: it never merges contexts, because merging two
    handshakes on challenge equality is the splicing mistake the tool avoids.
    """
    seen: Dict[bytes, List[str]] = {}
    for context_id, evidences in all_reports_input:
        for evidence in evidences:
            if (
                evidence.message_type == NTLM_MSG_CHALLENGE
                and evidence.server_challenge
            ):
                seen.setdefault(evidence.server_challenge, []).append(context_id)
    reasons = []
    for challenge, contexts in seen.items():
        unique = sorted(set(contexts))
        if len(unique) > 1:
            reasons.append(
                Reason(
                    "reused_server_challenge",
                    "Server challenge %s appears in contexts %s; they remain "
                    "separate and are never spliced for MIC verification."
                    % (challenge.hex(), ", ".join(unique)),
                )
            )
    return reasons
