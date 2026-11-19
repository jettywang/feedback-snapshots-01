"""Evidence extraction for offline NTLM handshake analysis.

The module turns raw NTLMSSP tokens into plain facts (flags, AV pairs, MIC
slot, channel-binding slot) without drawing any verdict. All interpretation
lives in :mod:`scapy.tools.ntlmmic.analysis`.

The design rule enforced here is that a fact is only recorded when it can be
read from the bytes. Anything that cannot be observed is left as ``None`` so
that later stages keep an *unknown* state instead of guessing.
"""

import base64
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.ntlm import (
    AV_PAIR,
    NTLM_AUTHENTICATE_V2,
    NTLM_CHALLENGE,
    NTLM_NEGOTIATE,
)

# AV pair identifiers from [MS-NLMP] section 2.2.2.1.
NTLM_AV_EOL = 0x0000
NTLM_AV_NB_COMPUTER_NAME = 0x0001
NTLM_AV_NB_DOMAIN_NAME = 0x0002
NTLM_AV_DNS_COMPUTER_NAME = 0x0003
NTLM_AV_DNS_DOMAIN_NAME = 0x0004
NTLM_AV_DNS_TREE_NAME = 0x0005
NTLM_AV_FLAGS = 0x0006
NTLM_AV_TIMESTAMP = 0x0007
NTLM_AV_SINGLE_HOST = 0x0008
NTLM_AV_TARGET_NAME = 0x0009
NTLM_AV_CHANNEL_BINDINGS = 0x000A

# Bits inside the MsvAvFlags value ([MS-NLMP] section 2.2.2.1).
NTLM_AVFLAG_MIC_INTEGRITY = 0x00000002
NTLM_AVFLAG_UNTRUSTED_SPN = 0x00000004

# Fixed offset of the 16-byte MIC field in a recent (post-Windows-2000)
# AUTHENTICATE_MESSAGE ([MS-NLMP] section 2.2.1.3).
NTLM_AUTH_MIC_OFFSET = 72
NTLM_AUTH_MIC_LENGTH = 16

# Message types from [MS-NLMP] section 2.2.
NTLM_MSG_NEGOTIATE = 1
NTLM_MSG_CHALLENGE = 2
NTLM_MSG_AUTHENTICATE = 3

MSG_TYPE_NAMES = {
    NTLM_MSG_NEGOTIATE: "NEGOTIATE",
    NTLM_MSG_CHALLENGE: "CHALLENGE",
    NTLM_MSG_AUTHENTICATE: "AUTHENTICATE",
}


def _av_value(av_pairs: List[AV_PAIR], av_id: int) -> Optional[Any]:
    """Return the first value for ``av_id`` among parsed AV pairs."""
    for pair in av_pairs:
        if pair.AvId == av_id:
            return pair.Value
    return None


def _has_av(av_pairs: List[AV_PAIR], av_id: int) -> bool:
    return any(pair.AvId == av_id for pair in av_pairs)


def _flag_names(flag_packet: Any) -> List[str]:
    """Return the list of set negotiate-flag names in a stable order."""
    # A scapy FlagValue is directly iterable and yields only the set flag
    # names, which is exactly the observable negotiated set.
    return sorted(set(flag_packet))


def _short(data: Optional[bytes], limit: int = 8) -> Optional[str]:
    if data is None:
        return None
    head = data[:limit].hex()
    if len(data) > limit:
        head += "..."
    return head


@dataclass
class TokenEvidence:
    """Facts read from a single NTLMSSP token.

    ``raw`` keeps the exact wire bytes because MIC verification hashes the
    concatenation of the three tokens and must use the captured encoding, not a
    re-serialised copy.
    """

    record_id: str
    context_id: str
    message_type: int
    raw: bytes
    flags: List[str] = field(default_factory=list)
    server_challenge: Optional[bytes] = None
    target_info_av: Dict[int, Any] = field(default_factory=dict)
    client_challenge_av: Dict[int, Any] = field(default_factory=dict)
    mic_value: Optional[bytes] = None
    mic_slot_present: bool = False
    channel_binding_value: Optional[bytes] = None
    channel_binding_present: bool = False
    user_name: Optional[str] = None
    domain_name: Optional[str] = None
    is_ntlmv2: bool = False
    parse_error: Optional[str] = None

    @property
    def message_name(self) -> str:
        return MSG_TYPE_NAMES.get(self.message_type, "UNKNOWN(%d)" % self.message_type)

    def to_summary(self) -> Dict[str, Any]:
        """JSON-serialisable view used by reports and tests."""
        return {
            "record_id": self.record_id,
            "context_id": self.context_id,
            "message_type": self.message_type,
            "message_name": self.message_name,
            "flags": self.flags,
            "server_challenge": _short(self.server_challenge),
            "target_info_av_ids": sorted(self.target_info_av.keys()),
            "client_challenge_av_ids": sorted(self.client_challenge_av.keys()),
            "mic_slot_present": self.mic_slot_present,
            "mic_value": self.mic_value.hex() if self.mic_value is not None else None,
            "channel_binding_present": self.channel_binding_present,
            "channel_binding_value": (
                self.channel_binding_value.hex()
                if self.channel_binding_value is not None
                else None
            ),
            "user_name": self.user_name,
            "domain_name": self.domain_name,
            "is_ntlmv2": self.is_ntlmv2,
            "parse_error": self.parse_error,
        }


def _extract_common(packet: Any, evidence: TokenEvidence) -> None:
    flags = getattr(packet, "NegotiateFlags", None)
    if flags is not None:
        evidence.flags = _flag_names(flags)


def _extract_challenge(packet: NTLM_CHALLENGE, evidence: TokenEvidence) -> None:
    evidence.server_challenge = bytes(packet.ServerChallenge or b"") or None
    target_info = list(packet.TargetInfo or [])
    evidence.target_info_av = {
        pair.AvId: pair.Value for pair in target_info if pair.AvId != NTLM_AV_EOL
    }


def _extract_authenticate(
    packet: NTLM_AUTHENTICATE_V2, evidence: TokenEvidence
) -> None:
    evidence.is_ntlmv2 = True
    # Recent variants always reserve the 16-byte MIC slot at offset 72. A
    # handshake without a MIC leaves it filled with zeroes, so an all-zero slot
    # must be read as "not populated" rather than as a carried value.
    mic = packet.fields.get("MIC", b"")
    if mic and any(mic):
        evidence.mic_slot_present = True
        evidence.mic_value = bytes(mic)
    else:
        evidence.mic_slot_present = False
        evidence.mic_value = None

    evidence.user_name = getattr(packet, "UserName", None)
    evidence.domain_name = getattr(packet, "DomainName", None)

    if evidence.is_ntlmv2:
        nt_response = packet.NtChallengeResponse
        av_pairs = list(nt_response.AvPairs or [])
        evidence.client_challenge_av = {
            pair.AvId: pair.Value for pair in av_pairs if pair.AvId != NTLM_AV_EOL
        }
        if _has_av(av_pairs, NTLM_AV_CHANNEL_BINDINGS):
            evidence.channel_binding_present = True
            evidence.channel_binding_value = bytes(
                _av_value(av_pairs, NTLM_AV_CHANNEL_BINDINGS) or b""
            ) or None


def build_token_evidence(
    record_id: str,
    context_id: str,
    raw_token: bytes,
) -> TokenEvidence:
    """Dissect one NTLMSSP token and return its observable facts.

    Parsing failures are captured on the returned object instead of raised so
    that the analyser can report a malformed record while keeping the rest of
    the capture usable.
    """
    evidence = TokenEvidence(
        record_id=record_id,
        context_id=context_id,
        message_type=0,
        raw=raw_token,
    )
    try:
        if raw_token[:8] != b"NTLMSSP\x00":
            raise ValueError("missing NTLMSSP signature")
        if len(raw_token) < 12:
            raise ValueError("token too short for MessageType")
        message_type = struct.unpack("<I", raw_token[8:12])[0]
        if message_type == NTLM_MSG_NEGOTIATE:
            packet = NTLM_NEGOTIATE(raw_token)
            evidence.message_type = NTLM_MSG_NEGOTIATE
            _extract_common(packet, evidence)
        elif message_type == NTLM_MSG_CHALLENGE:
            packet = NTLM_CHALLENGE(raw_token)
            evidence.message_type = NTLM_MSG_CHALLENGE
            _extract_common(packet, evidence)
            _extract_challenge(packet, evidence)
        elif message_type == NTLM_MSG_AUTHENTICATE:
            packet = NTLM_AUTHENTICATE_V2(raw_token)
            evidence.message_type = NTLM_MSG_AUTHENTICATE
            _extract_common(packet, evidence)
            _extract_authenticate(packet, evidence)
        else:
            raise ValueError("unknown NTLMSSP message type %d" % message_type)
    except (ValueError, KeyError, IndexError, struct.error) as exc:
        evidence.parse_error = "%s: %s" % (type(exc).__name__, exc)
    return evidence


@dataclass
class CaptureRecord:
    """One line of a capture file before dissection."""

    record_id: str
    context_id: str
    token_b64: str
    note: str = ""
    origin_context: Optional[str] = None

    def token_bytes(self) -> bytes:
        return base64.b64decode(self.token_b64)


def load_capture(path: str) -> List[CaptureRecord]:
    """Load a JSONL capture file.

    Each line is an object with ``context_id``, ``token_b64`` and an optional
    ``record_id`` / ``note``. Records keep their file order, which matters for
    interleaved handshakes.
    """
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            obj = json.loads(line)
            records.append(
                CaptureRecord(
                    record_id=obj.get("record_id", "rec-%d" % line_no),
                    context_id=obj["context_id"],
                    token_b64=obj["token_b64"],
                    note=obj.get("note", ""),
                    origin_context=obj.get("origin_context"),
                )
            )
    return records


def load_keymaterial(path: Optional[str]) -> Dict[str, bytes]:
    """Load defender-supplied exported session keys keyed by context id.

    The file maps ``context_id`` to a hex-encoded 16-byte NTLM exported session
    key. Absence of the file (or of an entry) means *unknown key*, never a
    failed verification.
    """
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        obj = json.load(handle)
    return {ctx: bytes.fromhex(value) for ctx, value in obj.items()}


def group_by_context(
    records: List[CaptureRecord],
) -> Dict[str, List[Tuple[CaptureRecord, TokenEvidence]]]:
    """Group dissected tokens by the explicit capture context id.

    Grouping never uses user names or server challenges: two handshakes that
    happen to share a challenge or a user must stay separate.
    """
    grouped: Dict[str, List[Tuple[CaptureRecord, TokenEvidence]]] = {}
    for record in records:
        evidence = build_token_evidence(
            record.record_id, record.context_id, record.token_bytes()
        )
        grouped.setdefault(record.context_id, []).append((record, evidence))
    return grouped
