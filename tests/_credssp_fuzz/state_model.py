# -*- coding: utf-8 -*-
# Independent CredSSP TSRequest state model.
#
# This is the test oracle. It deliberately does not import or call the
# production CredSSPProxy logic; it encodes the field combinations that are
# legal at each CredSSP handshake phase straight from MS-CSSP. Its job is to
# answer one question for every mutated request: are the fields present legal
# for the phase in which they were sent, and could they make an acceptor touch
# delegated credentials before the public-key binding is established.

import dataclasses
import enum
import typing

from spnego._asn1 import unpack_asn1

from .asn1_builder import (
    ALL_FIELD_TAGS,
    FIELD_NAMES,
    TAG_AUTH_INFO,
    TAG_CLIENT_NONCE,
    TAG_NEGO_TOKENS,
    TAG_PUB_KEY_AUTH,
    TAG_VERSION,
)


class Phase(enum.Enum):
    authentication = "authentication"
    public_key = "public_key"
    credential = "credential"


_PHASE_ALLOWED = {
    Phase.authentication: frozenset({TAG_VERSION, TAG_NEGO_TOKENS}),
    Phase.public_key: frozenset(
        {TAG_VERSION, TAG_NEGO_TOKENS, TAG_PUB_KEY_AUTH, TAG_CLIENT_NONCE}
    ),
    Phase.credential: frozenset({TAG_VERSION, TAG_AUTH_INFO}),
}


@dataclasses.dataclass(frozen=True)
class Evaluation:
    phase: Phase
    legal: bool
    decode_ok: bool
    reasons: typing.Tuple[str, ...]
    has_auth_info: bool
    has_pub_key_auth: bool
    has_trailing_object: bool

    @property
    def premature_credential(self) -> bool:
        """True when authInfo shows up anywhere other than the credential phase."""
        return self.has_auth_info and self.phase is not Phase.credential


def evaluate(encoded: bytes, phase: Phase) -> Evaluation:
    reasons: typing.List[str] = []
    decode_ok = True
    trailing = b""
    tags: typing.List[int] = []

    try:
        outer, trailing = unpack_asn1(encoded)
        remaining = outer.b_data
        while remaining:
            member, remaining = unpack_asn1(remaining)
            # A context tagged TSRequest member must wrap a nested TLV. An empty
            # body is not a decodable field even though the framing tag itself is
            # well formed, mirroring what the production codec rejects.
            if not member.b_data:
                raise ValueError("empty context tagged member %d" % member.tag_number)
            tags.append(member.tag_number)
    except Exception as e:
        decode_ok = False
        reasons.append("undecodable ASN.1: %s" % type(e).__name__)

    has_trailing_object = bool(trailing)
    if has_trailing_object:
        reasons.append("trailing ASN.1 object after the TSRequest")

    if decode_ok:
        version_count = tags.count(TAG_VERSION)
        if version_count != 1:
            reasons.append("version must occur exactly once, found %d" % version_count)

        allowed = _PHASE_ALLOWED[phase]
        for tag in tags:
            if tag not in ALL_FIELD_TAGS:
                reasons.append("unknown field tag %d" % tag)
            elif tag != TAG_VERSION and tag not in allowed:
                reasons.append("field %s illegal in phase %s" % (FIELD_NAMES.get(tag, tag), phase.value))

        if phase in (Phase.authentication, Phase.public_key) and TAG_NEGO_TOKENS not in tags:
            reasons.append("negoTokens required in phase %s" % phase.value)
        if phase == Phase.public_key and TAG_PUB_KEY_AUTH not in tags:
            reasons.append("pubKeyAuth required in public key phase")
        if phase == Phase.credential and TAG_AUTH_INFO not in tags:
            reasons.append("authInfo required in credential phase")

    return Evaluation(
        phase=phase,
        legal=decode_ok and not reasons,
        decode_ok=decode_ok,
        reasons=tuple(reasons),
        has_auth_info=TAG_AUTH_INFO in tags,
        has_pub_key_auth=TAG_PUB_KEY_AUTH in tags,
        has_trailing_object=has_trailing_object,
    )
