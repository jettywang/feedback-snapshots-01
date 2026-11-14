# -*- coding: utf-8 -*-
# Deterministic TSRequest mutation corpus for the CredSSP state fuzzer.
#
# Every sample is built from a phase-legal baseline, then one structural
# mutation is applied. The corpus intentionally mixes requests that still
# decode cleanly (the interesting state-machine cases) with truncations and
# concatenated objects that the codec itself must reject. A fixed seed makes
# the corpus reproducible across runs.

import dataclasses
import random
import typing

from .asn1_builder import (
    CREDSSP_VERSION,
    TAG_AUTH_INFO,
    TAG_CLIENT_NONCE,
    TAG_NEGO_TOKENS,
    TAG_PUB_KEY_AUTH,
    encode_error_code,
    encode_nego_tokens,
    encode_octet_field,
    encode_ts_request,
    encode_version,
    parse_tags,
    plausible_nego_token,
    random_octets,
)
from spnego._asn1 import TagClass, pack_asn1
from .state_model import Phase


@dataclasses.dataclass(frozen=True)
class Sample:
    name: str
    phase: Phase
    encoded: bytes


def _baseline_members(rng: random.Random, phase: Phase) -> typing.List[bytes]:
    members: typing.List[bytes] = [encode_version(CREDSSP_VERSION)]

    if phase in (Phase.authentication, Phase.public_key):
        members.append(encode_nego_tokens([plausible_nego_token(rng)]))

    if phase == Phase.public_key:
        members.append(encode_octet_field(TAG_CLIENT_NONCE, random_octets(rng, 32, 33)))
        members.append(encode_octet_field(TAG_PUB_KEY_AUTH, random_octets(rng)))

    if phase == Phase.credential:
        members.append(encode_octet_field(TAG_AUTH_INFO, random_octets(rng)))

    return members


def _strip_member(members: typing.List[bytes], tag: int) -> typing.List[bytes]:
    kept = []
    for member in members:
        member_tags, _ = parse_tags(encode_ts_request([member]))
        if member_tags[0] != tag:
            kept.append(member)
    return kept


def _empty_member_blob() -> bytes:
    """Builds a TSRequest whose authInfo member has no decodable body.

    The outer SEQUENCE and context tag are well formed, but the authInfo member
    carries an empty OCTET STRING body that a strict codec cannot unpack, so the
    whole TSRequest fails to decode even though its framing TLV is parseable.
    """
    broken_member = pack_asn1(TagClass.context_specific, True, TAG_AUTH_INFO, b"")
    return encode_ts_request([encode_version(CREDSSP_VERSION), broken_member])


def mutate(rng: random.Random, phase: Phase, index: int) -> Sample:
    members = _baseline_members(rng, phase)
    label = "case%02d" % index
    kind = index % 9

    if kind == 0:
        # Duplicate version, second copy advertises a lower protocol.
        members.insert(1, encode_version(CREDSSP_VERSION - 1))
        name = "%s-%s-dup_version" % (phase.value, label)

    elif kind == 1:
        # Multiple negoTokens, including an empty token entry.
        members = _strip_member(members, TAG_NEGO_TOKENS)
        tokens = [plausible_nego_token(rng), b"", plausible_nego_token(rng)]
        members.insert(1, encode_nego_tokens(tokens))
        name = "%s-%s-multi_nego_tokens" % (phase.value, label)

    elif kind == 2:
        # authInfo sent far too early, beside the legal phase fields.
        members.append(encode_octet_field(TAG_AUTH_INFO, random_octets(rng)))
        name = "%s-%s-early_auth_info" % (phase.value, label)

    elif kind == 3:
        # pubKeyAuth in a phase that must not carry it.
        members.append(encode_octet_field(TAG_PUB_KEY_AUTH, random_octets(rng)))
        name = "%s-%s-early_pub_key_auth" % (phase.value, label)

    elif kind == 4:
        # errorCode alongside credential-bearing fields.
        members.append(encode_error_code())
        if phase is not Phase.credential:
            members.append(encode_octet_field(TAG_AUTH_INFO, random_octets(rng)))
        name = "%s-%s-error_with_credentials" % (phase.value, label)

    elif kind == 5:
        # Truncation at an interior byte boundary.
        encoded = encode_ts_request(members)
        cut = rng.randrange(2, max(3, len(encoded) - 1))
        return Sample("%s-%s-truncated" % (phase.value, label), phase, encoded[:cut])

    elif kind == 6:
        # A second, complete ASN.1 TSRequest concatenated after the first.
        second = encode_ts_request(
            [encode_version(CREDSSP_VERSION), encode_octet_field(TAG_AUTH_INFO, b"second-object")]
        )
        encoded = encode_ts_request(members) + second
        return Sample("%s-%s-concat_second_object" % (phase.value, label), phase, encoded)

    elif kind == 7:
        # A context tagged member with no decodable body. The framing TLV is
        # well formed but the codec cannot unpack the empty member, so the whole
        # TSRequest fails to decode.
        return Sample("%s-%s-broken_length" % (phase.value, label), phase, _empty_member_blob())

    else:
        # Shuffled field order plus an unexpected clientNonce outside pub key.
        rng.shuffle(members)
        if phase is not Phase.public_key:
            members.append(encode_octet_field(TAG_CLIENT_NONCE, random_octets(rng)))
        name = "%s-%s-shuffled_fields" % (phase.value, label)

    return Sample(name, phase, encode_ts_request(members))


def generate_samples(seed: int, per_phase: int) -> typing.List[Sample]:
    samples: typing.List[Sample] = []
    for phase in Phase:
        rng = random.Random(seed + hash(phase.value))
        for index in range(per_phase):
            samples.append(mutate(rng, phase, index))
    return samples
