# -*- coding: utf-8 -*-
# Byte-level TSRequest builder used by the CredSSP state fuzzer.
#
# The production spnego TSRequest.pack() only emits well-formed, in-order,
# single-occurrence fields. State fuzzing needs shapes that still decode as
# ASN.1 but violate the TSRequest grammar (duplicate version, several
# negoTokens, trailing objects, ...). These helpers build the context tagged
# members directly while keeping every TLV individually DER valid.

import random
import typing

from spnego._asn1 import (
    TagClass,
    pack_asn1,
    pack_asn1_integer,
    pack_asn1_octet_string,
    pack_asn1_sequence,
    unpack_asn1,
)
from spnego._credssp_structures import NegoData

CREDSSP_VERSION = 6

TAG_VERSION = 0
TAG_NEGO_TOKENS = 1
TAG_AUTH_INFO = 2
TAG_PUB_KEY_AUTH = 3
TAG_ERROR_CODE = 4
TAG_CLIENT_NONCE = 5

ALL_FIELD_TAGS = (
    TAG_VERSION,
    TAG_NEGO_TOKENS,
    TAG_AUTH_INFO,
    TAG_PUB_KEY_AUTH,
    TAG_ERROR_CODE,
    TAG_CLIENT_NONCE,
)
FIELD_NAMES = {
    TAG_VERSION: "version",
    TAG_NEGO_TOKENS: "negoTokens",
    TAG_AUTH_INFO: "authInfo",
    TAG_PUB_KEY_AUTH: "pubKeyAuth",
    TAG_ERROR_CODE: "errorCode",
    TAG_CLIENT_NONCE: "clientNonce",
}


def _tagged(tag: int, content: bytes) -> bytes:
    return pack_asn1(TagClass.context_specific, True, tag, content)


def encode_version(value: int = CREDSSP_VERSION) -> bytes:
    return _tagged(TAG_VERSION, pack_asn1_integer(value))


def encode_nego_tokens(tokens: typing.List[bytes]) -> bytes:
    return _tagged(TAG_NEGO_TOKENS, pack_asn1_sequence([NegoData(t).pack() for t in tokens]))


def encode_octet_field(tag: int, value: bytes) -> bytes:
    return _tagged(tag, pack_asn1_octet_string(value))


def encode_error_code(value: int = 0xC000006D) -> bytes:
    return _tagged(TAG_ERROR_CODE, pack_asn1_integer(value))


def encode_ts_request(members: typing.List[bytes]) -> bytes:
    return pack_asn1_sequence(members)


def parse_tags(encoded: bytes) -> typing.Tuple[typing.List[int], bytes]:
    """Returns (top-level context tags, bytes trailing the first object)."""
    outer, trailing = unpack_asn1(encoded)
    tags: typing.List[int] = []
    remaining = outer.b_data
    while remaining:
        member, remaining = unpack_asn1(remaining)
        tags.append(member.tag_number)
    return tags, trailing


def plausible_nego_token(rng: random.Random) -> bytes:
    header = rng.choice(
        [
            b"NTLMSSP\x00\x01\x00\x00\x00",
            b"NTLMSSP\x00\x03\x00\x00\x00",
            b"\x60\x2c\x06\x06\x2b\x06\x01\x05\x05\x02",
        ]
    )
    return header + bytes(rng.randrange(1, 12))


def random_octets(rng: random.Random, low: int = 1, high: int = 32) -> bytes:
    return bytes(rng.randrange(low, high))
