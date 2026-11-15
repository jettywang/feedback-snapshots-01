# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Regression tests for the NTLM handshake MIC binding.

The MIC in the NTLM AUTHENTICATE message covers the NEGOTIATE, CHALLENGE, and AUTHENTICATE tokens as they were sent
on the wire. The field values in those messages do not fully describe the bytes of those messages, the security buffers
can be laid out in a different order, at different offsets, and with different padding. These tests build the same
field values in multiple legal layouts and prove that the acceptor verifies the MIC against the received bytes and not
against a message that was unpacked and packed again.

The expected MICs are calculated by an independent implementation of the NTLMv2 response and MIC logic that lives in
this module, they do not call the MIC helpers in the library under test.
"""

import hashlib
import hmac
import struct
import typing

import pytest

import spnego
from spnego._ntlm_raw.messages import Authenticate, AvId, Challenge, Negotiate, NegotiateFlags

PASSWORD = "Password"
DOMAIN = "Domain"
USER = "User"
WORKSTATION = "CLIENT"
SERVER = "SERVER"

# Static values so the tests produce the exact same sample every run.
SERVER_CHALLENGE = bytes.fromhex("0123456789abcdef")
CLIENT_CHALLENGE = bytes.fromhex("da1db1af88a41df3")
TIMESTAMP = bytes.fromhex("2c750671b130d601")
SESSION_KEY = bytes.fromhex("5a3b00dc0cb9eb28f8de5411dbe5617b")
VERSION = bytes([10, 0, 0x2C, 0x5D, 0, 0, 0, 0x0F])

BASE_FLAGS = (
    NegotiateFlags.unicode
    | NegotiateFlags.ntlm
    | NegotiateFlags.always_sign
    | NegotiateFlags.sign
    | NegotiateFlags.seal
    | NegotiateFlags.key_exch
    | NegotiateFlags.key_128
    | NegotiateFlags.key_56
    | NegotiateFlags.extended_session_security
    | NegotiateFlags.request_target
    | NegotiateFlags.target_info
)


def _md4(data: bytes) -> bytes:
    """Independent MD4 implementation, RFC 1320."""

    mask = 0xFFFFFFFF

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    def rol(value: int, count: int) -> int:
        return ((value << count) | (value >> (32 - count))) & mask

    message = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for block in range(0, len(message), 64):
        words = struct.unpack("<16I", message[block : block + 64])
        aa, bb, cc, dd = a, b, c, d

        for index in range(0, 16, 4):
            a = rol((a + f(b, c, d) + words[index]) & mask, 3)
            d = rol((d + f(a, b, c) + words[index + 1]) & mask, 7)
            c = rol((c + f(d, a, b) + words[index + 2]) & mask, 11)
            b = rol((b + f(c, d, a) + words[index + 3]) & mask, 19)

        for index in range(4):
            a = rol((a + g(b, c, d) + words[index] + 0x5A827999) & mask, 3)
            d = rol((d + g(a, b, c) + words[index + 4] + 0x5A827999) & mask, 5)
            c = rol((c + g(d, a, b) + words[index + 8] + 0x5A827999) & mask, 9)
            b = rol((b + g(c, d, a) + words[index + 12] + 0x5A827999) & mask, 13)

        for index, offset in [(0, 8), (2, 10), (1, 9), (3, 11)]:
            a = rol((a + h(b, c, d) + words[index] + 0x6ED9EBA1) & mask, 3)
            d = rol((d + h(a, b, c) + words[offset] + 0x6ED9EBA1) & mask, 9)
            c = rol((c + h(d, a, b) + words[index + 4] + 0x6ED9EBA1) & mask, 11)
            b = rol((b + h(c, d, a) + words[offset + 4] + 0x6ED9EBA1) & mask, 15)

        a, b, c, d = (a + aa) & mask, (b + bb) & mask, (c + cc) & mask, (d + dd) & mask

    return struct.pack("<4I", a, b, c, d)


def _hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def _rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    index = 0
    for pos in range(256):
        index = (index + state[pos] + key[pos % len(key)]) & 0xFF
        state[pos], state[index] = state[index], state[pos]

    output = bytearray()
    pos = index = 0
    for byte in data:
        pos = (pos + 1) & 0xFF
        index = (index + state[pos]) & 0xFF
        state[pos], state[index] = state[index], state[pos]
        output.append(byte ^ state[(state[pos] + state[index]) & 0xFF])

    return bytes(output)


def _response_key() -> bytes:
    return _hmac_md5(_md4(PASSWORD.encode("utf-16-le")), (USER.upper() + DOMAIN).encode("utf-16-le"))


def _target_info(av_flags: typing.Optional[int] = 2, timestamp: bool = True) -> bytes:
    data = b""

    for av_id, value in [
        (AvId.nb_computer_name, SERVER.encode("utf-16-le")),
        (AvId.nb_domain_name, "WORKSTATION".encode("utf-16-le")),
        (AvId.dns_computer_name, "server.example.com".encode("utf-16-le")),
    ]:
        data += struct.pack("<HH", av_id, len(value)) + value

    if av_flags is not None:
        data += struct.pack("<HH", AvId.flags, 4) + struct.pack("<I", av_flags)

    if timestamp:
        data += struct.pack("<HH", AvId.timestamp, 8) + TIMESTAMP

    target_name = "host/server.example.com".encode("utf-16-le")
    data += struct.pack("<HH", AvId.target_name, len(target_name)) + target_name
    data += struct.pack("<HH", AvId.eol, 0)

    return data


def _nt_response(
    target_info: bytes,
    server_challenge: bytes = SERVER_CHALLENGE,
    client_challenge: bytes = CLIENT_CHALLENGE,
    timestamp: bytes = TIMESTAMP,
) -> bytes:
    temp = b"\x01\x01" + b"\x00" * 6 + timestamp + client_challenge + b"\x00" * 4 + target_info + b"\x00" * 4
    proof = _hmac_md5(_response_key(), server_challenge + temp)
    return proof + temp


def _payload(entries: typing.List[typing.Tuple[int, bytes]], start: int) -> typing.Tuple[bytes, typing.Dict[int, int]]:
    """Place each entry at an offset relative to the payload start and record the absolute offsets."""

    data = bytearray()
    offsets = {}

    for relative_offset, value in sorted(entries):
        assert relative_offset >= len(data)
        data.extend(b"\x00" * (relative_offset - len(data)))
        offsets[relative_offset] = start + relative_offset
        data.extend(value)

    return bytes(data), offsets


def _security_buffer(length: int, offset: int) -> bytes:
    return struct.pack("<HHI", length, length, offset)


def _build_negotiate(
    flags: int,
    *,
    include_version: bool = True,
    leading_pad: int = 0,
    trailing_pad: int = 0,
) -> bytes:
    version = VERSION if include_version else b""
    if include_version:
        flags |= NegotiateFlags.version
    else:
        flags &= ~NegotiateFlags.version

    header_end = 32 + len(version)
    payload, _ = _payload([(leading_pad, b"")], header_end)
    body = payload + b"\x00" * trailing_pad

    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 1)
        + struct.pack("<I", flags)
        + _security_buffer(0, header_end + len(body))
        + _security_buffer(0, header_end + len(body))
        + version
        + body
    )


def _build_challenge(
    flags: int,
    target_info: bytes,
    *,
    include_version: bool = True,
    name_first: bool = True,
    leading_pad: int = 0,
    gap: int = 0,
    trailing_pad: int = 0,
) -> bytes:
    version = VERSION if include_version else b""
    if include_version:
        flags |= NegotiateFlags.version
    else:
        flags &= ~NegotiateFlags.version

    name = SERVER.encode("utf-16-le")
    start = 48 + len(version)

    if name_first:
        entries = [(leading_pad, name), (leading_pad + len(name) + gap, target_info)]
        name_rel = leading_pad
        info_rel = leading_pad + len(name) + gap
    else:
        entries = [(leading_pad, target_info), (leading_pad + len(target_info) + gap, name)]
        info_rel = leading_pad
        name_rel = leading_pad + len(target_info) + gap

    body, _ = _payload(entries, start)

    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + _security_buffer(len(name), start + name_rel)
        + struct.pack("<I", flags)
        + SERVER_CHALLENGE
        + b"\x00" * 8
        + _security_buffer(len(target_info), start + info_rel)
        + version
        + body
        + b"\x00" * trailing_pad
    )


def _build_authenticate(
    flags: int,
    *,
    include_version: bool = True,
    mic: typing.Optional[bytes],
    server_challenge: bytes = SERVER_CHALLENGE,
    field_order: typing.Tuple[str, ...] = ("lm", "nt", "domain", "user", "workstation", "key"),
    leading_pad: int = 0,
    gap: int = 0,
    trailing_pad: int = 0,
    target_info: typing.Optional[bytes] = None,
) -> bytes:
    version = VERSION if include_version else b""
    if include_version:
        flags |= NegotiateFlags.version
    else:
        flags &= ~NegotiateFlags.version

    if target_info is None:
        target_info = _target_info()

    nt_response = _nt_response(target_info, server_challenge=server_challenge)
    session_base_key = _hmac_md5(_response_key(), nt_response[:16])
    encrypted_session_key = _rc4(session_base_key, SESSION_KEY)

    fields = {
        "lm": b"\x00" * 24,
        "nt": nt_response,
        "domain": DOMAIN.encode("utf-16-le"),
        "user": USER.encode("utf-16-le"),
        "workstation": WORKSTATION.encode("utf-16-le"),
        "key": encrypted_session_key,
    }

    mic_offset = 64 + len(version)
    payload_start = mic_offset + (16 if mic else 0)

    entries = []
    offsets = {}
    current = leading_pad
    for index, name in enumerate(field_order):
        offsets[name] = current
        entries.append((current, fields[name]))
        current += len(fields[name]) + (gap if index < len(field_order) - 1 else 0)

    body, absolute = _payload(entries, payload_start)

    header = bytearray(b"NTLMSSP\x00" + struct.pack("<I", 3))
    for name in ("lm", "nt", "domain", "user", "workstation", "key"):
        header += _security_buffer(len(fields[name]), absolute[offsets[name]])
    header += struct.pack("<I", flags) + version + (mic or b"")

    assert len(header) == payload_start

    return bytes(header) + body + b"\x00" * trailing_pad


def _mic(session_key: bytes, negotiate: bytes, challenge: bytes, authenticate: bytes, mic_offset: int) -> bytes:
    message = bytearray(authenticate)
    message[mic_offset : mic_offset + 16] = b"\x00" * 16

    return _hmac_md5(session_key, negotiate + challenge + bytes(message))


def _canonical_message(kind: str, raw: bytes) -> bytes:
    """Re-encode a message from its parsed field values, dropping any layout detail."""

    if kind == "negotiate":
        msg = Negotiate.unpack(raw)
        return Negotiate(
            msg.flags,
            domain_name=msg.domain_name,
            workstation=msg.workstation,
            version=msg.version if msg.flags & NegotiateFlags.version else None,
        ).pack()

    elif kind == "challenge":
        msg = Challenge.unpack(raw)
        return Challenge(
            msg.flags,
            msg.server_challenge,
            target_name=msg.target_name,
            target_info=msg.target_info,
            version=msg.version if msg.flags & NegotiateFlags.version else None,
        ).pack()

    msg = Authenticate.unpack(raw)
    return Authenticate(
        msg.flags,
        msg.lm_challenge_response,
        msg.nt_challenge_response,
        msg.domain_name,
        msg.user_name,
        msg.workstation,
        msg.encrypted_random_session_key,
        version=msg.version if msg.flags & NegotiateFlags.version else None,
    ).pack()


# A byte-for-byte stable sample that distinguishes the raw transcript from a re-encoded transcript. The NEGOTIATE token
# has 12 bytes of trailing padding after the Version field, the CHALLENGE token has a 3 byte gap before the target name
# and 10 bytes of trailing padding, and the AUTHENTICATE token has a 9 byte leading pad followed by its fields in a
# different order with 3 byte gaps and 11 bytes of trailing padding.
GOLDEN_NEGOTIATE = bytes.fromhex(
    "4e544c4d5353500001000000358288e2000000003400000000000000340000000a00" "2c5d0000000f000000000000000000000000"
)
GOLDEN_CHALLENGE = bytes.fromhex(
    "4e544c4d53535000020000000c000c00d7000000358288e20123456789abcdef0000"
    "0000000000009c009c00380000000a002c5d0000000f01000c005300450052005600"
    "450052000200160057004f0052004b00530054004100540049004f004e0003002400"
    "7300650072007600650072002e006500780061006d0070006c0065002e0063006f00"
    "6d000600040002000000070008002c750671b130d60109002e0068006f0073007400"
    "2f007300650072007600650072002e006500780061006d0070006c0065002e006300"
    "6f006d00000000000000005300450052005600450052000000000000000000000000"
)
GOLDEN_AUTHENTICATE = bytes.fromhex(
    "4e544c4d5353500003000000180018006c010000cc00cc009d0000000c000c008e00"
    "000008000800830000000c000c00610000001000100070000000358288e20a002c5d"
    "0000000f0000000000000000000000000000000000000000000000000043004c0049"
    "0045004e005400000000ea2888ba46adafda17c1054a61f8763e0000005500730065"
    "00720000000044006f006d00610069006e0000000022eaaebe2a9f92f9305c4c39a6"
    "eefa0001010000000000002c750671b130d601da1db1af88a41df30000000001000c"
    "005300450052005600450052000200160057004f0052004b00530054004100540049"
    "004f004e00030024007300650072007600650072002e006500780061006d0070006c"
    "0065002e0063006f006d000600040002000000070008002c750671b130d60109002e"
    "0068006f00730074002f007300650072007600650072002e006500780061006d0070"
    "006c0065002e0063006f006d00000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000"
)
GOLDEN_MIC_OFFSET = 72
GOLDEN_RAW_MIC = "28b5f4522ee2575607497cf8e5616958"
GOLDEN_REENCODED_MIC = "16f2e8cd82185da714d3fe853ba39116"


LAYOUTS = {
    "canonical": {},
    "reordered": {
        "field_order": ("workstation", "key", "user", "domain", "nt", "lm"),
        "leading_pad": 9,
        "gap": 3,
        "trailing_pad": 11,
    },
    "padded": {"leading_pad": 5, "trailing_pad": 17},
    "reordered_no_version": {
        "include_version": False,
        "field_order": ("key", "workstation", "nt", "lm", "domain", "user"),
        "leading_pad": 9,
        "gap": 2,
        "trailing_pad": 11,
    },
}


def _build_transcript(layout: str) -> typing.Tuple[bytes, bytes, bytes, int]:
    options = LAYOUTS[layout]
    auth_options = dict(options)
    include_version = auth_options.pop("include_version", True)

    negotiate = _build_negotiate(
        BASE_FLAGS,
        include_version=include_version,
        leading_pad=auth_options.get("leading_pad", 0) % 4,
        trailing_pad=auth_options.get("trailing_pad", 0),
    )
    challenge = _build_challenge(
        BASE_FLAGS,
        _target_info(),
        include_version=include_version,
        name_first=layout != "reordered",
        leading_pad=auth_options.get("leading_pad", 0) % 3,
        gap=auth_options.get("gap", 0),
        trailing_pad=auth_options.get("trailing_pad", 0),
    )
    authenticate = _build_authenticate(BASE_FLAGS, mic=b"\x00" * 16, include_version=include_version, **auth_options)
    mic_offset = authenticate.index(b"\x00" * 16, 64)

    return negotiate, challenge, authenticate, mic_offset


def _acceptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: typing.Any,
    negotiate: bytes,
    challenge: bytes,
) -> spnego.ContextProxy:
    cred_file = tmp_path / "ntlm.creds"
    cred_file.write_text(f"{DOMAIN}:{USER}:{PASSWORD}")
    monkeypatch.setenv("NTLM_USER_FILE", str(cred_file))

    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    server._step_accept_negotiate(negotiate)

    # Use the exact challenge bytes that are covered by the MIC instead of the one the acceptor generated.
    server._temp_challenge = Challenge.unpack(challenge)
    server._temp_challenge_raw = challenge

    return server


def test_production_challenge_binds_raw_layout(monkeypatch, tmp_path):
    """The accept path uses its own generated CHALLENGE and still binds the MIC to the sent bytes."""

    cred_file = tmp_path / "ntlm.creds"
    cred_file.write_text(f"{DOMAIN}:{USER}:{PASSWORD}")
    monkeypatch.setenv("NTLM_USER_FILE", str(cred_file))

    negotiate = _build_negotiate(BASE_FLAGS)
    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    challenge = server.step(negotiate)
    challenge_msg = Challenge.unpack(challenge)

    target_info = challenge_msg.target_info
    assert target_info is not None and AvId.timestamp in target_info

    authenticate = _build_authenticate(
        BASE_FLAGS,
        mic=b"\x00" * 16,
        server_challenge=challenge_msg.server_challenge,
    )
    mic_offset = authenticate.index(b"\x00" * 16, 64)
    mic = _mic(SESSION_KEY, negotiate, challenge, authenticate, mic_offset)
    authenticate = authenticate[:mic_offset] + mic + authenticate[mic_offset + 16 :]

    server.step(authenticate)
    assert server.complete


def test_golden_sample_binds_raw_layout(monkeypatch, tmp_path):
    """The stored sample has the same fields as a re-encoded message but different bytes.

    A correct implementation accepts the MIC calculated over the stored bytes and rejects the MIC calculated over the
    re-encoded bytes. This fails if the acceptor ever starts verifying a message that was unpacked and packed again.
    """

    assert _build_transcript("reordered") == (
        GOLDEN_NEGOTIATE,
        GOLDEN_CHALLENGE,
        GOLDEN_AUTHENTICATE,
        GOLDEN_MIC_OFFSET,
    )

    raw_mic = _mic(SESSION_KEY, GOLDEN_NEGOTIATE, GOLDEN_CHALLENGE, GOLDEN_AUTHENTICATE, GOLDEN_MIC_OFFSET)
    assert raw_mic.hex() == GOLDEN_RAW_MIC

    reencoded = tuple(
        _canonical_message(kind, raw)
        for kind, raw in [
            ("negotiate", GOLDEN_NEGOTIATE),
            ("challenge", GOLDEN_CHALLENGE),
            ("authenticate", GOLDEN_AUTHENTICATE),
        ]
    )
    reencoded_mic = _mic(SESSION_KEY, *reencoded, GOLDEN_MIC_OFFSET)
    assert reencoded_mic.hex() == GOLDEN_REENCODED_MIC
    assert reencoded_mic != raw_mic

    valid = GOLDEN_AUTHENTICATE[:GOLDEN_MIC_OFFSET] + raw_mic + GOLDEN_AUTHENTICATE[GOLDEN_MIC_OFFSET + 16 :]

    server = _acceptor(monkeypatch, tmp_path, GOLDEN_NEGOTIATE, GOLDEN_CHALLENGE)
    server.step(valid)
    assert server.complete

    tampered = GOLDEN_AUTHENTICATE[:GOLDEN_MIC_OFFSET] + reencoded_mic + GOLDEN_AUTHENTICATE[GOLDEN_MIC_OFFSET + 16 :]

    server = _acceptor(monkeypatch, tmp_path, GOLDEN_NEGOTIATE, GOLDEN_CHALLENGE)
    with pytest.raises(spnego.exceptions.InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        server.step(tampered)


@pytest.mark.parametrize("layout", list(LAYOUTS))
def test_accepts_mic_over_raw_transcript(layout, monkeypatch, tmp_path):
    negotiate, challenge, authenticate, mic_offset = _build_transcript(layout)
    expected = _mic(SESSION_KEY, negotiate, challenge, authenticate, mic_offset)
    authenticate = authenticate[:mic_offset] + expected + authenticate[mic_offset + 16 :]

    server = _acceptor(monkeypatch, tmp_path, negotiate, challenge)
    server.step(authenticate)

    assert server.complete
    assert server.client_principal == f"{DOMAIN}\\{USER}"


@pytest.mark.parametrize("layout", ["reordered", "padded", "reordered_no_version"])
def test_rejects_mic_over_reencoded_transcript(layout, monkeypatch, tmp_path):
    negotiate, challenge, authenticate, mic_offset = _build_transcript(layout)

    canonical_negotiate = _canonical_message("negotiate", negotiate)
    canonical_challenge = _canonical_message("challenge", challenge)
    canonical_authenticate = _canonical_message("authenticate", authenticate)
    assert (canonical_negotiate, canonical_challenge, canonical_authenticate) != (
        negotiate,
        challenge,
        authenticate,
    )

    canonical_mic = _mic(SESSION_KEY, canonical_negotiate, canonical_challenge, canonical_authenticate, mic_offset)
    raw_mic = _mic(SESSION_KEY, negotiate, challenge, authenticate, mic_offset)
    assert canonical_mic != raw_mic

    tampered = authenticate[:mic_offset] + canonical_mic + authenticate[mic_offset + 16 :]

    server = _acceptor(monkeypatch, tmp_path, negotiate, challenge)
    with pytest.raises(spnego.exceptions.InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        server.step(tampered)


@pytest.mark.parametrize("layout", ["reordered", "padded"])
@pytest.mark.parametrize("token", ["negotiate", "challenge", "authenticate"])
def test_mic_covers_every_transcript_byte(layout, token, monkeypatch, tmp_path):
    negotiate, challenge, authenticate, mic_offset = _build_transcript(layout)
    expected = _mic(SESSION_KEY, negotiate, challenge, authenticate, mic_offset)
    authenticate = authenticate[:mic_offset] + expected + authenticate[mic_offset + 16 :]

    # Flip a padding byte in the token under test. The parsed field values do not change, only the raw layout does.
    targets = {"negotiate": negotiate, "challenge": challenge, "authenticate": authenticate}
    original = targets[token]
    mutated = bytearray(original)
    mutated[-1] ^= 0x01

    if token == "negotiate":
        negotiate = bytes(mutated)

    elif token == "challenge":
        challenge = bytes(mutated)

    else:
        authenticate = bytes(mutated)

    server = _acceptor(monkeypatch, tmp_path, negotiate, challenge)
    with pytest.raises(spnego.exceptions.InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        server.step(authenticate)


@pytest.mark.parametrize("av_flags", [None, 0])
def test_client_av_flag_cannot_disable_mic_check(av_flags, monkeypatch, tmp_path):
    target_info = _target_info(av_flags=av_flags)
    negotiate = _build_negotiate(BASE_FLAGS)
    challenge = _build_challenge(BASE_FLAGS, _target_info())
    authenticate = _build_authenticate(BASE_FLAGS, mic=b"\x00" * 16, target_info=target_info)
    mic_offset = authenticate.index(b"\x00" * 16, 64)

    # A MIC that matches the transcript must still be accepted even without the initiator AV flag.
    expected = _mic(SESSION_KEY, negotiate, challenge, authenticate, mic_offset)
    valid = authenticate[:mic_offset] + expected + authenticate[mic_offset + 16 :]

    server = _acceptor(monkeypatch, tmp_path, negotiate, challenge)
    server.step(valid)
    assert server.complete

    # Dropping the AV flag and the MIC entirely must not skip verification when the challenge had a timestamp.
    authenticate = _build_authenticate(BASE_FLAGS, mic=None, target_info=target_info)

    server = _acceptor(monkeypatch, tmp_path, negotiate, challenge)
    with pytest.raises(spnego.exceptions.InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        server.step(authenticate)


def test_real_mic_is_verified_without_av_flag(monkeypatch, tmp_path):
    """A supplied MIC is verified even when the initiator did not advertise MIC_PROVIDED."""

    target_info = _target_info(av_flags=None)
    negotiate = _build_negotiate(BASE_FLAGS)
    challenge = _build_challenge(BASE_FLAGS, _target_info())
    authenticate = _build_authenticate(BASE_FLAGS, mic=b"\x00" * 16, target_info=target_info)
    mic_offset = authenticate.index(b"\x00" * 16, 64)

    forged = authenticate[:mic_offset] + b"\x01" * 16 + authenticate[mic_offset + 16 :]

    server = _acceptor(monkeypatch, tmp_path, negotiate, challenge)
    with pytest.raises(spnego.exceptions.InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        server.step(forged)


def test_require_ntlm_mic_option_enforces_mic_without_timestamp(monkeypatch, tmp_path):
    target_info = _target_info(av_flags=None, timestamp=False)
    negotiate = _build_negotiate(BASE_FLAGS)
    challenge = _build_challenge(BASE_FLAGS, _target_info(timestamp=False))
    authenticate = _build_authenticate(BASE_FLAGS, mic=None, target_info=target_info)

    cred_file = tmp_path / "ntlm.creds"
    cred_file.write_text(f"{DOMAIN}:{USER}:{PASSWORD}")
    monkeypatch.setenv("NTLM_USER_FILE", str(cred_file))

    # Without the option the acceptor follows the negotiated policy, no timestamp means a MIC is not required.
    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    server._step_accept_negotiate(negotiate)
    server._temp_challenge = Challenge.unpack(challenge)
    server._temp_challenge_raw = challenge
    assert server._is_mic_required(server._temp_challenge) is False
    server.step(authenticate)
    assert server.complete

    # The explicit option makes the acceptor require the MIC even without a challenge timestamp.
    server = spnego.server(
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm | spnego.NegotiateOptions.require_ntlm_mic,
    )
    server._step_accept_negotiate(negotiate)
    server._temp_challenge = Challenge.unpack(challenge)
    server._temp_challenge_raw = challenge
    assert server._is_mic_required(server._temp_challenge) is True

    with pytest.raises(spnego.exceptions.InvalidTokenError, match="Invalid MIC in NTLM authentication message"):
        server.step(authenticate)
