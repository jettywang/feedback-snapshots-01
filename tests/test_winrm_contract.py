"""Independent send/receive contract tests for WinRM message wrapping.

A WinRM consumer assembles a message from the three values returned by
``wrap_winrm()``: an opaque authentication header, the wrapped data, and a
padding length. The business body is neither the header nor the padding, so
the declared ``OriginalContent ... Length=`` value has to stay equal to the
plaintext length no matter what the provider put in ``header`` or
``padding_length``.

The tests deliberately separate two rejection layers:

* The framing layer owns the ``int32 header length | header | data`` envelope
  and the declared business length. It rejects short/negative header lengths,
  transport streams with trailing or truncated records, and any decrypted
  length that does not match the declared business length.
* The crypto layer owns ``unwrap_winrm()``. It can reject modified ciphertext,
  a wrong header, replay and reordering, but it never sees
  ``padding_length`` and it cannot see message boundaries when a second valid
  record is concatenated to the first.

Negative tests name the layer that must reject the input and assert concrete
exception types; no test swallows ``Exception``.
"""

import dataclasses
import socket
import ssl
import struct
import typing

import pytest

import spnego
from spnego._context import WinRMWrapResult
from spnego.exceptions import BadMICError, SpnegoError

# [MS-WSMV] 2.2.9.1 ("Encrypted Message Types") puts a 4 byte little endian
# header length before the provider header and the encrypted data. There is no
# separate padding field on the wire; padding is part of ``data`` and its
# length is metadata.
_FRAME_LENGTH = struct.Struct("<i")
_TLS_RECORD_HEADER = struct.Struct(">BHH")  # content type, legacy version, length
_WINRM_CHUNK = 16384


class FramingError(Exception):
    """The independent receiver contract rejected the wire framing."""


def _body(size: int) -> bytes:
    return bytes(((index * 37) + 11) % 256 for index in range(size))


def parse_frame(wire: bytes) -> typing.Tuple[bytes, bytes]:
    """Splits the WinRM envelope without trusting the provider header."""
    if len(wire) < _FRAME_LENGTH.size:
        raise FramingError("frame is shorter than its 4 byte header length")

    (header_length,) = _FRAME_LENGTH.unpack_from(wire)
    if header_length < 0:
        raise FramingError(f"negative header length {header_length}")

    header_end = _FRAME_LENGTH.size + header_length
    if header_end > len(wire):
        raise FramingError(f"header length {header_length} exceeds frame of {len(wire)} bytes")

    return wire[_FRAME_LENGTH.size : header_end], wire[header_end:]


def parse_tls_records(wire: bytes) -> typing.List[bytes]:
    """Independently frames a CredSSP payload as complete TLS records."""
    records: typing.List[bytes] = []
    offset = 0
    while offset < len(wire):
        if len(wire) - offset < _TLS_RECORD_HEADER.size:
            raise FramingError("truncated TLS record header")

        content_type, version, record_length = _TLS_RECORD_HEADER.unpack_from(wire, offset)
        if content_type != 23:
            raise FramingError(f"unexpected TLS content type {content_type}")
        if version != 0x0303:
            raise FramingError(f"unexpected TLS record version {version:#06x}")

        record_end = offset + _TLS_RECORD_HEADER.size + record_length
        if record_end > len(wire):
            raise FramingError(f"TLS record length {record_length} exceeds remaining {len(wire) - offset} bytes")

        records.append(wire[offset:record_end])
        offset = record_end

    return records


def validate_ntlm_transport(header: bytes, data: bytes) -> None:
    """NTLM moves a fixed 16 byte signature into ``header``."""
    if len(header) != 16:
        raise FramingError(f"NTLM header must be 16 bytes, got {len(header)}")
    if header[0] != 1:
        raise FramingError(f"unexpected NTLM signature version {header[0]}")


def validate_credssp_transport(header: bytes, data: bytes) -> None:
    """CredSSP moves a TLS record prefix into ``header``; no length is assumed."""
    parse_tls_records(header + data)


@dataclasses.dataclass(frozen=True)
class Frame:
    """Independent model of what a WinRM consumer puts on the wire."""

    header: bytes
    data: bytes
    padding_length: int
    business_length: int

    def encode(self) -> bytes:
        if self.padding_length < 0:
            raise FramingError(f"negative padding length {self.padding_length}")
        if self.business_length < 0:
            raise FramingError(f"negative business length {self.business_length}")
        return _FRAME_LENGTH.pack(len(self.header)) + self.header + self.data


def receive(
    wire: bytes,
    unwrap: typing.Callable[[bytes, bytes], bytes],
    *,
    padding_length: int,
    business_length: int,
    validate_transport: typing.Optional[typing.Callable[[bytes, bytes], None]] = None,
) -> bytes:
    """Reference receive path.

    Framing is validated before and after the crypto call. Crypto exceptions
    propagate unchanged so callers can assert which layer detected tampering.
    """
    if padding_length < 0:
        raise FramingError(f"negative padding length {padding_length}")
    if business_length < 0:
        raise FramingError(f"negative business length {business_length}")

    header, data = parse_frame(wire)
    if validate_transport is not None:
        validate_transport(header, data)

    plaintext = unwrap(header, data)  # crypto layer, exceptions are not caught
    if padding_length > len(plaintext):
        raise FramingError(f"padding length {padding_length} exceeds decrypted length {len(plaintext)}")

    body = plaintext[: len(plaintext) - padding_length] if padding_length else plaintext
    if len(body) != business_length:
        raise FramingError(f"declared business length {business_length} != decrypted {len(body)}")

    return body


@dataclasses.dataclass
class WinRMProvider:
    name: str
    client: spnego.ContextProxy
    server: spnego.ContextProxy
    validate_transport: typing.Callable[[bytes, bytes], None]

    def wrap(self, body: bytes) -> WinRMWrapResult:
        return self.client.wrap_winrm(body)

    def unwrap(self, header: bytes, data: bytes) -> bytes:
        return self.server.unwrap_winrm(header, data)


def _complete_handshake(client: spnego.ContextProxy, server: spnego.ContextProxy) -> None:
    token: typing.Optional[bytes] = None
    for _ in range(20):
        if client.complete and server.complete:
            return
        if not client.complete:
            token = client.step(token)
        if not server.complete:
            token = server.step(token)

    raise AssertionError("authentication did not complete")


@pytest.fixture(params=["ntlm", "credssp"])
def winrm_factory(request: typing.Any, ntlm_cred: typing.Any) -> typing.Tuple[str, typing.Callable[[], WinRMProvider]]:
    """Creates fresh local NTLM or CredSSP contexts for each message exchange."""
    provider_name = request.param

    def make() -> WinRMProvider:
        if provider_name == "ntlm":
            client = spnego.client(
                ntlm_cred[0], ntlm_cred[1], protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm
            )
            server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
            validate_transport = validate_ntlm_transport
        else:
            client = spnego.client(
                ntlm_cred[0],
                ntlm_cred[1],
                hostname=socket.gethostname(),
                protocol="credssp",
                options=spnego.NegotiateOptions.use_ntlm,
            )
            server = spnego.server(protocol="credssp", options=spnego.NegotiateOptions.use_ntlm)
            validate_transport = validate_credssp_transport

        _complete_handshake(client, server)
        return WinRMProvider(provider_name, client, server, validate_transport)

    return provider_name, make


def _frame(result: WinRMWrapResult, business_length: int) -> Frame:
    return Frame(result.header, result.data, result.padding_length, business_length)


def _decode(provider: WinRMProvider, wire: bytes, result: WinRMWrapResult, business_length: int) -> bytes:
    return receive(
        wire,
        provider.unwrap,
        padding_length=result.padding_length,
        business_length=business_length,
        validate_transport=provider.validate_transport,
    )


# Reference-only tests. These prove the framing arithmetic before any provider
# is involved and do not need an authenticated context.


def test_reference_wire_is_byte_exact() -> None:
    result = WinRMWrapResult(header=b"hdr!", data=b"cipher-text", padding_length=0)
    frame = _frame(result, business_length=11)
    expected = struct.pack("<i", 4) + b"hdr!" + b"cipher-text"

    assert frame.encode() == expected
    assert len(frame.encode()) == 4 + len(result.header) + len(result.data)


def test_reference_declared_length_excludes_header_and_padding() -> None:
    result = WinRMWrapResult(header=b"0123456789abcdef", data=b"cipher" + b"PAD!", padding_length=4)
    frame = _frame(result, business_length=6)

    assert frame.business_length == 6
    assert frame.business_length not in (len(result.header), len(result.data), len(result.data) + 4)


def test_reference_trims_provider_padding_from_body() -> None:
    # A provider that reports padding keeps it in ``data``. The receiver must
    # remove exactly that many trailing plaintext bytes, even though local
    # NTLM/CredSSP providers report zero padding.
    result = WinRMWrapResult(header=b"header", data=b"ciphertext", padding_length=3)
    frame = _frame(result, business_length=5)

    def unwrap(_header: bytes, _data: bytes) -> bytes:
        return b"body!" + b"\x00\x00\x00"

    assert _decode_synthetic(frame, unwrap) == b"body!"


def _decode_synthetic(frame: Frame, unwrap: typing.Callable[[bytes, bytes], bytes]) -> bytes:
    return receive(frame.encode(), unwrap, padding_length=frame.padding_length, business_length=frame.business_length)


def test_reference_rejects_forged_zero_padding_leaving_padding_in_body() -> None:
    # If padding existed and the receiver trusted a forged zero length, the
    # padding would leak into the delivered body as extra plaintext.
    result = WinRMWrapResult(header=b"header", data=b"ciphertext", padding_length=0)
    frame = _frame(result, business_length=5)

    def unwrap(_header: bytes, _data: bytes) -> bytes:
        return b"body!" + b"\x00\x00\x00"

    with pytest.raises(FramingError, match="declared business length 5 != decrypted 8"):
        _decode_synthetic(frame, unwrap)


def test_reference_rejects_short_frame_header() -> None:
    with pytest.raises(FramingError, match="shorter than its 4 byte header length"):
        parse_frame(b"\x01\x00")


def test_reference_rejects_negative_header_length() -> None:
    with pytest.raises(FramingError, match="negative header length"):
        parse_frame(struct.pack("<i", -1) + b"data")


def test_reference_rejects_header_longer_than_frame() -> None:
    with pytest.raises(FramingError, match="exceeds frame"):
        parse_frame(struct.pack("<i", 10) + b"short")


def test_reference_rejects_truncated_tls_record() -> None:
    # 5 byte record header claiming 10 payload bytes, but only 3 are present.
    wire = bytes([23, 0x03, 0x03, 0x00, 0x0A]) + b"abc"

    with pytest.raises(FramingError, match="TLS record length 10 exceeds remaining"):
        parse_tls_records(wire)


def test_reference_rejects_trailing_bytes_after_complete_tls_records() -> None:
    record = bytes([23, 0x03, 0x03, 0x00, 0x01]) + b"a"

    with pytest.raises(FramingError, match="truncated TLS record header"):
        parse_tls_records(record + b"\x00")


# Provider contract tests. Every input is built from the actual values returned
# by wrap_winrm(); no provider is assumed to pad, and no header length is
# hardcoded outside the independent protocol validators.


def test_winrm_empty_body_keeps_auth_header_out_of_body(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    provider = make()

    empty_result = provider.wrap(b"")
    assert isinstance(empty_result, WinRMWrapResult)
    assert isinstance(empty_result.header, bytes)
    assert isinstance(empty_result.data, bytes)
    assert isinstance(empty_result.padding_length, int)
    assert empty_result.padding_length >= 0

    empty_wire = _frame(empty_result, business_length=0).encode()
    assert len(empty_wire) == 4 + len(empty_result.header) + len(empty_result.data)

    if provider_name == "ntlm":
        # A 16 byte NTLM signature is on the wire but zero bytes are business body.
        assert len(empty_result.header) == 16
        assert len(empty_result.data) == 0
        assert len(empty_wire) == 20

    assert _decode(provider, empty_wire, empty_result, business_length=0) == b""

    # The empty message consumes its own crypto state; the next message must
    # still decrypt in order.
    body = b"message-after-empty"
    result = provider.wrap(body)
    wire = _frame(result, business_length=len(body)).encode()

    assert _decode(provider, wire, result, business_length=len(body)) == body


@pytest.mark.parametrize("size", [1, 15, 16, 17, 16383, 16384, 16385, 32768])
def test_winrm_cross_block_lengths(winrm_factory: typing.Any, size: int) -> None:
    provider_name, make = winrm_factory
    provider = make()
    body = _body(size)

    result = provider.wrap(body)
    assert 0 <= result.padding_length <= max(len(result.data), 0)

    frame = _frame(result, business_length=len(body))
    wire = frame.encode()
    header, data = parse_frame(wire)
    assert (header, data) == (result.header, result.data)
    assert len(wire) == 4 + len(result.header) + len(result.data)

    provider.validate_transport(result.header, result.data)

    if provider_name == "ntlm":
        # RC4 is a stream cipher: the ciphertext length is the body length,
        # and the 16 byte signature is never part of that count.
        assert len(result.header) == 16
        assert len(result.data) == len(body) + result.padding_length

    if provider_name == "credssp" and size >= _WINRM_CHUNK + 1:
        # The CredSSP payload spans more than one TLS record; the independent
        # record parser must account for all of them, not a fixed split.
        assert len(parse_tls_records(result.header + result.data)) >= 2

    # A single wrapped message must decode to exactly the body for every size,
    # including bodies that CredSSP expands over several TLS records.
    assert _decode(provider, wire, result, business_length=len(body)) == body

    if size > _WINRM_CHUNK:
        # The WinRM consumer may instead split large bodies into 16384 byte
        # messages. A fresh context is required because the provider above
        # already consumed its message sequence. Verify the reassembled body,
        # not just that each tail decrypts.
        chunk_provider = make()
        chunks = [body[index : index + _WINRM_CHUNK] for index in range(0, len(body), _WINRM_CHUNK)]
        reassembled = bytearray()
        for chunk in chunks:
            chunk_result = chunk_provider.wrap(chunk)
            chunk_wire = _frame(chunk_result, business_length=len(chunk)).encode()
            decoded = _decode(chunk_provider, chunk_wire, chunk_result, business_length=len(chunk))
            assert decoded == chunk
            reassembled.extend(decoded)

        assert bytes(reassembled) == body

    assert len(body) == size


def test_winrm_two_consecutive_messages_keep_order_and_bodies(winrm_factory: typing.Any) -> None:
    _provider_name, make = winrm_factory
    provider = make()
    first = b"first message"
    second = b"second message with a different length"

    first_result = provider.wrap(first)
    first_wire = _frame(first_result, business_length=len(first)).encode()
    second_result = provider.wrap(second)
    second_wire = _frame(second_result, business_length=len(second)).encode()

    assert _decode(provider, first_wire, first_result, business_length=len(first)) == first
    assert _decode(provider, second_wire, second_result, business_length=len(second)) == second


def test_winrm_reversed_or_replayed_messages_are_rejected(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory

    reversed_provider = make()
    first = b"first message"
    second = b"second message"
    reversed_provider.wrap(first)
    second_result = reversed_provider.wrap(second)

    if provider_name == "ntlm":
        with pytest.raises(BadMICError):
            reversed_provider.unwrap(second_result.header, second_result.data)
    else:
        with pytest.raises(SpnegoError) as exc_info:
            reversed_provider.unwrap(second_result.header, second_result.data)
        assert isinstance(exc_info.value.__cause__, ssl.SSLError)

    replay_provider = make()
    replay_result = replay_provider.wrap(first)
    assert replay_provider.unwrap(replay_result.header, replay_result.data) == first
    if provider_name == "ntlm":
        with pytest.raises(BadMICError):
            replay_provider.unwrap(replay_result.header, replay_result.data)
    else:
        with pytest.raises(SpnegoError) as exc_info:
            replay_provider.unwrap(replay_result.header, replay_result.data)
        assert isinstance(exc_info.value.__cause__, ssl.SSLError)


def test_winrm_truncated_header_is_rejected_by_framing(winrm_factory: typing.Any) -> None:
    _provider_name, make = winrm_factory
    provider = make()
    body = b"body that must not leak"
    result = provider.wrap(body)

    # The declared header is one byte shorter than the real one. The bytes
    # that followed are then a truncated transport record: NTLM's fixed
    # signature is short and CredSSP's TLS record is short. Both are visible
    # before decryption, so the transport validator rejects them.
    wire = struct.pack("<i", len(result.header) - 1) + result.header[:-1] + result.data

    with pytest.raises(FramingError):
        _decode(provider, wire, result, business_length=len(body))


def test_winrm_ntlm_truncated_header_is_a_mic_failure_without_framing(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    if provider_name != "ntlm":
        pytest.skip("NTLM has a fixed signature that is verified as a MIC")

    provider = make()
    body = b"body that must not leak"
    result = provider.wrap(body)

    # Bypass the framing validator: the crypto layer alone must reject a short
    # signature rather than returning plaintext.
    with pytest.raises(BadMICError):
        provider.unwrap(result.header[:-1], result.data)


def test_winrm_credssp_truncated_header_is_a_tls_failure(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    if provider_name != "credssp":
        pytest.skip("CredSSP moves a TLS record prefix into the header")

    body = b"body that must not leak"

    probe_provider = make()
    probe_result = probe_provider.wrap(body)

    # The shifted split leaves a TLS record one byte short. Depending on the
    # TLS state machine this either raises or yields no plaintext; what matters
    # is that the ciphertext is never returned as the body.
    try:
        leaked = probe_provider.unwrap(probe_result.header[:-1], probe_result.data)
    except SpnegoError as error:
        assert isinstance(error.__cause__, ssl.SSLError)
    else:
        assert leaked == b""

    # Re-splitting the very same TLS bytes one byte earlier still decrypts the
    # body exactly, because CredSSP treats header+data as one stream. The
    # declared length check is therefore what keeps the body honest. A fresh
    # context is used because the probe above consumed crypto state.
    shifted_provider = make()
    shifted = shifted_provider.wrap(body)
    split_at = len(shifted.header) - 1
    assert shifted_provider.unwrap(shifted.header[:split_at], shifted.header[split_at:] + shifted.data) == body


def test_winrm_truncated_frame_header_rejected_without_crypto(winrm_factory: typing.Any) -> None:
    _provider_name, make = winrm_factory
    provider = make()
    body = b"body"
    result = provider.wrap(body)

    # Prefix claims more header bytes than the frame holds. This is detectable
    # before any decryption, so the crypto callback must never run.
    wire = struct.pack("<i", len(result.header) + len(result.data) + 1) + result.header + result.data

    def unwrap(_header: bytes, _data: bytes) -> bytes:
        raise AssertionError("crypto layer must not run for a short frame header")

    with pytest.raises(FramingError, match="exceeds frame"):
        receive(
            wire,
            unwrap,
            padding_length=result.padding_length,
            business_length=len(body),
            validate_transport=provider.validate_transport,
        )


def test_winrm_one_byte_short_data_cannot_deliver_extra_plaintext(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    body = b"body that must not leak"

    probe_provider = make()
    probe_result = probe_provider.wrap(body)
    if provider_name == "credssp":
        # Feeding only the truncated ciphertext directly must never yield the
        # body: TLS either raises or buffers the incomplete record.
        try:
            leaked = probe_provider.unwrap(probe_result.header, probe_result.data[:-1])
        except SpnegoError as error:
            assert isinstance(error.__cause__, ssl.SSLError)
        else:
            assert leaked == b""

    provider = make()
    result = provider.wrap(body)
    wire = _frame(result, business_length=len(body)).encode()[:-1]

    if provider_name == "ntlm":
        # NTLM verifies the MAC over the full ciphertext; a short ciphertext
        # is a crypto-layer failure, not merely a length check.
        with pytest.raises(BadMICError):
            _decode(provider, wire, result, business_length=len(body))
    else:
        # The independent record parser detects the short TLS record before
        # any decryption, so the delivery path never runs.
        with pytest.raises(FramingError, match="TLS record length"):
            _decode(provider, wire, result, business_length=len(body))


def test_winrm_forged_padding_length_is_rejected_by_framing(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    body = b"padding is not body"

    # wrap_winrm() does not authenticate padding_length. The crypto call sees
    # only header and data, so it cannot detect this forgery.
    crypto_provider = make()
    crypto_result = crypto_provider.wrap(body)
    forged_crypto = WinRMWrapResult(crypto_result.header, crypto_result.data, crypto_result.padding_length + 7)
    assert crypto_provider.unwrap(forged_crypto.header, forged_crypto.data) == body

    # A consumer that followed ``len(message) + padding_length`` would declare
    # padding as business body. Each attempt needs its own fresh context so the
    # wire from ``wrap_winrm()`` matches the server that unwraps it.
    declared_with_padding = make()
    declared_result = declared_with_padding.wrap(body)
    forged = WinRMWrapResult(declared_result.header, declared_result.data, declared_result.padding_length + 7)
    wire = _frame(forged, business_length=len(body)).encode()

    with pytest.raises(FramingError, match="declared business length"):
        receive(
            wire,
            declared_with_padding.unwrap,
            padding_length=forged.padding_length,
            business_length=len(body) + forged.padding_length,
            validate_transport=declared_with_padding.validate_transport,
        )

    # Even with the honest declared length, the forged padding makes the
    # receiver trim real body bytes; the length check still rejects it.
    honest_declared = make()
    honest_result = honest_declared.wrap(body)
    honest_forged = WinRMWrapResult(honest_result.header, honest_result.data, honest_result.padding_length + 7)
    honest_wire = _frame(honest_forged, business_length=len(body)).encode()

    with pytest.raises(FramingError, match="declared business length"):
        _decode(honest_declared, honest_wire, honest_forged, business_length=len(body))

    if provider_name == "ntlm":
        assert len(crypto_result.data) == len(body) + crypto_result.padding_length


def test_winrm_padding_length_is_metadata_not_ciphertext(winrm_factory: typing.Any) -> None:
    _provider_name, make = winrm_factory
    provider = make()
    body = _body(37)
    result = provider.wrap(body)

    # The wire is always header length, header and data. Changing only the
    # reported padding length must not add bytes or move the header/data split.
    honest = _frame(result, business_length=len(body)).encode()
    forged = _frame(
        WinRMWrapResult(result.header, result.data, result.padding_length + 9), business_length=len(body)
    ).encode()

    assert honest == forged
    assert len(honest) == 4 + len(result.header) + len(result.data)


def test_winrm_negative_padding_rejected_without_crypto(winrm_factory: typing.Any) -> None:
    _provider_name, make = winrm_factory
    provider = make()
    body = b"body"
    result = provider.wrap(body)
    wire = _frame(result, business_length=len(body)).encode()

    def unwrap(_header: bytes, _data: bytes) -> bytes:
        raise AssertionError("crypto layer must not run for negative padding")

    with pytest.raises(FramingError, match="negative padding length"):
        receive(wire, unwrap, padding_length=-1, business_length=len(body))


def test_winrm_ciphertext_byte_flip_is_only_visible_to_crypto(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    provider = make()
    body = b"body that must not leak"
    result = provider.wrap(body)
    assert len(result.data) > 0

    # Framing stays valid: same header length, same total size, same declared
    # business length. Only the cipher/MAC can notice the modified byte.
    flipped = bytes([result.data[0] ^ 0xFF]) + result.data[1:]
    wire = struct.pack("<i", len(result.header)) + result.header + flipped
    assert parse_frame(wire) == (result.header, flipped)
    provider.validate_transport(result.header, flipped)

    if provider_name == "ntlm":
        with pytest.raises(BadMICError):
            _decode(provider, wire, result, business_length=len(body))
    else:
        with pytest.raises(SpnegoError) as exc_info:
            _decode(provider, wire, result, business_length=len(body))
        assert isinstance(exc_info.value.__cause__, ssl.SSLError)


def test_winrm_appended_next_message_is_rejected_at_boundary(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    first = b"first message"
    second = b"second message"

    if provider_name == "credssp":
        probe_provider = make()
        first_result = probe_provider.wrap(first)
        second_result = probe_provider.wrap(second)
        appended = first_result.data + second_result.header + second_result.data

        # The TLS layer authenticates each record independently and cannot see
        # that a second message was concatenated; it returns both bodies.
        merged = probe_provider.unwrap(first_result.header, appended)
        assert merged == first + second

        # Only the framing layer's declared-length check catches this. A fresh
        # context is required because the probe consumed the TLS stream state.
        frame_provider = make()
        first_frame = frame_provider.wrap(first)
        second_frame = frame_provider.wrap(second)
        wire = (
            struct.pack("<i", len(first_frame.header))
            + first_frame.header
            + first_frame.data
            + second_frame.header
            + second_frame.data
        )

        with pytest.raises(FramingError, match="declared business length"):
            _decode(frame_provider, wire, first_frame, business_length=len(first))
    else:
        probe_provider = make()
        first_result = probe_provider.wrap(first)
        second_result = probe_provider.wrap(second)
        appended = first_result.data + second_result.header + second_result.data

        # NTLM's MAC covers the whole ciphertext, so the crypto layer rejects
        # the concatenation on its own.
        with pytest.raises(BadMICError):
            probe_provider.unwrap(first_result.header, appended)

        # The receive path fails at the same crypto layer, not at a later
        # length check: this is a message-integrity failure.
        frame_provider = make()
        first_frame = frame_provider.wrap(first)
        second_frame = frame_provider.wrap(second)
        wire = (
            struct.pack("<i", len(first_frame.header))
            + first_frame.header
            + first_frame.data
            + second_frame.header
            + second_frame.data
        )

        with pytest.raises(BadMICError):
            _decode(frame_provider, wire, first_frame, business_length=len(first))


def test_winrm_appended_partial_record_rejected_before_crypto(winrm_factory: typing.Any) -> None:
    provider_name, make = winrm_factory
    if provider_name != "credssp":
        pytest.skip("partial TLS record framing only applies to CredSSP")

    provider = make()
    first = b"first message"
    first_result = provider.wrap(first)

    # Append the start of a second TLS record: record header plus one byte.
    # The record body belongs to the next message, so concatenating it to the
    # previous ciphertext must be caught by framing, not by the length check
    # after a successful decrypt (there is no successful decrypt here).
    truncated_next_record = bytes([23, 0x03, 0x03, 0x00, 0x10]) + b"x"
    wire = struct.pack("<i", len(first_result.header)) + first_result.header + first_result.data
    wire += truncated_next_record

    def unwrap(_header: bytes, _data: bytes) -> bytes:
        raise AssertionError("crypto layer must not run for a truncated TLS record")

    with pytest.raises(FramingError, match="TLS record length 16 exceeds remaining"):
        receive(
            wire,
            unwrap,
            padding_length=first_result.padding_length,
            business_length=len(first),
            validate_transport=provider.validate_transport,
        )
