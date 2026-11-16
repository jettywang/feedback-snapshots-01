"""Authentication boundary tests for C2 packet recovery.

These tests prove that the default (verifying) path of
:class:`dissect.cobaltstrike.c2.C2Http` never turns an unauthenticated
``TaskPacket`` or ``CallbackPacket`` into trusted command evidence, and that
results obtained with the explicit ``verify_hmac=False`` analysis option are
distinguishable from default trusted results.

All tests go through HTTP recovery and packet type dispatch
(``C2Http.iter_recover_http``) using independently computed short vectors.
"""

import hmac
import struct

import pytest

from dissect.cobaltstrike.c2 import (
    BeaconCallback,
    BeaconCommand,
    BeaconKeys,
    C2Http,
    CallbackPacket,
    EncryptedPacket,
    TaskPacket,
    derive_aes_hmac_keys,
    encrypt_data,
)
from dissect.cobaltstrike.utils import p32be

AES_RAND = bytes.fromhex("caeab4f452fe41182d504aa24966fbd0")
AES_KEY, HMAC_KEY = derive_aes_hmac_keys(AES_RAND)
_, WRONG_HMAC_KEY = derive_aes_hmac_keys(b"not-the-session-rand")

TASK_EPOCH = 0x60197E90
TASK_DATA = b"\x00\x00\x00\xba\x00\x00\x00\x03.\\*"
TASK_PLAINTEXT = struct.pack(">IIII", TASK_EPOCH, 12 + len(TASK_DATA), BeaconCommand.COMMAND_FILE_LIST, len(TASK_DATA))
TASK_PLAINTEXT += TASK_DATA

CALLBACK_COUNTER = 0x2A
CALLBACK_DATA = b"beacon task output"
CALLBACK_PLAINTEXT = struct.pack(">III", CALLBACK_COUNTER, len(CALLBACK_DATA), BeaconCallback.CALLBACK_OUTPUT)
CALLBACK_PLAINTEXT += CALLBACK_DATA

DIRECTIONS = ("task", "callback")


def plaintext_for(direction):
    return TASK_PLAINTEXT if direction == "task" else CALLBACK_PLAINTEXT


def build_encrypted_packet(plaintext, hmac_key=HMAC_KEY):
    """Build an EncryptedPacket with the signature computed independently in this test."""
    ciphertext = encrypt_data(plaintext, AES_KEY, BeaconKeys.DEFAULT_AES_IV)
    signature = hmac.new(hmac_key, ciphertext, "sha256").digest()[:16]
    return EncryptedPacket(ciphertext, signature)


def task_http_response(enc_packet):
    body = enc_packet.ciphertext + enc_packet.signature
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


def callback_http_post(enc_packet):
    frame = enc_packet.ciphertext + enc_packet.signature
    body = p32be(len(frame)) + frame
    return (
        b"POST /submit.php?id=242569267 HTTP/1.1\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Host: redacted:8080\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )


def http_for(direction, enc_packet):
    return task_http_response(enc_packet) if direction == "task" else callback_http_post(enc_packet)


def valid_http(direction):
    return http_for(direction, build_encrypted_packet(plaintext_for(direction)))


def flip_byte(data, offset):
    return data[:offset] + bytes([data[offset] ^ 0xFF]) + data[offset + 1 :]


def tamper_hmac(direction):
    """Flip a bit in the HMAC signature only."""
    enc = build_encrypted_packet(plaintext_for(direction))
    forged = EncryptedPacket(enc.ciphertext, flip_byte(enc.signature, 0))
    return http_for(direction, forged)


def tamper_ciphertext(direction):
    """Flip a bit in the last ciphertext block, invalidating the HMAC."""
    enc = build_encrypted_packet(plaintext_for(direction))
    forged = EncryptedPacket(flip_byte(enc.ciphertext, len(enc.ciphertext) - 1), enc.signature)
    return http_for(direction, forged)


def tamper_frame_length(direction):
    """Break the packet length framing on the wire."""
    raw = valid_http(direction)
    header, _, body = raw.partition(b"\r\n\r\n")
    if direction == "task":
        body = body[:-1]
    else:
        frame = body[4:]
        body = p32be(len(frame) + 1) + frame
    return header + b"\r\n\r\n" + body


def tamper_plaintext_inner_length(direction, resign=False):
    """Corrupt the internal length field of the plaintext.

    With ``resign=False`` the stale signature of the original packet is kept,
    making the packet unauthenticated. With ``resign=True`` the forged
    plaintext is correctly signed (we hold the keys), yielding an
    authenticated but internally inconsistent packet.
    """
    plaintext = plaintext_for(direction)
    if direction == "task":
        forged_plaintext = plaintext[:12] + b"\x00\x00\xff\xff" + plaintext[16:]
    else:
        forged_plaintext = plaintext[:4] + b"\x00\x00\xff\xff" + plaintext[8:]
    ciphertext = encrypt_data(forged_plaintext, AES_KEY, BeaconKeys.DEFAULT_AES_IV)
    if resign:
        signature = hmac.new(HMAC_KEY, ciphertext, "sha256").digest()[:16]
    else:
        signature = build_encrypted_packet(plaintext).signature
    return http_for(direction, EncryptedPacket(ciphertext, signature))


def assert_no_confirmed_packets(c2http, raw_http, exc=ValueError, match=None):
    """Assert recovery raises and no packet was confirmed before the failure."""
    packets = []
    with pytest.raises(exc, match=match):
        for packet in c2http.iter_recover_http(raw_http):
            packets.append(packet)
    assert packets == []


@pytest.fixture
def c2http(c2test_beacon_bconfig) -> C2Http:
    return C2Http(c2test_beacon_bconfig, aes_key=AES_KEY, hmac_key=HMAC_KEY)


@pytest.fixture
def c2http_unverified(c2test_beacon_bconfig) -> C2Http:
    return C2Http(c2test_beacon_bconfig, aes_key=AES_KEY, hmac_key=HMAC_KEY, verify_hmac=False)


def test_valid_task_packet_is_trusted_and_scoped(c2http):
    enc_packet = build_encrypted_packet(TASK_PLAINTEXT)

    # authentication basis: signature matches an independently computed HMAC
    expected_signature = hmac.new(HMAC_KEY, enc_packet.ciphertext, "sha256").digest()[:16]
    assert hmac.compare_digest(enc_packet.signature, expected_signature)
    enc_packet.raise_for_signature(HMAC_KEY)

    packets = list(c2http.iter_recover_http(task_http_response(enc_packet)))
    assert len(packets) == 1
    task = packets[0]
    # source scope: server -> beacon direction yields a TaskPacket
    assert isinstance(task, TaskPacket)
    assert not isinstance(task, CallbackPacket)
    assert task.epoch == TASK_EPOCH
    assert task.command == BeaconCommand.COMMAND_FILE_LIST
    assert len(task.data) == task.size
    assert bytes(task.data) == TASK_DATA


def test_valid_callback_packet_is_trusted_and_scoped(c2http):
    enc_packet = build_encrypted_packet(CALLBACK_PLAINTEXT)

    expected_signature = hmac.new(HMAC_KEY, enc_packet.ciphertext, "sha256").digest()[:16]
    assert hmac.compare_digest(enc_packet.signature, expected_signature)
    enc_packet.raise_for_signature(HMAC_KEY)

    packets = list(c2http.iter_recover_http(callback_http_post(enc_packet)))
    assert len(packets) == 1
    callback = packets[0]
    # source scope: beacon -> server direction yields a CallbackPacket
    assert isinstance(callback, CallbackPacket)
    assert not isinstance(callback, TaskPacket)
    assert callback.counter == CALLBACK_COUNTER
    assert callback.callback == BeaconCallback.CALLBACK_OUTPUT
    assert len(callback.data) == callback.size
    assert bytes(callback.data) == CALLBACK_DATA


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_valid_packets_rejected_with_wrong_hmac_key(c2test_beacon_bconfig, direction):
    # authentication basis: the same valid bytes are not trusted under another HMAC key
    c2http = C2Http(c2test_beacon_bconfig, aes_key=AES_KEY, hmac_key=WRONG_HMAC_KEY)
    assert_no_confirmed_packets(c2http, valid_http(direction), match="Invalid HMAC signature")


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_tampered_hmac_rejected_by_default(c2http, direction):
    assert_no_confirmed_packets(c2http, tamper_hmac(direction), match="Invalid HMAC signature")


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_tampered_ciphertext_rejected_by_default(c2http, direction):
    assert_no_confirmed_packets(c2http, tamper_ciphertext(direction), match="Invalid HMAC signature")


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_tampered_frame_length_rejected_by_default(c2http, direction):
    assert_no_confirmed_packets(c2http, tamper_frame_length(direction), match="Invalid HMAC signature")


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_tampered_plaintext_inner_length_rejected_by_default(c2http, direction):
    # an edited internal length field cannot survive transport authentication
    assert_no_confirmed_packets(c2http, tamper_plaintext_inner_length(direction), match="Invalid HMAC signature")


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_authenticated_but_inconsistent_inner_length_not_confirmed(c2http, direction):
    # even a correctly signed packet with an inconsistent internal length
    # must not leave behind a confirmed command
    assert_no_confirmed_packets(c2http, tamper_plaintext_inner_length(direction, resign=True), exc=EOFError)


def test_bad_frame_after_good_frame_leaves_only_good_packet(c2http):
    good = build_encrypted_packet(CALLBACK_PLAINTEXT)
    bad = EncryptedPacket(good.ciphertext, flip_byte(good.signature, 0))
    good_frame = good.ciphertext + good.signature
    bad_frame = bad.ciphertext + bad.signature
    body = p32be(len(good_frame)) + good_frame + p32be(len(bad_frame)) + bad_frame
    raw_http = (
        b"POST /submit.php?id=242569267 HTTP/1.1\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Host: redacted:8080\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )

    packets = []
    with pytest.raises(ValueError, match="Invalid HMAC signature"):
        for packet in c2http.iter_recover_http(raw_http):
            packets.append(packet)

    # the good packet stays confirmed, the bad frame leaves nothing behind
    assert len(packets) == 1
    assert isinstance(packets[0], CallbackPacket)
    assert bytes(packets[0].data) == CALLBACK_DATA


@pytest.mark.parametrize("tamper", [tamper_hmac, tamper_ciphertext])
@pytest.mark.parametrize("direction", DIRECTIONS)
def test_unverified_option_results_differ_from_default(c2http, c2http_unverified, direction, tamper):
    raw_http = tamper(direction)

    # default trusted path: no packets, hard failure
    assert_no_confirmed_packets(c2http, raw_http, match="Invalid HMAC signature")

    # explicit analysis option: the difference shows up in the returned
    # results (packets vs. none), not merely in a log message
    unverified_packets = list(c2http_unverified.iter_recover_http(raw_http))
    assert len(unverified_packets) == 1

    trusted_packets = list(c2http.iter_recover_http(valid_http(direction)))
    assert len(trusted_packets) == 1
    # source scope is preserved even with verification disabled
    assert type(unverified_packets[0]) is type(trusted_packets[0])


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_unverified_ciphertext_tamper_content_diverges(c2http, c2http_unverified, direction):
    trusted = list(c2http.iter_recover_http(valid_http(direction)))
    forged = list(c2http_unverified.iter_recover_http(tamper_ciphertext(direction)))
    # the unverified result is observably different from trusted evidence
    assert bytes(forged[0].data) != bytes(trusted[0].data)
