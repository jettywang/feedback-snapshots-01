from __future__ import annotations

import hashlib
import hmac
import io
import itertools
import random
import struct
from bisect import bisect_right
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util import Counter

from dissect.evidence.ad1 import ad1
from dissect.evidence.adcrypt.adcrypt import ADCrypt
from dissect.evidence.adcrypt.stream import ADCryptStream
from dissect.evidence.ewf import ewf
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.evidence.ad1.ad1 import AD1, FileEntry
    from dissect.evidence.ewf.ewf import EWF

# Independently given key, passphrase, salt and plaintext for the synthetic containers.
SYNTH_KEY = bytes(range(32))
SYNTH_SALT = bytes(range(16, 32))
SYNTH_PASSPHRASE = "dissect.evidence adcrypt test passphrase"
SYNTH_COUNT = 1000

# Hardcoded AES-CTR known-answer vectors for SYNTH_KEY, computed independently of the implementation.
# The counter is the 128-bit little-endian value ``segment_index << 64 | offset // 16``.
VECTOR_PLAINTEXT = bytes(range(48))
VECTOR_CT_SEG0_OFF0 = bytes.fromhex("f29102b52e4c99d7a1fa9061d123798f")  # counter 0 << 64 | 0
VECTOR_CT_SEG0_OFF16 = bytes.fromhex("d7a40b977e04570bceb51dd01fe51fb7")  # counter 0 << 64 | 1
VECTOR_CT_SEG1_OFF0 = bytes.fromhex("90f0081bdb18c9166c73209991d95277")  # counter 1 << 64 | 0
VECTOR_CT_SEG0_OFF7 = bytes.fromhex("d7a1fa9061d123798fd7a40b977e04570bceb51dd01fe51fb76e")  # 26 bytes @ offset 7


def _segment_plaintext(index: int, size: int = 18000) -> bytes:
    # The first 48 bytes double as known-answer vector plaintext for every segment.
    return VECTOR_PLAINTEXT + bytes((index * 7 + i) % 256 for i in range(size - 48))


SEGMENT_PLAINTEXTS = [_segment_plaintext(i) for i in range(3)]


def _encrypt_segment(key: bytes, index: int, plaintext: bytes) -> bytes:
    ctr = Counter.new(128, initial_value=index << 64, little_endian=True)
    return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(plaintext)


def _adcrypt_header(pkey: bytes, salt_field: bytes, key: bytes, count: int) -> bytes:
    """Build a 512 byte ADCRYPT header, deriving EKEY and its HMAC with hashlib/hmac only."""
    ekey = AES.new(pkey, AES.MODE_CTR, counter=Counter.new(128, initial_value=0, little_endian=True)).encrypt(key)
    mac = hmac.new(pkey, ekey, hashlib.sha256).digest()
    header = struct.pack(
        "<8sIIhhh2sIIIIII",
        b"ADCRYPT\x00",  # magic
        1,  # version
        512,  # header_size
        -1,  # num_passwords
        -1,  # num_raw_keys
        -1,  # num_certificates
        b"\x00\x00",  # reserved
        3,  # EncAlgo.AES256
        1,  # HashAlgo.SHA256
        count,  # pbkdf2_count
        len(salt_field),  # salt_len
        len(key),  # key_len
        len(mac),  # hmac_len
    )
    return (header + salt_field + ekey + mac).ljust(512, b"\x00")


def _passphrase_pkey(passphrase: str, salt: bytes, count: int, key_len: int) -> bytes:
    passphrase_hash = hashlib.sha256(passphrase.encode()).digest()
    return hashlib.pbkdf2_hmac("sha1", passphrase_hash, salt, count, key_len)


def _build_passphrase_container() -> list[bytes]:
    pkey = _passphrase_pkey(SYNTH_PASSPHRASE, SYNTH_SALT, SYNTH_COUNT, len(SYNTH_KEY))
    header = _adcrypt_header(pkey, SYNTH_SALT, SYNTH_KEY, SYNTH_COUNT)
    return [header + _encrypt_segment(SYNTH_KEY, 0, SEGMENT_PLAINTEXTS[0])] + [
        _encrypt_segment(SYNTH_KEY, i, SEGMENT_PLAINTEXTS[i]) for i in range(1, len(SEGMENT_PLAINTEXTS))
    ]


def _build_certificate_container(rsa_key: RSA.RsaKey) -> list[bytes]:
    enc_salt = PKCS1_v1_5.new(rsa_key.publickey()).encrypt(SYNTH_SALT)
    # With certificate based unlocking the passphrase hash is empty and the salt is RSA wrapped.
    pkey = hashlib.pbkdf2_hmac("sha1", b"", SYNTH_SALT, SYNTH_COUNT, len(SYNTH_KEY))
    header = _adcrypt_header(pkey, enc_salt, SYNTH_KEY, SYNTH_COUNT)
    return [header + _encrypt_segment(SYNTH_KEY, 0, SEGMENT_PLAINTEXTS[0])] + [
        _encrypt_segment(SYNTH_KEY, i, SEGMENT_PLAINTEXTS[i]) for i in range(1, len(SEGMENT_PLAINTEXTS))
    ]


def _unlocked_adcrypt(files: list[bytes], **kwargs) -> ADCrypt:
    adcrypt = ADCrypt(io.BytesIO(files[0]))
    adcrypt.unlock(**kwargs)
    return adcrypt


def test_stream_known_answer_vectors() -> None:
    """Decrypt hardcoded AES-CTR short vectors at the segment start, a cipher block boundary,
    an unaligned offset crossing that boundary, and the start of the next segment.
    """
    files = _build_passphrase_container()

    # The independently built container must reproduce the hardcoded vectors.
    assert files[0][512 : 512 + 16] == VECTOR_CT_SEG0_OFF0
    assert files[0][512 + 16 : 512 + 32] == VECTOR_CT_SEG0_OFF16
    assert files[0][512 + 7 : 512 + 33] == VECTOR_CT_SEG0_OFF7
    assert files[1][0:16] == VECTOR_CT_SEG1_OFF0

    adcrypt = _unlocked_adcrypt(files, passphrase=SYNTH_PASSPHRASE)
    assert adcrypt.key == SYNTH_KEY

    seg0 = adcrypt.wrap(io.BytesIO(files[0]), 0)
    seg1 = adcrypt.wrap(io.BytesIO(files[1]), 1)

    # Segment start (segment 0 skips the 512 byte ADCRYPT header).
    seg0.seek(0)
    assert seg0.read(16) == VECTOR_PLAINTEXT[:16]

    # Cipher block boundary.
    seg0.seek(16)
    assert seg0.read(16) == VECTOR_PLAINTEXT[16:32]

    # Unaligned read crossing the block boundary.
    seg0.seek(7)
    assert seg0.read(26) == VECTOR_PLAINTEXT[7:33]

    # Next segment start: identical plaintext, different keystream (segment index is part of the counter).
    seg1.seek(0)
    assert seg1.read(16) == VECTOR_PLAINTEXT[:16]


def test_stream_known_answer_vectors_certificate() -> None:
    """The same vectors must decrypt identically when unlocking with a certificate instead of a passphrase."""
    rsa_key = RSA.generate(1024)
    files = _build_certificate_container(rsa_key)

    adcrypt = _unlocked_adcrypt(files, private_key=rsa_key.export_key())
    assert adcrypt.key == SYNTH_KEY

    seg0 = adcrypt.wrap(io.BytesIO(files[0]), 0)
    seg1 = adcrypt.wrap(io.BytesIO(files[1]), 1)

    seg0.seek(0)
    assert seg0.read(16) == VECTOR_PLAINTEXT[:16]
    seg0.seek(16)
    assert seg0.read(16) == VECTOR_PLAINTEXT[16:32]
    seg1.seek(0)
    assert seg1.read(16) == VECTOR_PLAINTEXT[:16]

    # A wrong private key is detected through the RSA wrapped salt, not through payload decryption.
    with pytest.raises(ValueError, match="Failed to decrypt salt"):
        _unlocked_adcrypt(files, private_key=RSA.generate(1024).export_key())


def test_stream_counter_offsets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the AES-CTR counter is initialised as ``segment_index << 64 | offset // 16``.

    Reads are aligned by AlignedStream (8192 bytes), so the counter offset is the
    aligned read offset; the stream slices the requested range out of the decrypted run.
    """
    calls = []

    class CounterSpy:
        @staticmethod
        def new(bits: int, initial_value: int, little_endian: bool):
            calls.append((bits, initial_value, little_endian))
            return Counter.new(bits, initial_value=initial_value, little_endian=little_endian)

    monkeypatch.setattr("dissect.evidence.adcrypt.stream.Counter", CounterSpy)

    files = _build_passphrase_container()
    adcrypt = _unlocked_adcrypt(files, passphrase=SYNTH_PASSPHRASE)

    # Use a fresh stream per read so the AlignedStream cache cannot coalesce reads.
    for offset in (0, 8192, 16384, 7):
        seg1 = adcrypt.wrap(io.BytesIO(files[1]), 1)
        seg1.seek(offset)
        seg1.read(16)

    assert calls == [
        (128, (1 << 64) | 0, True),
        (128, (1 << 64) | 512, True),
        (128, (1 << 64) | 1024, True),
        (128, (1 << 64) | 0, True),  # offset 7 aligns down to 0
    ]


def test_stream_random_read_order_and_size() -> None:
    """The same logical range must decrypt identically regardless of read order and read chunk size."""
    files = _build_passphrase_container()
    adcrypt = _unlocked_adcrypt(files, passphrase=SYNTH_PASSPHRASE)
    streams = [adcrypt.wrap(io.BytesIO(file), i) for i, file in enumerate(files)]

    rng = random.Random(0xADC)

    # Random reads over all segments, in shuffled segment order.
    for idx in rng.sample(range(len(streams)), len(streams)):
        stream, plaintext = streams[idx], SEGMENT_PLAINTEXTS[idx]
        for _ in range(32):
            offset = rng.randrange(len(plaintext))
            length = rng.randrange(1, len(plaintext) - offset + 1)
            stream.seek(offset)
            assert stream.read(length) == plaintext[offset : offset + length]

    # Full reassembly with varying read chunk sizes, including non block aligned ones.
    for idx, stream in enumerate(streams):
        plaintext = SEGMENT_PLAINTEXTS[idx]
        stream.seek(0)
        buf = b""
        for chunk_size in itertools.cycle([1, 15, 16, 17, 100, 4096]):
            if len(buf) >= len(plaintext):
                break
            buf += stream.read(min(chunk_size, len(plaintext) - len(buf)))
        assert buf == plaintext


def test_unlock_wrong_passphrase_detected() -> None:
    """A wrong wrapping key derived from a wrong passphrase is detected by the HMAC of EKEY."""
    files = _build_passphrase_container()

    adcrypt = ADCrypt(io.BytesIO(files[0]))
    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        adcrypt.unlock(passphrase="wrong passphrase")
    assert adcrypt.is_locked()


def test_unlock_tampered_enc_key_detected() -> None:
    """A tampered EKEY in the header is detected by the same HMAC, even with the correct passphrase."""
    files = _build_passphrase_container()
    tampered = bytearray(files[0])
    tampered[48 + 16] ^= 0xFF  # Flip a byte inside enc_key (fixed header part is 48 bytes, salt is 16)

    adcrypt = ADCrypt(io.BytesIO(bytes(tampered)))
    with pytest.raises(ValueError, match="Unable to unlock: HMAC verification of passphrase failed"):
        adcrypt.unlock(passphrase=SYNTH_PASSPHRASE)
    assert adcrypt.is_locked()


def test_stream_wrong_index_not_detectable_by_ctr() -> None:
    """Decrypting a segment with the wrong index yields garbage without any error.

    AES-CTR is malleable and provides no integrity: the stream happily returns bytes,
    so these must never be treated as authentic. Only container structure (magic,
    segment numbers) or authentication information (hashes, HMAC) can detect this.
    """
    files = _build_passphrase_container()

    stream = ADCryptStream(io.BytesIO(files[1]), SYNTH_KEY, 0)  # Correct key, wrong segment index
    buf = stream.read(16)
    assert len(buf) == 16
    assert buf != SEGMENT_PLAINTEXTS[1][:16]


def test_stream_wrong_key_not_detectable_by_ctr() -> None:
    """Decrypting with a wrong payload key yields garbage without any error.

    The HMAC of EKEY in the header is what actually authenticates the key during
    unlock; raw CTR decryption of the payload cannot. Bytes decrypted with an
    unverified key are not to be trusted as the original content.
    """
    files = _build_passphrase_container()
    wrong_key = bytes(b ^ 0xA5 for b in SYNTH_KEY)

    stream = ADCryptStream(io.BytesIO(files[0]), wrong_key, 0)
    buf = stream.read(16)
    assert len(buf) == 16
    assert buf != SEGMENT_PLAINTEXTS[0][:16]


def _ewf_pattern(offset: int, length: int) -> bytes:
    result = bytearray()
    while length > 0:
        block, offset_in_block = divmod(offset, 4096)
        read_size = min(length, 4096 - offset_in_block)
        result += bytes([block % 256]) * read_size
        offset += read_size
        length -= read_size
    return bytes(result)


def _assert_ewf_random_reads(e: EWF) -> None:
    rng = random.Random(20261115)
    ranges = [(rng.randrange(e.size), 0) for _ in range(64)]
    ranges = [(offset, rng.randrange(1, min(65536, e.size - offset) + 1)) for offset, _ in ranges]
    # Explicit edge cases: image start, chunk boundary crossings, image end and a full read.
    ranges += [(0, 16), (4096 - 8, 16), (3 * 4096 - 8, 16), (e.size - 16, 16), (0, e.size)]

    # Read every range in shuffled and reversed order; the bytes must be identical.
    stream = e.open()
    for offset, length in rng.sample(ranges, len(ranges)) + list(reversed(ranges)):
        stream.seek(offset)
        assert stream.read(length) == _ewf_pattern(offset, length), f"Mismatch at offset {offset:#x}"

    # Full sequential passes with different, non chunk aligned read sizes.
    for read_size in (4095, 4097, 65536 + 13):
        stream = e.open()
        buf = b""
        while len(buf) < e.size:
            buf += stream.read(min(read_size, e.size - len(buf)))
        assert buf == _ewf_pattern(0, e.size)


def test_ewf_adcrypt_random_read_passphrase(ewf_encrypted_passphrase, monkeypatch: pytest.MonkeyPatch) -> None:
    """Random reads through the public EWF entry point after passphrase unlock.

    Reads must be independent of read order, read chunk size and the open segment cache.
    """
    monkeypatch.setattr(ewf, "MAX_OPEN_SEGMENTS", 1)
    e = ewf.EWF(ewf_encrypted_passphrase)
    e.unlock(passphrase="password")
    _assert_ewf_random_reads(e)


def test_ewf_adcrypt_random_read_certificate(ewf_encrypted_certificate, monkeypatch: pytest.MonkeyPatch) -> None:
    """Random reads through the public EWF entry point after certificate unlock."""
    monkeypatch.setattr(ewf, "MAX_OPEN_SEGMENTS", 1)
    e = ewf.EWF(ewf_encrypted_certificate)
    e.unlock(private_key=absolute_path("_data/ewf/encrypted-certificate/key"))
    _assert_ewf_random_reads(e)


def _largest_file(entry: FileEntry) -> FileEntry:
    largest = None
    stack = [entry]
    while stack:
        entry = stack.pop()
        if entry.is_dir():
            stack.extend(entry.iterdir())
        elif entry.is_file() and (largest is None or entry.size > largest.size):
            largest = entry
    return largest


def _assert_ad1_random_reads(fs: AD1, paths: list[Path], monkeypatch: pytest.MonkeyPatch) -> None:
    # Spy on wrap to verify every segment file is decrypted with its positional segment index.
    wrapped = []
    real_wrap = fs.adcrypt.wrap

    def wrap_spy(fh, index):
        wrapped.append((Path(fh.name).name, index))
        return real_wrap(fh, index)

    monkeypatch.setattr(fs.adcrypt, "wrap", wrap_spy)

    target = _largest_file(fs.get("C:/Users/User/Downloads"))
    stream = target.open()

    # The target file must actually span segment boundaries for this test to be meaningful.
    boundaries = [b for b in fs._segment_offsets if stream.chunks[0] < b < stream.chunks[-1]]
    assert boundaries, "Test file does not span any segment boundary"

    # The SHA-1 stored in the AD1 metadata is the authentication information that
    # anchors the decrypted content; CTR decryption alone cannot provide this.
    reference = target.open().read()
    assert hashlib.sha1(reference).hexdigest() == target.sha1

    rng = random.Random(20261116)
    slices = set()
    for _ in range(48):
        offset = rng.randrange(target.size)
        slices.add((offset, rng.randrange(1, min(262144, target.size - offset) + 1)))
    # Slices guaranteed to straddle each segment boundary inside the file data.
    for boundary in boundaries:
        chunk_idx = bisect_right(stream.chunks, boundary) - 1
        offset = chunk_idx * stream.chunk_size
        slices.add((offset, min(2 * stream.chunk_size, target.size - offset)))
    slices = sorted(slices)

    # Read all slices in shuffled and reversed order through the public entry point.
    for offset, length in rng.sample(slices, len(slices)) + list(reversed(slices)):
        fh = target.open()
        fh.seek(offset)
        assert fh.read(length) == reference[offset : offset + length], f"Mismatch at offset {offset:#x}"

    # Reassemble the file with varying, non chunk aligned read sizes.
    fh = target.open()
    buf = b""
    for read_size in itertools.cycle([65536 - 13, 100000, 1 << 20]):
        if len(buf) >= target.size:
            break
        buf += fh.read(min(read_size, target.size - len(buf)))
    assert hashlib.sha1(buf).hexdigest() == target.sha1

    # Every segment was opened through wrap with the index matching its position in the file list.
    assert {index for _, index in wrapped} == set(range(len(paths)))
    for name, index in wrapped:
        assert name == paths[index].name


def test_ad1_adcrypt_random_read_passphrase(
    ad1_encrypted_passphrase: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cross-segment random reads through the public AD1 entry point after passphrase unlock.

    Forces LRU eviction of open segments to prove the cache does not influence reads.
    """
    monkeypatch.setattr(ad1, "MAX_OPEN_SEGMENTS", 2)
    fs = ad1.AD1(ad1_encrypted_passphrase)
    fs.unlock(passphrase="password")
    _assert_ad1_random_reads(fs, ad1_encrypted_passphrase, monkeypatch)


def test_ad1_adcrypt_random_read_certificate(
    ad1_encrypted_certificate: list[Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cross-segment random reads through the public AD1 entry point after certificate unlock."""
    monkeypatch.setattr(ad1, "MAX_OPEN_SEGMENTS", 2)
    fs = ad1.AD1(ad1_encrypted_certificate)
    fs.unlock(private_key=absolute_path("_data/ad1/encrypted-certificate/key"))
    _assert_ad1_random_reads(fs, ad1_encrypted_certificate, monkeypatch)


def test_ad1_adcrypt_swapped_segments_detected(ad1_encrypted_passphrase: list[Path]) -> None:
    """Swapping two segments is detected by the container structure.

    The swapped segment is decrypted with the wrong positional index, so its AD1
    magic and segment number no longer validate. Note this detection comes from
    the AD1 container structure, not from the CTR encryption itself.
    """
    paths = list(ad1_encrypted_passphrase)
    paths[1], paths[2] = paths[2], paths[1]

    fs = ad1.AD1(paths)
    with pytest.raises(ValueError, match="Invalid AD1 segment"):
        fs.unlock(passphrase="password")
