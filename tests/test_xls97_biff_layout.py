"""Record-layout regression for the XLS97 RC4 / RC4-CryptoAPI decrypt path.

Old XLS files can decrypt fine in the first half while the second half is
garbled.  That class of defect comes from getting the BIFF record layout, the
plaintext/ciphertext bookkeeping, or the 1024-byte RC4 block rekeying wrong.
These tests build short, fully deterministic BIFF8 streams from scratch (no
Excel and no binary fixtures are needed) and pin every byte-level rule:

* which bytes are copied verbatim (record headers, the FilePass record, the
  BoundSheet8 header + lbPlyPos prefix) versus which consume the RC4 keystream;
* that plaintext bytes still occupy a position in the cipher stream, so the
  keystream index only advances for the encrypted payload that follows;
* that a fresh block key is derived every 1024 bytes, including for a record
  whose payload straddles a block boundary;
* that a corrupted record length cannot make the following record "succeed" at
  a borrowed offset.

A deliberately broken reference decryptor that skips keystream-position
advancement over plaintext regions is used to prove the expectations actually
catch the regression they target.
"""

import hashlib
import io
import struct
import unittest

import olefile
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher

try:  # cryptography>=43 moved ARC4 but keeps the old import with a warning
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
except ImportError:  # pragma: no cover - older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4

import msoffcrypto
from msoffcrypto import exceptions
from msoffcrypto.format.xls97 import recordNameNum
from msoffcrypto.method.rc4 import _makekey as rc4_makekey
from msoffcrypto.method.rc4_cryptoapi import _makekey as cryptoapi_makekey

BLOCK_SIZE = 1024
PASSWORD = "Password1234_"
STREAM_SIZE = 4096  # >=4096 keeps the synthetic CFB stream out of the mini stream

# BIFF record identifiers used in the synthetic stream.
BOF = recordNameNum["BOF"]
FILEPASS = recordNameNum["FilePass"]
INTERFACE_HDR = recordNameNum["InterfaceHdr"]
CODEPAGE = recordNameNum["CodePage"]
MMS = recordNameNum["Mms"]
BOUND_SHEET = recordNameNum["BoundSheet8"]
NUMBER = recordNameNum["Number"]
LABEL_SST = recordNameNum["LabelSst"]
EOF = recordNameNum["EOF"]

# Records whose entire encoding (header + payload) stays in plaintext and is
# copied verbatim.  Mirrors MS-XLS 2.2.6.1 and the msoffcrypto allow-list.
FULLY_PLAIN_RECORDS = frozenset({BOF, FILEPASS, INTERFACE_HDR})


def rc4_keystream(key, length):
    """Return *length* raw RC4 keystream bytes for *key*."""
    encryptor = Cipher(ARC4(key), mode=None, backend=default_backend()).encryptor()
    return encryptor.update(b"\x00" * length)


def cryptoapi_block_key(password, salt, block):
    return cryptoapi_makekey(password, salt, 128, block)


def rc4_block_key(password, salt, block):
    return rc4_makekey(password, salt, block)


def make_filepass_cryptoapi(password, salt, verifier):
    """Build a v2.2 RC4-CryptoAPI FilePass payload (wEncryptionType=1)."""
    keystream = rc4_keystream(cryptoapi_block_key(password, salt, 0), 36)
    encrypted_verifier = bytes(a ^ b for a, b in zip(verifier, keystream[:16]))
    verifier_hash = hashlib.sha1(verifier).digest()
    encrypted_hash = bytes(a ^ b for a, b in zip(verifier_hash, keystream[16:36]))

    csp_name = "Microsoft Strong Cryptographic Provider".encode("UTF-16LE")
    encryption_header = struct.pack(
        "<IIIIIII",
        0,  # flags
        28 + len(csp_name),  # header size: seven DWORDs + CSP name
        0x00006801,  # algId = RC4
        0x00008004,  # algIdHash = SHA-1
        128,  # keySize
        1,  # providerType = PROV_RSA_FULL
        0,  # reserved
    ) + csp_name

    return (
        struct.pack("<H", 1)  # wEncryptionType: RC4
        + struct.pack("<HH", 2, 2)  # vMajor / vMinor: RC4 CryptoAPI
        + struct.pack("<I", 0)  # encryption header flags
        + struct.pack("<I", len(encryption_header))
        + encryption_header
        + struct.pack("<I", 16)  # salt size
        + salt
        + encrypted_verifier
        + struct.pack("<I", 20)  # SHA-1 verifier hash size
        + encrypted_hash
    )


def make_filepass_rc4(password, salt, verifier):
    """Build a v1.1 legacy RC4 FilePass payload (wEncryptionType=1)."""
    keystream = rc4_keystream(rc4_block_key(password, salt, 0), 32)
    encrypted_verifier = bytes(a ^ b for a, b in zip(verifier, keystream[:16]))
    verifier_hash = hashlib.md5(verifier).digest()
    encrypted_hash = bytes(a ^ b for a, b in zip(verifier_hash, keystream[16:32]))
    return (
        struct.pack("<H", 1)  # wEncryptionType: RC4
        + struct.pack("<HH", 1, 1)  # vMajor / vMinor: legacy RC4
        + salt
        + encrypted_verifier
        + encrypted_hash
    )


def record(num, payload):
    return struct.pack("<HH", num, len(payload)) + payload


def build_biff_layout(filepass_payload):
    """Return (plaintext_records, plaintext, encryption_mask, annotation).

    The layout is sized so that two interesting boundaries land on exact
    positions, regardless of the FilePass payload length:

    * a large Number record spans the block 0 -> block 1 boundary;
    * the second BoundSheet8 record has its 8 plaintext prefix bytes ending
      exactly at offset 1024, so its encrypted sheet-name payload is the very
      first thing encrypted with the block-1 key at local offset zero;
    * a second large Number record crosses the block 1 -> block 2 boundary and
      is followed by an independent sentinel record entirely inside block 2.
    """
    salt = bytes(range(16))
    verifier = bytes(range(16, 32))

    bof_payload = struct.pack("<HHHHII", 0x0809, 0x0600, 0x0DBB, 0x07D9, 0, 0)
    sheet_one = b"\x06" + "Sheet1".encode("UTF-16LE")
    sheet_two = b"\x06" + "Sheet2".encode("UTF-16LE")

    records = [
        record(BOF, bof_payload),
        record(FILEPASS, filepass_payload),
        record(INTERFACE_HDR, b"\xe0\x04"),
        record(CODEPAGE, struct.pack("<H", 1200)),
        record(MMS, b"\x01\x00"),
        record(BOUND_SHEET, struct.pack("<I", 0x400) + sheet_one),
    ]
    offset = sum(map(len, records))

    # Filler 1: leave exactly the 22-byte BoundSheet8 record starting at 1004,
    # i.e. its 8-byte plaintext prefix occupies 1016..1023.
    filler_one_size = BLOCK_SIZE - offset - 4 - 8
    records.append(record(NUMBER, bytes((i * 3 + 1) & 0xFF for i in range(filler_one_size))))
    offset += 4 + filler_one_size
    assert offset == BLOCK_SIZE - 8

    bound_sheet_two = record(BOUND_SHEET, struct.pack("<I", 0x800) + sheet_two)
    records.append(bound_sheet_two)
    bs2_start = offset
    offset += len(bound_sheet_two)
    assert bs2_start + 8 == BLOCK_SIZE  # prefix ends exactly on the boundary
    assert (offset - 1) // BLOCK_SIZE == 1  # encrypted suffix lives in block 1

    first_sentinel = record(LABEL_SST, b"FIRST-SENTINEL-" + bytes(range(20)))
    records.append(first_sentinel)
    offset += len(first_sentinel)

    # Filler 2: end exactly 8 bytes before the block 2 boundary so the second
    # sentinel is wholly inside block 2.
    filler_two_size = 2 * BLOCK_SIZE - offset - 4 - 8
    records.append(record(NUMBER, bytes((i * 5 + 2) & 0xFF for i in range(filler_two_size))))
    offset += 4 + filler_two_size
    assert offset == 2 * BLOCK_SIZE - 8

    second_sentinel = record(LABEL_SST, b"SECOND-SENTINEL" + bytes(range(19)))
    records.append(second_sentinel)
    offset += len(second_sentinel)

    records.append(record(EOF, b""))
    offset += 4

    # Pad to the fixed container size with one final ordinary encrypted record
    # so there are no phantom zero records to confuse strict parsing.
    records.append(record(NUMBER, b"\xA5" * (STREAM_SIZE - offset - 4)))
    assert sum(map(len, records)) == STREAM_SIZE

    plaintext = b"".join(records)

    mask = bytearray(STREAM_SIZE)  # 1 = encrypted byte, 0 = verbatim/plaintext
    annotation = []  # (start, end_exclusive, kind) for the explicit byte audit

    def add_annotation(start, end, kind):
        # Split spans at RC4 block boundaries so every annotated encrypted span
        # is governed by exactly one derived block key.
        cursor = start
        while cursor < end:
            next_boundary = ((cursor // BLOCK_SIZE) + 1) * BLOCK_SIZE
            piece_end = min(end, next_boundary)
            if piece_end > cursor:
                annotation.append((cursor, piece_end, kind))
            cursor = piece_end

    cursor = 0
    for chunk in records:
        num, size = struct.unpack_from("<HH", chunk, 0)
        span = 4 + size
        start = cursor
        if num in FULLY_PLAIN_RECORDS:
            add_annotation(start, cursor + span, "verbatim")
        elif num == BOUND_SHEET:
            for j in range(8, span):
                mask[cursor + j] = 1
            add_annotation(start, cursor + 8, "verbatim")  # header + lbPlyPos
            if span > 8:
                add_annotation(cursor + 8, cursor + span, "encrypted")
        else:
            for j in range(4, span):
                mask[cursor + j] = 1
            add_annotation(start, cursor + 4, "verbatim")  # record header
            if span > 4:
                add_annotation(cursor + 4, cursor + span, "encrypted")
        cursor += span

    assert cursor == STREAM_SIZE
    return records, plaintext, bytes(mask), annotation, salt


def encrypt_layout(plaintext, mask, block_key, password, salt):
    """Encrypt exactly the masked byte positions with per-block RC4 keys."""
    encrypted = bytearray(plaintext)
    for block in range((STREAM_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE):
        keystream = rc4_keystream(block_key(password, salt, block), BLOCK_SIZE)
        lo = block * BLOCK_SIZE
        for i in range(lo, lo + BLOCK_SIZE):
            if mask[i]:
                encrypted[i] = plaintext[i] ^ keystream[i % BLOCK_SIZE]
    return bytes(encrypted)


def reference_decrypt(encrypted, plaintext, mask, block_key, password, salt, *, buggy=False):
    """Two-phase model of msoffcrypto's XLS decryption.

    When ``buggy`` is true the cipher position is *not* advanced over plaintext
    regions, reproducing the "second half corrupted" regression.  The correct
    model advances one position for every byte in the full-length buffer.
    """
    out = bytearray(len(encrypted))
    cipher_position = 0
    for block in range((len(encrypted) + BLOCK_SIZE - 1) // BLOCK_SIZE):
        keystream = rc4_keystream(block_key(password, salt, block), BLOCK_SIZE)
        for j in range(BLOCK_SIZE):
            index = block * BLOCK_SIZE + j
            if index >= len(encrypted):
                break
            if mask[index]:
                out[index] = encrypted[index] ^ keystream[cipher_position % BLOCK_SIZE]
                cipher_position += 1
            else:
                out[index] = plaintext[index]
                if not buggy:
                    cipher_position += 1
    return bytes(out)


def build_cfb(stream_bytes, name="Workbook"):
    """Build a minimal but spec-compliant 512-byte-sector CFB container."""
    sector_size = 512
    data_sectors = (len(stream_bytes) + sector_size - 1) // sector_size

    fat = [0xFFFFFFFF] * 128
    fat[0] = 0xFFFFFFFC  # FAT sector
    fat[1] = 0xFFFFFFFE  # directory sector: end of chain
    for i in range(data_sectors):  # workbook data chain starts at sector 2
        fat[2 + i] = 0xFFFFFFFE if i == data_sectors - 1 else 3 + i

    # Layout matches olefile's '<8s16sHHHHHHLLLLLLLLLL' header parse.
    header_packed = struct.pack(
        "<8s16sHHHHHHLLLLLLLLLL",
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        b"\x00" * 16,
        0x003E,  # minor version
        3,  # major version (512-byte sectors)
        0xFFFE,  # byte order
        9,  # sector shift (2**9 = 512)
        6,  # mini sector shift (2**6 = 64)
        0,  # reserved USHORT
        0,  # reserved ULONG
        0,  # directory sector count (must be zero for 512-byte sectors)
        1,  # number of FAT sectors
        1,  # first directory sector
        0,  # transaction signature
        4096,  # mini stream cutoff
        0xFFFFFFFE,  # first mini FAT sector (none)
        0,  # mini FAT sector count
        0xFFFFFFFE,  # first DIFAT sector (none)
        0,  # DIFAT sector count
    )
    assert len(header_packed) == 76
    header = header_packed + struct.pack("<I", 0)  # DIFAT[0] -> FAT sector 0
    header += b"\x00" * (sector_size - len(header))

    directory = bytearray(sector_size)

    def put_entry(offset, entry_name, entry_type, start_sector, size, color, child=0xFFFFFFFF):
        entry = bytearray(128)
        name_bytes = entry_name.encode("UTF-16LE") + b"\x00\x00"
        entry[0:len(name_bytes)] = name_bytes
        struct.pack_into("<H", entry, 64, (len(entry_name) + 1) * 2)  # includes NUL
        entry[66] = entry_type
        entry[67] = color  # 0 = black, 1 = red
        entry[68:72] = b"\xFF" * 4  # left child
        entry[72:76] = b"\xFF" * 4  # right child
        struct.pack_into("<I", entry, 76, child)
        struct.pack_into("<I", entry, 116, start_sector)
        struct.pack_into("<Q", entry, 120, size)
        directory[offset:offset + 128] = entry

    put_entry(0, "Root Entry", 5, 0xFFFFFFFE, 0, 0, child=1)
    put_entry(128, name, 2, 2, len(stream_bytes), 1)

    return bytes(header) + struct.pack("<128I", *fat) + bytes(directory) + stream_bytes


def parse_records(buf):
    """Independently walk BIFF records up to EOF; fail on any misalignment."""
    parsed = []
    pos = 0
    while pos + 4 <= len(buf):
        num, size = struct.unpack_from("<HH", buf, pos)
        if pos + 4 + size > len(buf):
            raise AssertionError("record at %d overruns stream" % pos)
        parsed.append((num, size, pos, buf[pos + 4:pos + 4 + size]))
        pos += 4 + size
        if num == EOF:
            return parsed
    raise AssertionError("stream ended before EOF")


class Xls97LayoutFixture:
    """Build one synthetic encrypted workbook for an encryption variant."""

    def __init__(self, variant):
        if variant == "cryptoapi":
            self.block_key = cryptoapi_block_key
            self.filepass = make_filepass_cryptoapi
        elif variant == "rc4":
            self.block_key = rc4_block_key
            self.filepass = make_filepass_rc4
        else:  # pragma: no cover - programming error
            raise ValueError(variant)
        self.variant = variant
        (
            self.records,
            self.plaintext,
            self.mask,
            self.annotation,
            self.salt,
        ) = build_biff_layout(self.filepass(PASSWORD, bytes(range(16)), bytes(range(16, 32))))
        self.encrypted = encrypt_layout(self.plaintext, self.mask, self.block_key, PASSWORD, self.salt)
        self.container = build_cfb(self.encrypted)

    def decrypt_with_msoffcrypto(self, corrupted_delta=0):
        encrypted = bytearray(self.encrypted)
        codepage_offset = self.record_offset(CODEPAGE)
        if corrupted_delta:
            original_size = struct.unpack_from("<H", encrypted, codepage_offset + 2)[0]
            struct.pack_into("<H", encrypted, codepage_offset + 2, (original_size + corrupted_delta) & 0xFFFF)
        office = msoffcrypto.OfficeFile(io.BytesIO(build_cfb(bytes(encrypted))))
        office.load_key(password=PASSWORD)
        out = io.BytesIO()
        office.decrypt(out)
        out.seek(0)
        return olefile.OleFileIO(out).openstream("Workbook").read()

    def record_offset(self, num, occurrence=0):
        seen = 0
        cursor = 0
        for chunk in self.records:
            rec_num, size = struct.unpack_from("<HH", chunk, 0)
            if rec_num == num:
                if seen == occurrence:
                    return cursor
                seen += 1
            cursor += 4 + size
        raise KeyError(num)


class BiffLayoutTest(unittest.TestCase):
    VARIANTS = ("cryptoapi", "rc4")

    def setUp(self):
        self.fixtures = {variant: Xls97LayoutFixture(variant) for variant in self.VARIANTS}

    def test_container_and_encryption_detection(self):
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                self.assertTrue(olefile.OleFileIO(io.BytesIO(fixture.container)).exists("Workbook"))
                office = msoffcrypto.OfficeFile(io.BytesIO(fixture.container))
                self.assertTrue(office.is_encrypted())
                # A wrong password must be rejected, proving the verifier round-trips.
                bad = msoffcrypto.OfficeFile(io.BytesIO(fixture.container))
                with self.assertRaises(exceptions.InvalidKeyError):
                    bad.load_key(password="wrong-password")

    def test_annotation_partitions_every_byte(self):
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                covered = 0
                for start, end, kind in fixture.annotation:
                    self.assertLess(start, end)
                    self.assertEqual(covered, start)
                    if kind == "verbatim":
                        self.assertTrue(all(fixture.mask[i] == 0 for i in range(start, end)))
                    else:
                        self.assertTrue(all(fixture.mask[i] == 1 for i in range(start, end)))
                    covered = end
                self.assertEqual(covered, STREAM_SIZE)
                # Explicit block-rekey boundary: adjacent encrypted spans meeting at 1024.
                encrypted_spans = [(s, e) for s, e, kind in fixture.annotation if kind == "encrypted"]
                boundary_meetings = [
                    e0 for (s0, e0), (s1, e1) in zip(encrypted_spans, encrypted_spans[1:])
                    if e0 == s1 and e0 % BLOCK_SIZE == 0
                ]
                self.assertTrue(boundary_meetings, "expected an encrypted payload crossing a block boundary")

    def test_plaintext_bytes_still_consume_cipher_positions(self):
        # The masked stream must contain enough encrypted bytes after every
        # plaintext region; independently recompute the keystream position and
        # show plaintext and encrypted indices differ across a plaintext gap.
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                bs2_start = fixture.record_offset(BOUND_SHEET, 1)
                self.assertEqual((bs2_start + 8) % BLOCK_SIZE, 0)
                # 1016..1023 are the verbatim prefix and must not be encrypted...
                self.assertTrue(all(fixture.mask[i] == 0 for i in range(bs2_start, bs2_start + 8)))
                # ...while 1024 onward is encrypted with the block-1 key.
                self.assertTrue(all(fixture.mask[i] == 1 for i in range(1024, bs2_start + 21)))
                keystream = rc4_keystream(fixture.block_key(PASSWORD, fixture.salt, 1), BLOCK_SIZE)
                first_encrypted = bs2_start + 8  # == 1024
                expected = fixture.plaintext[first_encrypted] ^ keystream[0]
                self.assertEqual(fixture.encrypted[first_encrypted], expected)

    def test_block_key_rotates_every_1024_bytes(self):
        # A fresh RC4 key is derived per 1024-byte block: the same plaintext
        # byte at the same in-block offset is masked differently in block 0 and
        # block 1, and each side of a straddling encrypted span matches its own
        # block key.
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                key_zero = fixture.block_key(PASSWORD, fixture.salt, 0)
                key_one = fixture.block_key(PASSWORD, fixture.salt, 1)
                key_two = fixture.block_key(PASSWORD, fixture.salt, 2)
                self.assertNotEqual(key_zero, key_one)
                self.assertNotEqual(key_one, key_two)

                stream_zero = rc4_keystream(key_zero, BLOCK_SIZE)
                stream_one = rc4_keystream(key_one, BLOCK_SIZE)
                block_count = (STREAM_SIZE + BLOCK_SIZE - 1) // BLOCK_SIZE
                keystreams = tuple(
                    rc4_keystream(fixture.block_key(PASSWORD, fixture.salt, block), BLOCK_SIZE)
                    for block in range(block_count)
                )
                # An encrypted record straddling a boundary appears as two adjacent
                # encrypted spans meeting exactly at a 1024-byte boundary.
                encrypted_spans = [(s, e) for s, e, kind in fixture.annotation if kind == "encrypted"]
                boundaries = [
                    e0 for (s0, e0), (s1, e1) in zip(encrypted_spans, encrypted_spans[1:])
                    if e0 == s1 and e0 % BLOCK_SIZE == 0
                ]
                self.assertTrue(boundaries)
                for boundary in boundaries:
                    block_before = (boundary // BLOCK_SIZE) - 1
                    block_after = boundary // BLOCK_SIZE
                    # Last encrypted byte before the boundary: block key at local offset 1023.
                    self.assertEqual(
                        fixture.encrypted[boundary - 1],
                        fixture.plaintext[boundary - 1]
                        ^ keystreams[block_before][BLOCK_SIZE - 1],
                    )
                    # First encrypted byte after it: the new block key at local offset 0.
                    self.assertEqual(
                        fixture.encrypted[boundary],
                        fixture.plaintext[boundary] ^ keystreams[block_after][0],
                    )
                # All encrypted bytes validate against the key of their own block.
                for start, end in encrypted_spans:
                    block = start // BLOCK_SIZE
                    for index in range(start, end):
                        self.assertEqual(
                            fixture.encrypted[index],
                            fixture.plaintext[index] ^ keystreams[block][index % BLOCK_SIZE],
                        )
                # The stream genuinely reaches the third 1024-byte region.
                self.assertTrue(any(s >= 2 * BLOCK_SIZE for s, _ in encrypted_spans))

    def test_encrypted_stream_keeps_plaintext_record_headers(self):
        # Real Excel leaves record headers readable so the layout can be walked
        # before decryption; only payload bytes are masked.
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                cursor = 0
                for chunk in fixture.records:
                    num, size = struct.unpack_from("<HH", chunk, 0)
                    self.assertEqual(fixture.encrypted[cursor:cursor + 4], chunk[:4])
                    if num not in FULLY_PLAIN_RECORDS and size:
                        encrypted_payload = fixture.encrypted[cursor + 4:cursor + 4 + size]
                        if num == BOUND_SHEET:
                            self.assertEqual(
                                fixture.encrypted[cursor + 4:cursor + 8], chunk[4:8]
                            )
                            self.assertNotEqual(
                                fixture.encrypted[cursor + 8:cursor + 4 + size], chunk[8:]
                            )
                        else:
                            self.assertNotEqual(encrypted_payload, chunk[4:])
                    cursor += 4 + size
                # The raw encrypted stream is therefore walkable up to EOF on headers.
                self.assertEqual(parse_records(fixture.encrypted)[-1][0], EOF)

    def test_decryption_matches_independent_record_expectations(self):
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                decrypted = fixture.decrypt_with_msoffcrypto()
                expected_records = parse_records(fixture.plaintext)
                observed = parse_records(decrypted)
                self.assertEqual(len(observed), len(expected_records))

                filepass_offset = fixture.record_offset(FILEPASS)
                for (num, size, offset, payload), (obs_num, obs_size, obs_off, obs_payload) in zip(
                    expected_records, observed
                ):
                    self.assertEqual(obs_off, offset)
                    if offset == filepass_offset:
                        # msoffcrypto zeroes the id and payload but retains the size.
                        self.assertEqual(
                            decrypted[offset:offset + 4 + size],
                            b"\x00\x00" + struct.pack("<H", size) + b"\x00" * size,
                        )
                        continue
                    self.assertEqual((obs_num, obs_size), (num, size))
                    if num in FULLY_PLAIN_RECORDS or num == BOUND_SHEET:
                        # Header and the BoundSheet8 lbPlyPos prefix are byte-for-byte preserved.
                        prefix = 8 if num == BOUND_SHEET else 4
                        self.assertEqual(decrypted[offset:offset + prefix],
                                         fixture.plaintext[offset:offset + prefix])
                    self.assertEqual(obs_payload, payload)

    def test_corrupted_record_length_cannot_borrow_offsets(self):
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                decrypted = fixture.decrypt_with_msoffcrypto(corrupted_delta=10)
                codepage_offset = fixture.record_offset(CODEPAGE)
                _, corrupted_size = struct.unpack_from("<HH", decrypted, codepage_offset)
                borrowed = codepage_offset + 4 + corrupted_size

                true_mms_offset = fixture.record_offset(MMS)
                true_mms_size = struct.unpack_from("<HH", fixture.plaintext, true_mms_offset + 2)[0]
                self.assertNotEqual(borrowed, true_mms_offset)
                self.assertNotEqual(
                    decrypted[borrowed:borrowed + 4],
                    struct.pack("<HH", MMS, true_mms_size),
                )

                # Walking from the borrowed offset must never realign onto an
                # intact independent sentinel record.
                sentinel_offset = fixture.record_offset(LABEL_SST)
                _, sentinel_size = struct.unpack_from("<HH", fixture.plaintext, sentinel_offset)
                sentinel_payload = fixture.plaintext[sentinel_offset + 4:sentinel_offset + 4 + sentinel_size]
                cursor = borrowed
                realigned = False
                while cursor + 4 <= len(decrypted):
                    num, size = struct.unpack_from("<HH", decrypted, cursor)
                    if num == LABEL_SST and decrypted[cursor + 4:cursor + 4 + size] == sentinel_payload:
                        realigned = True
                        break
                    cursor += 4 + size
                self.assertFalse(realigned)

                # The undamaged sentinel still decrypts correctly at its true offset,
                # proving the failure is layout misalignment rather than bad crypto.
                self.assertEqual(
                    decrypted[sentinel_offset + 4:sentinel_offset + 4 + sentinel_size],
                    sentinel_payload,
                )

    def test_buggy_plaintext_position_skip_is_caught(self):
        for variant, fixture in self.fixtures.items():
            with self.subTest(variant=variant):
                correct = reference_decrypt(
                    fixture.encrypted, fixture.plaintext, fixture.mask,
                    fixture.block_key, PASSWORD, fixture.salt,
                )
                buggy = reference_decrypt(
                    fixture.encrypted, fixture.plaintext, fixture.mask,
                    fixture.block_key, PASSWORD, fixture.salt, buggy=True,
                )
                self.assertEqual(correct, fixture.plaintext)
                self.assertNotEqual(buggy, fixture.plaintext)

                # The independent per-record expectations reject the buggy output.
                expected_records = parse_records(fixture.plaintext)
                failures = []
                for num, size, offset, payload in expected_records:
                    if num == FILEPASS:
                        continue
                    if buggy[offset + 4:offset + 4 + size] != payload:
                        failures.append(num)
                self.assertIn(LABEL_SST, failures)
                self.assertTrue(failures)

                # And the same expectations accept msoffcrypto itself.
                decrypted = fixture.decrypt_with_msoffcrypto()
                for num, size, offset, payload in expected_records:
                    if num == FILEPASS:
                        continue
                    self.assertEqual(decrypted[offset + 4:offset + 4 + size], payload)


if __name__ == "__main__":
    unittest.main()
