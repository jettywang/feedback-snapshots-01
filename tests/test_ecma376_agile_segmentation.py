"""Regression tests for Office Agile (ECMA-376) segmented CBC decryption.

These tests independently catch a wrong segment IV or wrong handling of the
padded final block in :meth:`ECMA376Agile.decrypt`. Expected ciphertext is built
by a *separate* constructor below (raw ``cryptography`` primitives plus the
MS-OFFCRYPTO segment rules); it never calls the implementation under test, so
this is not an encrypt/decrypt round-trip of the same code.

The agile package layout exercised here is:

* an 8-byte little-endian header holding the declared (unpadded) plaintext size;
* one ciphertext segment per 4096 plaintext bytes;
* per segment ``n`` the IV is ``SHA512(keyDataSalt || uint32_le(n))[:16]``;
* the final block of the last segment is zero-padded up to the 16-byte AES
  block size.
"""

import io
import unittest
from hashlib import sha512
from struct import pack

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from msoffcrypto.method.ecma376_agile import ECMA376Agile

#: Fixed AES-256 key and key-data salt so every vector is deterministic and
#: cheap (no password key derivation is involved).
KEY = bytes((index * 5 + 1) & 0xFF for index in range(32))
KEY_DATA_SALT = bytes((index * 3 + 9) & 0xFF for index in range(16))
HASH_ALGORITHM = "SHA512"

#: MS-OFFCRYPTO agile segment/block sizes.
SEGMENT_LENGTH = 4096
BLOCK_SIZE = 16

#: Plaintext lengths that hit every boundary of the segmenting logic.
BOUNDARY_LENGTHS = (0, 1, 4095, 4096, 4097)


def reference_plaintext(length):
    """Return deterministic, mostly non-zero plaintext.

    The bytes are aperiodic and the lengths used below end on non-zero bytes,
    so any leaked zero padding or content pulled from a neighbouring segment is
    immediately visible rather than blending into the expected data.
    """
    return bytes(((index * 131 + 17) & 0xFF) for index in range(length))


def segment_iv(salt, segment_number):
    """Derive the CBC IV for ``segment_number`` straight from the specification.

    ``IV_n = SHA512(keyDataSalt || uint32_le(n))`` truncated to the block size.
    This is intentionally independent of the implementation under test.
    """
    return sha512(salt + pack("<I", segment_number)).digest()[:BLOCK_SIZE]


def build_encrypted_package(
    plaintext,
    *,
    salt=KEY_DATA_SALT,
    key=KEY,
    index_bias=0,
    declared_size=None,
):
    """Construct an agile ``EncryptedPackage`` without the production encryptor.

    Returns ``(package_bytes, manifest)`` where the manifest records, for every
    segment, its zero-based segment number, the IV input (salt + segment
    number), the plaintext span it covers and how many zero padding bytes the
    final block received. ``index_bias`` deliberately corrupts the segment
    numbering; ``declared_size`` overrides the 8-byte length header.
    """
    declared_size = len(plaintext) if declared_size is None else declared_size

    package = io.BytesIO()
    package.write(pack("<Q", declared_size))

    manifest = []
    segment_number = 0
    for start in range(0, len(plaintext), SEGMENT_LENGTH):
        chunk = plaintext[start : start + SEGMENT_LENGTH]

        # The IV input is keyDataSalt concatenated with the segment number as a
        # little-endian uint32; index_bias simulates off-by-one numbering.
        iv_index = segment_number + index_bias
        iv = segment_iv(salt, iv_index)

        # Only the final block of the whole payload is padded, with zeros, up
        # to the AES block size; full segments are written untouched.
        padding_length = (-len(chunk)) % BLOCK_SIZE
        padded_chunk = chunk + b"\x00" * padding_length

        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded_chunk) + encryptor.finalize()
        package.write(ciphertext)

        manifest.append(
            {
                "segment_number": segment_number,
                "iv_index": iv_index,
                "iv": iv,
                "plaintext_start": start,
                "plaintext_end": start + len(chunk),
                "padding_length": padding_length,
                "ciphertext_length": len(ciphertext),
            }
        )
        segment_number += 1

    return package.getvalue(), manifest


def decrypt_package(package, *, salt=KEY_DATA_SALT, key=KEY):
    """Run the implementation under test against an in-memory package."""
    return ECMA376Agile.decrypt(key, salt, HASH_ALGORITHM, io.BytesIO(package))


def with_declared_size(package, size):
    """Rewrite only the 8-byte declared-length header."""
    return pack("<Q", size) + package[8:]


class ExactLengthDecryptionTest(unittest.TestCase):
    """Decrypted bytes must be exactly the declared plaintext."""

    def test_boundary_lengths_decrypt_byte_for_byte(self):
        for length in BOUNDARY_LENGTHS:
            with self.subTest(length=length):
                plaintext = reference_plaintext(length)
                package, _ = build_encrypted_package(plaintext)

                decrypted = decrypt_package(package)

                # Exact equality covers both length (no padding left over) and
                # content (no bytes borrowed from an adjacent segment).
                self.assertEqual(decrypted, plaintext)
                self.assertEqual(len(decrypted), length)

    def test_empty_package_has_only_the_header(self):
        package, manifest = build_encrypted_package(reference_plaintext(0))

        self.assertEqual(len(package), 8)
        self.assertEqual(manifest, [])
        self.assertEqual(decrypt_package(package), b"")

    def test_short_document_spans_exactly_two_segments(self):
        # 4097 is the smallest document that needs a second segment.
        plaintext = reference_plaintext(4097)
        package, manifest = build_encrypted_package(plaintext)

        self.assertEqual(len(manifest), 2)
        self.assertEqual(
            [entry["segment_number"] for entry in manifest], [0, 1]
        )
        self.assertEqual(
            [entry["iv_index"] for entry in manifest], [0, 1]
        )

        first, last = manifest
        self.assertEqual(first["plaintext_start"], 0)
        self.assertEqual(first["plaintext_end"], SEGMENT_LENGTH)
        self.assertEqual(first["padding_length"], 0)
        self.assertEqual(first["ciphertext_length"], SEGMENT_LENGTH)

        # The lone trailing byte is padded to a full 16-byte final block.
        self.assertEqual(last["plaintext_start"], SEGMENT_LENGTH)
        self.assertEqual(last["plaintext_end"], 4097)
        self.assertEqual(last["padding_length"], BLOCK_SIZE - 1)
        self.assertEqual(last["ciphertext_length"], BLOCK_SIZE)

        expected_size = 8 + SEGMENT_LENGTH + BLOCK_SIZE
        self.assertEqual(len(package), expected_size)

        decrypted = decrypt_package(package)
        self.assertEqual(decrypted, plaintext)
        self.assertEqual(len(decrypted), 4097)
        # Boundary bytes on either side of the segment cut must be exact.
        self.assertEqual(decrypted[4095], plaintext[4095])
        self.assertEqual(decrypted[4096], plaintext[4096])
        # The final segment's 15 padding bytes must not survive, and there is no
        # third segment from which extra content could leak.
        self.assertEqual(decrypted[-1:], plaintext[-1:])
        self.assertNotEqual(decrypted[-1:], b"\x00")


class SegmentIvAndNumberingTest(unittest.TestCase):
    """The regression core: detect a wrong IV or wrong segment numbering."""

    def test_each_segment_uses_salt_and_its_own_number_as_iv_input(self):
        plaintext = reference_plaintext(4097)
        package, manifest = build_encrypted_package(plaintext)

        for entry in manifest:
            with self.subTest(segment=entry["segment_number"]):
                expected_iv = segment_iv(KEY_DATA_SALT, entry["segment_number"])
                self.assertEqual(entry["iv"], expected_iv)
                self.assertEqual(
                    entry["iv"],
                    sha512(
                        KEY_DATA_SALT + pack("<I", entry["segment_number"])
                    ).digest()[:BLOCK_SIZE],
                )

        # A package whose every IV was derived from those inputs must decrypt
        # exactly; a single wrong IV would flip the first block of its segment.
        self.assertEqual(decrypt_package(package), plaintext)

    def test_modified_segment_numbering_is_rejected(self):
        plaintext = reference_plaintext(4097)
        # Every segment is encrypted with the number of the following segment.
        misnumbered, _ = build_encrypted_package(plaintext, index_bias=1)

        decrypted = decrypt_package(misnumbered)

        # This assertion must start failing if the decryptor's segment number
        # computation changes (e.g. it starts numbering segments at one).
        self.assertNotEqual(decrypted, plaintext)
        # The first segment already uses the wrong IV, so its opening block is
        # garbage even before the second segment comes into play.
        self.assertNotEqual(decrypted[:BLOCK_SIZE], plaintext[:BLOCK_SIZE])

    def test_single_segment_numbering_change_is_rejected(self):
        plaintext = reference_plaintext(1)
        misnumbered, _ = build_encrypted_package(plaintext, index_bias=1)
        self.assertNotEqual(decrypt_package(misnumbered), plaintext)

    def test_wrong_salt_iv_input_is_rejected(self):
        plaintext = reference_plaintext(SEGMENT_LENGTH + 1)
        # Encrypt with a foreign salt so the IV inputs differ, then decrypt with
        # the real key-data salt: the key is right but every IV is wrong.
        foreign_salt = b"\x7f" * BLOCK_SIZE
        package, _ = build_encrypted_package(plaintext, salt=foreign_salt)

        decrypted = decrypt_package(package, salt=KEY_DATA_SALT)
        self.assertNotEqual(decrypted, plaintext)
        self.assertNotEqual(decrypted[:BLOCK_SIZE], plaintext[:BLOCK_SIZE])


class FinalBlockPaddingTest(unittest.TestCase):
    """Zero padding on the last block must be stripped, never returned."""

    def test_padding_is_removed_for_partial_final_blocks(self):
        for length in (1, 17, 4095, 4097):
            with self.subTest(length=length):
                plaintext = reference_plaintext(length)
                package, manifest = build_encrypted_package(plaintext)

                # The independent builder really did pad the final block.
                self.assertGreater(manifest[-1]["padding_length"], 0)
                self.assertEqual(
                    len(package) - 8,
                    length + manifest[-1]["padding_length"],
                )

                decrypted = decrypt_package(package)
                self.assertEqual(decrypted, plaintext)
                self.assertEqual(len(decrypted), length)
                self.assertEqual(decrypted[-1:], plaintext[-1:])

    def test_full_final_block_needs_no_padding(self):
        for length in (4096, 8192):
            with self.subTest(length=length):
                plaintext = reference_plaintext(length)
                _, manifest = build_encrypted_package(plaintext)
                self.assertEqual(manifest[-1]["padding_length"], 0)
                self.assertEqual(
                    decrypt_package(build_encrypted_package(plaintext)[0]),
                    plaintext,
                )


class DeclaredLengthAndTruncationTest(unittest.TestCase):
    """Mismatches between the header length and the real ciphertext.

    Two distinct failure shapes must stay distinguishable:

    * explainable padding -- the output gains trailing zero bytes left over from
      the padded final block;
    * missing data -- ciphertext is absent, so the output is simply shorter and
      no padding is invented to fill the gap.
    """

    def test_declared_size_smaller_truncates_to_declared_prefix(self):
        plaintext = reference_plaintext(4097)
        package, _ = build_encrypted_package(plaintext)

        shrunk = with_declared_size(package, 100)
        decrypted = decrypt_package(shrunk)

        # Honest truncation: exactly the declared prefix, no padding or filler.
        self.assertEqual(len(decrypted), 100)
        self.assertEqual(decrypted, plaintext[:100])
        self.assertFalse(decrypted.endswith(b"\x00"))

    def test_declared_size_larger_exposes_only_explainable_padding(self):
        plaintext = reference_plaintext(4097)
        package, manifest = build_encrypted_package(plaintext)
        final_padding = manifest[-1]["padding_length"]

        grown = with_declared_size(package, len(plaintext) + final_padding)
        decrypted = decrypt_package(grown)

        # The only extra bytes available are the real zeros placed in the padded
        # final block; nothing is pulled from another segment.
        self.assertEqual(decrypted[: len(plaintext)], plaintext)
        self.assertEqual(decrypted[len(plaintext) :], b"\x00" * final_padding)
        self.assertEqual(len(decrypted), len(plaintext) + final_padding)

        # Asking beyond even the padded ciphertext cannot fabricate more data.
        overstated = with_declared_size(
            package, len(plaintext) + final_padding + 8
        )
        decrypted_over = decrypt_package(overstated)
        self.assertEqual(len(decrypted_over), len(plaintext) + final_padding)
        self.assertEqual(decrypted_over, decrypted)

    def test_block_aligned_truncation_is_missing_data(self):
        plaintext = reference_plaintext(4097)
        package, _ = build_encrypted_package(plaintext)

        # Keep the header plus the first full segment, drop the second segment.
        truncated = package[: 8 + SEGMENT_LENGTH]
        decrypted = decrypt_package(truncated)

        # Pure data loss: shorter output, equal to the available prefix, and no
        # padding bytes appended to mask the missing segment.
        self.assertEqual(len(decrypted), SEGMENT_LENGTH)
        self.assertEqual(decrypted, plaintext[:SEGMENT_LENGTH])
        self.assertEqual(len(decrypted), len(plaintext[:SEGMENT_LENGTH]))

    def test_unaligned_truncation_cannot_be_explained_as_padding(self):
        plaintext = reference_plaintext(4097)
        package, _ = build_encrypted_package(plaintext)

        # 100 trailing ciphertext bytes are not a multiple of the 16-byte block.
        truncated = package[: 8 + 100]
        with self.assertRaises(ValueError):
            decrypt_package(truncated)


if __name__ == "__main__":
    unittest.main()
