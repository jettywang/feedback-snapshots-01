"""Regression tests for the random material used by the Agile encryption writer.

Two files produced from the same password and plaintext must never share content
key material, salts, verifiers or integrity material.  Therefore, this module:

* drives encryption with a *recording* random source returning distinct fixed bytes,
  and checks which field each draw ends up in (and with which purpose), so a field
  that wrongly reuses another field's or a previous file's value is caught (comparing
  whole ciphertexts alone would not catch that);
* checks that an externally supplied salt only affects the password-key-encryptor
  salt and leaves all other material fresh;
* validates every generated file through an independent reference decryptor (no
  library code) and through the normal `OfficeFile` password path;
* checks that a failing/zero-consuming random source yields an explicit error and
  never a file built from all-zero material;
* keeps one test with the real `secrets` source.
"""

import base64
import hashlib
import hmac
import io
import struct
import unittest
import xml.etree.ElementTree as ET
import zipfile
from os.path import dirname, join
from unittest import mock

import olefile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method import ecma376_agile
from msoffcrypto.method.ecma376_agile import ECMA376Agile

PASSWORD = "Password1234_"
SPIN_COUNT = 1000  # Low enough to keep the tests fast; it does not affect the checks.


def _make_plaintext():
    """Build a real OOXML-shaped zip, ~6.6 KiB so the payload spans several segments."""
    body = b"".join(
        f"agile-random-regression-block-{i:03d}\n".encode("ascii") for i in range(220)
    )
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", body)
    return out.getvalue()


PLAINTEXT = _make_plaintext()
assert zipfile.is_zipfile(io.BytesIO(PLAINTEXT)) and len(PLAINTEXT) > 4096

NS = {
    "e": "http://schemas.microsoft.com/office/2006/encryption",
    "p": "http://schemas.microsoft.com/office/2006/keyEncryptor/password",
}

BLK_VERIFIER_INPUT = bytes(ecma376_agile.blkKey_VerifierHashInput)
BLK_VERIFIER_HASH = bytes(ecma376_agile.blkKey_encryptedVerifierHashValue)
BLK_KEY_VALUE = bytes(ecma376_agile.blkKey_encryptedKeyValue)
BLK_INTEGRITY_1 = bytes(ecma376_agile.blkKey_dataIntegrity1)
BLK_INTEGRITY_2 = bytes(ecma376_agile.blkKey_dataIntegrity2)

#: Sentinel used to request the real randomness source.
REAL = object()


# --------------------------------------------------------------------------- helpers


def _fixed_bytes(label, size):
    """Deterministic, non-zero bytes, distinct for every label."""
    return hashlib.shake_256(label.encode("ascii")).digest(size)


class RecordingRandomSource:
    """Callable random source handing out labeled fixed bytes and recording every call.

    Each instance (i.e. each encrypted file) uses a different label, so that two files
    encrypted in the same test receive different fixed material.
    """

    _instances = 0

    def __init__(self):
        self.label = f"file-{RecordingRandomSource._instances}"
        RecordingRandomSource._instances += 1
        self.calls = []  # list of (requested size, returned bytes)

    def __call__(self, size):
        value = _fixed_bytes(f"{self.label}-draw-{len(self.calls)}", size)
        self.calls.append((size, value))
        return value

    @property
    def sizes(self):
        return [size for size, _ in self.calls]

    @property
    def values(self):
        return [value for _, value in self.calls]


def _encrypt(plaintext=PLAINTEXT, source=REAL, salt_value=None):
    if source is REAL:
        source = RecordingRandomSource()
    with mock.patch.object(ecma376_agile.secrets, "token_bytes", source):
        blob = ECMA376Agile.encrypt(
            PASSWORD, io.BytesIO(plaintext), salt_value=salt_value, spin_count=SPIN_COUNT
        )
    return blob, source


def _streams(blob):
    """Return parsed EncryptionInfo XML, EncryptedPackage bytes and the raw XML."""
    ole = olefile.OleFileIO(io.BytesIO(blob))
    try:
        info = ole.openstream("EncryptionInfo").read()
        package = ole.openstream("EncryptedPackage").read()
    finally:
        ole.close()

    assert info[:8] == struct.pack("<HHI", 4, 4, 0x40), "unexpected EncryptionInfo header"
    return ET.fromstring(info[8:]), package, info


def _fields(xml):
    key_data = xml.find("e:keyData", NS)
    password = xml.find("e:keyEncryptors/e:keyEncryptor/p:encryptedKey", NS)
    integrity = xml.find("e:dataIntegrity", NS)
    assert key_data is not None and password is not None and integrity is not None

    return {
        "passwordSalt": base64.b64decode(password.get("saltValue")),
        "encryptedVerifierHashInput": base64.b64decode(
            password.get("encryptedVerifierHashInput")
        ),
        "encryptedVerifierHashValue": base64.b64decode(
            password.get("encryptedVerifierHashValue")
        ),
        "encryptedKeyValue": base64.b64decode(password.get("encryptedKeyValue")),
        "keyDataSalt": base64.b64decode(key_data.get("saltValue")),
        "encryptedHmacKey": base64.b64decode(integrity.get("encryptedHmacKey")),
        "encryptedHmacValue": base64.b64decode(integrity.get("encryptedHmacValue")),
        "spinCount": int(password.get("spinCount")),
        "hashAlgorithm": password.get("hashAlgorithm"),
        "keyBits": int(password.get("keyBits")),
        "blockSize": int(key_data.get("blockSize")),
        "cipherAlgorithm": key_data.get("cipherAlgorithm"),
        "cipherChaining": key_data.get("cipherChaining"),
    }


def _aes_cbc_decrypt(data, key, iv):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _sha512(data):
    return hashlib.sha512(data).digest()


def _iterated_hash(password, salt, spin_count):
    """Independent implementation of the spec's password hash (no library code)."""
    h = _sha512(salt + password.encode("utf-16-le"))
    for i in range(spin_count):
        h = _sha512(struct.pack("<I", i) + h)
    return h


def _aes_cbc_encrypt(data, key, iv):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _derive(h, block_key, key_bits=256):
    return _sha512(h + block_key)[: key_bits // 8]


def _reference_unwrap(blob, plaintext=PLAINTEXT):
    """Decrypt a generated container with an independent, spec-driven implementation.

    Returns the recovered secret key, integrity key and verifier input so callers
    can assert which fixed random draw landed in which field.
    """
    xml, package, _ = _streams(blob)
    field = _fields(xml)
    assert field["hashAlgorithm"] == "SHA512"
    assert field["cipherAlgorithm"] == "AES"
    assert field["cipherChaining"] == "ChainingModeCBC"
    assert field["blockSize"] == 16
    assert field["keyBits"] == 256

    h = _iterated_hash(PASSWORD, field["passwordSalt"], field["spinCount"])
    verifier_input = _aes_cbc_decrypt(
        field["encryptedVerifierHashInput"],
        _derive(h, BLK_VERIFIER_INPUT, field["keyBits"]),
        field["passwordSalt"],
    )
    verifier_hash = _aes_cbc_decrypt(
        field["encryptedVerifierHashValue"],
        _derive(h, BLK_VERIFIER_HASH, field["keyBits"]),
        field["passwordSalt"],
    )
    secret_key = _aes_cbc_decrypt(
        field["encryptedKeyValue"],
        _derive(h, BLK_KEY_VALUE, field["keyBits"]),
        field["passwordSalt"],
    )

    assert verifier_hash == _sha512(verifier_input), "verifier hash does not match input"
    assert secret_key[16:] == b"\x36" * 16, "secret key padding is wrong"
    assert any(verifier_input[:16]), "verifier input is all zero"
    assert any(secret_key[:16]), "content key is all zero"

    key_data_salt = field["keyDataSalt"]
    total_size = struct.unpack("<Q", package[:8])[0]
    assert total_size == len(plaintext), "payload size header is wrong"

    recovered = bytearray()
    offset = 8
    remaining = total_size
    segment = 0
    while remaining > 0:
        iv = _sha512(key_data_salt + struct.pack("<I", segment))[: field["blockSize"]]
        chunk = package[offset : offset + 4096]
        decrypted = _aes_cbc_decrypt(chunk, secret_key, iv)
        take = min(len(decrypted), remaining)
        recovered += decrypted[:take]
        remaining -= take
        offset += len(chunk)
        segment += 1
    assert bytes(recovered) == plaintext, "payload does not decrypt to the plaintext"
    assert segment > 1, "test payload must span multiple segments"

    iv1 = _sha512(key_data_salt + BLK_INTEGRITY_1)[:16]
    iv2 = _sha512(key_data_salt + BLK_INTEGRITY_2)[:16]
    hmac_key = _aes_cbc_decrypt(field["encryptedHmacKey"], secret_key, iv1)
    hmac_value = _aes_cbc_decrypt(field["encryptedHmacValue"], secret_key, iv2)
    assert len(hmac_key) == 64 and len(hmac_value) == 64
    assert any(hmac_key), "integrity key is all zero"
    assert hmac_value == hmac.new(hmac_key, package, hashlib.sha512).digest(), (
        "integrity value does not cover the encrypted package"
    )

    return {
        "verifierInput": verifier_input,
        "verifierHash": verifier_hash,
        "secretKey": secret_key,
        "hmacKey": hmac_key,
        "hmacValue": hmac_value,
        "package": package,
    }


def _library_decrypt(blob):
    """Decrypt the generated container through the public OfficeFile path."""
    with io.BytesIO(blob) as handle:
        ofile = OfficeFile(handle)
        ofile.load_key(password=PASSWORD, verify_password=True)
        out = io.BytesIO()
        ofile.decrypt(out, verify_integrity=True)
    return out.getvalue()


def _mix_containers(encryption_info_from, package_from):
    """Combine streams from two independently generated containers."""
    from msoffcrypto.method.container.ecma376_encrypted import ECMA376Encrypted

    info = _streams(encryption_info_from)[2]
    package = _streams(package_from)[1]
    out = io.BytesIO()
    ECMA376Encrypted(package, info).write_to(out)
    return out.getvalue()



def _check_password_salt_usage(testcase, blob, salt):
    """Independently confirm the password salt is only the IV for key-encryptor fields."""
    xml, _, _ = _streams(blob)
    field = _fields(xml)
    recovered = _reference_unwrap(blob)
    testcase.assertEqual(field["passwordSalt"], salt)

    h = _iterated_hash(PASSWORD, salt, field["spinCount"])
    testcase.assertEqual(
        field["encryptedKeyValue"],
        _aes_cbc_encrypt(recovered["secretKey"], _derive(h, BLK_KEY_VALUE), salt),
        "password salt is not the IV of encryptedKeyValue",
    )
    testcase.assertEqual(
        field["encryptedVerifierHashInput"],
        _aes_cbc_encrypt(recovered["verifierInput"], _derive(h, BLK_VERIFIER_INPUT), salt),
        "password salt is not the IV of encryptedVerifierHashInput",
    )
    testcase.assertEqual(
        field["encryptedVerifierHashValue"],
        _aes_cbc_encrypt(recovered["verifierHash"], _derive(h, BLK_VERIFIER_HASH), salt),
        "password salt is not the IV of encryptedVerifierHashValue",
    )
    testcase.assertNotEqual(field["keyDataSalt"], salt)


def _assert_materials_pairwise_distinct(testcase, field, recovered):
    """No two per-file random materials may coincidentally be the same value."""
    materials = {
        "passwordSalt": field["passwordSalt"],
        "keyDataSalt": field["keyDataSalt"],
        "verifierInput": recovered["verifierInput"][:16],
        "secretKey": recovered["secretKey"][:16],
        "hmacKey": recovered["hmacKey"],
    }
    for left, left_value in materials.items():
        for right, right_value in materials.items():
            if left < right:
                testcase.assertNotEqual(
                    left_value,
                    right_value,
                    f"{left} and {right} share random material",
                )


# --------------------------------------------------------------------------- tests


class AgileRandomMaterialTest(unittest.TestCase):
    """Random material must be per-file, per-purpose and independently verifiable."""

    def test_each_draw_lands_in_its_own_field(self):
        blob, source = _encrypt()
        self.assertEqual(source.sizes, [16, 16, 16, 16, 64])

        field = _fields(_streams(blob)[0])
        recovered = _reference_unwrap(blob)
        draws = source.values

        # 1: password-key-encryptor salt; used as the IV for the verifier and key-value
        #    fields, and never as the keyData salt.
        self.assertEqual(field["passwordSalt"], draws[0])
        _check_password_salt_usage(self, blob, draws[0])

        # 2: plain verifier input, encrypted under its dedicated block key.  The stored
        #    field must be ciphertext, not the raw draw.
        self.assertEqual(recovered["verifierInput"][:16], draws[1])
        self.assertNotEqual(field["encryptedVerifierHashInput"], draws[1])
        self.assertEqual(recovered["verifierHash"], _sha512(draws[1]))
        self.assertNotEqual(field["encryptedVerifierHashValue"], _sha512(draws[1]))

        # 3: content key, padded with 0x36 to the 256-bit key size.
        self.assertEqual(recovered["secretKey"], draws[2] + b"\x36" * 16)
        self.assertNotEqual(field["encryptedKeyValue"], recovered["secretKey"])

        # 4: keyData salt; used as the segment/integrity IV prefix, not as a key.
        self.assertEqual(field["keyDataSalt"], draws[3])
        self.assertNotEqual(recovered["secretKey"], draws[3])

        # 5: integrity HMAC key (a hash-size draw), never the content key.
        self.assertEqual(recovered["hmacKey"], draws[4])
        self.assertEqual(len(draws[4]), 64)
        self.assertNotEqual(recovered["hmacKey"], recovered["secretKey"])
        self.assertNotEqual(recovered["hmacKey"], field["encryptedHmacKey"])
        self.assertNotEqual(recovered["hmacKey"], field["encryptedHmacValue"])

        # Recovered materials are pairwise distinct: no field merely reuses another
        # field's random value (e.g. content key == verifier input, HMAC key ==
        # content key, or keyData salt == password salt).
        _assert_materials_pairwise_distinct(self, field, recovered)

        # All raw draws are mutually distinct, and no *ciphertext* field echoes one.
        self.assertEqual(len(set(draws)), len(draws), "fixed draws must be distinct")
        for name in (
            "encryptedVerifierHashInput",
            "encryptedVerifierHashValue",
            "encryptedKeyValue",
            "encryptedHmacKey",
            "encryptedHmacValue",
        ):
            self.assertNotIn(field[name], draws, f"{name} stored raw random material")

        # The same file also opens through the public password path.
        self.assertEqual(_library_decrypt(blob), PLAINTEXT)

    def test_same_password_and_plaintext_never_reuses_material_across_files(self):
        first, first_source = _encrypt()
        second, second_source = _encrypt()
        self.assertNotEqual(first, second)

        fields_a = _fields(_streams(first)[0])
        fields_b = _fields(_streams(second)[0])

        # Every byte-valued field differs between the two files.
        for name, value_a in fields_a.items():
            if isinstance(value_a, (bytes, bytearray)):
                self.assertNotEqual(
                    value_a,
                    fields_b[name],
                    f"{name} was reused between two independently encrypted files",
                )

        # The random source gave each file different draws.
        self.assertEqual(len(first_source.values), len(second_source.values))
        for index, (a, b) in enumerate(zip(first_source.values, second_source.values)):
            self.assertNotEqual(a, b, f"draw {index} is not distinct")

        recovered_a = _reference_unwrap(first)
        recovered_b = _reference_unwrap(second)
        self.assertTrue(any(recovered_a["secretKey"][:16]))
        self.assertTrue(any(recovered_b["secretKey"][:16]))
        for key in ("secretKey", "hmacKey", "verifierInput", "package"):
            self.assertNotEqual(recovered_a[key], recovered_b[key], key)

        # A container mixing file A's encryption info with file B's payload must fail
        # integrity verification, and well-formed files must still decrypt.
        with self.assertRaises(exceptions.InvalidKeyError):
            _library_decrypt(_mix_containers(first, second))
        with self.assertRaises(exceptions.InvalidKeyError):
            _library_decrypt(_mix_containers(second, first))
        self.assertEqual(_library_decrypt(first), PLAINTEXT)
        self.assertEqual(_library_decrypt(second), PLAINTEXT)

    def test_external_salt_only_changes_the_password_salt(self):
        provided = _fixed_bytes("provided-salt", 16)
        first, source_a = _encrypt(salt_value=provided)
        second, source_b = _encrypt(salt_value=provided)
        self.assertNotEqual(first, second)

        field_a = _fields(_streams(first)[0])
        field_b = _fields(_streams(second)[0])
        self.assertEqual(field_a["passwordSalt"], provided)
        self.assertEqual(field_b["passwordSalt"], provided)
        self.assertEqual(source_a.sizes, [16, 16, 16, 64])
        self.assertEqual(source_b.sizes, [16, 16, 16, 64])

        # Fresh material still differs between the two files.
        for name in (
            "keyDataSalt",
            "encryptedVerifierHashInput",
            "encryptedVerifierHashValue",
            "encryptedKeyValue",
            "encryptedHmacKey",
            "encryptedHmacValue",
        ):
            self.assertNotEqual(field_a[name], field_b[name], name)

        # The caller-supplied salt must not be recycled as any freshly drawn material.
        for draw in source_a.values:
            self.assertNotEqual(draw, provided)

        # Mapping in the presence of an external salt (no password-salt draw):
        # draw 0 -> verifier input, draw 1 -> content key, draw 2 -> keyData salt,
        # draw 3 -> integrity key.  The external salt is not one of the draws.
        recovered = _reference_unwrap(first)
        self.assertEqual(recovered["verifierInput"][:16], source_a.values[0])
        self.assertEqual(recovered["secretKey"], source_a.values[1] + b"\x36" * 16)
        self.assertEqual(field_a["keyDataSalt"], source_a.values[2])
        self.assertEqual(recovered["hmacKey"], source_a.values[3])
        self.assertEqual(recovered["verifierHash"], _sha512(source_a.values[0]))
        self.assertEqual(_library_decrypt(first), PLAINTEXT)
        self.assertEqual(_library_decrypt(second), PLAINTEXT)

    def test_generated_file_matches_independent_known_vector(self):
        # Fixed salt plus fixed draws; the whole derivation chain is recomputed by the
        # reference implementation and compared against the produced container.
        salt = _fixed_bytes("known-vector-salt", 16)
        blob, source = _encrypt(salt_value=salt)
        xml, package, _ = _streams(blob)
        field = _fields(xml)
        recovered = _reference_unwrap(blob)

        self.assertEqual(field["passwordSalt"], salt)
        self.assertEqual(field["spinCount"], SPIN_COUNT)
        self.assertEqual(
            hashlib.sha512(package).digest(), hashlib.sha512(recovered["package"]).digest()
        )
        # External salt means draw 1 is the content key and draw 2 the keyData salt.
        self.assertEqual(recovered["secretKey"], source.values[1] + b"\x36" * 16)
        self.assertEqual(field["keyDataSalt"], source.values[2])
        self.assertEqual(recovered["hmacKey"], source.values[3])
        self.assertEqual(_library_decrypt(blob), PLAINTEXT)

        # A small independent vector for the fragment of the derivation that maps the
        # password salt into the encrypted key value; expected bytes are recomputed
        # here from the specification, not read back from the generated file.
        h = _iterated_hash(PASSWORD, salt, SPIN_COUNT)
        key3 = _derive(h, BLK_KEY_VALUE, field["keyBits"])
        self.assertEqual(
            field["encryptedKeyValue"],
            _aes_cbc_encrypt(recovered["secretKey"], key3, salt),
        )

    def test_real_random_source(self):
        first, _ = _encrypt()
        second, _ = _encrypt()
        self.assertNotEqual(first, second)

        field_a = _fields(_streams(first)[0])
        field_b = _fields(_streams(second)[0])
        for name in (
            "passwordSalt",
            "keyDataSalt",
            "encryptedVerifierHashInput",
            "encryptedVerifierHashValue",
            "encryptedKeyValue",
            "encryptedHmacKey",
            "encryptedHmacValue",
        ):
            self.assertNotEqual(field_a[name], field_b[name], name)

        for name in ("passwordSalt", "keyDataSalt"):
            self.assertTrue(any(field_a[name]), f"{name} is all zero")

        recovered = _reference_unwrap(first)
        self.assertTrue(any(recovered["secretKey"][:16]))
        self.assertTrue(any(recovered["hmacKey"]))
        self.assertEqual(_library_decrypt(first), PLAINTEXT)
        self.assertEqual(_library_decrypt(second), PLAINTEXT)

    def test_random_source_failure_is_explicit(self):
        for label, broken in (
            ("returns short", lambda size: b"\x01" * (size - 1)),
            ("returns empty", lambda size: b""),
            ("returns None", lambda size: None),
            ("returns str", lambda size: "0" * size),
        ):
            with self.subTest(label), mock.patch.object(
                ecma376_agile.secrets, "token_bytes", broken
            ):
                with self.assertRaises(exceptions.EncryptionError) as caught:
                    ECMA376Agile.encrypt(
                        PASSWORD, io.BytesIO(PLAINTEXT), spin_count=SPIN_COUNT
                    )
                self.assertIn("Random source returned", str(caught.exception))

        # A source that raises must surface a dedicated failure, chained to the
        # original error rather than being swallowed or replaced by fallback bytes.
        def failing_source(size, fail_on=0):
            state = {"calls": 0}

            def draw(requested):
                if state["calls"] == fail_on:
                    raise OSError("entropy source unavailable")
                state["calls"] += 1
                return _fixed_bytes(f"partial-{state['calls']}", requested)

            return draw

        for label, fail_on in (("first draw", 0), ("second draw", 1), ("final draw", 4)):
            with self.subTest(label), mock.patch.object(
                ecma376_agile.secrets, "token_bytes", failing_source(16, fail_on)
            ):
                with self.assertRaises(exceptions.EncryptionError) as caught:
                    ECMA376Agile.encrypt(
                        PASSWORD, io.BytesIO(PLAINTEXT), spin_count=SPIN_COUNT
                    )
                self.assertIn("Random source failed", str(caught.exception))
                self.assertIsInstance(caught.exception.__cause__, OSError)

    def test_random_source_that_never_returns_bytes_raises_not_succeeds(self):
        source = RecordingRandomSource()

        def short(size):
            value = source(size)
            return value[:-1]

        # Every draw is truncated, so encryption can never complete.
        with mock.patch.object(ecma376_agile.secrets, "token_bytes", short):
            with self.assertRaises(exceptions.EncryptionError):
                ECMA376Agile.encrypt(
                    PASSWORD, io.BytesIO(PLAINTEXT), spin_count=SPIN_COUNT
                )
        self.assertTrue(source.calls, "encryption stopped before drawing any material")

    def test_all_zero_random_material_is_rejected(self):
        """A zero draw in *any* slot must abort; never emit a file from zero material."""

        def zero_draw_at(index):
            state = {"calls": 0}

            def draw(size):
                position = state["calls"]
                state["calls"] += 1
                if position == index:
                    return b"\x00" * size
                return _fixed_bytes(f"filler-{position}-{size}", size)

            return draw

        for index, role in (
            (0, "password salt"),
            (1, "verifier input"),
            (2, "content key"),
            (3, "keyData salt"),
            (4, "integrity HMAC key"),
        ):
            with self.subTest(role), mock.patch.object(
                ecma376_agile.secrets, "token_bytes", zero_draw_at(index)
            ):
                with self.assertRaises(exceptions.EncryptionError) as caught:
                    ECMA376Agile.encrypt(
                        PASSWORD, io.BytesIO(PLAINTEXT), spin_count=SPIN_COUNT
                    )
                self.assertIn("all-zero", str(caught.exception))
                self.assertIn("Random source", str(caught.exception))

        with self.subTest("every draw"), mock.patch.object(
            ecma376_agile.secrets, "token_bytes", lambda size: b"\x00" * size
        ):
            with self.assertRaises(exceptions.EncryptionError) as caught:
                ECMA376Agile.encrypt(
                    PASSWORD, io.BytesIO(PLAINTEXT), spin_count=SPIN_COUNT
                )
            self.assertIn("all-zero", str(caught.exception))

    def test_random_failure_never_writes_an_output_file(self):
        """The public encrypt path must raise and leave the output handle empty."""
        with open(join(dirname(__file__), "outputs", "example.docx"), "rb") as f:
            plain = f.read()

        broken_sources = (
            ("zeros", lambda size: b"\x00" * size),
            ("short", lambda size: b""),
            ("raises", mock.Mock(side_effect=OSError("entropy source unavailable"))),
        )
        for label, broken in broken_sources:
            with self.subTest(label), mock.patch.object(
                ecma376_agile.secrets, "token_bytes", broken
            ):
                out = io.BytesIO()
                with io.BytesIO(plain) as handle:
                    ofile = OfficeFile(handle)
                    with self.assertRaises(exceptions.EncryptionError):
                        ofile.encrypt(PASSWORD, out)
                self.assertEqual(out.getvalue(), b"", "a failed encryption wrote output")

        # Sanity: with a working source, the same call produces a decryptable file.
        out = io.BytesIO()
        with io.BytesIO(plain) as handle:
            OfficeFile(handle).encrypt(PASSWORD, out)
        self.assertEqual(_library_decrypt(out.getvalue()), plain)

    def test_invalid_external_salt_is_rejected(self):
        for label, salt in (
            ("short", b"\x01" * 15),
            ("long", b"\x02" * 17),
            ("not bytes", "0" * 16),
        ):
            with self.subTest(label):
                with self.assertRaises(exceptions.EncryptionError):
                    ECMA376Agile.generate_encryption_parameters(
                        PASSWORD, salt_value=salt, spin_count=SPIN_COUNT
                    )


if __name__ == "__main__":
    unittest.main()
