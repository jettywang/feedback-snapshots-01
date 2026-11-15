"""
Tests for olefile.encaudit (read-only encrypted Office envelope audit).

Synthetic OLE2/CFB containers are built from scratch so the audit can be
exercised against valid envelopes, contradictory algorithm declarations and
truncated packages without any real encrypted documents.
"""

import base64
import hashlib
import os
import struct
import tempfile
import unittest

from olefile import encaudit
from olefile.encaudit import (
    STATUS_FAIL,
    STATUS_NOT_PERFORMED,
    STATUS_PASS,
    STATUS_UNSUPPORTED,
    audit_encrypted_office,
)

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


# --- minimal CFB (compound file) builder ------------------------------------

def _dir_entry(name, entry_type, start, size, child=NOSTREAM, right=NOSTREAM):
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    entry = bytearray(128)
    entry[0:len(encoded)] = encoded
    struct.pack_into("<H", entry, 64, len(encoded))
    struct.pack_into("<B", entry, 66, entry_type)
    struct.pack_into("<B", entry, 67, 1)  # black
    struct.pack_into("<I", entry, 68, NOSTREAM)
    struct.pack_into("<I", entry, 72, right)
    struct.pack_into("<I", entry, 76, child)
    struct.pack_into("<I", entry, 116, start)
    struct.pack_into("<Q", entry, 120, size)
    return bytes(entry)


def build_cfb(streams):
    """Build a minimal but valid v3 CFB file holding the given root streams
    (dict of name -> bytes). Supports the mini stream for small streams."""
    names = list(streams)
    mini_cutoff = 4096
    ministream = bytearray()
    minifat = []
    mini_start = {}
    big = {}
    for name in names:
        data = streams[name]
        if len(data) < mini_cutoff:
            mini_start[name] = len(minifat)
            count = max(1, -(-len(data) // 64))
            start = len(minifat)
            for i in range(count):
                minifat.append(start + i + 1 if i < count - 1 else ENDOFCHAIN)
            ministream += data.ljust(count * 64, b"\x00")
        else:
            big[name] = data

    sectors = []
    fat = []

    def add_chain(data, sector_size=512):
        count = -(-len(data) // sector_size)
        start = len(sectors)
        for i in range(count):
            sectors.append(data[i * sector_size:(i + 1) * sector_size]
                           .ljust(sector_size, b"\x00"))
            fat.append(len(sectors) if i < count - 1 else ENDOFCHAIN)
        return start

    big_start = {name: add_chain(data) for name, data in big.items()}
    mini_container_start = add_chain(bytes(ministream)) if ministream else ENDOFCHAIN
    if minifat:
        entries = list(minifat)
        entries += [FREESECT] * (-(-len(minifat) // 128) * 128 - len(entries))
        minifat_start = add_chain(struct.pack("<%dI" % len(entries), *entries))
        num_minifat_sectors = -(-len(minifat) // 128)
    else:
        minifat_start = ENDOFCHAIN
        num_minifat_sectors = 0

    dir_entries = bytearray()
    dir_entries += _dir_entry(
        "Root Entry", 5,
        mini_container_start if ministream else ENDOFCHAIN,
        len(ministream), child=1 if names else NOSTREAM)
    for index, name in enumerate(names):
        right = index + 2 if index < len(names) - 1 else NOSTREAM
        if name in big_start:
            start, size = big_start[name], len(streams[name])
        else:
            start, size = mini_start[name], len(streams[name])
        dir_entries += _dir_entry(name, 2, start, size, right=right)
    dir_entries += b"\x00" * (-len(dir_entries) % 512)
    dir_start = add_chain(bytes(dir_entries))

    num_fat = 1
    while True:
        needed = -(-(len(sectors) + num_fat) // 128)
        if needed == num_fat:
            break
        num_fat = needed
    fat_start = len(sectors)
    fat_entries = list(fat) + [FATSECT] * num_fat
    fat_entries += [FREESECT] * (num_fat * 128 - len(fat_entries))
    for i in range(num_fat):
        sectors.append(struct.pack("<128I", *fat_entries[i * 128:(i + 1) * 128]))

    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 24, 0x003E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 40, 0)
    struct.pack_into("<I", header, 44, num_fat)
    struct.pack_into("<I", header, 48, dir_start)
    struct.pack_into("<I", header, 56, 4096)
    struct.pack_into("<I", header, 60, minifat_start)
    struct.pack_into("<I", header, 64, num_minifat_sectors)
    struct.pack_into("<I", header, 68, ENDOFCHAIN)
    struct.pack_into("<I", header, 72, 0)
    difat = [fat_start + i for i in range(num_fat)] + [FREESECT] * (109 - num_fat)
    struct.pack_into("<109I", header, 76, *difat)
    return bytes(header) + b"".join(sectors)


# --- EncryptionInfo fixtures --------------------------------------------------

STANDARD_FLAGS = encaudit.FLAG_FCRYPTOAPI | encaudit.FLAG_FAES  # 0x24


def make_standard_info(alg_id=0x0000660E, key_size=128, flags=STANDARD_FLAGS,
                       alg_id_hash=0x00008004, vmajor=4, vminor=2):
    csp = ("Microsoft Enhanced RSA and AES Cryptographic Provider"
           .encode("utf-16-le") + b"\x00\x00")
    header = struct.pack("<8I", flags, 0, alg_id, alg_id_hash, key_size,
                         0x18, 0, 0) + csp
    verifier = (struct.pack("<I", 16) + b"\x11" * 16 + b"\x22" * 16
                + struct.pack("<I", 20) + b"\x33" * 32)
    return struct.pack("<HHII", vmajor, vminor, flags, len(header)) \
        + header + verifier


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def make_agile_info(key_data_cipher="AES", encryptor_cipher="AES",
                    key_data_hash="SHA1", encryptor_hash="SHA1",
                    extra_xml="", xml_override=None):
    if xml_override is not None:
        descriptor = xml_override
    else:
        descriptor = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" '
            'xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">'
            '<keyData saltSize="16" blockSize="16" keyBits="128" hashSize="20" '
            'cipherAlgorithm="%s" cipherChaining="ChainingModeCBC" '
            'hashAlgorithm="%s" saltValue="%s"/>'
            '<dataIntegrity encryptedHmacKey="%s" encryptedHmacValue="%s"/>'
            '<keyEncryptors>'
            '<keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">'
            '<p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" '
            'keyBits="128" hashSize="20" cipherAlgorithm="%s" '
            'cipherChaining="ChainingModeCBC" hashAlgorithm="%s" saltValue="%s" '
            'encryptedVerifierHashInput="%s" encryptedVerifierHashValue="%s" '
            'encryptedKeyValue="%s"/>'
            '</keyEncryptor>'
            '</keyEncryptors>'
            '%s'
            '</encryption>'
        ) % (
            key_data_cipher, key_data_hash, _b64(b"\x01" * 16),
            _b64(b"\x02" * 32), _b64(b"\x03" * 32),
            encryptor_cipher, encryptor_hash, _b64(b"\x04" * 16),
            _b64(b"\x05" * 16), _b64(b"\x06" * 32), _b64(b"\x07" * 16),
            extra_xml,
        )
    return struct.pack("<HHI", 4, 4, 0x40) + descriptor.encode("utf-8")


def make_encrypted_package(declared_size, actual_size):
    return struct.pack("<Q", declared_size) + b"\xAB" * actual_size


def agile_padded_size(declared):
    full, remainder = divmod(declared, 4096)
    padded_remainder = remainder if remainder % 16 == 0 \
        else remainder + 16 - remainder % 16
    return full * 4096 + padded_remainder


# --- test harness --------------------------------------------------------------

class EncAuditTestBase(unittest.TestCase):
    def audit_streams(self, streams):
        data = build_cfb(streams)
        fd, path = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            return audit_encrypted_office(path)
        finally:
            os.unlink(path)

    def find_check(self, report, name):
        for check in report.checks:
            if check.name == name:
                return check
        self.fail("check %r not found in report" % name)

    def assert_gates_not_green(self, report):
        self.assertEqual(report.password_verification, STATUS_NOT_PERFORMED)
        self.assertEqual(report.content_integrity, STATUS_NOT_PERFORMED)


class TestValidEnvelopes(EncAuditTestBase):
    def test_standard_valid(self):
        declared = 5000
        actual = 5008  # round_up(5000, AES block 16)
        package = make_encrypted_package(declared, actual)
        report = self.audit_streams({
            "EncryptionInfo": make_standard_info(),
            "EncryptedPackage": package,
        })
        self.assertTrue(report.is_encrypted_container)
        self.assertEqual(report.encryption_format, "standard")
        self.assertEqual(report.structural_status, STATUS_PASS,
                         [c for c in report.checks if c.status == STATUS_FAIL])
        self.assertEqual(report.declared_stream_size, declared)
        self.assertEqual(report.actual_encrypted_size, actual)
        self.assertEqual(report.ciphertext_sha256,
                         hashlib.sha256(package).hexdigest())
        self.assert_gates_not_green(report)

    def test_agile_valid(self):
        declared = 5000
        actual = agile_padded_size(declared)
        package = make_encrypted_package(declared, actual)
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(),
            "EncryptedPackage": package,
        })
        self.assertEqual(report.encryption_format, "agile")
        self.assertEqual(report.structural_status, STATUS_PASS,
                         [c for c in report.checks if c.status == STATUS_FAIL])
        self.assertEqual(report.ciphertext_sha256,
                         hashlib.sha256(package).hexdigest())
        self.assert_gates_not_green(report)


class TestContradictions(EncAuditTestBase):
    def test_standard_keysize_contradicts_alg_id(self):
        # Declares AES-128 in AlgID but a 256-bit KeySize.
        report = self.audit_streams({
            "EncryptionInfo": make_standard_info(alg_id=0x0000660E,
                                                 key_size=256),
            "EncryptedPackage": make_encrypted_package(5000, 5008),
        })
        check = self.find_check(report, "钥长与算法一致")
        self.assertEqual(check.status, STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)
        self.assert_gates_not_green(report)

    def test_standard_flags_copy_mismatch(self):
        info = bytearray(make_standard_info())
        struct.pack_into("<I", info, 4, 0xDEADBEEF)  # corrupt the flags copy
        report = self.audit_streams({
            "EncryptionInfo": bytes(info),
            "EncryptedPackage": make_encrypted_package(5000, 5008),
        })
        self.assertEqual(self.find_check(report, "Flags 副本一致").status,
                         STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)

    def test_agile_cipher_conflict_not_last_one_wins(self):
        # keyData says AES, passwordKeyEncryptor says DES: the auditor must
        # flag the contradiction instead of silently taking either one.
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(encryptor_cipher="DES"),
            "EncryptedPackage": make_encrypted_package(5000, 5008),
        })
        check = self.find_check(report, "算法声明一致 (cipher)")
        self.assertEqual(check.status, STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)
        self.assert_gates_not_green(report)

    def test_agile_hash_conflict(self):
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(encryptor_hash="SHA256"),
            "EncryptedPackage": make_encrypted_package(5000, 5008),
        })
        self.assertEqual(self.find_check(report, "算法声明一致 (hash)").status,
                         STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)

    def test_agile_hashsize_contradicts_algorithm(self):
        info = make_agile_info().replace(b'hashSize="20"', b'hashSize="64"',
                                         1)
        report = self.audit_streams({
            "EncryptionInfo": info,
            "EncryptedPackage": make_encrypted_package(5000, 5008),
        })
        self.assertEqual(self.find_check(report, "keyData.hashSize").status,
                         STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)


class TestTruncatedPackage(EncAuditTestBase):
    def test_truncated_package(self):
        # Declares 8192 plaintext bytes but carries only 100 ciphertext bytes.
        report = self.audit_streams({
            "EncryptionInfo": make_standard_info(),
            "EncryptedPackage": make_encrypted_package(8192, 100),
        })
        check = self.find_check(report, "EncryptedPackage 长度一致")
        self.assertEqual(check.status, STATUS_FAIL)
        self.assertIn("截断", check.detail)
        self.assertEqual(report.structural_status, STATUS_FAIL)
        # The digest is still computed over what is actually there.
        self.assertEqual(
            report.ciphertext_sha256,
            hashlib.sha256(make_encrypted_package(8192, 100)).hexdigest())
        self.assert_gates_not_green(report)


class TestUnsupportedSchemes(EncAuditTestBase):
    def test_extensible_encryption_unsupported(self):
        info = struct.pack("<HH", 4, 3) + b"\x00" * 64
        report = self.audit_streams({
            "EncryptionInfo": info,
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        self.assertEqual(self.find_check(report, "加密方案").status,
                         STATUS_UNSUPPORTED)
        self.assertEqual(report.structural_status, STATUS_UNSUPPORTED)
        self.assert_gates_not_green(report)

    def test_unknown_version_unsupported(self):
        info = struct.pack("<HH", 9, 9) + b"\x00" * 64
        report = self.audit_streams({
            "EncryptionInfo": info,
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        self.assertEqual(self.find_check(report, "加密方案").status,
                         STATUS_UNSUPPORTED)
        self.assertEqual(report.structural_status, STATUS_UNSUPPORTED)

    def test_standard_fexternal_unsupported(self):
        flags = encaudit.FLAG_FEXTERNAL
        report = self.audit_streams({
            "EncryptionInfo": make_standard_info(flags=flags),
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        self.assertEqual(self.find_check(report, "加密方案归属").status,
                         STATUS_UNSUPPORTED)

    def test_unknown_key_encryptor_uri_unsupported(self):
        xml = (
            '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption">'
            '<keyData saltSize="16" blockSize="16" keyBits="128" hashSize="20" '
            'cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" '
            'hashAlgorithm="SHA1" saltValue="%s"/>'
            '<keyEncryptors>'
            '<keyEncryptor uri="http://example.com/custom/encryptor"/>'
            '</keyEncryptors>'
            '</encryption>'
        ) % _b64(b"\x01" * 16)
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(xml_override=xml),
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        self.assertEqual(self.find_check(report, "keyEncryptor 方案").status,
                         STATUS_UNSUPPORTED)
        self.assertEqual(report.structural_status, STATUS_UNSUPPORTED)


class TestXmlHardening(EncAuditTestBase):
    def test_dtd_rejected(self):
        xml = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE encryption [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption">'
            '<keyData saltSize="16" blockSize="16" keyBits="128" hashSize="20" '
            'cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" '
            'hashAlgorithm="SHA1" saltValue="%s"/>'
            '<keyEncryptors><keyEncryptor '
            'uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"/>'
            '</keyEncryptors></encryption>'
        ) % _b64(b"\x01" * 16)
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(xml_override=xml),
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        self.assertEqual(self.find_check(report, "XML 外部引用").status,
                         STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)
        self.assert_gates_not_green(report)

    def test_duplicate_keydata_rejected(self):
        key_data = (
            '<keyData saltSize="16" blockSize="16" keyBits="128" hashSize="20" '
            'cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" '
            'hashAlgorithm="SHA1" saltValue="%s"/>'
        ) % _b64(b"\x01" * 16)
        xml = (
            '<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption">'
            + key_data + key_data +
            '<keyEncryptors><keyEncryptor '
            'uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"/>'
            '</keyEncryptors></encryption>'
        )
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(xml_override=xml),
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        check = self.find_check(report, "keyData 唯一性")
        self.assertEqual(check.status, STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)

    def test_malformed_xml_rejected(self):
        report = self.audit_streams({
            "EncryptionInfo": make_agile_info(xml_override="<encryption><unclosed>"),
            "EncryptedPackage": make_encrypted_package(64, 64),
        })
        self.assertEqual(self.find_check(report, "XML 解析").status,
                         STATUS_FAIL)
        self.assertEqual(report.structural_status, STATUS_FAIL)


class TestContainerLevel(EncAuditTestBase):
    def test_not_ole_container(self):
        fd, path = tempfile.mkstemp(suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(b"PK\x03\x04" + b"\x00" * 256)
            report = audit_encrypted_office(path)
        finally:
            os.unlink(path)
        self.assertFalse(report.is_encrypted_container)
        self.assertEqual(self.find_check(report, "容器格式").status, STATUS_FAIL)
        self.assert_gates_not_green(report)

    def test_missing_encryption_streams(self):
        report = self.audit_streams({"SomeOtherStream": b"\x00" * 32})
        self.assertFalse(report.is_encrypted_container)
        self.assertEqual(self.find_check(report, "加密封装结构").status,
                         STATUS_FAIL)


class TestReportRendering(EncAuditTestBase):
    def test_report_text_marks_unexecuted_verifications(self):
        report = self.audit_streams({
            "EncryptionInfo": make_standard_info(),
            "EncryptedPackage": make_encrypted_package(5000, 5008),
        })
        text = report.to_text()
        self.assertIn("结构自洽 (本工具检查范围): PASS", text)
        self.assertIn("口令验证: NOT_PERFORMED", text)
        self.assertIn("内容完整性 (HMAC): NOT_PERFORMED", text)
        # No verification that was not executed may appear as passed.
        self.assertNotIn("口令验证: PASS", text)
        self.assertNotIn("内容完整性 (HMAC): PASS", text)
        self.assertIn(report.ciphertext_sha256, text)


if __name__ == "__main__":
    unittest.main()
