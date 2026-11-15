"""
encaudit - read-only structural audit of encrypted Office (OOXML) containers.

This module inspects ECMA-376 encrypted documents stored in an OLE2/CFB
container (the "EncryptedPackage" + "EncryptionInfo" layout described in
[MS-OFFCRYPTO]) and reports whether the encryption envelope is structurally
self-consistent.  It is strictly read-only and never attempts password
cracking, key derivation or decryption.

Three verification levels are reported separately and never conflated:

1. structural consistency  - format/algorithm/length declarations agree with
   each other and with the actual stream sizes (this is what this tool checks);
2. password verification   - proving a password matches the verifier (NOT
   performed by this tool);
3. content integrity       - recomputing the agile HMAC over the ciphertext
   (requires the password-derived key; NOT performed by this tool).

A verification that was not executed is reported as NOT_PERFORMED and is
never shown as passed.

Usage as a script:
    python -m olefile.encaudit file1.docx [file2.xlsx ...]
"""

import base64
import binascii
import hashlib
import re
import struct
import xml.etree.ElementTree as ET

from .olefile import OleFileIO, isOleFile

# --- check statuses ---------------------------------------------------------
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_WARNING = "WARNING"
STATUS_NOT_PERFORMED = "NOT_PERFORMED"
STATUS_UNSUPPORTED = "UNSUPPORTED"

ENCRYPTION_INFO = "EncryptionInfo"
ENCRYPTED_PACKAGE = "EncryptedPackage"

# EncryptionInfo is a small descriptor; anything larger is anomalous.  The
# cap also prevents loading absurd declared streams into memory at once.
MAX_ENCRYPTION_INFO_SIZE = 1 << 20
# Chunk size for streaming the ciphertext digest (never copy it wholesale).
DIGEST_CHUNK_SIZE = 1 << 16

# [MS-OFFCRYPTO] 2.3.2 EncryptionHeader algorithm identifiers.
ALG_ID_AES = {0x0000660E: 128, 0x0000660F: 192, 0x00006610: 256}
ALG_ID_HASH_SHA1 = 0x00008004
PROVIDER_TYPE_AES = 0x00000018

# EncryptionHeaderFlags bits ([MS-OFFCRYPTO] 2.3.1).
FLAG_FCRYPTOAPI = 0x00000004
FLAG_FDOCPROPS = 0x00000008
FLAG_FEXTERNAL = 0x00000010
FLAG_FAES = 0x00000020

# Agile encryption ([MS-OFFCRYPTO] 2.3.4.10).
AGILE_RESERVED_VALUE = 0x00000040
NS_ENCRYPTION = "http://schemas.microsoft.com/office/2006/encryption"
NS_KEY_ENCRYPTOR_PASSWORD = (
    "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
)
NS_KEY_ENCRYPTOR_CERTIFICATE = (
    "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate"
)
KNOWN_CIPHER_ALGORITHMS = {"AES", "RC2", "DES", "DESX", "3DES", "3DES_112"}
KNOWN_CIPHER_CHAINING = {"ChainingModeCBC", "ChainingModeCFB"}
AES_KEY_BITS = {128, 192, 256}
# Digest output sizes for the hash algorithms named in [MS-OFFCRYPTO] 2.3.4.10.
# Office writes "SHA1" in practice; the spec table lists "SHA-1".  Both map.
HASH_OUTPUT_SIZES = {
    "SHA-1": 20, "SHA1": 20,
    "SHA256": 32, "SHA-256": 32,
    "SHA384": 48, "SHA-384": 48,
    "SHA512": 64, "SHA-512": 64,
    "MD5": 16, "MD4": 16, "MD2": 16,
    "RIPEMD-128": 16, "RIPEMD-160": 20,
    "WHIRLPOOL": 64,
}
MAX_SPIN_COUNT = 10000000
AGILE_SEGMENT_SIZE = 4096

# DTD / entity declarations are forbidden outright: the descriptor must be a
# self-contained XML document with no external or internal references.
_DTD_PATTERN = re.compile(br"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class Check:
    """One structural check result."""

    __slots__ = ("name", "status", "detail")

    def __init__(self, name, status, detail=""):
        self.name = name
        self.status = status
        self.detail = detail

    def __repr__(self):
        return "Check(%r, %r, %r)" % (self.name, self.status, self.detail)


class EncryptionAuditReport:
    """Result of a read-only audit of one encrypted Office container."""

    def __init__(self, source):
        self.source = source
        self.is_encrypted_container = False
        self.encryption_format = None  # "standard" | "agile" | None
        self.checks = []
        self.declared_stream_size = None
        self.actual_encrypted_size = None
        self.ciphertext_sha256 = None
        # These two gates are never executed by this tool; they stay
        # NOT_PERFORMED so the report cannot be misread as "verified".
        self.password_verification = STATUS_NOT_PERFORMED
        self.content_integrity = STATUS_NOT_PERFORMED

    def add(self, name, status, detail=""):
        check = Check(name, status, detail)
        self.checks.append(check)
        return check

    @property
    def structural_status(self):
        statuses = {c.status for c in self.checks}
        if STATUS_UNSUPPORTED in statuses:
            return STATUS_UNSUPPORTED
        if STATUS_FAIL in statuses:
            return STATUS_FAIL
        if not statuses:
            return STATUS_FAIL
        return STATUS_PASS

    def to_text(self):
        lines = []
        lines.append("加密 Office 封装只读审计报告")
        lines.append("文件: %s" % self.source)
        if not self.is_encrypted_container:
            lines.append("结论: 不是可识别的加密 Office 封装 (缺少 EncryptionInfo/"
                         "EncryptedPackage 或不是 OLE2 复合文档)")
        fmt = {
            "standard": "Standard (二进制 EncryptionInfo)",
            "agile": "Agile (XML EncryptionInfo)",
        }.get(self.encryption_format, "未知/不支持")
        lines.append("加密格式: %s" % fmt)
        lines.append("")
        lines.append("结构检查:")
        for check in self.checks:
            line = "  [%s] %s" % (check.status, check.name)
            if check.detail:
                line += " - %s" % check.detail
            lines.append(line)
        lines.append("")
        lines.append("验证结论 (三级严格区分, 未执行的验证不标绿):")
        lines.append("  结构自洽 (本工具检查范围): %s" % self.structural_status)
        lines.append("  口令验证: %s (本工具不尝试口令, 不破解不验证)"
                     % self.password_verification)
        lines.append("  内容完整性 (HMAC): %s (需要口令派生密钥, 未执行)"
                     % self.content_integrity)
        if self.declared_stream_size is not None:
            lines.append("")
            lines.append("EncryptedPackage 长度核对:")
            lines.append("  声明的明文长度 (StreamSize): %d 字节"
                         % self.declared_stream_size)
            lines.append("  实际密文长度: %s 字节"
                         % (self.actual_encrypted_size
                            if self.actual_encrypted_size is not None else "未知"))
        if self.ciphertext_sha256 is not None:
            lines.append("密文 SHA-256 (流式计算, 未全量复制):")
            lines.append("  %s" % self.ciphertext_sha256)
        return "\n".join(lines)


# --- small parsing helpers --------------------------------------------------

def _b64decode(value):
    """Strict base64 decode; returns bytes or None on malformed input."""
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, binascii.Error, UnicodeEncodeError):
        return None


def _parse_uint(text):
    try:
        return int(text, 10)
    except (TypeError, ValueError):
        return None


# --- Standard encryption (binary EncryptionInfo, [MS-OFFCRYPTO] 2.3.4.5) ----

def _parse_standard(data, report):
    """Parse a binary (standard) EncryptionInfo stream. Returns the cipher
    block size in bytes on success, or None when parsing cannot continue."""
    if len(data) < 12:
        report.add("EncryptionInfo 最小长度", STATUS_FAIL,
                   "流仅 %d 字节, 不足 12 字节头部" % len(data))
        return None
    vmajor, vminor = struct.unpack_from("<HH", data, 0)
    if vmajor in (2, 3, 4) and vminor == 2:
        report.add("EncryptionInfo 版本", STATUS_PASS,
                   "vMajor=%d vMinor=%d (Standard)" % (vmajor, vminor))
    else:
        report.add("EncryptionInfo 版本", STATUS_FAIL,
                   "vMajor=%d vMinor=%d, Standard 要求 vMajor in "
                   "{2,3,4} 且 vMinor=2" % (vmajor, vminor))
    flags_copy, header_size = struct.unpack_from("<II", data, 4)
    if header_size < 32 or len(data) < 12 + header_size:
        report.add("EncryptionHeader 长度", STATUS_FAIL,
                   "声明 headerSize=%d, 流剩余 %d 字节"
                   % (header_size, max(0, len(data) - 12)))
        return None
    header = data[12:12 + header_size]
    (flags, size_extra, alg_id, alg_id_hash, key_size,
     provider_type, _reserved1, reserved2) = struct.unpack_from("<8I", header, 0)
    csp_name_raw = header[32:]

    if flags_copy == flags:
        report.add("Flags 副本一致", STATUS_PASS,
                   "前置副本与 EncryptionHeader.Flags 均为 0x%08X" % flags)
    else:
        report.add("Flags 副本一致", STATUS_FAIL,
                   "前置副本 0x%08X != EncryptionHeader.Flags 0x%08X"
                   % (flags_copy, flags))

    if flags & FLAG_FEXTERNAL:
        report.add("加密方案归属", STATUS_UNSUPPORTED,
                   "fExternal 已置位: 外部/可扩展加密模块, 不在本工具支持范围")
        return None
    if (flags & FLAG_FCRYPTOAPI) and (flags & FLAG_FAES):
        report.add("Flags 算法位", STATUS_PASS,
                   "fCryptoAPI 与 fAES 均置位 (ECMA-376 Standard)")
    else:
        report.add("Flags 算法位", STATUS_FAIL,
                   "Standard 要求 fCryptoAPI 与 fAES 同时置位, "
                   "Flags=0x%08X" % flags)
    if flags & FLAG_FDOCPROPS:
        report.add("fDocProps 位", STATUS_FAIL,
                   "Standard 要求 fDocProps=0, Flags=0x%08X" % flags)

    if size_extra == 0:
        report.add("SizeExtra", STATUS_PASS, "0x00000000")
    else:
        report.add("SizeExtra", STATUS_FAIL,
                   "必须为 0, 实际 0x%08X" % size_extra)
    if reserved2 == 0:
        report.add("Reserved2", STATUS_PASS, "0x00000000")
    else:
        report.add("Reserved2", STATUS_FAIL,
                   "必须为 0, 实际 0x%08X" % reserved2)

    if alg_id in ALG_ID_AES:
        report.add("加密算法 AlgID", STATUS_PASS,
                   "0x%08X (AES-%d)" % (alg_id, ALG_ID_AES[alg_id]))
    else:
        report.add("加密算法 AlgID", STATUS_FAIL,
                   "0x%08X, Standard 仅允许 AES-128/192/256 "
                   "(0x660E/0x660F/0x6610)" % alg_id)
    if alg_id_hash == ALG_ID_HASH_SHA1:
        report.add("摘要算法 AlgIDHash", STATUS_PASS, "0x00008004 (SHA-1)")
    else:
        report.add("摘要算法 AlgIDHash", STATUS_FAIL,
                   "0x%08X, Standard 要求 0x00008004 (SHA-1)" % alg_id_hash)

    expected_bits = ALG_ID_AES.get(alg_id)
    if expected_bits is not None and key_size == expected_bits:
        report.add("钥长与算法一致", STATUS_PASS,
                   "KeySize=%d 与 AES-%d 匹配" % (key_size, expected_bits))
    elif expected_bits is not None:
        report.add("钥长与算法一致", STATUS_FAIL,
                   "AlgID 声明 AES-%d 但 KeySize=%d, 算法声明互相矛盾"
                   % (expected_bits, key_size))
    else:
        report.add("钥长与算法一致", STATUS_FAIL,
                   "AlgID 未知, 无法核对 KeySize=%d" % key_size)

    if provider_type == PROVIDER_TYPE_AES:
        report.add("ProviderType", STATUS_PASS, "0x00000018 (AES)")
    else:
        report.add("ProviderType", STATUS_WARNING,
                   "0x%08X, 规范建议 0x00000018 (AES)" % provider_type)

    if len(csp_name_raw) >= 2 and csp_name_raw.endswith(b"\x00\x00") \
            and len(csp_name_raw) % 2 == 0:
        try:
            csp_name = csp_name_raw[:-2].decode("utf-16-le")
            report.add("CSPName", STATUS_PASS, repr(csp_name))
        except UnicodeDecodeError:
            report.add("CSPName", STATUS_FAIL, "不是合法的 UTF-16LE 字符串")
    else:
        report.add("CSPName", STATUS_FAIL,
                   "不是以空字符结尾的 UTF-16LE 字符串")

    # EncryptionVerifier directly follows the header.
    verifier = data[12 + header_size:]
    if len(verifier) < 40:
        report.add("EncryptionVerifier 长度", STATUS_FAIL,
                   "剩余 %d 字节, 不足 40 字节固定部分" % len(verifier))
        return None
    salt_size = struct.unpack_from("<I", verifier, 0)[0]
    if salt_size == 16:
        report.add("Verifier SaltSize", STATUS_PASS, "16 字节")
    else:
        report.add("Verifier SaltSize", STATUS_FAIL,
                   "必须为 16, 实际 %d" % salt_size)
    verifier_hash_size = struct.unpack_from("<I", verifier, 36)[0]
    if verifier_hash_size == 20:
        report.add("VerifierHashSize", STATUS_PASS, "20 (SHA-1 输出长度)")
    else:
        report.add("VerifierHashSize", STATUS_FAIL,
                   "SHA-1 要求 20, 实际 %d" % verifier_hash_size)
    encrypted_hash_len = len(verifier) - 40
    if encrypted_hash_len == 32:
        report.add("EncryptedVerifierHash 长度", STATUS_PASS,
                   "32 字节 (AES 加密 SHA-1 摘要的两个分组)")
    elif encrypted_hash_len > 32:
        report.add("EncryptedVerifierHash 长度", STATUS_WARNING,
                   "%d 字节, AES 期望 32, 存在 %d 字节尾部数据"
                   % (encrypted_hash_len, encrypted_hash_len - 32))
    else:
        report.add("EncryptedVerifierHash 长度", STATUS_FAIL,
                   "%d 字节, AES 要求 32" % encrypted_hash_len)
    return 16  # AES block size in bytes


# --- Agile encryption (XML EncryptionInfo, [MS-OFFCRYPTO] 2.3.4.10) ---------

def _children_by_tag(element, tag):
    return [child for child in element if child.tag == tag]


def _check_required_attrs(report, element_name, attrs, required):
    missing = [name for name in required if name not in attrs]
    if missing:
        report.add("%s 必需属性" % element_name, STATUS_FAIL,
                   "缺少: %s" % ", ".join(missing))
        return False
    return True


def _check_crypto_params(report, element_name, attrs):
    """Check the shared agile crypto parameter attributes. Returns a dict of
    parsed values, or None if a hard failure prevents further checks."""
    if not _check_required_attrs(
            report, element_name, attrs,
            ("saltSize", "blockSize", "keyBits", "hashSize",
             "cipherAlgorithm", "cipherChaining", "hashAlgorithm",
             "saltValue")):
        return None
    values = {}
    ok = True
    for attr in ("saltSize", "blockSize", "keyBits", "hashSize"):
        values[attr] = _parse_uint(attrs[attr])
        if values[attr] is None or values[attr] < 0:
            report.add("%s.%s" % (element_name, attr), STATUS_FAIL,
                       "非无符号整数: %r" % attrs[attr])
            ok = False
    if not ok:
        return None

    salt_size = values["saltSize"]
    if 1 <= salt_size <= 65536:
        report.add("%s.saltSize" % element_name, STATUS_PASS, str(salt_size))
    else:
        report.add("%s.saltSize" % element_name, STATUS_FAIL,
                   "%d 超出 [1, 65536]" % salt_size)

    block_size = values["blockSize"]
    if 2 <= block_size <= 4096 and block_size % 2 == 0:
        report.add("%s.blockSize" % element_name, STATUS_PASS, str(block_size))
    else:
        report.add("%s.blockSize" % element_name, STATUS_FAIL,
                   "%d 不在 [2, 4096] 或不是 2 的倍数" % block_size)

    key_bits = values["keyBits"]
    if key_bits >= 8 and key_bits % 8 == 0:
        report.add("%s.keyBits" % element_name, STATUS_PASS, str(key_bits))
    else:
        report.add("%s.keyBits" % element_name, STATUS_FAIL,
                   "%d 小于 8 或不是 8 的倍数" % key_bits)

    cipher = attrs["cipherAlgorithm"]
    values["cipherAlgorithm"] = cipher
    if cipher == "RC4":
        report.add("%s.cipherAlgorithm" % element_name, STATUS_FAIL,
                   "RC4 在 Agile 加密中被明确禁止")
    elif cipher in KNOWN_CIPHER_ALGORITHMS:
        report.add("%s.cipherAlgorithm" % element_name, STATUS_PASS, cipher)
    else:
        report.add("%s.cipherAlgorithm" % element_name, STATUS_WARNING,
                   "%r 不是规范定义的算法, 无法核对钥长" % cipher)
    if cipher == "AES" and key_bits not in AES_KEY_BITS:
        report.add("%s AES 钥长" % element_name, STATUS_FAIL,
                   "AES 仅允许 128/192/256, 声明 keyBits=%d" % key_bits)

    chaining = attrs["cipherChaining"]
    if chaining in KNOWN_CIPHER_CHAINING:
        report.add("%s.cipherChaining" % element_name, STATUS_PASS, chaining)
    else:
        report.add("%s.cipherChaining" % element_name, STATUS_FAIL,
                   "%r 不是 ChainingModeCBC/ChainingModeCFB" % chaining)

    hash_alg = attrs["hashAlgorithm"]
    values["hashAlgorithm"] = hash_alg
    hash_size = values["hashSize"]
    digest_size = HASH_OUTPUT_SIZES.get(hash_alg)
    if digest_size is None:
        report.add("%s.hashAlgorithm" % element_name, STATUS_WARNING,
                   "%r 不是规范定义的摘要算法, 无法核对 hashSize" % hash_alg)
    elif hash_size == digest_size:
        report.add("%s.hashSize" % element_name, STATUS_PASS,
                   "%d 与 %s 输出长度一致" % (hash_size, hash_alg))
    else:
        report.add("%s.hashSize" % element_name, STATUS_FAIL,
                   "声明 %d 字节, 但 %s 输出为 %d 字节, 摘要声明矛盾"
                   % (hash_size, hash_alg, digest_size))

    salt = _b64decode(attrs["saltValue"])
    if salt is None:
        report.add("%s.saltValue" % element_name, STATUS_FAIL,
                   "不是合法的 base64")
    elif len(salt) == salt_size:
        report.add("%s.saltValue" % element_name, STATUS_PASS,
                   "解码后 %d 字节, 与 saltSize 一致" % len(salt))
    else:
        report.add("%s.saltValue" % element_name, STATUS_FAIL,
                   "解码后 %d 字节, 与 saltSize=%d 不符" % (len(salt), salt_size))
    return values


def _parse_agile(data, report):
    """Parse an XML (agile) EncryptionInfo stream. Returns the declared
    block size in bytes on success, or None when parsing cannot continue."""
    if len(data) < 8:
        report.add("EncryptionInfo 最小长度", STATUS_FAIL,
                   "流仅 %d 字节, 不足 8 字节头部" % len(data))
        return None
    vmajor, vminor, reserved = struct.unpack_from("<HHI", data, 0)
    if (vmajor, vminor) == (4, 4):
        report.add("EncryptionInfo 版本", STATUS_PASS, "4.4 (Agile)")
    else:
        report.add("EncryptionInfo 版本", STATUS_FAIL,
                   "Agile 要求 4.4, 实际 %d.%d" % (vmajor, vminor))
    if reserved == AGILE_RESERVED_VALUE:
        report.add("Agile 保留字段", STATUS_PASS, "0x00000040")
    else:
        report.add("Agile 保留字段", STATUS_FAIL,
                   "必须为 0x00000040, 实际 0x%08X" % reserved)

    xml_bytes = data[8:]
    if _DTD_PATTERN.search(xml_bytes):
        report.add("XML 外部引用", STATUS_FAIL,
                   "描述符包含 DOCTYPE/ENTITY 声明, 外部引用与实体扩展被禁止")
        return None
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        # Expat rejects duplicate attributes and malformed XML here; such
        # input is refused rather than repaired.
        report.add("XML 解析", STATUS_FAIL, "XML 不合法: %s" % exc)
        return None
    report.add("XML 解析", STATUS_PASS, "无 DTD/外部实体, 解析成功")

    expected_root = "{%s}encryption" % NS_ENCRYPTION
    if root.tag != expected_root:
        report.add("XML 根元素", STATUS_FAIL,
                   "期望 %r, 实际 %r" % (expected_root, root.tag))
        return None

    # Element multiplicity is enforced strictly: a repeated or conflicting
    # declaration is a structural error, never "last one wins".
    key_data_elems = _children_by_tag(root, "{%s}keyData" % NS_ENCRYPTION)
    integrity_elems = _children_by_tag(root, "{%s}dataIntegrity" % NS_ENCRYPTION)
    encryptors_elems = _children_by_tag(root, "{%s}keyEncryptors" % NS_ENCRYPTION)
    if len(key_data_elems) != 1:
        report.add("keyData 唯一性", STATUS_FAIL,
                   "必须恰好 1 个 keyData, 实际 %d 个; 重复声明不予采信"
                   % len(key_data_elems))
        return None
    if len(encryptors_elems) != 1:
        report.add("keyEncryptors 唯一性", STATUS_FAIL,
                   "必须恰好 1 个 keyEncryptors, 实际 %d 个; 重复声明不予采信"
                   % len(encryptors_elems))
        return None
    if len(integrity_elems) > 1:
        report.add("dataIntegrity 唯一性", STATUS_FAIL,
                   "至多 1 个 dataIntegrity, 实际 %d 个; 重复声明不予采信"
                   % len(integrity_elems))
        return None
    report.add("顶层元素唯一性", STATUS_PASS,
               "keyData/keyEncryptors 各 1 个, dataIntegrity %d 个"
               % len(integrity_elems))

    key_data_values = _check_crypto_params(report, "keyData",
                                           key_data_elems[0].attrib)
    block_size = (key_data_values or {}).get("blockSize")

    if integrity_elems:
        attrs = integrity_elems[0].attrib
        if _check_required_attrs(report, "dataIntegrity", attrs,
                                 ("encryptedHmacKey", "encryptedHmacValue")):
            for attr in ("encryptedHmacKey", "encryptedHmacValue"):
                if _b64decode(attrs[attr]) is None:
                    report.add("dataIntegrity.%s" % attr, STATUS_FAIL,
                               "不是合法的 base64")
            report.add("dataIntegrity 存在", STATUS_PASS,
                       "HMAC 已声明; 校验需口令派生密钥, 本工具不执行")
    else:
        report.add("dataIntegrity 存在", STATUS_WARNING,
                   "缺少 dataIntegrity, 内容完整性无法校验")

    key_encryptors = _children_by_tag(encryptors_elems[0],
                                      "{%s}keyEncryptor" % NS_ENCRYPTION)
    if not key_encryptors:
        report.add("keyEncryptor 存在", STATUS_FAIL,
                   "keyEncryptors 内至少要有 1 个 keyEncryptor")
        return block_size
    password_encryptors = []
    unsupported_uris = []
    for encryptor in key_encryptors:
        uri = encryptor.attrib.get("uri", "")
        if uri == NS_KEY_ENCRYPTOR_PASSWORD:
            password_encryptors.append(encryptor)
        elif uri == NS_KEY_ENCRYPTOR_CERTIFICATE:
            report.add("证书 keyEncryptor", STATUS_PASS,
                       "存在证书加密器; 口令路径与其无关")
        else:
            unsupported_uris.append(uri or "(无 uri)")
    if unsupported_uris:
        report.add("keyEncryptor 方案", STATUS_UNSUPPORTED,
                   "未知/外部 keyEncryptor URI: %s"
                   % ", ".join(unsupported_uris))
    if len(password_encryptors) == 1:
        report.add("口令 keyEncryptor 唯一性", STATUS_PASS, "恰好 1 个")
    else:
        report.add("口令 keyEncryptor 唯一性", STATUS_FAIL,
                   "必须恰好 1 个口令加密器, 实际 %d 个; 重复声明不予采信"
                   % len(password_encryptors))
        return block_size

    encrypted_key_elems = _children_by_tag(
        password_encryptors[0], "{%s}encryptedKey" % NS_KEY_ENCRYPTOR_PASSWORD)
    if len(encrypted_key_elems) != 1:
        report.add("encryptedKey 唯一性", STATUS_FAIL,
                   "口令加密器内必须恰好 1 个 encryptedKey, 实际 %d 个"
                   % len(encrypted_key_elems))
        return block_size
    attrs = encrypted_key_elems[0].attrib
    enc_values = _check_crypto_params(report, "passwordKeyEncryptor", attrs)
    if enc_values is None:
        return block_size

    if key_data_values is not None:
        if enc_values["cipherAlgorithm"] == key_data_values["cipherAlgorithm"]:
            report.add("算法声明一致 (cipher)", STATUS_PASS,
                       "keyData 与 passwordKeyEncryptor 均为 %s"
                       % enc_values["cipherAlgorithm"])
        else:
            report.add("算法声明一致 (cipher)", STATUS_FAIL,
                       "keyData 声明 %r 而 passwordKeyEncryptor 声明 %r, "
                       "算法声明互相矛盾" % (key_data_values["cipherAlgorithm"],
                                            enc_values["cipherAlgorithm"]))
        if enc_values["hashAlgorithm"] == key_data_values["hashAlgorithm"]:
            report.add("算法声明一致 (hash)", STATUS_PASS,
                       "keyData 与 passwordKeyEncryptor 均为 %s"
                       % enc_values["hashAlgorithm"])
        else:
            report.add("算法声明一致 (hash)", STATUS_FAIL,
                       "keyData 声明 %r 而 passwordKeyEncryptor 声明 %r, "
                       "算法声明互相矛盾" % (key_data_values["hashAlgorithm"],
                                            enc_values["hashAlgorithm"]))

    spin_count = _parse_uint(attrs.get("spinCount"))
    if spin_count is None:
        report.add("spinCount", STATUS_FAIL,
                   "非无符号整数: %r" % attrs.get("spinCount"))
    elif spin_count <= MAX_SPIN_COUNT:
        report.add("spinCount", STATUS_PASS, str(spin_count))
    else:
        report.add("spinCount", STATUS_FAIL,
                   "%d 超过上限 10000000" % spin_count)

    enc_block = enc_values["blockSize"]
    enc_hash_size = enc_values["hashSize"]
    for attr, minimum in (
            ("encryptedVerifierHashInput", 16),
            ("encryptedVerifierHashValue", enc_hash_size),
            ("encryptedKeyValue", max(1, enc_values["keyBits"] // 8))):
        decoded = _b64decode(attrs.get(attr, ""))
        if decoded is None:
            report.add("passwordKeyEncryptor.%s" % attr, STATUS_FAIL,
                       "不是合法的 base64")
        elif enc_block and len(decoded) % enc_block == 0 \
                and len(decoded) >= minimum:
            report.add("passwordKeyEncryptor.%s" % attr, STATUS_PASS,
                       "%d 字节, 为 blockSize=%d 的整数倍"
                       % (len(decoded), enc_block))
        else:
            report.add("passwordKeyEncryptor.%s" % attr, STATUS_FAIL,
                       "%d 字节, 不是 blockSize=%d 的整数倍或小于最小长度 %d"
                       % (len(decoded), enc_block, minimum))
    return block_size


# --- EncryptionInfo dispatch ------------------------------------------------

def _parse_encryption_info(data, report):
    """Dispatch on the EncryptionInfo version. Returns the cipher block size
    in bytes when known, else None."""
    if len(data) < 4:
        report.add("EncryptionInfo 最小长度", STATUS_FAIL,
                   "流仅 %d 字节" % len(data))
        return None
    vmajor, vminor = struct.unpack_from("<HH", data, 0)
    if vminor == 2 and vmajor in (2, 3, 4):
        report.encryption_format = "standard"
        return _parse_standard(data, report)
    if (vmajor, vminor) == (4, 4):
        report.encryption_format = "agile"
        return _parse_agile(data, report)
    if vminor == 3 and vmajor in (3, 4):
        report.add("加密方案", STATUS_UNSUPPORTED,
                   "版本 %d.%d 为可扩展 (外部) 加密模块, 不支持"
                   % (vmajor, vminor))
        return None
    report.add("加密方案", STATUS_UNSUPPORTED,
               "未知 EncryptionInfo 版本 %d.%d, 不支持" % (vmajor, vminor))
    return None


# --- EncryptedPackage length + streaming digest -----------------------------

def _round_up(value, multiple):
    return value if value % multiple == 0 else value + multiple - value % multiple


def _expected_encrypted_size(declared, block_size, encryption_format):
    if encryption_format == "agile" and block_size:
        full_segments, remainder = divmod(declared, AGILE_SEGMENT_SIZE)
        return full_segments * AGILE_SEGMENT_SIZE + _round_up(remainder, block_size)
    if block_size:
        return _round_up(declared, block_size)
    return declared


def _audit_encrypted_package(ole, report, block_size):
    """Check the declared StreamSize against the real stream length and
    compute the ciphertext digest by streaming (never buffering it whole)."""
    stream_size = ole.get_size(ENCRYPTED_PACKAGE)
    if stream_size < 8:
        report.add("EncryptedPackage 最小长度", STATUS_FAIL,
                   "流仅 %d 字节, 不足 8 字节 StreamSize 头" % stream_size)
        return
    stream = ole.openstream(ENCRYPTED_PACKAGE)
    try:
        header = stream.read(8)
        declared = struct.unpack("<Q", header)[0]
        actual = stream_size - 8
        report.declared_stream_size = declared
        report.actual_encrypted_size = actual
        if actual < declared:
            report.add("EncryptedPackage 长度一致", STATUS_FAIL,
                       "声明明文 %d 字节, 但密文仅 %d 字节: 包被截断"
                       % (declared, actual))
        else:
            expected = _expected_encrypted_size(declared, block_size,
                                                report.encryption_format)
            if actual == expected:
                report.add("EncryptedPackage 长度一致", STATUS_PASS,
                           "密文 %d 字节, 与声明 %d 及分组填充规则一致"
                           % (actual, declared))
            elif actual < expected:
                report.add("EncryptedPackage 长度一致", STATUS_WARNING,
                           "密文 %d 字节, 小于按分组填充期望的 %d 字节"
                           % (actual, expected))
            else:
                report.add("EncryptedPackage 长度一致", STATUS_WARNING,
                           "密文 %d 字节, 超出按分组填充期望的 %d 字节"
                           % (actual, expected))
        digest = hashlib.sha256()
        stream.seek(0)
        while True:
            chunk = stream.read(DIGEST_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        report.ciphertext_sha256 = digest.hexdigest()
        report.add("密文摘要", STATUS_PASS,
                   "SHA-256 已流式计算 (64KiB 分块, 未全量复制)")
    finally:
        stream.close()


# --- top-level audit --------------------------------------------------------

def audit_encrypted_office(path):
    """Run the read-only structural audit on one file. Returns an
    EncryptionAuditReport. Never modifies the file, never touches passwords."""
    report = EncryptionAuditReport(str(path))
    if not isOleFile(str(path)):
        report.add("容器格式", STATUS_FAIL, "不是 OLE2 复合文档 (CFB)")
        return report
    ole = OleFileIO(str(path))
    try:
        missing = [name for name in (ENCRYPTION_INFO, ENCRYPTED_PACKAGE)
                   if not ole.exists(name)]
        if missing:
            report.add("加密封装结构", STATUS_FAIL,
                       "缺少流: %s" % ", ".join(missing))
            return report
        report.is_encrypted_container = True
        info_size = ole.get_size(ENCRYPTION_INFO)
        if info_size > MAX_ENCRYPTION_INFO_SIZE:
            report.add("EncryptionInfo 大小", STATUS_FAIL,
                       "%d 字节超出合理上限 %d" % (info_size,
                                                 MAX_ENCRYPTION_INFO_SIZE))
            return report
        info_stream = ole.openstream(ENCRYPTION_INFO)
        try:
            info_data = info_stream.read()
        finally:
            info_stream.close()
        block_size = _parse_encryption_info(info_data, report)
        _audit_encrypted_package(ole, report, block_size)
        return report
    finally:
        ole.close()


def main(argv=None):
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("用法: python -m olefile.encaudit <加密Office文件> [...]")
        return 2
    worst = 0
    for path in args:
        report = audit_encrypted_office(path)
        print(report.to_text())
        print()
        status = report.structural_status
        if status == STATUS_FAIL:
            worst = max(worst, 1)
        elif status == STATUS_UNSUPPORTED or not report.is_encrypted_container:
            worst = max(worst, 2)
    return worst


if __name__ == "__main__":
    import sys
    sys.exit(main())
