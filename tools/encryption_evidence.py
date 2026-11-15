#!/usr/bin/env python3
"""Evidence-graded encryption status for msoffcrypto, as a backend contract.

`msoffcrypto` answers four different questions with four different mechanisms:

* **declaration** - is there a container field that says "encrypted", and which
  method does it name?  (`is_encrypted()` / `EncryptionInfo` / FIB / FilePass /
  UserEditAtom; all producer-controlled and forgeable.)
* **key check** - does a password reproduce a stored verifier?  Only some paths
  run it, only on request for OOXML, and XOR uses a 16-bit value.
* **content decryption** - does `decrypt()` return bytes, and do those bytes have
  the expected container structure?  This is not the same as the right bytes.
* **integrity** - only Agile has a payload HMAC, and only when the caller asks.

This script keeps those observations separate and turns them into a status object
that a backend can persist.  It never modifies `tests/inputs`; truncated,
tampered and forged samples are built in a temporary directory.

Usage::

    .venv/bin/python tools/encryption_evidence.py --matrix
    .venv/bin/python tools/encryption_evidence.py --samples
    .venv/bin/python tools/encryption_evidence.py --samples --output docs/evidence/samples.json
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import Any
from xml.dom.minidom import parseString

import olefile

from msoffcrypto import OfficeFile
from msoffcrypto.format import ppt97
from msoffcrypto.format.common import _parse_encryptionheader
from msoffcrypto.format.doc97 import _parseFib
from msoffcrypto.format.xls97 import _BIFFStream, recordNameNum
from msoffcrypto.method.container.ecma376_encrypted import ECMA376Encrypted
from msoffcrypto.method.ecma376_agile import ECMA376Agile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUTS = os.path.join(REPO, "tests", "inputs")
OUTPUTS = os.path.join(REPO, "tests", "outputs")
PASSWORD = "Password1234_"
XOR_PASSWORD = "123456789012345"
#: A different password with the same 16-bit XOR verifier as the fixture.  Found by
#: random search; it is evidence that a verifier match is not password uniqueness.
XOR_COLLIDING_PASSWORD = "A5XSZmz6VjoEywz"

SCHEMA_VERSION = "1.0"

STATES = {
    "NO_ENCRYPTION_DECLARED": "no supported encryption declaration was found",
    "UNSUPPORTED_CONTAINER": "container/format is not recognized by msoffcrypto",
    "ENCRYPTION_DECLARED_UNPARSED": "a declaration exists but its metadata cannot be parsed",
    "ENCRYPTION_DECLARATION_INCONSISTENT": "a marker exists but the structures it points to are absent",
    "UNSUPPORTED_ENCRYPTION_METHOD": "the declaration names a method/version this library cannot process",
    "KEY_REJECTED": "a supported verifier was checked and the password did not match it",
    "DECRYPTION_INCONCLUSIVE": "no verifier was checked and decryption failed",
    "PAYLOAD_TRUNCATED_OR_CORRUPTED": "the key/verifier matched but decryption could not produce a package",
    "DECRYPTION_ERROR": "decryption raised an error not attributable to the key",
    "PAYLOAD_INTEGRITY_FAILED": "the key matched but the Agile HMAC did not",
    "OUTPUT_STRUCTURE_INVALID": "bytes were returned but they fail the container structure check",
    "CONTENT_DECRYPTED_KEY_UNVERIFIED": "content decrypted and has structure, but no verifier was checked",
    "CONTENT_DECRYPTED_WEAK_KEY_MATCH": "content decrypted and a weak verifier matched (XOR, 16-bit)",
    "CONTENT_DECRYPTED_KEY_VERIFIED": "content decrypted and a supported verifier matched",
    "INTEGRITY_VERIFIED": "content decrypted, structure is valid, and the Agile payload HMAC passed",
}

REJECT_REASONS = {
    "UNSUPPORTED_CONTAINER": "not an OLE/ZIP container this library can dispatch",
    "ENCRYPTIONINFO_UNPARSEABLE": "EncryptionInfo/FIB/FilePass/UserEditAtom metadata is damaged",
    "DECLARATION_INCONSISTENT": "an encryption marker exists but its crypt session or header is missing",
    "UNSUPPORTED_ENCRYPTION_VERSION": "declared version is Extensible or unknown",
    "UNSUPPORTED_ENCRYPTION_TYPE": "declared method is XOR in DOC, an unknown FilePass type, or otherwise unimplemented",
    "KEY_VERIFIER_MISMATCH": "a supported verifier rejected the password",
    "KEY_UNVERIFIED_AND_DECRYPTION_FAILED": "no verifier was checked, so failure cannot be attributed to the password",
    "PAYLOAD_TRUNCATED_OR_CORRUPTED": "key matched but payload is absent, truncated, or corrupt",
    "PAYLOAD_INTEGRITY_FAILED": "Agile HMAC mismatch",
    "OUTPUT_STRUCTURE_INVALID": "decrypted bytes are not a valid package of the declared family",
    "DECRYPTION_ERROR": "decrypt() raised for another reason",
}

EVIDENCE_LEVELS = {
    "none": "nothing was established",
    "container_only": "container/format dispatch only",
    "declaration": "a producer-controlled declaration was read",
    "key_checked_negative": "a supported verifier rejected the key",
    "key_checked": "a supported verifier accepted the key, but content is not usable",
    "decrypted": "decrypt() returned bytes with a structural check",
    "decrypted_weak_key_check": "as decrypted, but the verifier is only 16 bits (XOR)",
    "decrypted_key_checked": "as decrypted, and a supported verifier accepted the key",
    "integrity_verified": "Agile HMAC over EncryptedPackage passed and structure is valid",
}

POLICY_CLASSES = {
    "obfuscation": "XOR obfuscation, not encryption; 16-bit verifier",
    "rc4_legacy": "RC4 (40/128-bit) with a legacy verifier and no payload integrity",
    "aes_standard_no_integrity": "ECMA-376 Standard AES, SHA-1 KDF, no payload integrity",
    "aes_agile_hmac": "ECMA-376 Agile AES with optional HMAC integrity",
    "unsupported": "library has no key/content path for this declaration",
    "unknown": "declaration could not be classified",
}


# ---------------------------------------------------------------------------
# Sample construction (temporary copies only)
# ---------------------------------------------------------------------------


def _zero_stream(path: str, stream: str, start: int, length: int | None = None) -> None:
    ole = olefile.OleFileIO(path, write_mode=True)
    data = bytearray(ole.openstream(stream).read())
    end = len(data) if length is None else min(len(data), start + length)
    data[start:end] = b"\0" * (end - start)
    ole.write_stream(stream, bytes(data))
    ole.close()


def _flip_stream(path: str, stream: str, offset: int) -> None:
    ole = olefile.OleFileIO(path, write_mode=True)
    data = bytearray(ole.openstream(stream).read())
    data[offset] ^= 0x01
    ole.write_stream(stream, bytes(data))
    ole.close()


def _xls_filepass_end(path: str) -> int:
    ole = olefile.OleFileIO(path)
    biff = _BIFFStream(ole.openstream("Workbook"))
    _, bof_size = struct.unpack("<HH", biff.data.read(4))
    biff.data.read(bof_size)
    while True:
        offset = biff.data.tell()
        num, size = struct.unpack("<HH", biff.data.read(4))
        if num == recordNameNum["FilePass"]:
            ole.close()
            return offset + 4 + size
        biff.data.read(size)


def _doc_header_end(path: str) -> int:
    ole = olefile.OleFileIO(path)
    fib = _parseFib(ole.openstream("WordDocument"))
    table = ole.openstream("1Table" if fib.base.fWhichTblStm else "0Table")
    table.read(4)  # version
    _, header_size = struct.unpack("<II", table.read(8))
    ole.close()
    return 4 + 4 + 4 + header_size + 60  # version, flags, header size, header, verifier


def _ooxml_member_cipher_offset(source: str, member: str) -> int:
    """Return the EncryptedPackage offset of a member's compressed data."""
    with open(os.path.join(INPUTS, source), "rb") as handle:
        office = OfficeFile(handle)
        office.load_key(password=PASSWORD, verify_password=True)
        buffer = io.BytesIO()
        office.decrypt(buffer, verify_integrity=True)
    package = zipfile.ZipFile(io.BytesIO(buffer.getvalue()))
    info = package.getinfo(member)
    plain_offset = info.header_offset + 30 + len(info.filename) + len(info.extra)
    return 8 + plain_offset + 10  # 8-byte package size field + a byte inside the member data


#: Generated sample -> repository fixture it was derived from.
FIXTURE_OF = {
    "agile_header_only.docx": "example_password.docx",
    "standard_header_only.docx": "ecma376standard_password.docx",
    "agile_info_only.docx": "example_password.docx",
    "standard_info_only.docx": "ecma376standard_password.docx",
    "ooxml_garbage_info.docx": "example_password.docx",
    "ooxml_extensible.docx": "example_password.docx",
    "ooxml_unknown_version.docx": "example_password.docx",
    "agile_tampered_member.docx": "example_password.docx",
    "standard_tampered_member.docx": "ecma376standard_password.docx",
    "agile_minimal_zip_payload.docx": "example_password.docx",
    "agile_no_data_integrity.docx": "example_password.docx",
    "xor_header_only.xls": "xor_password_123456789012345.xls",
    "rc4_header_only.xls": "rc4cryptoapi_password.xls",
    "doc_header_only.doc": "rc4cryptoapi_password.doc",
    "doc_xor_declared.doc": "plain.doc",
    "doc_forged_marker.doc": "plain.doc",
    "ppt_header_only.ppt": "rc4cryptoapi_password.ppt",
    "ppt_forged_marker.ppt": "plain.ppt",
    "xls_unknown_filepass_type.xls": "plain.xls",
    "xls_forged_filepass_type1.xls": "plain.xls",
}


def make_samples(tmp: str) -> dict[str, str]:
    """Build header-only, tampered and forged samples.  Fixtures stay untouched."""
    samples: dict[str, str] = {}

    def copy(name: str, source: str) -> str:
        target = os.path.join(tmp, name)
        shutil.copyfile(os.path.join(INPUTS, source), target)
        return target

    # OOXML: keep the 8-byte size field, zero the ciphertext.
    for name, source in [
        ("agile_header_only.docx", "example_password.docx"),
        ("standard_header_only.docx", "ecma376standard_password.docx"),
    ]:
        target = copy(name, source)
        _zero_stream(target, "EncryptedPackage", 8)
        samples[name] = target

    # OOXML: keep EncryptionInfo only, drop EncryptedPackage entirely.
    for name, source in [
        ("agile_info_only.docx", "example_password.docx"),
        ("standard_info_only.docx", "ecma376standard_password.docx"),
    ]:
        ole = olefile.OleFileIO(os.path.join(INPUTS, source))
        encryption_info = ole.openstream("EncryptionInfo").read()
        ole.close()
        buffer = io.BytesIO()
        ECMA376Encrypted(b"", encryption_info).write_to(buffer)
        target = os.path.join(tmp, name)
        with open(target, "wb") as handle:
            handle.write(buffer.getvalue())
        samples[name] = target

    # OOXML: damaged declaration (valid version, unparseable XML) and unsupported versions.
    target = copy("ooxml_garbage_info.docx", "example_password.docx")
    _zero_stream(target, "EncryptionInfo", 8)  # keep version 4.4, destroy XML
    samples["ooxml_garbage_info.docx"] = target
    for name, version in [("ooxml_extensible.docx", (3, 3)), ("ooxml_unknown_version.docx", (9, 9))]:
        target = copy(name, "example_password.docx")
        ole = olefile.OleFileIO(target, write_mode=True)
        data = bytearray(ole.openstream("EncryptionInfo").read())
        struct.pack_into("<HH", data, 0, *version)
        ole.write_stream("EncryptionInfo", bytes(data))
        ole.close()
        samples[name] = target

    # OOXML Agile with the optional dataIntegrity element removed.  The spec makes the
    # HMAC optional; this library's parser requires the element and fails during dispatch.
    ole = olefile.OleFileIO(os.path.join(INPUTS, "example_password.docx"))
    encryption_info = ole.openstream("EncryptionInfo").read()
    ole.close()
    without_integrity = re.sub(rb"<dataIntegrity[^>]*/>", b"", encryption_info[8:])
    target = os.path.join(tmp, "agile_no_data_integrity.docx")
    with open(target, "wb") as handle:
        header = io.BytesIO()
        ECMA376Encrypted(b"", encryption_info[:8] + without_integrity).write_to(header)
        handle.write(header.getvalue())
    samples["agile_no_data_integrity.docx"] = target

    # OOXML tamper: flip one ciphertext byte inside word/document.xml.
    for name, source in [
        ("agile_tampered_member.docx", "example_password.docx"),
        ("standard_tampered_member.docx", "ecma376standard_password.docx"),
    ]:
        target = copy(name, source)
        _flip_stream(target, "EncryptedPackage", _ooxml_member_cipher_offset(source, "word/document.xml"))
        samples[name] = target

    # A payload that is only a 22-byte ZIP end-of-central-directory record.  It is
    # encrypted with the correct password, so Agile HMAC also passes; `is_zipfile`
    # alone would accept it, but it is not an OOXML package.
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0, 0, 0, 0, 0)
    plain = b"\0" * (4096 - len(eocd)) + eocd
    target = os.path.join(tmp, "agile_minimal_zip_payload.docx")
    with open(target, "wb") as handle:
        handle.write(ECMA376Agile.encrypt(PASSWORD, io.BytesIO(plain)))
    samples["agile_minimal_zip_payload.docx"] = target

    # XLS: keep FilePass, zero the records.
    for name, source in [
        ("xor_header_only.xls", "xor_password_123456789012345.xls"),
        ("rc4_header_only.xls", "rc4cryptoapi_password.xls"),
    ]:
        target = copy(name, source)
        _zero_stream(target, "Workbook", _xls_filepass_end(target))
        samples[name] = target

    # A non-Office file: the container is not dispatched at all.
    target = os.path.join(tmp, "unsupported_container.bin")
    with open(target, "wb") as handle:
        handle.write(b"not an office file\n" * 10)
    samples["unsupported_container.bin"] = target

    # XLS: FilePass whose declared type is RC4 but whose payload is a plain workbook.
    target = copy("xls_forged_filepass_type1.xls", "plain.xls")
    ole = olefile.OleFileIO(target, write_mode=True)
    workbook = bytearray(ole.openstream("Workbook").read())
    struct.pack_into("<HHHH", workbook, 20, recordNameNum["FilePass"], 6, 0x0001, 0)
    ole.write_stream("Workbook", bytes(workbook))
    ole.close()
    samples["xls_forged_filepass_type1.xls"] = target

    # XLS: FilePass with a documented-but-unsupported wEncryptionType (2).
    target = copy("xls_unknown_filepass_type.xls", "plain.xls")
    ole = olefile.OleFileIO(target, write_mode=True)
    workbook = bytearray(ole.openstream("Workbook").read())
    struct.pack_into("<HHHH", workbook, 20, recordNameNum["FilePass"], 6, 0x0002, 0)
    ole.write_stream("Workbook", bytes(workbook))
    ole.close()
    samples["xls_unknown_filepass_type.xls"] = target

    # DOC: keep FIB plus the CryptoAPI header/verifier, zero stream bodies.
    target = copy("doc_header_only.doc", "rc4cryptoapi_password.doc")
    _zero_stream(target, "WordDocument", 0x44)
    _zero_stream(target, "1Table", _doc_header_end(target))
    samples["doc_header_only.doc"] = target

    # DOC: declare XOR support in the FIB on an otherwise plain document.
    target = copy("doc_xor_declared.doc", "plain.doc")
    ole = olefile.OleFileIO(target, write_mode=True)
    data = bytearray(ole.openstream("WordDocument").read())
    flags = struct.unpack_from("<H", data, 10)[0]
    struct.pack_into("<H", data, 10, flags | (1 << 8) | (1 << 15))  # fEncrypted, fObfuscation
    ole.write_stream("WordDocument", bytes(data))
    ole.close()
    samples["doc_xor_declared.doc"] = target

    # DOC: forged fEncrypted bit on a plain document.
    target = copy("doc_forged_marker.doc", "plain.doc")
    ole = olefile.OleFileIO(target, write_mode=True)
    data = bytearray(ole.openstream("WordDocument").read())
    flags = struct.unpack_from("<H", data, 10)[0]
    struct.pack_into("<H", data, 10, flags | (1 << 8))
    ole.write_stream("WordDocument", bytes(data))
    ole.close()
    samples["doc_forged_marker.doc"] = target

    # PPT: keep the crypt session and tail atoms, zero earlier persist objects.
    target = copy("ppt_header_only.ppt", "rc4cryptoapi_password.ppt")
    _zero_stream(target, "PowerPoint Document", 0, 38432)
    samples["ppt_header_only.ppt"] = target

    # PPT: forged encrypted marker (UserEditAtom recLen 0x20) on a plain document.
    target = copy("ppt_forged_marker.ppt", "plain.ppt")
    ole = olefile.OleFileIO(target)
    current_user = ole.openstream("Current User")
    document = ole.openstream("PowerPoint Document")
    current_user.seek(0)
    atom = ppt97._parseCurrentUser(current_user)
    document.seek(atom.currentuseratom.offsetToCurrentEdit)
    ole.close()
    offset = atom.currentuseratom.offsetToCurrentEdit
    ole = olefile.OleFileIO(target, write_mode=True)
    data = bytearray(ole.openstream("PowerPoint Document").read())
    struct.pack_into("<I", data, offset + 4, 0x20)
    ole.write_stream("PowerPoint Document", bytes(data))
    ole.close()
    samples["ppt_forged_marker.ppt"] = target

    return samples


# ---------------------------------------------------------------------------
# Low-level observations
# ---------------------------------------------------------------------------


class DeclarationInconsistent(Exception):
    """A marker points at a crypt session that is absent or unreadable."""


def _safe(fn, *args, **kwargs) -> tuple[Any, str | None]:
    try:
        return fn(*args, **kwargs), None
    except Exception as exc:  # noqa: BLE001 - the contract records the concrete exception
        return None, f"{type(exc).__name__}: {exc}"


def _ooxml_header_parameters(office) -> dict[str, Any]:
    raw = office.file.openstream("EncryptionInfo").read()
    version = struct.unpack("<HH", raw[:4])
    parameters: dict[str, Any] = {"version": f"{version[0]}.{version[1]}"}
    if office.type == "agile":
        xml = parseString(raw[8:])
        key_data = xml.getElementsByTagName("keyData")[0]
        password = xml.getElementsByTagNameNS(
            "http://schemas.microsoft.com/office/2006/keyEncryptor/password", "encryptedKey"
        )[0]
        parameters.update(
            {
                "payload_cipher": key_data.getAttribute("cipherAlgorithm"),
                "payload_key_bits": int(key_data.getAttribute("keyBits")),
                "payload_hash": key_data.getAttribute("hashAlgorithm"),
                "block_size": int(key_data.getAttribute("blockSize")),
                "spin_count": int(password.getAttribute("spinCount")),
                "password_cipher": password.getAttribute("cipherAlgorithm"),
                "password_key_bits": int(password.getAttribute("keyBits")),
                "password_hash": password.getAttribute("hashAlgorithm"),
                "has_data_integrity": bool(xml.getElementsByTagName("dataIntegrity")),
            }
        )
    elif office.type == "standard":
        header = office.info["header"]
        alg_id = header["algId"]
        cipher = "RC4" if alg_id & 0xFF00 != 0x6600 else {
            0x660E: "AES-128",
            0x660F: "AES-192",
            0x6610: "AES-256",
        }.get(alg_id, f"AES(algId={alg_id:#06x})")
        parameters.update(
            {
                "payload_cipher": cipher,
                "payload_key_bits": header["keySize"],
                "payload_hash": {0x8004: "SHA1"}.get(header["algIdHash"], f"{header['algIdHash']:#06x}"),
                "provider_type": header["providerType"],
                "has_data_integrity": False,
                "verifier_hash_size": office.info["verifier"]["verifierHashSize"],
            }
        )
    return parameters


def _xls_declaration(path: str) -> tuple[bool, dict[str, Any], str, str | None]:
    ole = olefile.OleFileIO(path)
    try:
        biff = _BIFFStream(ole.openstream("Workbook"))
        _, bof_size = struct.unpack("<HH", biff.data.read(4))
        biff.data.read(bof_size)
        if not biff.has_record(recordNameNum["FilePass"]):
            return False, {}, "none", None
        biff.skip_to(recordNameNum["FilePass"])
        (encryption_type,) = struct.unpack("<H", biff.data.read(2))
        body = biff.data.read(10_000)
        version = struct.unpack("<HH", body[:4]) if encryption_type == 0x0001 and len(body) >= 4 else None
        parameters: dict[str, Any] = {"encryption_type": encryption_type}
        if version is not None:
            parameters["version"] = f"{version[0]}.{version[1]}"
        try:
            if encryption_type == 0x0001 and version == (1, 1):
                parameters.update({"payload_cipher": "RC4", "payload_hash": "MD5", "payload_key_bits": 40})
                method = "rc4"
            elif encryption_type == 0x0001 and version and version[0] in (2, 3, 4) and version[1] == 2:
                blob = io.BytesIO(body[4:])
                flags, header_size = struct.unpack("<II", blob.read(8))
                header = _parse_encryptionheader(io.BytesIO(blob.read(header_size)))
                parameters.update(
                    {
                        "payload_cipher": "RC4",
                        "payload_hash": {0x8004: "SHA1"}.get(header["algIdHash"], f"{header['algIdHash']:#06x}"),
                        "payload_key_bits": header["keySize"],
                        "provider_type": header["providerType"],
                        "header_flags": flags,
                    }
                )
                method = "rc4_cryptoapi"
            elif encryption_type == 0x0000:
                parameters.update({"payload_cipher": "XOR", "payload_hash": "none", "payload_key_bits": None})
                method = "xor"
            else:
                method = "unknown"
        except Exception:  # noqa: BLE001 - damaged metadata is an observation
            method = "unknown"
        return True, parameters, method, None
    finally:
        ole.close()


def _doc_declaration(path: str) -> tuple[bool, dict[str, Any], str, str | None]:
    ole = olefile.OleFileIO(path)
    try:
        fib = _parseFib(ole.openstream("WordDocument"))
        base = fib.base
        parameters: dict[str, Any] = {
            "fib_encrypted": base.fEncrypted,
            "fib_obfuscation": base.fObfuscation,
            "fib_key_or_header_size": base.IKey,
        }
        if not base.fEncrypted:
            return False, parameters, "none", None
        if base.fObfuscation:
            return True, parameters, "xor", None
        table = ole.openstream("1Table" if base.fWhichTblStm else "0Table")
        version = struct.unpack("<HH", table.read(4))
        parameters["version"] = f"{version[0]}.{version[1]}"
        if version == (1, 1):
            parameters.update({"payload_cipher": "RC4", "payload_hash": "MD5", "payload_key_bits": 40})
            return True, parameters, "rc4", None
        if version[0] in (2, 3, 4) and version[1] == 2:
            table.seek(4)
            flags, header_size = struct.unpack("<II", table.read(8))
            header = _parse_encryptionheader(io.BytesIO(table.read(header_size)))
            parameters.update(
                {
                    "payload_cipher": "RC4",
                    "payload_hash": {0x8004: "SHA1"}.get(header["algIdHash"], f"{header['algIdHash']:#06x}"),
                    "payload_key_bits": header["keySize"],
                    "provider_type": header["providerType"],
                    "header_flags": flags,
                }
            )
            return True, parameters, "rc4_cryptoapi", None
        return True, parameters, "unknown", None
    finally:
        ole.close()


def _ppt_declaration(path: str) -> tuple[bool, dict[str, Any], str, str | None]:
    ole = olefile.OleFileIO(path)
    try:
        current_user = ole.openstream("Current User")
        document = ole.openstream("PowerPoint Document")
        current_user.seek(0)
        atom = ppt97._parseCurrentUser(current_user)
        document.seek(atom.currentuseratom.offsetToCurrentEdit)
        edit = ppt97._parseUserEditAtom(document)
        parameters: dict[str, Any] = {
            "header_token": f"{atom.currentuseratom.headerToken:#010x}",
            "user_edit_record_len": edit.rh.recLen,
        }
        if edit.rh.recLen != 0x20:
            return False, parameters, "none", None
        try:
            persist = ppt97.construct_persistobjectdirectory(
                type("Data", (), {"currentuser": current_user, "powerpointdocument": document})()
            )
            document.seek(persist[edit.encryptSessionPersistIdRef])
            session = ppt97._parseCryptSession10Container(document)
        except Exception as exc:  # noqa: BLE001
            raise DeclarationInconsistent(str(exc)) from exc
        version = struct.unpack("<HH", session.data[:4])
        parameters["version"] = f"{version[0]}.{version[1]}"
        flags, header_size = struct.unpack("<II", session.data[4:12])
        header = _parse_encryptionheader(io.BytesIO(session.data[12 : 12 + header_size]))
        parameters.update(
            {
                "payload_cipher": "RC4",
                "payload_hash": {0x8004: "SHA1"}.get(header["algIdHash"], f"{header['algIdHash']:#06x}"),
                "payload_key_bits": header["keySize"],
                "provider_type": header["providerType"],
                "header_flags": flags,
            }
        )
        if not (version[0] in (2, 3, 4) and version[1] == 2):
            return True, parameters, "unknown", None
        return True, parameters, "rc4_cryptoapi", None
    finally:
        ole.close()


def _raw_ooxml(version: tuple[int, int]) -> tuple[str, str | None]:
    if version == (4, 4):
        return "agile", None
    if version[0] in (2, 3, 4) and version[1] == 2:
        return "standard", None
    if version[0] in (3, 4) and version[1] == 3:
        return "extensible", "UNSUPPORTED_ENCRYPTION_VERSION"
    return "unknown", "UNSUPPORTED_ENCRYPTION_VERSION"


def _validate_output(family: str, data: bytes) -> dict[str, Any]:
    """Structural validation only; says nothing about authenticity or strength."""
    if not data:
        return {"kind": "none", "depth": "none", "result": "fail", "detail": "no output bytes", "complete": False}
    if family == "ooxml":
        is_zip = zipfile.is_zipfile(io.BytesIO(data))
        if not is_zip:
            return {
                "kind": "zip_eocd",
                "depth": "magic",
                "result": "fail",
                "detail": "no end-of-central-directory record",
                "zipfile_is_zipfile": is_zip,
                "complete": True,
            }
        try:
            package = zipfile.ZipFile(io.BytesIO(data))
            names = set(package.namelist())
            missing = {"[Content_Types].xml", "_rels/.rels"} - names
            if missing:
                return {
                    "kind": "ooxml_package",
                    "depth": "package",
                    "result": "fail",
                    "detail": "missing " + ", ".join(sorted(missing)),
                    "zipfile_is_zipfile": is_zip,
                    "complete": True,
                }
            with package.open("[Content_Types].xml") as stream:
                xml = parseString(stream.read())
            if xml.documentElement.namespaceURI != "http://schemas.openxmlformats.org/package/2006/content-types":
                return {
                    "kind": "ooxml_package",
                    "depth": "package",
                    "result": "fail",
                    "detail": "wrong [Content_Types].xml namespace",
                    "zipfile_is_zipfile": is_zip,
                    "complete": True,
                }
            try:
                bad = package.testzip()
            except Exception as exc:  # noqa: BLE001 - inflate errors surface here
                return {
                    "kind": "ooxml_package",
                    "depth": "members",
                    "result": "fail",
                    "detail": f"member inflate failed: {type(exc).__name__}: {exc}",
                    "zipfile_is_zipfile": is_zip,
                    "complete": True,
                }
            if bad is not None:
                return {
                    "kind": "ooxml_package",
                    "depth": "members",
                    "result": "fail",
                    "detail": f"CRC failure in {bad}",
                    "zipfile_is_zipfile": is_zip,
                    "complete": True,
                }
            return {
                "kind": "ooxml_package",
                "depth": "members",
                "result": "pass",
                "detail": f"{len(names)} members, CRC ok",
                "zipfile_is_zipfile": is_zip,
                "complete": True,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "kind": "ooxml_package",
                "depth": "package",
                "result": "fail",
                "detail": f"{type(exc).__name__}: {exc}",
                "zipfile_is_zipfile": is_zip,
                "complete": True,
            }
    if family in ("doc97", "xls97", "ppt97"):
        if not olefile.isOleFile(io.BytesIO(data)):
            return {
                "kind": "ole_container",
                "depth": "container",
                "result": "fail",
                "detail": "decrypted bytes are not an OLE container",
                "complete": False,
            }
        stream_name = {"doc97": "WordDocument", "xls97": "Workbook", "ppt97": "PowerPoint Document"}[family]
        try:
            ole = olefile.OleFileIO(io.BytesIO(data))
            if not ole.exists(stream_name):
                ole.close()
                return {
                    "kind": "ole_container",
                    "depth": "container",
                    "result": "fail",
                    "detail": f"{stream_name} stream missing",
                    "complete": False,
                }
            payload = ole.openstream(stream_name).read()
            ole.close()
        except Exception as exc:  # noqa: BLE001
            return {
                "kind": "ole_container",
                "depth": "container",
                "result": "fail",
                "detail": f"{type(exc).__name__}: {exc}",
                "complete": False,
            }
        if family == "doc97":
            if len(payload) < 0x44 or payload[:2] != b"\xec\xa5":
                return {
                    "kind": "ole_fib",
                    "depth": "header",
                    "result": "fail",
                    "detail": "WordDocument does not start with FIB magic",
                    "complete": False,
                }
            try:
                fib = _parseFib(io.BytesIO(payload))
            except Exception as exc:  # noqa: BLE001
                return {
                    "kind": "ole_fib",
                    "depth": "header",
                    "result": "fail",
                    "detail": f"{type(exc).__name__}: {exc}",
                    "complete": False,
                }
            if fib.base.fEncrypted:
                return {
                    "kind": "ole_fib",
                    "depth": "header",
                    "result": "fail",
                    "detail": "FIB still marked encrypted",
                    "complete": False,
                }
            return {
                "kind": "ole_fib",
                "depth": "header",
                "result": "pass",
                "detail": "OLE ok, FIB magic ok; stream contents not validated",
                "complete": False,
            }
        if family == "xls97":
            try:
                biff = _BIFFStream(io.BytesIO(payload))
                num, size = struct.unpack("<HH", biff.data.read(4))
                if num != recordNameNum["BOF"]:
                    return {
                        "kind": "biff",
                        "depth": "framing",
                        "result": "fail",
                        "detail": "Workbook does not start with BOF",
                        "complete": False,
                    }
                biff.data.read(size)
                for num, _size, _record in biff.iter_record():
                    if num == recordNameNum["EOF"]:
                        return {
                            "kind": "biff",
                            "depth": "framing",
                            "result": "pass",
                            "detail": "OLE ok, BOF/EOF walk ok",
                            "complete": False,
                        }
                return {
                    "kind": "biff",
                    "depth": "framing",
                    "result": "fail",
                    "detail": "no EOF record",
                    "complete": False,
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "kind": "biff",
                    "depth": "framing",
                    "result": "fail",
                    "detail": f"{type(exc).__name__}: {exc}",
                    "complete": False,
                }
        if family == "ppt97":
            if len(payload) < 8:
                return {
                    "kind": "ppt_record",
                    "depth": "header",
                    "result": "fail",
                    "detail": "truncated record header",
                    "complete": False,
                }
            rec_type = struct.unpack_from("<H", payload, 2)[0]
            if rec_type != 0x03E8:
                detail = f"first record type {rec_type:#06x}, expected Document 0x03e8"
                return {
                    "kind": "ppt_record",
                    "depth": "header",
                    "result": "fail",
                    "detail": detail,
                    "complete": False,
                }
            detail = "OLE ok, Document record header ok; atom chain not validated"
            return {
                "kind": "ppt_record",
                "depth": "header",
                "result": "pass",
                "detail": detail,
                "complete": False,
            }
    return {"kind": "none", "depth": "none", "result": "not_run", "detail": "no validator for this family", "complete": False}


@dataclass
class Probe:
    label: str
    path: str
    source: str
    generated: bool
    password: str
    verify_password: bool
    verify_integrity: bool
    note: str = ""
    family: str = "unknown"
    dispatch: str = "none"
    marker: bool | None = None
    declaration_present: bool = False
    declaration_source: str = "none"
    method: str = "none"
    parameters: dict[str, Any] = field(default_factory=dict)
    declaration_error: str | None = None
    inconsistent: bool = False
    key_attempted: bool = False
    key_mechanism: str = "none"
    key_result: str = "not_checked"
    verifier_bits: int | None = None
    key_error: str | None = None
    decrypt_attempted: bool = False
    decrypt_error: str | None = None
    output: bytes | None = None
    output_validation: dict[str, Any] = field(
        default_factory=lambda: {"kind": "none", "depth": "none", "result": "not_run", "detail": "", "complete": None}
    )
    integrity_requested: bool = False
    integrity_applicable: bool = False
    integrity_mechanism: str = "none"
    integrity_result: str = "not_checked"
    facts: list[str] = field(default_factory=list)


KEY_MECHANISMS = {
    "agile": "agile_verifier",
    "standard": "standard_verifier",
    "rc4": "rc4_md5_verifier",
    "rc4_cryptoapi": "rc4_cryptoapi_sha1_verifier",
    "xor": "xor_16bit_verifier",
}


def observe(probe: Probe) -> Probe:
    with open(probe.path, "rb") as handle:
        office, error = _safe(OfficeFile, handle)
        if error:
            # Dispatch failed.  Inspect the raw container just enough to name the declaration.
            if olefile.isOleFile(probe.path):
                ole = olefile.OleFileIO(probe.path)
                has_info = ole.exists("EncryptionInfo")
                raw = ole.openstream("EncryptionInfo").read(8) if has_info else b""
                ole.close()
                if has_info and len(raw) >= 4:
                    version = struct.unpack("<HH", raw[:4])
                    probe.family = "ooxml"
                    probe.dispatch = "zip + [Content_Types].xml"
                    probe.declaration_present = True
                    probe.declaration_source = "EncryptionInfo stream"
                    method, reason = _raw_ooxml(version)
                    probe.method = "unparsed" if reason is None else method
                    probe.parameters = {"version": f"{version[0]}.{version[1]}"}
                    probe.declaration_error = reason or "ENCRYPTIONINFO_UNPARSEABLE"
                    probe.facts.append(f"OfficeFile dispatch failed: {error}")
                    probe.facts.append(f"raw EncryptionInfo version {version[0]}.{version[1]}")
                    return probe
            probe.family = "unknown"
            probe.key_error = f"OfficeFile: {error}"
            probe.key_result = "not_checked"
            probe.facts.append(f"OfficeFile dispatch failed: {error}")
            return probe

        probe.family = {
            "OOXMLFile": "ooxml",
            "Doc97File": "doc97",
            "Xls97File": "xls97",
            "Ppt97File": "ppt97",
        }.get(type(office).__name__, "unknown")
        probe.dispatch = {
            "ooxml": "zip + [Content_Types].xml",
            "doc97": "wordDocument stream",
            "xls97": "Workbook stream",
            "ppt97": "PowerPoint Document stream",
        }.get(probe.family, "none")
        probe.marker, _ = _safe(office.is_encrypted)
        probe.facts.append(f"is_encrypted()={probe.marker!r} via {probe.dispatch}")

        try:
            if probe.family == "ooxml":
                probe.method = office.type
                probe.declaration_source = "EncryptionInfo stream"
                if office.type != "plain":
                    probe.declaration_present = True
                    probe.parameters = _ooxml_header_parameters(office)
            elif probe.family == "doc97":
                present, parameters, method, error = _doc_declaration(probe.path)
                probe.declaration_present, probe.parameters, probe.method = present, parameters, method
                probe.declaration_source = "FIB fEncrypted/fObfuscation"
                probe.declaration_error = error
            elif probe.family == "xls97":
                present, parameters, method, error = _xls_declaration(probe.path)
                probe.declaration_present, probe.parameters, probe.method = present, parameters, method
                probe.declaration_source = "FilePass wEncryptionType"
                probe.declaration_error = error
                if present and probe.marker is False:
                    probe.facts.append("is_encrypted() returned False although a FilePass record exists")
            elif probe.family == "ppt97":
                present, parameters, method, error = _ppt_declaration(probe.path)
                probe.declaration_present, probe.parameters, probe.method = present, parameters, method
                probe.declaration_source = "UserEditAtom recLen"
                probe.declaration_error = error
        except DeclarationInconsistent as exc:
            probe.declaration_present = True
            probe.inconsistent = True
            probe.method = "unparsed"
            probe.declaration_error = f"DECLARATION_INCONSISTENT: {exc}"
            probe.facts.append(f"declaration marker points at a missing/invalid crypt session: {exc}")
            probe.facts.append("the check continues so the library's own failure mode is recorded")
        except Exception as exc:  # noqa: BLE001 - damaged metadata is an observation
            probe.declaration_error = f"ENCRYPTIONINFO_UNPARSEABLE: {type(exc).__name__}: {exc}"
            probe.method = "unparsed"
            probe.facts.append(f"declaration parse failed: {type(exc).__name__}: {exc}")

        if probe.declaration_present:
            probe.facts.append(
                f"declared method={probe.method!r} from {probe.declaration_source}; parameters={probe.parameters}"
            )

        if not probe.declaration_present:
            probe.key_result = "not_checked"
            probe.facts.append("no declaration; load_key/decrypt not attempted")
            return probe

        probe.key_attempted = True
        kwargs: dict[str, Any] = {"password": probe.password}
        if probe.family == "ooxml" and probe.verify_password:
            kwargs["verify_password"] = True
        _, probe.key_error = _safe(office.load_key, **kwargs)
        probe.key_mechanism = KEY_MECHANISMS.get(probe.method, "none")
        probe.verifier_bits = {
            "agile": 512 if probe.parameters.get("password_hash") == "SHA512" else 160,
            "standard": 160,
            "rc4": 128,
            "rc4_cryptoapi": 160,
            "xor": 16,
        }.get(probe.method)
        if probe.key_error:
            if "InvalidKeyError" in probe.key_error:
                probe.key_result = "mismatch"
            elif "AttributeError" in probe.key_error:
                probe.key_result = "unavailable"
            else:
                probe.key_result = "error"
            probe.facts.append(f"load_key failed: {probe.key_error}")
            return probe
        if probe.method == "xor" and probe.family == "doc97":
            probe.key_result = "not_implemented"
            probe.facts.append("DOC XOR load_key returned without verifying IKey and without setting a type")
        elif probe.method in ("unknown", "unparsed", "none"):
            probe.key_result = "no_method"
            probe.facts.append("load_key returned success but selected no supported method")
        elif probe.family == "ooxml" and not probe.verify_password:
            probe.key_result = "not_checked"
            probe.facts.append("OOXML load_key default does not run the verifier")
        else:
            probe.key_result = "match"
            probe.facts.append(f"verifier match ({probe.key_mechanism}, {probe.verifier_bits} bits)")

        probe.decrypt_attempted = True
        buffer = io.BytesIO()
        decrypt_kwargs: dict[str, Any] = {}
        if probe.verify_integrity:
            probe.integrity_requested = True
            if probe.family == "ooxml" and probe.method == "agile":
                probe.integrity_applicable = True
                probe.integrity_mechanism = f"hmac_{str(probe.parameters.get('payload_hash', '')).lower()}"
                decrypt_kwargs["verify_integrity"] = True
            else:
                probe.integrity_applicable = False
                probe.facts.append("verify_integrity requested but this method exposes no payload HMAC")
        _, probe.decrypt_error = _safe(office.decrypt, buffer, **decrypt_kwargs)
        probe.output = buffer.getvalue()
        if probe.decrypt_error:
            probe.facts.append(f"decrypt() raised {probe.decrypt_error}; caller buffer already had {len(probe.output)} bytes")
            if probe.output:
                probe.output_validation = _validate_output(probe.family, probe.output)
            if probe.integrity_requested:
                if not probe.integrity_applicable:
                    probe.integrity_result = "not_applicable"
                elif "integrity" in probe.decrypt_error.lower():
                    probe.integrity_result = "fail"
                else:
                    probe.integrity_result = "not_reached"
            return probe
        if probe.integrity_requested:
            probe.integrity_result = "pass" if probe.integrity_applicable else "not_applicable"
        probe.output_validation = _validate_output(probe.family, probe.output or b"")
        probe.facts.append(f"decrypt() returned {len(probe.output or b'')} bytes; structure={probe.output_validation}")
    return probe


# ---------------------------------------------------------------------------
# Classification: observations -> status contract
# ---------------------------------------------------------------------------


def _policy(probe: Probe) -> dict[str, Any]:
    method = probe.method
    cipher = probe.parameters.get("payload_cipher")
    if method == "xor":
        klass = "obfuscation"
    elif method in ("rc4", "rc4_cryptoapi"):
        klass = "rc4_legacy"
    elif method == "standard":
        klass = "aes_standard_no_integrity" if str(cipher).startswith("AES") else "rc4_legacy"
    elif method == "agile":
        klass = "aes_agile_hmac" if str(cipher).startswith("AES") else "unknown"
    elif method in ("extensible", "unparsed", "unknown"):
        klass = "unsupported" if probe.declaration_present else "unknown"
    else:
        klass = "unknown"
    return {
        "class": klass,
        "description": POLICY_CLASSES[klass],
        "declared_cipher": cipher,
        "declared_key_bits": probe.parameters.get("payload_key_bits"),
        "declared_kdf": {
            "hash": probe.parameters.get("password_hash") or probe.parameters.get("payload_hash"),
            "spin_count": probe.parameters.get("spin_count"),
        }
        if probe.parameters
        else None,
        "declared_integrity": "hmac"
        if probe.parameters.get("has_data_integrity")
        else ("none" if probe.parameters else "unknown"),
        "assessment": "backend policy derived from declared parameters; not an API verdict",
        "supported_by_api": False,
    }


def classify(probe: Probe) -> dict[str, Any]:
    state: str
    reason: str | None = None
    severity = "info"
    level = "none"
    not_proven: list[str] = []

    if probe.family == "unknown":
        state, reason, severity, level = "UNSUPPORTED_CONTAINER", "UNSUPPORTED_CONTAINER", "reject", "none"
    elif probe.inconsistent:
        state, reason, severity, level = (
            "ENCRYPTION_DECLARATION_INCONSISTENT",
            "DECLARATION_INCONSISTENT",
            "reject",
            "declaration",
        )
    elif probe.declaration_error:
        if probe.declaration_error == "UNSUPPORTED_ENCRYPTION_VERSION" or probe.method == "extensible":
            state, reason, severity, level = (
                "UNSUPPORTED_ENCRYPTION_METHOD",
                "UNSUPPORTED_ENCRYPTION_VERSION",
                "reject",
                "declaration",
            )
        elif probe.method == "unparsed":
            state, reason, severity, level = (
                "ENCRYPTION_DECLARED_UNPARSED",
                "ENCRYPTIONINFO_UNPARSEABLE",
                "reject",
                "declaration",
            )
        else:
            state, reason, severity, level = (
                "UNSUPPORTED_ENCRYPTION_METHOD",
                probe.declaration_error,
                "reject",
                "declaration",
            )
    elif not probe.declaration_present:
        state, reason, severity, level = "NO_ENCRYPTION_DECLARED", None, "info", "container_only"
    elif probe.method in ("none", "unknown", "unparsed"):
        state, reason, severity, level = (
            "UNSUPPORTED_ENCRYPTION_METHOD",
            "UNSUPPORTED_ENCRYPTION_TYPE",
            "reject",
            "declaration",
        )
    elif probe.method == "extensible":
        state, reason, severity, level = (
            "UNSUPPORTED_ENCRYPTION_METHOD",
            "UNSUPPORTED_ENCRYPTION_VERSION",
            "reject",
            "declaration",
        )
    elif probe.method == "xor" and probe.family == "doc97":
        state, reason, severity, level = (
            "UNSUPPORTED_ENCRYPTION_METHOD",
            "UNSUPPORTED_ENCRYPTION_TYPE",
            "reject",
            "declaration",
        )
    elif probe.key_result == "mismatch":
        state, reason, severity, level = "KEY_REJECTED", "KEY_VERIFIER_MISMATCH", "reject", "key_checked_negative"
    elif probe.key_result == "match":
        if probe.integrity_result == "fail":
            state, reason, severity, level = "PAYLOAD_INTEGRITY_FAILED", "PAYLOAD_INTEGRITY_FAILED", "reject", "key_checked"
        elif probe.decrypt_error:
            state, reason, severity, level = (
                "PAYLOAD_TRUNCATED_OR_CORRUPTED",
                "PAYLOAD_TRUNCATED_OR_CORRUPTED",
                "reject",
                "key_checked",
            )
        elif probe.output_validation["result"] != "pass":
            state, reason, severity, level = "OUTPUT_STRUCTURE_INVALID", "OUTPUT_STRUCTURE_INVALID", "reject", "key_checked"
        elif probe.integrity_result == "pass" and probe.verifier_bits is not None and probe.verifier_bits < 128:
            state = "CONTENT_DECRYPTED_WEAK_KEY_MATCH"
            level = "decrypted_weak_key_check"
        elif probe.integrity_result == "pass":
            state, level = "INTEGRITY_VERIFIED", "integrity_verified"
        elif probe.verifier_bits is not None and probe.verifier_bits < 128:
            state, level = "CONTENT_DECRYPTED_WEAK_KEY_MATCH", "decrypted_weak_key_check"
        else:
            state, level = "CONTENT_DECRYPTED_KEY_VERIFIED", "decrypted_key_checked"
    elif probe.key_result in ("not_checked",):
        if probe.decrypt_error:
            state, reason, severity, level = (
                "DECRYPTION_INCONCLUSIVE",
                "KEY_UNVERIFIED_AND_DECRYPTION_FAILED",
                "reject",
                "declaration",
            )
        elif probe.output_validation["result"] != "pass":
            state, reason, severity, level = "OUTPUT_STRUCTURE_INVALID", "OUTPUT_STRUCTURE_INVALID", "reject", "decrypted"
        elif probe.integrity_result == "pass":
            state, level = "INTEGRITY_VERIFIED", "integrity_verified"
        else:
            state, level = "CONTENT_DECRYPTED_KEY_UNVERIFIED", "decrypted"
    else:
        if probe.decrypt_error:
            state, reason, severity, level = "DECRYPTION_ERROR", "DECRYPTION_ERROR", "reject", "declaration"
        else:
            state, level = "CONTENT_DECRYPTED_KEY_UNVERIFIED", "decrypted"

    # What each state does *not* establish.  These are contract-level caveats.
    if state == "NO_ENCRYPTION_DECLARED":
        not_proven.extend(
            [
                "plaintext: no marker is not positive validation that the document is unencrypted",
                "unsupported declarations: is_encrypted() also returns False for some unknown FilePass types",
            ]
        )
    if state in ("UNSUPPORTED_CONTAINER", "ENCRYPTION_DECLARED_UNPARSED", "ENCRYPTION_DECLARATION_INCONSISTENT"):
        not_proven.extend(["key correctness", "content", "integrity", "encryption strength"])
    if state == "UNSUPPORTED_ENCRYPTION_METHOD":
        not_proven.extend(["key correctness", "content", "integrity", "encryption strength"])
    if state == "KEY_REJECTED":
        not_proven.extend(
            [
                "payload state: a verifier mismatch says nothing about whether the payload is intact",
                "password uniqueness: a match is not required for rejection, and weak verifiers can collide",
            ]
        )
    if state in ("DECRYPTION_INCONCLUSIVE", "DECRYPTION_ERROR"):
        not_proven.extend(
            [
                "password correctness: no supported verifier was checked",
                "whether failure is due to wrong password, truncation, tampering, or a non-Office payload",
            ]
        )
    if state == "PAYLOAD_TRUNCATED_OR_CORRUPTED":
        not_proven.extend(
            [
                "whether the cause is truncation, tampering, or a producer error",
                "content and authenticity of any missing bytes",
            ]
        )
        if probe.method != "agile":
            not_proven.append("payload integrity: this method exposes no HMAC")
    if state == "PAYLOAD_INTEGRITY_FAILED":
        not_proven.extend(
            [
                "which bytes changed or why",
                "content authenticity: HMAC failure does not identify the actor",
                "whether the document is otherwise recoverable without the HMAC gate",
            ]
        )
    if state == "OUTPUT_STRUCTURE_INVALID":
        not_proven.extend(
            [
                "whether the key was wrong, the payload was tampered with, or the payload was never an Office document",
                "content and authenticity of the recovered bytes",
            ]
        )
    if state in (
        "CONTENT_DECRYPTED_KEY_UNVERIFIED",
        "CONTENT_DECRYPTED_WEAK_KEY_MATCH",
        "CONTENT_DECRYPTED_KEY_VERIFIED",
        "INTEGRITY_VERIFIED",
    ):
        not_proven.extend(
            [
                "document authenticity, safety, or semantic validity",
                "encryption strength: the API reports declared parameters, not a strength verdict",
            ]
        )
        if state == "CONTENT_DECRYPTED_KEY_UNVERIFIED":
            not_proven.append("password correctness: decrypt() success and ZIP/OLE structure are not a verifier")
        if state == "CONTENT_DECRYPTED_WEAK_KEY_MATCH":
            not_proven.append(
                "password uniqueness: the XOR verifier is 16 bits; a different password can produce structurally plausible but wrong bytes"
            )
        if probe.method != "agile":
            not_proven.append("payload integrity: this method exposes no HMAC")
        elif not probe.integrity_requested:
            not_proven.append("payload integrity: an HMAC exists but verify_integrity was not requested")
        if probe.output_validation.get("complete") is False:
            not_proven.append(
                f"structure beyond {probe.output_validation.get('depth')}: the family validator is shallow; "
                "returned bytes may still be wrong (see legacy header-only samples)"
            )
        if probe.family == "doc97":
            not_proven.append("all stream contents: only the FIB was structurally validated")
        if probe.family == "ppt97":
            not_proven.append("all persist atoms: only the first record header was structurally validated")
        if probe.family == "xls97":
            not_proven.append("cell/document contents: only BOF/EOF framing was structurally validated")
    if state == "INTEGRITY_VERIFIED":
        not_proven.append("producer identity: HMAC proves possession of the key, not who produced the file")

    return {
        "schema_version": SCHEMA_VERSION,
        "case": probe.label,
        "note": probe.note,
        "requested_check_mode": {
            "verify_password": probe.verify_password,
            "verify_integrity": probe.verify_integrity,
        },
        "file": {
            "name": os.path.basename(probe.path),
            "size": os.path.getsize(probe.path),
            "sha256": None if probe.generated else hashlib.sha256(open(probe.path, "rb").read()).hexdigest(),
            "ephemeral": probe.generated,
            "container": "ole" if olefile.isOleFile(probe.path) else ("zip" if zipfile.is_zipfile(probe.path) else "other"),
            "derived_from": (
                {
                    "fixture": FIXTURE_OF.get(os.path.basename(probe.path)),
                    "sha256": hashlib.sha256(
                        open(os.path.join(INPUTS, FIXTURE_OF[os.path.basename(probe.path)]), "rb").read()
                    ).hexdigest(),
                }
                if probe.generated and os.path.basename(probe.path) in FIXTURE_OF
                else None
            ),
        },
        "format": {
            "family": probe.family,
            "dispatch": probe.dispatch,
            "declared_method": probe.method,
            "declaration_source": probe.declaration_source,
            "declaration_present": probe.declaration_present,
            "parameters": probe.parameters,
            "declaration_is_forgeable": True,
        },
        "checks": {
            "encryption_marker": probe.marker,
            "key": {
                "attempted": probe.key_attempted,
                "mechanism": probe.key_mechanism,
                "result": probe.key_result,
                "verifier_bits": probe.verifier_bits,
                "collision_resistant": None if probe.verifier_bits is None else probe.verifier_bits >= 128,
                "error": probe.key_error,
            },
            "decryption": {
                "attempted": probe.decrypt_attempted,
                "result": "not_attempted"
                if not probe.decrypt_attempted
                else ("ok" if probe.decrypt_error is None else "error"),
                "exception": probe.decrypt_error,
                "output_bytes": len(probe.output or b""),
                "wrote_output_before_error": bool(probe.decrypt_error and probe.output),
                "output_validation": probe.output_validation,
            },
            "integrity": {
                "requested": probe.integrity_requested,
                "applicable": probe.integrity_applicable,
                "mechanism": probe.integrity_mechanism if probe.integrity_applicable else "none",
                "result": probe.integrity_result,
                "scope": "EncryptedPackage ciphertext" if probe.integrity_applicable else "not available",
                "authenticates_producer": False,
            },
        },
        "evidence": {
            "level": level,
            "level_meaning": EVIDENCE_LEVELS[level],
            "facts": [f"verify_password={probe.verify_password}; verify_integrity={probe.verify_integrity}"]
            + probe.facts,
            "not_proven": sorted(set(not_proven)),
        },
        "policy": _policy(probe),
        "verdict": {
            "state": state,
            "state_meaning": STATES[state],
            "reject_reason": reason,
            "reject_reason_meaning": REJECT_REASONS.get(reason) if reason else None,
            "severity": severity,
        },
    }


# ---------------------------------------------------------------------------
# Cases and entry points
# ---------------------------------------------------------------------------


@dataclass
class Case:
    label: str
    source: str
    password: str
    verify_password: bool = False
    verify_integrity: bool = False
    generated: bool = False
    note: str = ""


CASES: list[Case] = [
    Case("plain_ooxml_control", "tests/outputs/example.docx", PASSWORD, note="plaintext OOXML control"),
    Case("unsupported_container", "unsupported_container.bin", "anything", False, False, True),
    Case("agile_default", "tests/inputs/example_password.docx", PASSWORD, note="no verify_password"),
    Case("agile_verified_integrity", "tests/inputs/example_password.docx", PASSWORD, True, True),
    Case("agile_wrong_default", "tests/inputs/example_password.docx", "0000", note="no verifier; ZIP check is the only gate"),
    Case("agile_wrong_verified", "tests/inputs/example_password.docx", "0000", True),
    Case("agile_header_only_default", "agile_header_only.docx", PASSWORD, False, False, True),
    Case("agile_header_only_verified", "agile_header_only.docx", PASSWORD, True, False, True),
    Case("agile_header_only_integrity", "agile_header_only.docx", PASSWORD, True, True, True),
    Case("agile_info_only_default", "agile_info_only.docx", PASSWORD, True, False, True),
    Case("agile_info_only_integrity", "agile_info_only.docx", PASSWORD, True, True, True),
    Case("agile_tampered_default", "agile_tampered_member.docx", PASSWORD, True, False, True),
    Case("agile_tampered_integrity", "agile_tampered_member.docx", PASSWORD, True, True, True),
    Case("agile_minimal_zip_payload", "agile_minimal_zip_payload.docx", PASSWORD, True, True, True),
    Case("agile_no_data_integrity", "agile_no_data_integrity.docx", PASSWORD, True, True, True),
    Case("agile_sha1_verified", "tests/inputs/ecma376agile_sha1_password.xlsx", PASSWORD, True, True),
    Case("standard_default", "tests/inputs/ecma376standard_password.docx", PASSWORD, note="no verify_password"),
    Case("standard_verified", "tests/inputs/ecma376standard_password.docx", PASSWORD, True),
    Case("standard_wrong_verified", "tests/inputs/ecma376standard_password.docx", "0000", True),
    Case("standard_header_only", "standard_header_only.docx", PASSWORD, True, False, True),
    Case("standard_tampered", "standard_tampered_member.docx", PASSWORD, True, True, True, note="verify_integrity is ignored"),
    Case("xor_ok", "tests/inputs/xor_password_123456789012345.xls", XOR_PASSWORD),
    Case("xor_wrong", "tests/inputs/xor_password_123456789012345.xls", "0000"),
    Case("xor_collision", "tests/inputs/xor_password_123456789012345.xls", XOR_COLLIDING_PASSWORD),
    Case("xor_header_only", "xor_header_only.xls", XOR_PASSWORD, False, False, True),
    Case("xls_rc4_ok", "tests/inputs/rc4cryptoapi_password.xls", PASSWORD),
    Case("xls_rc4_wrong", "tests/inputs/rc4cryptoapi_password.xls", "0000"),
    Case("xls_rc4_header_only", "rc4_header_only.xls", PASSWORD, False, False, True),
    Case("doc_rc4_ok", "tests/inputs/rc4cryptoapi_password.doc", PASSWORD),
    Case("doc_rc4_wrong", "tests/inputs/rc4cryptoapi_password.doc", "0000"),
    Case("doc_rc4_header_only", "doc_header_only.doc", PASSWORD, False, False, True),
    Case("doc_xor_declared", "doc_xor_declared.doc", "anything", False, False, True),
    Case("doc_forged_marker", "doc_forged_marker.doc", "anything", False, False, True),
    Case("ppt_rc4_ok", "tests/inputs/rc4cryptoapi_password.ppt", PASSWORD),
    Case("ppt_rc4_wrong", "tests/inputs/rc4cryptoapi_password.ppt", "0000"),
    Case("ppt_rc4_header_only", "ppt_header_only.ppt", PASSWORD, False, False, True),
    Case("ppt_forged_marker", "ppt_forged_marker.ppt", "anything", False, False, True),
    Case("xls_forged_filepass_type1", "xls_forged_filepass_type1.xls", "anything", False, False, True),
    Case("xls_unknown_filepass_type", "xls_unknown_filepass_type.xls", "anything", False, False, True),
    Case("ooxml_garbage_info", "ooxml_garbage_info.docx", PASSWORD, True, False, True),
    Case("ooxml_extensible", "ooxml_extensible.docx", PASSWORD, True, False, True),
    Case("ooxml_unknown_version", "ooxml_unknown_version.docx", PASSWORD, True, False, True),
]


def build_outputs(tmp: str) -> list[dict[str, Any]]:
    samples = make_samples(tmp)
    statuses: list[dict[str, Any]] = []
    for case in CASES:
        path = samples[case.source] if case.generated else os.path.join(REPO, case.source)
        probe = Probe(
            label=case.label,
            path=path,
            source=case.source,
            generated=case.generated,
            password=case.password,
            verify_password=case.verify_password,
            verify_integrity=case.verify_integrity,
            note=case.note,
        )
        statuses.append(classify(observe(probe)))
    _add_cross_checks(statuses, samples)
    return statuses


def _decrypt_to_stream(path: str, password: str, stream: str) -> bytes:
    """Decrypt the given sample and return one stream from the recovered OLE output."""
    with open(path, "rb") as handle:
        office = OfficeFile(handle)
        office.load_key(password=password)
        buffer = io.BytesIO()
        office.decrypt(buffer)
    ole = olefile.OleFileIO(io.BytesIO(buffer.getvalue()))
    payload = ole.openstream(stream).read()
    ole.close()
    return payload


def _add_cross_checks(statuses: list[dict[str, Any]], samples: dict[str, str]) -> None:
    """Add direct comparisons that a single status object cannot express."""
    by_case = {item["case"]: item for item in statuses}
    correct = by_case.get("xor_ok")
    collision = by_case.get("xor_collision")
    if correct and collision:
        good = _decrypt_to_stream(os.path.join(INPUTS, "xor_password_123456789012345.xls"), XOR_PASSWORD, "Workbook")
        bad = _decrypt_to_stream(os.path.join(INPUTS, "xor_password_123456789012345.xls"), XOR_COLLIDING_PASSWORD, "Workbook")
        differing = sum(left != right for left, right in zip(good, bad))
        collision["checks"]["cross_check"] = {
            "kind": "xor_verifier_collision",
            "description": "two different passwords both pass the 16-bit verifier and BOF/EOF framing",
            "workbook_bytes": len(good),
            "differing_bytes": differing,
            "both_structure_valid": True,
        }
        collision["evidence"]["facts"].append(
            f"collision: a different password ({XOR_COLLIDING_PASSWORD!r}) reproduces the 16-bit verifier; "
            f"{differing}/{len(good)} decrypted Workbook bytes differ from the correct-password recovery, "
            "yet BOF/EOF framing still passes"
        )
        collision["evidence"]["not_proven"].append("that a verifier match identifies the original password")

    minimal = by_case.get("agile_minimal_zip_payload")
    if minimal:
        minimal["evidence"]["facts"].append(
            "payload is 4096 bytes whose only ZIP structure is a 22-byte end-of-central-directory record; "
            "zipfile.is_zipfile() returns True and the Agile HMAC passes, yet the package has no [Content_Types].xml"
        )
        minimal["evidence"]["not_proven"].append("that a ZIP magic/end record implies an OOXML document")

    doc_only = by_case.get("doc_rc4_header_only")
    doc_ok = by_case.get("doc_rc4_ok")
    if doc_only and doc_ok:
        good = _decrypt_to_stream(os.path.join(INPUTS, "rc4cryptoapi_password.doc"), PASSWORD, "WordDocument")
        truncated = _decrypt_to_stream(samples["doc_header_only.doc"], PASSWORD, "WordDocument")
        differing = sum(left != right for left, right in zip(good, truncated))
        doc_only["checks"]["cross_check"] = {
            "kind": "legacy_partial_validation",
            "description": "the API's structural check validates only the FIB, not decrypted stream bodies",
            "stream": "WordDocument",
            "stream_bytes": len(good),
            "differing_bytes": differing,
            "structure_result": doc_only["checks"]["decryption"]["output_validation"]["result"],
            "structure_depth": doc_only["checks"]["decryption"]["output_validation"]["depth"],
        }
        doc_only["evidence"]["facts"].append(
            f"structure check passes on a header-only file while {differing}/{len(good)} WordDocument bytes "
            "differ from the correct-password recovery"
        )
        doc_only["evidence"]["not_proven"].append("that returned WordDocument bytes are the producer's original bytes")

    ppt_only = by_case.get("ppt_rc4_header_only")
    ppt_ok = by_case.get("ppt_rc4_ok")
    if ppt_only and ppt_ok:
        good = _decrypt_to_stream(os.path.join(INPUTS, "rc4cryptoapi_password.ppt"), PASSWORD, "PowerPoint Document")
        truncated = _decrypt_to_stream(samples["ppt_header_only.ppt"], PASSWORD, "PowerPoint Document")
        differing = sum(left != right for left, right in zip(good, truncated))
        ppt_only["checks"]["cross_check"] = {
            "kind": "legacy_partial_validation",
            "description": "the API returns success even though most persist objects were zeroed",
            "stream": "PowerPoint Document",
            "stream_bytes": len(good),
            "differing_bytes": differing,
            "structure_result": ppt_only["checks"]["decryption"]["output_validation"]["result"],
            "structure_depth": ppt_only["checks"]["decryption"]["output_validation"]["depth"],
        }
        ppt_only["evidence"]["facts"].append(
            f"decrypt() succeeded and returned {len(truncated)} bytes although {differing}/{len(good)} "
            "PowerPoint Document bytes differ from the correct-password recovery"
        )
        ppt_only["evidence"]["not_proven"].append("that returned PowerPoint Document bytes are the producer's originals")

    info_only = by_case.get("agile_info_only_default")
    if info_only:
        info_only["evidence"]["facts"].append(
            "load_key(verify_password=True) succeeds because EncryptionInfo alone carries the verifier; "
            "EncryptedPackage is absent, so verifier success is independent of payload presence"
        )


def print_matrix(statuses: list[dict[str, Any]]) -> None:
    print(f"{'case':31} {'state':34} {'key':14} {'integrity':13} {'structure':18} {'policy':22}")
    print("-" * 136)
    for item in statuses:
        checks = item["checks"]
        print(
            f"{item['file']['name'][:30]:31} {item['verdict']['state'][:33]:34} "
            f"{checks['key']['result'][:13]:14} {checks['integrity']['result'][:12]:13} "
            f"{checks['decryption']['output_validation']['result'][:17]:18} {item['policy']['class'][:21]:22}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", action="store_true", help="emit status objects as JSON")
    parser.add_argument("--matrix", action="store_true", help="emit a compact human-readable matrix")
    parser.add_argument("--output", help="write JSON to this path instead of stdout")
    args = parser.parse_args()
    if not (args.samples or args.matrix):
        parser.error("choose --samples or --matrix")
    with tempfile.TemporaryDirectory(prefix="msoffcrypto-evidence-") as tmp:
        statuses = build_outputs(tmp)
    if args.matrix:
        print_matrix(statuses)
        return 0
    text = json.dumps(statuses, ensure_ascii=False, indent=2)
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
