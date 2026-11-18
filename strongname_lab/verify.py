"""Independent verifiers for strong-name and Authenticode material.

Nothing here loads or executes a PE.  pefile is used for structural parsing;
all cryptographic decisions are made by this module and checked against
explicit coverage rules.
"""

from __future__ import annotations

import hashlib
import struct

import pefile

from . import crypto, der

CLI_FLAG_ILONLY = 0x00000001
CLI_FLAG_STRONGNAMESIGNED = 0x00000008
ASSEMBLY_FLAG_PUBLIC_KEY = 0x0001

SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
SPC_PE_IMAGE_DATA_OID = "1.3.6.1.4.1.311.2.1.15"
PKCS7_SIGNED_DATA_OID = "1.2.840.113549.1.7.2"
CONTENT_TYPE_OID = "1.2.840.113549.1.9.3"
MESSAGE_DIGEST_OID = "1.2.840.113549.1.9.4"
SIGNING_TIME_OID = "1.2.840.113549.1.9.5"
RSA_OID = "1.2.840.113549.1.1.1"
SHA256_WITH_RSA_OID = "1.2.840.113549.1.1.11"
EXTENSION_EKU_OID = "2.5.29.37"
EXTENSION_BASIC_CONSTRAINTS_OID = "2.5.29.19"
EKU_CODE_SIGNING_OID = "1.3.6.1.5.5.7.3.3"

SIGNATURE_ALGORITHM_HASHES = {
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
}


class VerifyError(ValueError):
    pass


# --------------------------------------------------------------------------
# ELF-independent helpers
# --------------------------------------------------------------------------

def _optional_header_offset(image: bytes) -> int:
    if len(image) < 0x40 or image[:2] != b"MZ":
        raise VerifyError("not an MZ file")
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    if image[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise VerifyError("missing PE signature")
    return e_lfanew + 24


def _data_directory_offset(image: bytes, index: int) -> int:
    optional = _optional_header_offset(image)
    magic = struct.unpack_from("<H", image, optional)[0]
    base = 96 if magic == 0x10B else 112
    return optional + base + index * 8


def _check_range(image: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(image):
        raise VerifyError(f"{label} range {offset:#x}+{size:#x} exceeds file size {len(image):#x}")


# --------------------------------------------------------------------------
# Managed PE / strong name
# --------------------------------------------------------------------------

def parse_managed(image: bytes) -> dict:
    pe = pefile.PE(data=image)
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 14:
        raise VerifyError("no COM descriptor directory")
    com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if not com.VirtualAddress or com.Size < 72:
        raise VerifyError("no CLI header")
    cli_offset = pe.get_offset_from_rva(com.VirtualAddress)
    _check_range(image, cli_offset, 72, "CLI header")
    fields = struct.unpack_from("<IHH" + "I" * 16, image, cli_offset)
    (
        cb, major, minor, metadata_rva, metadata_size, flags, entry_point,
        resources_rva, resources_size, strong_name_rva, strong_name_size,
        _cm_rva, _cm_size, _vt_rva, _vt_size, _eat_rva, _eat_size, _native_rva, _native_size,
    ) = fields
    if cb != 72:
        raise VerifyError(f"unexpected CLI header size {cb}")
    metadata_offset = pe.get_offset_from_rva(metadata_rva)
    _check_range(image, metadata_offset, metadata_size, "metadata")
    from . import metadata as md

    meta = md.Metadata(image[metadata_offset:metadata_offset + metadata_size], metadata_rva)
    assembly = meta.assembly
    public_key = assembly["PublicKey"]
    token = crypto.token_from_public_key_blob(public_key) if public_key else None
    signature_offset = None
    if strong_name_rva and strong_name_size:
        signature_offset = pe.get_offset_from_rva(strong_name_rva)
        _check_range(image, signature_offset, strong_name_size, "strong-name signature")
    method_entries = []
    for row in meta.table_rows.get(md.TABLE_METHODDEF, []):
        entry = {"rva": row["RVA"], "name": row["Name"], "offset": None}
        if row["RVA"]:
            entry["offset"] = pe.get_offset_from_rva(row["RVA"])
        method_entries.append(entry)
    return {
        "pe": pe,
        "cli_offset": cli_offset,
        "method_entries": method_entries,
        "cli_flags": flags,
        "metadata_offset": metadata_offset,
        "metadata_size": metadata_size,
        "metadata": meta,
        "assembly": assembly,
        "public_key": public_key,
        "public_key_token": token,
        "strong_name_rva": strong_name_rva,
        "strong_name_size": strong_name_size,
        "signature_offset": signature_offset,
        "entry_point_token": entry_point,
    }


def strong_name_covered_ranges(image: bytes, signature_offset: int | None, signature_size: int) -> list[tuple[int, int, str]]:
    """ECMA-335 strong-name hash coverage as explicit file ranges."""
    pe = pefile.PE(data=image, fast_load=True)
    optional = _optional_header_offset(image)
    checksum_offset = optional + 64
    cert_entry_offset = _data_directory_offset(image, 4)
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    _check_range(image, 0, size_of_headers, "headers")
    ranges: list[tuple[int, int, str]] = []
    ranges.append((0, checksum_offset, "PE headers before checksum"))
    ranges.append((checksum_offset + 4, cert_entry_offset, "between checksum and certificate directory entry"))
    ranges.append((cert_entry_offset + 8, size_of_headers, "after certificate directory entry to SizeOfHeaders"))
    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if start == 0 or end == 0:
            continue
        _check_range(image, start, section.SizeOfRawData, f"section {section.Name!r}")
        if signature_offset is not None and start <= signature_offset < end:
            slot_end = signature_offset + signature_size
            if slot_end > end:
                raise VerifyError("strong-name slot crosses section boundary")
            ranges.append((start, signature_offset, f"section {section.Name!r} before signature"))
            ranges.append((slot_end, end, f"section {section.Name!r} after signature"))
        else:
            ranges.append((start, end, f"section {section.Name!r}"))
    return ranges


def strong_name_digest(image: bytes, signature_offset: int | None, signature_size: int, hash_name: str) -> tuple[bytes, list[tuple[int, int, str]]]:
    ranges = strong_name_covered_ranges(image, signature_offset, signature_size)
    blob = bytearray()
    for start, end, _ in ranges:
        blob += image[start:end]
    return hashlib.new(hash_name, blob).digest(), ranges


def _recover_digest_info(modulus: int, exponent: int, signature: bytes) -> bytes:
    k = (modulus.bit_length() + 7) // 8
    if len(signature) != k:
        raise VerifyError(f"signature length {len(signature)} != {k}")
    value = pow(int.from_bytes(signature, "big"), exponent, modulus)
    return value.to_bytes(k, "big")


def strong_name_check(image: bytes) -> dict:
    info = parse_managed(image)
    assembly = info["assembly"]
    public_key = info["public_key"]
    hash_id = assembly["HashAlgId"]
    hash_name = crypto.HASH_ALG_IDS.get(hash_id)
    result = {
        "identity": {
            "name": assembly["Name"],
            "version": ".".join(str(assembly[name]) for name in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")),
            "culture": assembly["Culture"],
            "flags": assembly["Flags"],
            "has_public_key": bool(public_key),
            "public_key_sha256": crypto.public_key_blob_sha256(public_key) if public_key else None,
            "public_key_token": info["public_key_token"],
            "hash_algorithm_id": f"0x{hash_id:08x}",
            "hash_algorithm": hash_name,
        },
        "cli": {
            "flags": info["cli_flags"],
            "il_only": bool(info["cli_flags"] & CLI_FLAG_ILONLY),
            "strong_name_signed_flag": bool(info["cli_flags"] & CLI_FLAG_STRONGNAMESIGNED),
            "strong_name_rva": info["strong_name_rva"],
            "strong_name_size": info["strong_name_size"],
            "signature_file_offset": info["signature_offset"],
        },
        "checks": {},
        "digest": None,
        "embedded_digest": None,
        "covered_ranges": [],
        "verdict": {},
    }
    checks = result["checks"]
    checks["public_key_present"] = bool(public_key)
    checks["public_key_flag_matches_blob"] = bool(assembly["Flags"] & ASSEMBLY_FLAG_PUBLIC_KEY) and bool(public_key)
    checks["signature_slot_present"] = bool(info["signature_offset"] and info["strong_name_size"])
    checks["strong_name_signed_flag_matches_valid_material"] = bool(
        bool(info["cli_flags"] & CLI_FLAG_STRONGNAMESIGNED) == bool(info["signature_offset"])
    )
    checks["signature_slot_size_matches_key"] = None
    if info["signature_offset"] and public_key:
        signature = image[info["signature_offset"]:info["signature_offset"] + info["strong_name_size"]]
        key = crypto.parse_public_key_blob(public_key)
        expected_size = (key["bits"] + 7) // 8
        checks["signature_slot_size_matches_key"] = info["strong_name_size"] == expected_size
        checks["signature_nonzero"] = any(signature)
        if hash_name is None:
            checks["digest_supported"] = False
        else:
            checks["digest_supported"] = True
            digest, ranges = strong_name_digest(image, info["signature_offset"], info["strong_name_size"], hash_name)
            result["digest"] = digest.hex()
            result["covered_ranges"] = [
                {"start": start, "end": end, "label": label, "length": end - start} for start, end, label in ranges
            ]
            if any(signature):
                embedded_em = _recover_digest_info(key["modulus"], key["exponent"], crypto.strong_name_signature_to_be(signature))
                embedded_digest = _extract_digest_info(embedded_em)
                result["embedded_digest"] = embedded_digest.hex() if embedded_digest else None
                checks["embedded_digest_matches_content"] = embedded_digest == digest if embedded_digest else False
                ok, reason = crypto.pkcs1_v15_verify(
                    key["modulus"], key["exponent"],
                    crypto.strong_name_signature_to_be(signature),
                    crypto.digest_info(hash_name, digest),
                )
                checks["rsa_signature_valid"] = ok
                checks["rsa_verification_detail"] = reason
            else:
                checks["embedded_digest_matches_content"] = False
                checks["rsa_signature_valid"] = False
                checks["rsa_verification_detail"] = "signature slot is all zero (delay-signed or stripped)"
    else:
        checks["signature_nonzero"] = False
        checks["rsa_signature_valid"] = False
        checks["rsa_verification_detail"] = "no signature slot or no public key"

    integrity = bool(checks.get("rsa_signature_valid"))
    flag_only = info["cli_flags"] & CLI_FLAG_STRONGNAMESIGNED
    result["verdict"] = {
        "signature_integrity": "valid" if integrity else "invalid",
        "covered_content_integrity": "intact for selected ranges" if checks.get("embedded_digest_matches_content") else "not established",
        "key_identity": "token + public key match each other by construction" if info["public_key_token"] else "absent",
        "publisher_trust": "not established by strong name",
        "flag_alone_is_not_evidence": bool(flag_only) and not integrity,
        "note": "A valid strong-name signature proves possession of the private key for the embedded public key and integrity of the hashed ranges. It does not establish a trusted publisher.",
    }
    return result


def _extract_digest_info(em: bytes) -> bytes | None:
    """Return the OCTET STRING digest from a PKCS#1 v1.5 encoded message, if parseable."""
    if len(em) < 11 or em[0] != 0 or em[1] != 1:
        return None
    index = 2
    while index < len(em) and em[index] == 0xFF:
        index += 1
    if index >= len(em) or em[index] != 0:
        return None
    try:
        tag, content, end, _ = der.read_tlv(em, index + 1)
        if tag != 0x30 or end != len(em):
            return None
        fields = der.children(content)
        if len(fields) != 2 or fields[1][0] != 0x04:
            return None
        return fields[1][1]
    except der.DerError:
        return None


# --------------------------------------------------------------------------
# Authenticode
# --------------------------------------------------------------------------

def authenticode_ranges(image: bytes, cert_offset: int, cert_size: int) -> list[tuple[int, int, str]]:
    pe = pefile.PE(data=image, fast_load=True)
    optional = _optional_header_offset(image)
    checksum_offset = optional + 64
    cert_entry_offset = _data_directory_offset(image, 4)
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    ranges = [
        (0, checksum_offset, "headers before checksum"),
        (checksum_offset + 4, cert_entry_offset, "between checksum and certificate directory entry"),
        (cert_entry_offset + 8, size_of_headers, "after certificate directory entry to SizeOfHeaders"),
    ]
    total = size_of_headers
    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        start = section.PointerToRawData
        size = section.SizeOfRawData
        if start == 0 or size == 0:
            continue
        ranges.append((start, start + size, f"section {section.Name!r}"))
        total += size
    if cert_offset:
        # Authenticode hashes extra data between the end of the last section
        # and the certificate table.  It does not hash the certificate table
        # itself, nor bytes appended after it.
        if total < cert_offset:
            ranges.append((total, cert_offset, "extra data before certificate table"))
    elif total < len(image):
        ranges.append((total, len(image), "extra data after sections"))
    for start, end, label in ranges:
        _check_range(image, start, end - start, label)
    return ranges


def authenticode_digest(image: bytes, hash_name: str = "sha256") -> tuple[bytes, list[tuple[int, int, str]], int]:
    pe = pefile.PE(data=image, fast_load=True)
    cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    ranges = authenticode_ranges(image, cert.VirtualAddress, cert.Size)
    blob = bytearray()
    for start, end, _ in ranges:
        blob += image[start:end]
    return hashlib.new(hash_name, blob).digest(), ranges, cert.VirtualAddress


def parse_win_certificates(image: bytes) -> list[dict]:
    pe = pefile.PE(data=image, fast_load=True)
    cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if not cert.VirtualAddress or not cert.Size:
        return []
    _check_range(image, cert.VirtualAddress, cert.Size, "certificate table")
    entries = []
    cursor = cert.VirtualAddress
    end = cert.VirtualAddress + cert.Size
    while cursor + 8 <= end:
        length, revision, cert_type = struct.unpack_from("<IHH", image, cursor)
        if length < 8 or cursor + length > end:
            raise VerifyError("malformed WIN_CERTIFICATE length")
        entries.append({
            "offset": cursor,
            "length": length,
            "padded_length": (length + 7) & ~7,
            "revision": revision,
            "certificate_type": cert_type,
            "data": image[cursor + 8:cursor + length],
        })
        cursor += (length + 7) & ~7
    return entries


def parse_pkcs7(payload: bytes) -> dict:
    tag, content, end, _ = der.read_tlv(payload, 0)
    if tag != 0x30:
        raise VerifyError("PKCS#7 is not a SEQUENCE")
    fields = der.children(content)
    if len(fields) != 2 or fields[0][0] != 0x06:
        raise VerifyError("malformed ContentInfo")
    content_type = der.decode_oid(fields[0][1])
    if content_type != PKCS7_SIGNED_DATA_OID:
        raise VerifyError(f"not signedData: {content_type}")
    if fields[1][0] != 0xA0:
        raise VerifyError("missing signedData wrapper")
    sd_tag, sd_content, _, _ = der.read_tlv(fields[1][1], 0)
    sd = der.children(sd_content)
    if len(sd) < 4:
        raise VerifyError("truncated SignedData")
    digest_algorithms = [der.decode_oid(item[1]) for item in der.children(sd[1][1]) if item[0] == 0x30]
    encap = sd[2]
    encap_fields = der.children(encap[1])
    encap_oid = der.decode_oid(encap_fields[0][1]) if encap_fields and encap_fields[0][0] == 0x06 else None
    inner = b""
    if len(encap_fields) > 1 and encap_fields[1][0] == 0xA0:
        inner = encap_fields[1][1]
    certs = []
    signer_infos = []
    for field in sd[3:]:
        if field[0] == 0xA0:
            cert_cursor = 0
            while cert_cursor < len(field[1]):
                _, _, cert_cursor, raw = der.read_tlv(field[1], cert_cursor)
                certs.append(parse_certificate(raw))
        elif field[0] == 0x31:
            signer_infos = [parse_signer_info(item[2]) for item in der.children(field[1]) if item[0] == 0x30]
    return {
        "content_type": content_type,
        "digest_algorithms": digest_algorithms,
        "encap_content_type": encap_oid,
        "encap_content": inner,
        "certificates": certs,
        "signer_infos": signer_infos,
    }


def parse_certificate(raw: bytes) -> dict:
    tag, content, _, _ = der.read_tlv(raw, 0)
    if tag != 0x30:
        raise VerifyError("certificate is not a SEQUENCE")
    fields = der.children(content)
    if len(fields) != 3:
        raise VerifyError("malformed certificate")
    tbs_tag, tbs_content, _, tbs_raw = der.read_tlv(fields[0][2], 0)
    tbs = der.children(tbs_content)
    index = 0
    version = 1
    if tbs and tbs[0][0] == 0xA0:
        version = der.decode_integer(der.children(tbs[0][1])[0][1]) + 1
        index = 1
    serial = der.decode_integer(tbs[index][1])
    signature_alg = der.decode_oid(der.children(tbs[index + 1][1])[0][1])
    issuer_raw = tbs[index + 2][2]
    validity = tbs[index + 3][1]
    subject_raw = tbs[index + 4][2]
    spki_raw = tbs[index + 5][2]
    validity_fields = der.children(validity)
    not_before = der.decode_time(validity_fields[0][0], validity_fields[0][1])
    not_after = der.decode_time(validity_fields[1][0], validity_fields[1][1])
    extensions = {}
    for field in tbs[index + 6:]:
        if field[0] == 0xA3:
            wrapper = der.children(field[1])
            if len(wrapper) != 1 or wrapper[0][0] != 0x30:
                raise VerifyError("malformed Extensions wrapper")
            for ext in der.children(wrapper[0][1]):
                if ext[0] != 0x30:
                    raise VerifyError("malformed Extension")
                ext_fields = der.children(ext[1])
                ext_oid = der.decode_oid(ext_fields[0][1])
                value = b""
                for tag_value, content, _ in ext_fields[1:]:
                    if tag_value == 0x04:
                        value = content
                extensions[ext_oid] = value
    spki_fields = der.children(der.content_of(spki_raw))
    algorithm = der.decode_oid(der.children(spki_fields[0][1])[0][1])
    key_bits = spki_fields[1][1][1:] if spki_fields[1][0] == 0x03 else b""
    rsa_key = der.read_tlv(key_bits, 0)
    rsa_fields = der.children(rsa_key[1])
    modulus = der.decode_integer(rsa_fields[0][1])
    exponent = der.decode_integer(rsa_fields[1][1])
    eku = _parse_eku(extensions.get(EXTENSION_EKU_OID, b""))
    is_ca = _parse_basic_constraints_ca(extensions.get(EXTENSION_BASIC_CONSTRAINTS_OID))
    return {
        "raw": raw,
        "version": version,
        "serial": serial,
        "signature_algorithm": signature_alg,
        "issuer_raw": issuer_raw,
        "subject_raw": subject_raw,
        "not_before": not_before,
        "not_after": not_after,
        "public_key_algorithm": algorithm,
        "modulus": modulus,
        "exponent": exponent,
        "extensions": dict(extensions),
        "eku": eku,
        "is_ca": is_ca,
        "is_self_issued": issuer_raw == subject_raw,
        "tbs_raw": tbs_raw,
        "signature": fields[2][1][1:] if fields[2][0] == 0x03 else fields[2][1],
    }


def _parse_eku(value: bytes) -> list[str]:
    if not value:
        return []
    try:
        tag, content, _, _ = der.read_tlv(value, 0)
        if tag != 0x30:
            return []
        result = []
        for item in der.children(content):
            if item[0] == 0x06:
                result.append(der.decode_oid(item[1]))
        return result
    except der.DerError:
        return []


def _parse_basic_constraints_ca(value: bytes | None) -> bool:
    if not value:
        return False
    try:
        tag, content, _, _ = der.read_tlv(value, 0)
        if tag != 0x30:
            return False
        fields = der.children(content)
        return bool(fields) and fields[0][0] == 0x01 and fields[0][1] != b"\x00"
    except der.DerError:
        return False


def parse_signer_info(raw: bytes) -> dict:
    tag, content, _, _ = der.read_tlv(raw, 0)
    if tag != 0x30:
        raise VerifyError("SignerInfo is not a SEQUENCE")
    fields = der.children(content)
    version = der.decode_integer(fields[0][1])
    issuer_serial = der.children(fields[1][1])
    issuer_raw = issuer_serial[0][2]
    serial = der.decode_integer(issuer_serial[1][1])
    digest_algorithm = der.decode_oid(der.children(fields[2][1])[0][1])
    index = 3
    signed_attrs = None
    signed_attrs_raw = None
    if fields[index][0] == 0xA0:
        attrs_content = fields[index][1]
        signed_attrs_raw = der.set_of([item[2] for item in der.children(attrs_content)])
        signed_attrs = {}
        for item in der.children(attrs_content):
            attr_fields = der.children(item[1])
            attr_oid = der.decode_oid(attr_fields[0][1])
            values = der.children(attr_fields[1][1]) if len(attr_fields) > 1 else []
            signed_attrs.setdefault(attr_oid, []).append(values[0][1] if values else b"")
        index += 1
    signature_algorithm = der.decode_oid(der.children(fields[index][1])[0][1])
    signature = fields[index + 1][1]
    return {
        "version": version,
        "issuer_raw": issuer_raw,
        "serial": serial,
        "digest_algorithm": digest_algorithm,
        "signed_attributes": signed_attrs,
        "signed_attributes_raw": signed_attrs_raw,
        "signature_algorithm": signature_algorithm,
        "signature": signature,
    }


def _hash_name_from_oid(oid_value: str) -> str | None:
    return crypto.OID_HASHES.get(oid_value)


def _verify_cert_signature(cert: dict, issuer: dict) -> tuple[bool, str]:
    digest_name = SIGNATURE_ALGORITHM_HASHES.get(cert["signature_algorithm"])
    if not digest_name:
        return False, f"unsupported certificate signature algorithm {cert['signature_algorithm']}"
    digest = hashlib.new(digest_name, cert["tbs_raw"]).digest()
    return crypto.pkcs1_v15_verify(
        issuer["modulus"], issuer["exponent"], cert["signature"],
        crypto.digest_info(digest_name, digest),
    )


def verify_certificate_chain(leaf: dict, pool: list[dict], anchors: list[dict]) -> dict:
    """Build and verify a simple issuer chain; trust only comes from anchors."""
    chain = [leaf]
    current = leaf
    seen = {leaf["serial"]}
    problems = []
    while True:
        if any(current["issuer_raw"] == anchor["subject_raw"] and current["issuer_raw"] != current["subject_raw"]
               for anchor in anchors):
            issuer = next(anchor for anchor in anchors if current["issuer_raw"] == anchor["subject_raw"])
            chain.append(issuer)
            break
        if current["is_self_issued"]:
            break
        issuer = next((cert for cert in pool if cert["subject_raw"] == current["issuer_raw"] and cert["serial"] not in seen), None)
        if issuer is None:
            problems.append("issuer not found in supplied pool or trust anchors")
            break
        chain.append(issuer)
        seen.add(issuer["serial"])
        current = issuer
    verified = True
    for child, parent in zip(chain, chain[1:]):
        ok, reason = _verify_cert_signature(child, parent)
        if not ok:
            verified = False
            problems.append(f"certificate {child['serial']} signature: {reason}")
    root = chain[-1]
    anchored = any(root["raw"] == anchor["raw"] for anchor in anchors)
    leaf_is_ca = leaf["is_ca"]
    return {
        "chain_serials": [cert["serial"] for cert in chain],
        "chain_subjects": [_name_to_text(cert["subject_raw"]) for cert in chain],
        "signatures_verified": verified,
        "anchored_in_supplied_store": anchored,
        "leaf_is_ca": leaf_is_ca,
        "problems": problems,
        "trusted": verified and anchored and not leaf_is_ca,
    }


def _decode_directory_string(tag: int, value: bytes) -> str:
    if tag == 0x1E:
        return value.decode("utf-16-be", "replace")
    if tag in (0x13, 0x16, 0x0C):
        return value.decode("utf-8", "replace")
    return value.hex()


def _name_to_text(raw: bytes) -> str:
    try:
        tag, content, _, _ = der.read_tlv(raw, 0)
        parts = []
        for rdn in der.children(content):
            for attr in der.children(rdn[1]):
                fields = der.children(attr[1])
                if len(fields) >= 2:
                    parts.append(f"{der.decode_oid(fields[0][1])}={_decode_directory_string(fields[1][0], fields[1][1])}")
        return ", ".join(parts)
    except (der.DerError, IndexError):
        return raw.hex()


def authenticode_check(image: bytes, anchors: list[dict] | None = None, now=None) -> dict:
    import datetime as dt

    anchors = anchors or []
    if now is None:
        now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert_entries = parse_win_certificates(image)
    result = {
        "certificate_entries": [
            {
                "offset": entry["offset"],
                "length": entry["length"],
                "revision": entry["revision"],
                "certificate_type": entry["certificate_type"],
                "pkcs7_length": len(entry["data"]),
            }
            for entry in cert_entries
        ],
        "authenticode_digest": None,
        "covered_ranges": [],
        "signed_content_digest": None,
        "digest_matches": None,
        "signer_signature_valid": None,
        "message_digest_attribute_matches": None,
        "certificate_chain": None,
        "verdict": {},
    }
    if not cert_entries:
        result["verdict"] = {
            "signature": "absent",
            "trust": "not applicable",
            "note": "No WIN_CERTIFICATE entry; the file has no Authenticode signature.",
        }
        return result
    entry = next((item for item in cert_entries if item["certificate_type"] == 0x0002), None)
    if entry is None:
        result["verdict"] = {"signature": "unsupported certificate type", "trust": "not established"}
        return result
    try:
        pkcs7 = parse_pkcs7(entry["data"])
    except (der.DerError, VerifyError) as exc:
        result["verdict"] = {"signature": "malformed", "trust": "not established", "error": str(exc)}
        return result
    digest_name = None
    signed_content = pkcs7["encap_content"]
    signed_digest = None
    if signed_content:
        try:
            tag, content, _, _ = der.read_tlv(signed_content, 0)
            fields = der.children(content)
            digest_info = der.children(fields[1][1])
            digest_name = _hash_name_from_oid(der.decode_oid(der.children(digest_info[0][1])[0][1]))
            signed_digest = digest_info[1][1]
        except (der.DerError, IndexError):
            pass
    image_digest, ranges, cert_offset = authenticode_digest(image, digest_name or "sha256")
    cert_size = pefile.PE(data=image, fast_load=True).OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
    trailing_start = cert_offset + cert_size if cert_offset else len(image)
    trailing_bytes = max(0, len(image) - trailing_start)
    result["authenticode_digest"] = image_digest.hex()
    result["signed_content_digest"] = signed_digest.hex() if signed_digest else None
    result["covered_ranges"] = [
        {"start": start, "end": end, "label": label, "length": end - start} for start, end, label in ranges
    ]
    result["digest_matches"] = bool(signed_digest) and signed_digest == image_digest
    result["unauthenticated_trailing_bytes"] = trailing_bytes
    result["coverage_note"] = (
        "Authenticode does not hash the certificate table nor bytes appended after it; "
        "those bytes are outside the signed content."
    )
    if not pkcs7["signer_infos"]:
        result["verdict"] = {"signature": "no SignerInfo", "trust": "not established"}
        return result
    signer = pkcs7["signer_infos"][0]
    attrs = signer["signed_attributes"] or {}
    content_type_attr = attrs.get(CONTENT_TYPE_OID, [b""])[0]
    message_digest_attr = attrs.get(MESSAGE_DIGEST_OID, [b""])[0]
    result["message_digest_attribute_matches"] = (
        bool(message_digest_attr) and bool(signed_content)
        and hashlib.new(digest_name, signed_content).digest() == message_digest_attr
    ) if digest_name else None
    leaf = next((cert for cert in pkcs7["certificates"] if cert["serial"] == signer["serial"] and cert["issuer_raw"] == signer["issuer_raw"]), None)
    if leaf is None:
        result["verdict"] = {"signature": "signer certificate not found", "trust": "not established"}
        return result
    ok = False
    detail = "no signed attributes"
    if signer["signed_attributes_raw"] and digest_name:
        digest = hashlib.new(digest_name, signer["signed_attributes_raw"]).digest()
        ok, detail = crypto.pkcs1_v15_verify(leaf["modulus"], leaf["exponent"], signer["signature"], crypto.digest_info(digest_name, digest))
    result["signer_signature_valid"] = ok
    result["signer_signature_detail"] = detail
    result["signer"] = {
        "subject": _name_to_text(leaf["subject_raw"]),
        "issuer": _name_to_text(leaf["issuer_raw"]),
        "serial": leaf["serial"],
        "not_before": leaf["not_before"].isoformat(),
        "not_after": leaf["not_after"].isoformat(),
        "eku": leaf["eku"],
        "signature_algorithm": leaf["signature_algorithm"],
    }
    chain = verify_certificate_chain(leaf, pkcs7["certificates"], anchors)
    result["certificate_chain"] = chain
    within_validity = leaf["not_before"] <= now <= leaf["not_after"]
    code_signing_eku = EKU_CODE_SIGNING_OID in leaf["eku"]
    result["leaf_within_validity"] = within_validity
    result["leaf_has_code_signing_eku"] = code_signing_eku
    result["timestamp_present"] = False
    signature_ok = bool(ok and result["digest_matches"] and result["message_digest_attribute_matches"])
    trust_ok = bool(chain["trusted"] and within_validity and code_signing_eku)
    result["verdict"] = {
        "signature": "cryptographically valid" if signature_ok else "invalid",
        "unauthenticated_trailing_bytes": trailing_bytes,
        # Independent axes: a mathematically valid signature over an untrusted
        # certificate is still "not trusted"; a broken signature over a trusted
        # certificate is still "invalid".
        "trust": "trusted by supplied anchors" if trust_ok else "not trusted",
        "published_by_trusted_publisher": bool(signature_ok and trust_ok),
        "publisher_identity": "certificate subject only, and only if the chain is trusted",
        "note": "Authenticode covers the whole file except checksum, the certificate directory entry and the certificate table. A mathematical signature over an untrusted certificate does not make the publisher trustworthy.",
    }
    return result
