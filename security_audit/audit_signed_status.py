#!/usr/bin/env python3
"""Audit: where do "signed capsule" and "AUTH_VALID" claims actually come from?

Three experiments, all printing real call results as JSON:

A. GuidDefinedSection authStatus: is it crypto, or a status bit echo?
B. Aptio "signed" capsule: is anything verified, or only the GUID name?
C. Independent cryptographic verification (openssl) of the same capsule
   body, with a tampered control, to show what real verification requires.
"""

import contextlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from uefi_firmware import AutoParser
from uefi_firmware.misc.checker import AptioSignedCapsuleTester
from uefi_firmware.structs.uefi_structs import (
    APTIO_SIGNED_CAPSULE_GUID,
    APTIO_UNSIGNED_CAPSULE_GUID,
    FIRMWARE_VOLUME_GUIDS,
)
from uefi_firmware.uefi import FirmwareFileSystemSection, FirmwareVolume

UNKNOWN_SECTION_GUID = uuid.UUID("01234567-89ab-4def-8123-456789abcdef").bytes_le
FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le


def quietly(function, *args):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args)


# ---------------------------------------------------------------- builders

def make_guided_section(attrs, payload, preamble=b""):
    """Common header (type 0x02) + GUID-defined header with a chosen attrs."""
    offset = 4 + 20 + len(preamble)
    body = UNKNOWN_SECTION_GUID + struct.pack("<HH", offset, attrs) \
        + preamble + payload
    size = 4 + len(body)
    return struct.pack("<I", size)[:3] + b"\x02" + body


def parse_guided(section_bytes):
    section = FirmwareFileSystemSection(section_bytes, FILE_GUID)
    quietly(section.process)
    return section.parsed_object.to_dict()


def make_volume(size=0x1000):
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = FirmwareVolume._HEADER_SIZE + len(block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le,
        size, b"_FVH", 0, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + b"\xff" * (size - hdrlen)


def make_rom():
    return b"\xff" * 0x100 + make_volume() + b"\xff" * 0x100


def make_aptio_capsule(guid, rom, header_size=0x40):
    header = uuid.UUID(guid).bytes_le + struct.pack(
        "<IIIHH", header_size, 0, header_size + len(rom), header_size, 0)
    return header.ljust(header_size, b"\x00") + rom


def parse_capsule(data):
    capsule = AutoParser(data).parse()
    ok = quietly(capsule.process)
    return capsule, ok


# ------------------------------------------------------- A. AUTH_VALID bit

def experiment_a():
    payload = b"firmware payload, signed or not"
    tampered = b"firmware payload, TAMPERED!!!"

    out = {"claim_under_test": "authStatus == 'AUTH_VALID' means the section "
                               "content was cryptographically verified"}
    for label, attrs, body in [
        ("bit set, original payload", 0x02, payload),
        ("bit set, tampered payload", 0x02, tampered),
        ("bit clear, original payload", 0x00, payload),
    ]:
        info = parse_guided(make_guided_section(attrs, body))
        out[label] = {
            "attrs_field": attrs,
            "payload_sha256_first8": __import__("hashlib").sha256(body)
            .hexdigest()[:8],
            "parser_reported_authStatus": info["authStatus"],
        }
    out["source_of_truth"] = (
        "uefi_firmware/uefi.py GuidDefinedSection.to_dict()/showinfo(): "
        "authStatus is 'AUTH_VALID' iff the 2-byte attrs field in the "
        "section header == 0x02 (ATTR_AUTH_STATUS_VALID). No signature, "
        "certificate or hash is ever checked.")
    return out


# ------------------------------------------------- B. signed capsule GUID

def experiment_b():
    rom = make_rom()
    signed = make_aptio_capsule(APTIO_SIGNED_CAPSULE_GUID, rom)
    unsigned = make_aptio_capsule(APTIO_UNSIGNED_CAPSULE_GUID, rom)
    tampered = bytearray(signed)
    tampered[0x40 + 0x80] ^= 0xFF  # flip a byte inside the ROM body

    results = {"claim_under_test": "a capsule carrying "
                                   "APTIO_SIGNED_CAPSULE_GUID had its "
                                   "signature verified"}
    for label, data in [("signed GUID, intact ROM", bytes(signed)),
                        ("unsigned GUID, same ROM", bytes(unsigned)),
                        ("signed GUID, tampered ROM", bytes(tampered))]:
        capsule, ok = parse_capsule(data)
        results[label] = {
            "parsed_type": type(capsule).__name__,
            "process_returned": ok,
            "capsule_guid": capsule.to_dict()["capsuleGuid"],
            "signature_error_raised": False,
        }
    results["detector_implementation"] = (
        "misc/checker.py AptioSignedCapsuleTester.match(): "
        "data[:16] == GUID bytes, nothing else")
    results["detector_accepts_guid_plus_garbage"] = \
        AptioSignedCapsuleTester().match(
            uuid.UUID(APTIO_SIGNED_CAPSULE_GUID).bytes_le + b"\x00" * 64)
    results["source_of_truth"] = (
        "uefi.py FirmwareCapsule.parse_capsule_header(): the signed and "
        "unsigned Aptio GUIDs take the identical code path; the AMI "
        "signing block is never located, parsed or verified.")
    return results


# ----------------------------- C. independent cryptographic verification

def run(cmd, **kw):
    proc = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def experiment_c():
    """Sign the capsule body with openssl; verify intact and tampered."""
    rom = make_rom()
    capsule = make_aptio_capsule(APTIO_SIGNED_CAPSULE_GUID, rom)
    body_offset = 0x40  # RomImageOffset in our fixture
    body = capsule[body_offset:]

    tmp = tempfile.mkdtemp(prefix="capsule_audit_")
    key = os.path.join(tmp, "audit_key.pem")
    cert = os.path.join(tmp, "audit_cert.pem")
    sig = os.path.join(tmp, "body.sig")
    good = os.path.join(tmp, "body.bin")
    bad = os.path.join(tmp, "body.tampered.bin")

    with open(good, "wb") as fh:
        fh.write(body)
    tampered = bytearray(body)
    tampered[0x80] ^= 0xFF
    with open(bad, "wb") as fh:
        fh.write(bytes(tampered))

    log = {}
    log["keygen"] = run(["openssl", "genrsa", "-out", key, "2048"])
    log["selfsigned_cert"] = run([
        "openssl", "req", "-new", "-x509", "-key", key, "-out", cert,
        "-days", "1", "-subj", "/CN=audit-demo-untrusted-root"])
    log["sign_body_sha256"] = run([
        "openssl", "dgst", "-sha256", "-sign", key, "-out", sig, good])
    pub = _pubkey(tmp, cert)
    log["verify_intact"] = run([
        "openssl", "dgst", "-sha256", "-verify", pub,
        "-signature", sig, good])
    log["verify_tampered"] = run([
        "openssl", "dgst", "-sha256", "-verify", pub,
        "-signature", sig, bad])

    return {
        "signed_byte_range": "capsule[0x%x:0x%x] (RomImageOffset..end), "
                             "%d bytes" % (body_offset, len(capsule),
                                           len(body)),
        "trust_material": "caller-supplied certificate (%s); self-signed "
                          "here, i.e. NO real trust anchor. uefi_firmware "
                          "ships no vendor keys and has no API to accept "
                          "one." % cert,
        "openssl_transcript": {
            k: {"returncode": v[0], "output": v[1]}
            for k, v in log.items()},
        "conclusion": "math verification is possible only with (1) an "
                      "explicit byte range, (2) a signature blob located "
                      "by real parsing, (3) a caller-supplied trust root. "
                      "None of the three exists in uefi_firmware today.",
    }


def _pubkey(tmp, cert):
    pub = os.path.join(tmp, "audit_pub.pem")
    subprocess.run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"],
                   stdout=open(pub, "w"), check=True)
    return pub


if __name__ == "__main__":
    report = {
        "A_auth_valid_status_bit": experiment_a(),
        "B_signed_capsule_guid": experiment_b(),
        "C_independent_crypto_check": experiment_c(),
    }
    print(json.dumps(report, indent=2))
