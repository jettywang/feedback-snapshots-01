#!/usr/bin/env python3
"""Generates minimal Authenticode-signed PE samples for the dual-signature
investigation. Fully offline; uses the openssl CLI only for key/certificate
generation and RSA signing, and signify itself for authentihash calculation.

Layouts produced (all in investigation/samples/):
  A  multi-cert-entry.exe   PE Certificate Table with TWO WIN_CERTIFICATE entries
                            (entry 1: SHA-1 SignedData by leaf1,
                             entry 2: SHA-256 SignedData by leaf2)
  A' multi-cert-tampered.exe  same as A but one byte of the .text section flipped
                            (negative control for the file-digest check)
  B  nested-signature.exe   ONE SignedData (SHA-1, leaf1) carrying a second
                            SignedData (SHA-256, leaf2) in the
                            microsoft_nested_signature unauthenticated attribute
  C1 multi-signerinfo-same-digest.exe
                            ONE SignedData with TWO SignerInfos, both SHA-256
  C2 multi-signerinfo-two-digests.exe
                            ONE SignedData with TWO SignerInfos (SHA-1 + SHA-256)
"""

import hashlib
import pathlib
import struct
import subprocess

from asn1crypto import algos, cms
from asn1crypto import x509 as ax509

from signify.asn1 import spc
from signify.authenticode.signed_file.pe import SignedPEFile

HERE = pathlib.Path(__file__).resolve().parent
KEYS = HERE / "keys"
SAMPLES = HERE / "samples"

SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"
NESTED_SIG_CLASS_ID = "a6b586d5-b4a1-2466-ae05-a217da8e60d6"


# ---------------------------------------------------------------------------
# certificates (openssl CLI)
# ---------------------------------------------------------------------------

def run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True)


def make_certificates() -> None:
    KEYS.mkdir(exist_ok=True)
    if (KEYS / "ca.crt").exists():
        return
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(KEYS / "ca.key"), "-out", str(KEYS / "ca.crt"),
        "-days", "3650", "-subj", "/CN=Investigation Root CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    for name in ("leaf1", "leaf2"):
        run(
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(KEYS / f"{name}.key"), "-out", str(KEYS / f"{name}.csr"),
            "-subj", f"/CN=DualSign {name}",
        )
        ext = KEYS / f"{name}.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=codeSigning\n"
        )
        run(
            "openssl", "x509", "-req", "-in", str(KEYS / f"{name}.csr"),
            "-CA", str(KEYS / "ca.crt"), "-CAkey", str(KEYS / "ca.key"),
            "-CAcreateserial", "-days", "1825", "-out", str(KEYS / f"{name}.crt"),
            "-extfile", str(ext),
        )


def load_cert(name: str) -> ax509.Certificate:
    pem = (KEYS / f"{name}.crt").read_bytes()
    return ax509.Certificate.load(__import__("asn1crypto").pem.unarmor(pem)[2])


def rsa_sign(digest: str, key_name: str, data: bytes) -> bytes:
    proc = subprocess.run(
        ["openssl", "dgst", f"-{digest}", "-sign", str(KEYS / f"{key_name}.key")],
        input=data, capture_output=True, check=True,
    )
    return proc.stdout


# ---------------------------------------------------------------------------
# minimal PE32 file
# ---------------------------------------------------------------------------

def build_pe(cert_table: bytes) -> bytes:
    pe_offset = 0x80
    opt_size = 0xE0
    opt_offset = pe_offset + 24
    section_header_offset = opt_offset + opt_size
    section_data_offset = 0x200
    section_data = bytes(
        (i * 7 + 13) % 256 for i in range(0x200)
    )  # deterministic "code"
    cert_offset = section_data_offset + len(section_data)

    dos = bytearray(pe_offset)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    coff = struct.pack(
        "<HHIIIHH",
        0x14C,  # Machine: i386 (page size 0x1000)
        1,      # NumberOfSections
        0, 0, 0,
        opt_size,
        0x0102,  # Characteristics: executable, 32-bit
    )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)          # PE32 magic
    struct.pack_into("<I", opt, 4, 0x1000)         # AddressOfEntryPoint
    struct.pack_into("<I", opt, 16, 0x400000)      # ImageBase
    struct.pack_into("<I", opt, 20, 0x1000)        # SectionAlignment
    struct.pack_into("<I", opt, 24, 0x200)         # FileAlignment
    # CheckSum at +64 stays 0 (excluded from the hash anyway)
    struct.pack_into("<H", opt, 68, 3)             # Subsystem: console
    struct.pack_into("<I", opt, 92, 16)            # NumberOfRvaAndSizes
    # Data Directory [4] = Certificate Table (file offset, not RVA)
    struct.pack_into("<II", opt, 128, cert_offset, len(cert_table))

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", 0x200, 0x1000, len(section_data),
        section_data_offset, 0, 0, 0, 0, 0x60000020,
    )

    pe = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + section
    pe = pe.ljust(section_data_offset, b"\0") + section_data
    assert len(pe) == cert_offset
    return pe + cert_table


def build_cert_table(blobs: list[bytes]) -> bytes:
    table = b""
    for i, blob in enumerate(blobs):
        length = 8 + len(blob)
        entry = struct.pack("<IHH", length, 0x0200, 0x0002) + blob
        if i < len(blobs) - 1:
            entry = entry.ljust(length + (8 - length % 8) % 8, b"\0")
        table += entry
    return table


# ---------------------------------------------------------------------------
# Authenticode SignedData construction
# ---------------------------------------------------------------------------

def build_indirect_data(digest: str, authentihash: bytes) -> spc.SpcIndirectDataContent:
    pe_image_data = spc.SpcPeImageData({
        "flags": {"include_resources"},
        "file": ("moniker", spc.SpcSerializedObject({
            "class_id": NESTED_SIG_CLASS_ID,
            # empty SET OF, so that page-hash parsing yields nothing
            "serialized_data": spc.SetOfSpcAttributeTypeAndOptionalValue([]),
        })),
    })
    return spc.SpcIndirectDataContent({
        "data": spc.SpcAttributeTypeAndOptionalValue({
            "type": "microsoft_spc_pe_image_data",
            "value": pe_image_data,
        }),
        "message_digest": algos.DigestInfo({
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": digest}),
            "digest": authentihash,
        }),
    })


def build_signer_info(
    digest: str, key_name: str, ca: ax509.Certificate, leaf: ax509.Certificate,
    content_tlv: bytes, unsigned_attrs: "cms.CMSAttributes | None" = None,
) -> cms.SignerInfo:
    message_digest = hashlib.new(digest, content_tlv).digest()
    attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": [SPC_INDIRECT_DATA_OID]}),
        cms.CMSAttribute({"type": "message_digest", "values": [message_digest]}),
    ])
    signature = rsa_sign(digest, key_name, attrs.dump())
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": ca.subject,
                "serial_number": leaf.serial_number,
            })
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": digest}),
        "signed_attrs": attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm(
            {"algorithm": f"{digest}_rsa"}
        ),
        "signature": signature,
    })
    if unsigned_attrs is not None:
        si["unsigned_attrs"] = unsigned_attrs
    return si


def build_envelope(
    digest_algorithms: list[str],
    indirect: spc.SpcIndirectDataContent,
    signer_infos: list[cms.SignerInfo],
    certs: list[ax509.Certificate],
) -> bytes:
    # v1 SignedData uses the PKCS#7 ContentInfo form: eContent is
    # [0] EXPLICIT SpcIndirectDataContent (same layout as real Authenticode).
    encap = cms.ContentInfo({
        "content_type": "microsoft_spc_indirect_data_content",
        "content": indirect,
    })
    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [
            algos.DigestAlgorithm({"algorithm": d}) for d in digest_algorithms
        ],
        "encap_content_info": encap,
        "certificates": certs,
        "signer_infos": signer_infos,
    })
    return cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


def content_bytes_of(indirect: spc.SpcIndirectDataContent) -> bytes:
    """The bytes hashed into SignerInfo.messageDigest: the *contents* of the
    SpcIndirectDataContent SEQUENCE, tag and length stripped (RFC 2315 §9.3;
    see SignedData.get_content_digest). Verified against real-world
    Authenticode files (7z, sigcheck, SolarWinds, ...)."""
    return indirect.contents


def authentihash(pe: bytes, digest: str) -> bytes:
    import io

    spe = SignedPEFile(io.BytesIO(pe))
    return spe.get_fingerprint(getattr(hashlib, digest))


# ---------------------------------------------------------------------------
# sample assembly
# ---------------------------------------------------------------------------

def main() -> None:
    make_certificates()
    SAMPLES.mkdir(exist_ok=True)

    ca = load_cert("ca")
    leaf1 = load_cert("leaf1")
    leaf2 = load_cert("leaf2")

    # authentihashes are computed over the PE; the certificate table and its
    # data-directory entry are excluded, so hashes are layout-independent.
    # We compute them against a PE with an empty (but present) cert table.
    empty_pe = build_pe(b"")
    hashes = {d: authentihash(empty_pe, d) for d in ("sha1", "sha256")}

    indirect = {d: build_indirect_data(d, hashes[d]) for d in ("sha1", "sha256")}
    content_bytes = {d: content_bytes_of(indirect[d]) for d in ("sha1", "sha256")}

    def si(
        digest: str, key: str, leaf: ax509.Certificate, content_digest: str | None = None
    ) -> cms.SignerInfo:
        # content_digest selects which eContent the signer signs; all signers in
        # one SignedData must sign the SAME eContent, each with their own
        # digest algorithm (RFC 2315 §9.3).
        return build_signer_info(
            digest, key, ca, leaf, content_bytes[content_digest or digest]
        )

    # --- Layout A: two PE certificate table entries -------------------------
    env_a1 = build_envelope(["sha1"], indirect["sha1"], [si("sha1", "leaf1", leaf1)],
                            [leaf1, ca])
    env_a2 = build_envelope(["sha256"], indirect["sha256"],
                            [si("sha256", "leaf2", leaf2)], [leaf2, ca])
    sample_a = build_pe(build_cert_table([env_a1, env_a2]))
    (SAMPLES / "A-multi-cert-entry.exe").write_bytes(sample_a)

    # negative control: flip one byte inside .text (covered by the authentihash)
    tampered = bytearray(sample_a)
    tampered[0x200] ^= 0xFF
    (SAMPLES / "A-tampered.exe").write_bytes(bytes(tampered))

    # --- Layout B: nested signature -----------------------------------------
    env_b_inner = build_envelope(["sha256"], indirect["sha256"],
                                 [si("sha256", "leaf2", leaf2)], [leaf2, ca])
    nested_attr = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "microsoft_nested_signature",
            "values": [cms.ContentInfo.load(env_b_inner)],
        })
    ])
    si_outer = build_signer_info("sha1", "leaf1", ca, leaf1, content_bytes["sha1"],
                                 unsigned_attrs=nested_attr)
    env_b = build_envelope(["sha1"], indirect["sha1"], [si_outer], [leaf1, ca])
    (SAMPLES / "B-nested-signature.exe").write_bytes(
        build_pe(build_cert_table([env_b]))
    )

    # --- Layout C1: two SignerInfos, same digest algorithm ------------------
    env_c1 = build_envelope(
        ["sha256"], indirect["sha256"],
        [si("sha256", "leaf1", leaf1), si("sha256", "leaf2", leaf2)],
        [leaf1, leaf2, ca],
    )
    (SAMPLES / "C1-multi-signerinfo-same-digest.exe").write_bytes(
        build_pe(build_cert_table([env_c1]))
    )

    # --- Layout C2: two SignerInfos, different digest algorithms ------------
    env_c2 = build_envelope(
        ["sha1", "sha256"], indirect["sha256"],
        [si("sha1", "leaf1", leaf1, "sha256"), si("sha256", "leaf2", leaf2)],
        [leaf1, leaf2, ca],
    )
    (SAMPLES / "C2-multi-signerinfo-two-digests.exe").write_bytes(
        build_pe(build_cert_table([env_c2]))
    )

    # --- Layout D: multi-SignerInfo entry followed by a valid entry --------
    # shows whether one unsupported entry poisons the remaining entries
    env_d2 = build_envelope(["sha256"], indirect["sha256"],
                            [si("sha256", "leaf2", leaf2)], [leaf2, ca])
    (SAMPLES / "D-poisoned-first-entry.exe").write_bytes(
        build_pe(build_cert_table([env_c1, env_d2]))
    )

    for path in sorted(SAMPLES.iterdir()):
        print(f"wrote {path.name}: {path.stat().st_size} bytes")


if __name__ == "__main__":
    main()
