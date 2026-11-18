"""Deterministic fixture matrix for the strong-name / Authenticode lab.

Every image is a synthetic managed PE file.  Nothing here executes an
analysed assembly.  Keys are derived from fixed seeds so reruns produce
byte-identical fixtures.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from Crypto.PublicKey import RSA

from . import authenticode, crypto, pe_builder, verify

SEED = b"strongname-lab-v1"


def _rng(seed: bytes):
    counter = 0
    while True:
        block = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        yield block
        counter += 1


def _key_from_seed(label: str, bits: int = 2048, exponent: int = 65537) -> RSA.RsaKey:
    """Deterministic RSA key whose modulus is exactly *bits* bits."""
    from Crypto.Util.number import getPrime

    for attempt in range(64):
        material = hashlib.sha512(SEED + b":" + label.encode() + attempt.to_bytes(2, "big")).digest()
        # getPrime accepts a randfunc; feed it a deterministic stream derived
        # from the label so the fixture bytes never change between runs.
        stream = _rng(material)
        buffer = bytearray()

        def randfunc(n: int, source=stream, buf=buffer) -> bytes:
            while len(buf) < n:
                buf.extend(next(source))
            chunk = bytes(buf[:n])
            del buf[:n]
            return chunk

        p = getPrime(bits // 2, randfunc=randfunc)
        q = getPrime(bits // 2, randfunc=randfunc)
        if p == q:
            continue
        modulus = p * q
        if modulus.bit_length() != bits:
            continue
        return RSA.construct((modulus, exponent, pow(exponent, -1, (p - 1) * (q - 1))))
    raise RuntimeError(f"could not derive a {bits}-bit key for {label}")


def keys():
    return {
        "signer": _key_from_seed("signer"),
        "twin": _key_from_seed("twin"),
        "root": _key_from_seed("root"),
        "other_root": _key_from_seed("other-root"),
    }


def _root_and_leaf(label: str):
    material = keys()
    root_key = material["root"]
    leaf_key = material["signer"]
    root_subject = authenticode.name(
        (authenticode.OID_CN, "Strong-Name Lab Root"),
        (authenticode.OID_O, "Offline Lab"),
    )
    leaf_subject = authenticode.name(
        (authenticode.OID_CN, "Contoso Example Publisher"),
        (authenticode.OID_O, "Offline Lab"),
        (authenticode.OID_OU, "Code Signing"),
    )
    root_cert = authenticode.build_certificate(
        subject=root_subject,
        issuer=root_subject,
        subject_key=root_key,
        issuer_key=root_key,
        serial=0x1001,
        not_before=dt.datetime(2024, 1, 1),
        not_after=dt.datetime(2032, 1, 1),
        ca=True,
        path_length=0,
    )
    leaf_cert = authenticode.build_certificate(
        subject=leaf_subject,
        issuer=root_subject,
        subject_key=leaf_key,
        issuer_key=root_key,
        serial=0x2001,
        not_before=dt.datetime(2024, 1, 1),
        not_after=dt.datetime(2028, 1, 1),
        ca=False,
        eku=[authenticode.OID_CODE_SIGNING],
    )
    return root_cert, leaf_cert, root_key, leaf_key


class Fixture:
    def __init__(self, path: Path, data: bytes, notes: list[str]):
        self.path = path
        self.data = data
        self.notes = notes

    def write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(self.data)


def _build_base(*, key: RSA.RsaKey, signed: bool, slot: bool | None = None, flag: bool | None = None,
                name: str = "Contoso.Utils", version: str = "1.0.0.0", body: bytes = b"\x00\x2a") -> bytes:
    blob = crypto.public_key_blob(key)
    image = pe_builder.build_managed_pe(
        assembly_name=name,
        version=version,
        key=key,
        strong_name_signed=signed,
        public_key_blob=blob,
        strong_name_slot=slot,
        strong_name_flag=flag,
        method_body=body,
    )
    if signed:
        info = verify.parse_managed(image)
        image = pe_builder.sign_strong_name(image, key, info["signature_offset"], info["strong_name_size"])
    return image


def _build_without_public_key_flag(key: RSA.RsaKey, *, name: str, version: str) -> bytes:
    """Valid signature over an assembly whose PublicKey flag is not set."""
    image = pe_builder.build_managed_pe(
        assembly_name=name, version=version, key=key, strong_name_signed=True,
        public_key_blob=crypto.public_key_blob(key), assembly_flags=0,
    )
    info = verify.parse_managed(image)
    return pe_builder.sign_strong_name(
        image, key, info["signature_offset"], info["strong_name_size"],
    )


def build_all(root: Path) -> dict[str, dict]:
    root = Path(root)
    key_set = keys()
    root_cert, leaf_cert, root_key, leaf_key = _root_and_leaf("signer")
    other_root_subject = authenticode.name(
        (authenticode.OID_CN, "Other Root"), (authenticode.OID_O, "Elsewhere"),
    )
    other_root_cert = authenticode.build_certificate(
        subject=other_root_subject, issuer=other_root_subject,
        subject_key=key_set["other_root"], issuer_key=key_set["other_root"], serial=0x3001,
        not_before=dt.datetime(2024, 1, 1), not_after=dt.datetime(2032, 1, 1), ca=True, path_length=0,
    )
    other_leaf_cert = authenticode.build_certificate(
        subject=authenticode.name((authenticode.OID_CN, "Contoso Example Publisher"), (authenticode.OID_O, "Offline Lab")),
        issuer=other_root_subject, subject_key=leaf_key, issuer_key=key_set["other_root"], serial=0x3002,
        not_before=dt.datetime(2024, 1, 1), not_after=dt.datetime(2028, 1, 1), ca=False,
        eku=[authenticode.OID_CODE_SIGNING],
    )

    images: dict[str, bytes] = {}
    images["sn_full"] = _build_base(key=leaf_key, signed=True, name="Contoso.Utils", version="1.0.0.0")
    images["sn_delay"] = _build_base(key=leaf_key, signed=False, slot=True, flag=False,
                                     name="Contoso.Utils", version="1.0.0.0")
    images["sn_flag_only"] = _build_base(key=leaf_key, signed=False, slot=False, flag=True,
                                         name="Contoso.Utils", version="1.0.0.0")
    images["sn_no_material"] = _build_base(key=leaf_key, signed=False, slot=False, flag=False,
                                           name="Contoso.Utils", version="1.0.0.0")
    images["sn_sha256"] = _build_sha256(leaf_key, name="Contoso.Utils", version="1.0.0.0")
    images["sn_flag_without_public_key_flag"] = _build_without_public_key_flag(
        leaf_key, name="Contoso.Utils", version="1.0.0.0",
    )

    # Same identity strings, different key, fully valid signature.  This is the
    # contrast to the token-forgery case: name/version/token surface are not
    # sufficient; only signature verification binds the file to the key.
    other_key = _key_from_seed("other-signer")
    images["sn_other_key_valid"] = _build_base(
        key=other_key, signed=True, name="Contoso.Utils", version="1.0.0.0",
    )

    # Same public key/token, body byte changed after signing.
    tampered = bytearray(images["sn_full"])
    info = verify.parse_managed(bytes(tampered))
    method_offset = info["method_entries"][0]["offset"]
    if method_offset is None:
        raise RuntimeError("fixture method has no RVA")
    tampered[method_offset + 1] ^= 0x01
    images["sn_body_tampered"] = bytes(tampered)

    # Token-preserving forgery: sign with a different private key, then swap
    # in the original public key blob.  The token therefore stays the same
    # because the token is derived from the blob, not from the signature.
    forgery_key = _key_from_seed("forger")
    forged = _build_base(key=forgery_key, signed=True, name="Contoso.Utils", version="1.0.0.0")
    forged_blob = crypto.public_key_blob(forgery_key)
    signer_blob = crypto.public_key_blob(leaf_key)
    if len(forged_blob) != len(signer_blob):
        raise RuntimeError("fixture keys must have equal modulus sizes")
    if forged.count(forged_blob) != 1:
        raise RuntimeError("expected exactly one public-key blob in the image")
    forged = forged.replace(forged_blob, signer_blob)
    images["sn_token_forgery"] = forged

    # Authenticode images.
    images["auth_full"] = authenticode.sign_authenticode(
        images["sn_full"], leaf_cert=leaf_cert, leaf_key=leaf_key, extra_certs=[root_cert],
    )
    images["auth_untrusted_root"] = authenticode.sign_authenticode(
        images["sn_full"], leaf_cert=other_leaf_cert, leaf_key=leaf_key,
        extra_certs=[other_root_cert],
    )
    images["auth_wrong_digest"] = authenticode.sign_authenticode(
        images["sn_full"], leaf_cert=leaf_cert, leaf_key=leaf_key, extra_certs=[root_cert],
        tamper_image_digest=True,
    )
    auth_tampered = bytearray(images["auth_full"])
    auth_info = verify.parse_managed(bytes(auth_tampered))
    auth_tampered[auth_info["method_entries"][0]["offset"] + 1] ^= 0x01
    images["auth_body_tampered"] = bytes(auth_tampered)

    # Coverage contrast: data appended between the sections and the certificate
    # table is inside the Authenticode digest but outside the strong-name hash.
    # Sign with the overlay present, then flip one overlay byte.
    overlay = b"OVERLAY-BEFORE-CERTIFICATE-TABLE"
    overlay_signed = authenticode.sign_authenticode(
        images["sn_full"] + overlay, leaf_cert=leaf_cert, leaf_key=leaf_key, extra_certs=[root_cert],
    )
    overlay_offset = len(images["sn_full"])
    overlay_edit = bytearray(overlay_signed)
    overlay_edit[overlay_offset] ^= 0x01
    images["dual_overlay"] = bytes(overlay_edit)

    # Bytes appended after the certificate table are outside both digests, so
    # neither scheme notices them.  This is a coverage limit, not a strength.
    images["dual_trailing"] = images["auth_full"] + b"APPENDED-AFTER-CERTIFICATE-TABLE"

    # Both schemes exclude the PE checksum field: editing it keeps both valid.
    checksum_edit = bytearray(images["auth_full"])
    checksum_offset = verify._optional_header_offset(images["auth_full"]) + 64
    checksum_edit[checksum_offset] ^= 0x01
    images["dual_checksum_edit"] = bytes(checksum_edit)

    notes = {
        "sn_full": ["完整强名称：公钥存在、槽位存在、SHA-1 签名有效"],
        "sn_delay": ["延迟签名：分配了签名槽和公钥，但槽位为零"],
        "sn_flag_only": ["仅设置 COMIMAGE_FLAGS_STRONGNAMESIGNED，没有任何签名材料"],
        "sn_no_material": ["无公钥、无槽位、无标志的对照"],
        "sn_sha256": ["Assembly.HashAlgId=SHA-256 的强名称签名"],
        "sn_flag_without_public_key_flag": ["签名有效，但 AssemblyFlags.PublicKey 未设置；公钥 blob 仍在"],
        "sn_other_key_valid": ["同样的名称/版本，另一密钥的完整有效签名（token 不同）"],
        "sn_body_tampered": ["签名后修改 IL 方法体一个字节"],
        "sn_token_forgery": ["换用另一私钥签名后把原公钥写回元数据；token 不变，签名不成立"],
        "auth_full": ["强名称 + Authenticode，链锚定到随附根证书"],
        "auth_untrusted_root": ["签名数学有效，但颁发者不在随附信任锚中"],
        "auth_wrong_digest": ["PKCS#7 里封装的 PE 摘要被改坏"],
        "auth_body_tampered": ["Authenticode 签名后修改方法体"],
        "dual_overlay": ["签名后修改节与证书表之间的附加数据：强名称仍有效，Authenticode 失效"],
        "dual_trailing": ["签名后在证书表之后追加数据：两者都不覆盖，故都仍有效"],
        "dual_checksum_edit": ["修改 PE 校验和字段：两者都排除校验和，仍有效"],
    }
    manifest = {}
    for name, data in images.items():
        path = root / f"{name}.bin"
        Fixture(path, data, notes.get(name, [])).write()
        manifest[name] = {
            "path": path.name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "notes": notes.get(name, []),
        }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def _build_sha256(key: RSA.RsaKey, *, name: str, version: str) -> bytes:
    image = pe_builder.build_managed_pe(
        assembly_name=name, version=version, key=key, strong_name_signed=True,
        public_key_blob=crypto.public_key_blob(key), hash_name="sha256",
    )
    info = verify.parse_managed(image)
    return pe_builder.sign_strong_name(
        image, key, info["signature_offset"], info["strong_name_size"], hash_name="sha256",
    )
