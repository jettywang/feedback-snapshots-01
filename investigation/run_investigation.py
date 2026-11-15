#!/usr/bin/env python3
"""Runs signify: ../.venv/bin/python run_investigation.py  (from investigation/)

Exercises signify's public API against the generated dual-signature layouts
and records, for each sample:

  * how many AuthenticodeSignature objects the parser yields (signer selection
    surface), incl. nested signatures;
  * SignedData.digestAlgorithms vs SpcIndirectDataContent vs SignerInfo digest
    algorithm consistency;
  * authenticated attributes (content_type / message_digest) and whether the
    content digest matches;
  * the file-digest check (authentihash vs IndirectData.digest);
  * verify() outcome per multi_verify_mode, or the exact public exception.
"""

import io
import pathlib

from asn1crypto import pem, x509 as ax509

from signify.authenticode import AuthenticodeFile, AuthenticodeSignature
from signify.x509 import Certificate, CertificateStore

HERE = pathlib.Path(__file__).resolve().parent
SAMPLES = HERE / "samples"

CA = Certificate(
    ax509.Certificate.load(pem.unarmor((HERE / "keys" / "ca.crt").read_bytes())[2])
)
TRUST = CertificateStore([CA], trusted=True)


def cn(cert: Certificate) -> str:
    return cert.subject.dn


def describe_signature(sig: AuthenticodeSignature, pe) -> None:
    print(f"    SignedData.digestAlgorithms : "
          f"{[a['algorithm'].native for a in sig.asn1['digest_algorithms']]}")
    print(f"    signer_infos count          : {len(sig.signer_infos)}")
    si = sig.signer_info
    print(f"    signer                      : {si.issuer.dn}"
          f" serial={si.serial_number}")
    print(f"    SignerInfo.digestAlgorithm  : {si.digest_algorithm().name}")
    print(f"    IndirectData.digestAlgorithm: {sig.indirect_data.digest_algorithm().name}")
    print(f"    authenticated attributes    : {sorted(si.authenticated_attributes)}")
    print(f"    unauthenticated attributes  : {sorted(si.unauthenticated_attributes)}")
    md_ok = sig.get_content_digest() == si.message_digest
    print(f"    content digest == messageDigest attr: {md_ok}")
    authentihash = pe.get_fingerprint(sig.indirect_data.digest_algorithm)
    print(f"    authentihash == IndirectData.digest : "
          f"{authentihash == sig.indirect_data.digest}")


def run_verify(pe, mode: str) -> None:
    try:
        results = pe.verify(multi_verify_mode=mode, trusted_certificate_store=TRUST)
    except Exception as e:
        print(f"    verify[{mode:>5}] -> {type(e).__name__}: {e}")
        return
    for sd, indirect, chains in results:
        for chain in chains:
            print(f"    verify[{mode:>5}] -> OK  digest={sd.digest_algorithm().name}"
                  f"  chain={' -> '.join(cn(c) for c in chain)}")


def investigate(path: pathlib.Path) -> None:
    print(f"\n=== {path.name} ".ljust(66, "="))
    pe = AuthenticodeFile.from_stream(io.BytesIO(path.read_bytes()))
    print(f"  file type: {type(pe).__name__}")

    # 1. signature enumeration (parser surface, default flags)
    try:
        pe = AuthenticodeFile.from_stream(io.BytesIO(path.read_bytes()))
        sigs = list(pe.iter_embedded_signatures(include_nested=True))
    except Exception as e:
        print(f"  iter_embedded_signatures -> {type(e).__name__}: {e}")
        sigs = []
    else:
        print(f"  embedded signatures (incl. nested): {len(sigs)}")

    for i, sig in enumerate(sigs):
        print(f"  --- signature #{i} ---")
        try:
            describe_signature(sig, pe)
        except Exception as e:
            print(f"    describe -> {type(e).__name__}: {e}")

    # 2. verification per multi_verify_mode
    for mode in ("any", "first", "all", "best"):
        pe = AuthenticodeFile.from_stream(io.BytesIO(path.read_bytes()))
        run_verify(pe, mode)

    # 3. explain_verify (the high-level verdict API)
    pe = AuthenticodeFile.from_stream(io.BytesIO(path.read_bytes()))
    result, exc = pe.explain_verify(trusted_certificate_store=TRUST)
    print(f"    explain_verify -> {result.name}"
          + (f" ({type(exc).__name__}: {exc})" if exc else ""))


def main() -> None:
    for path in sorted(SAMPLES.iterdir()):
        investigate(path)

    # Low-level: parse the C envelopes directly, outside any PE container.
    print("\n=== direct envelope parsing (C layouts) ".ljust(66, "="))
    for name in ("C1-multi-signerinfo-same-digest.exe",
                 "C2-multi-signerinfo-two-digests.exe"):
        pe = AuthenticodeFile.from_stream(io.BytesIO((SAMPLES / name).read_bytes()))
        blob = next(pe._parse_cert_table())["certificate"]
        try:
            AuthenticodeSignature.from_envelope(blob)
        except Exception as e:
            print(f"  {name}: AuthenticodeSignature.from_envelope -> "
                  f"{type(e).__name__}: {e}")
        else:
            print(f"  {name}: AuthenticodeSignature.from_envelope -> parsed OK"
                  f" (unexpected)")

    # Generic pkcs7 layer: base SignedData has no exactly-1-signer check.
    print("\n=== generic pkcs7.SignedData layer (C layouts) ".ljust(66, "="))
    from signify.pkcs7 import SignedData as GenericSignedData

    for name in ("C1-multi-signerinfo-same-digest.exe",
                 "C2-multi-signerinfo-two-digests.exe"):
        pe = AuthenticodeFile.from_stream(io.BytesIO((SAMPLES / name).read_bytes()))
        blob = next(pe._parse_cert_table())["certificate"]
        try:
            sd = GenericSignedData.from_envelope(blob)
        except Exception as e:
            print(f"  {name}: parse -> {type(e).__name__}: {e}")
            continue
        print(f"  {name}: parse OK, signer_infos={len(sd.signer_infos)}")
        try:
            sd.verify(verification_context=None)
        except Exception as e:
            print(f"  {name}: verify -> {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
