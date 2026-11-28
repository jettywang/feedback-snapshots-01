#!/usr/bin/env python3
"""Generate the self-contained release-matrix demo fixtures.

The fixtures are cryptographically real: a local Sigstore trust root signs
the attestations, and the resulting bundles verify offline with
`sigstore.verify.Verifier`. This script is intentionally not part of the
`pypi-attestations` package; it exists so the demo can be reproduced.

Run from the repository root:

    .venv/bin/python tools/gen_release_matrix_demo.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
from pypi_attestations import Attestation
from sigstore.dsse import _pae
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify import Verifier, policy
from sigstore_models.bundle import v1 as bundle_v1
from sigstore_models.common import v1 as common_v1
from sigstore_models.intoto import Envelope as IntotoEnvelope
from sigstore_models.intoto import Signature as IntotoSignature
from sigstore_models.rekor import v1 as rekor_v1
from sigstore_models.trustroot import v1 as trustroot_v1

OUT = Path("test/assets/release-matrix-demo")
SCT_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
IDENTITY = "https://example.com/demo/.github/workflows/release.yml@refs/tags/v1.2.3"
PREDICATE = "https://docs.pypi.org/attestations/publish/v1"

ARTIFACTS = {
    "demo_project-1.2.3-py3-none-any.whl": b"demo universal wheel\n",
    "demo_project-1.2.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": (
        b"demo linux wheel\n"
    ),
    "demo_project-1.2.3.tar.gz": b"demo sdist\n",
}


def b64(data: bytes) -> str:
    """Return the base64 encoding of `data`."""
    return base64.b64encode(data).decode()


def der(tag: int, value: bytes) -> bytes:
    """Encode a DER TLV with the given tag and value."""
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def key_id(key: object) -> bytes:
    """Return the RFC 6962 key ID for a public key."""
    return hashlib.sha256(
        key.public_key().public_bytes(  # type: ignore[attr-defined]
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).digest()


def leaf_hash(data: bytes) -> bytes:
    """Return the RFC 6962 Merkle leaf hash of `data`."""
    return hashlib.sha256(b"\x00" + data).digest()


class DemoAuthority:
    """A minimal, self-contained Sigstore CA/CT/Rekor authority."""

    def __init__(self) -> None:
        """Create a fresh demo authority with ephemeral keys."""
        self.now = datetime.now(UTC)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.leaf_key = ec.generate_private_key(ec.SECP256R1())
        self.ct_key = ec.generate_private_key(ec.SECP256R1())
        self.rekor_key = ec.generate_private_key(ec.SECP256R1())
        self.ct_id = key_id(self.ct_key)
        self.rekor_id = key_id(self.rekor_key)
        self.ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo-root")])
        self.ca_cert = self._build_ca()

    def _build_ca(self) -> x509.Certificate:
        now = self.now
        return (
            x509.CertificateBuilder()
            .subject_name(self.ca_name)
            .issuer_name(self.ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def _leaf_builder(self) -> x509.CertificateBuilder:
        now = self.now
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.ca_name)
            .public_key(self.leaf_key.public_key())
            .serial_number(self.leaf_serial)
            .not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(IDENTITY)]),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False,
            )
        )

    def _sct_extension(self, signature: bytes) -> bytes:
        sct = (
            struct.pack("!B", 0) + self.ct_id + struct.pack("!Q", int(self.now.timestamp() * 1000))
        )
        sct += struct.pack("!H", 0)
        sct += struct.pack("!BB", 4, 3) + struct.pack("!H", len(signature)) + signature
        inner = struct.pack("!H", len(sct)) + sct
        tls_list = struct.pack("!H", len(inner)) + inner
        return der(0x04, tls_list)

    def build_leaf(self) -> x509.Certificate:
        """Create and sign the leaf signing certificate, including its SCT."""
        self.leaf_serial = x509.random_serial_number()
        placeholder = self._sct_extension(b"\x30\x06\x02\x01\x00\x02\x01\x00")
        provisional = (
            self._leaf_builder()
            .add_extension(x509.UnrecognizedExtension(SCT_OID, placeholder), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        tbs = provisional.tbs_precertificate_bytes
        signed = struct.pack("!BBQH", 0, 0, int(self.now.timestamp() * 1000), 1)
        signed += key_id(self.ca_key) + len(tbs).to_bytes(3, "big") + tbs
        signed += struct.pack("!H", 0)
        signature = self.ct_key.sign(signed, ec.ECDSA(hashes.SHA256()))

        return (
            self._leaf_builder()
            .add_extension(
                x509.UnrecognizedExtension(SCT_OID, self._sct_extension(signature)),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def sign_artifact(self, leaf: x509.Certificate, artifact_name: str, digest: str) -> Bundle:
        """Create a Sigstore bundle for one artifact."""
        statement = json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": artifact_name, "digest": {"sha256": digest}}],
                "predicateType": PREDICATE,
                "predicate": None,
            },
            separators=(",", ":"),
        ).encode()
        payload_type = "application/vnd.in-toto+json"
        pae = _pae(payload_type, statement)
        signature = self.leaf_key.sign(pae, ec.ECDSA(hashes.SHA256()))

        body = json.dumps(
            {
                "apiVersion": "0.0.1",
                "kind": "dsse",
                "spec": {
                    "envelopeHash": {
                        "algorithm": "sha256",
                        "value": hashlib.sha256(b"").hexdigest(),
                    },
                    "payloadHash": {
                        "algorithm": "sha256",
                        "value": hashlib.sha256(statement).hexdigest(),
                    },
                    "signatures": [
                        {
                            "signature": b64(signature),
                            "verifier": b64(leaf.public_bytes(serialization.Encoding.PEM)),
                        }
                    ],
                },
            },
            separators=(",", ":"),
        ).encode()

        log_index = 0
        tree_size = 1
        root_hash = leaf_hash(body)
        checkpoint_note = f"rekor.demo.invalid - 1\n{tree_size}\n{b64(root_hash)}\n"
        checkpoint_signature = self.rekor_key.sign(
            checkpoint_note.encode(), ec.ECDSA(hashes.SHA256())
        )
        note_signature = struct.pack(">4s", self.rekor_id[:4]) + checkpoint_signature
        checkpoint = checkpoint_note + "\n— rekor.demo.invalid " + b64(note_signature) + "\n"

        integrated_time = int(self.now.timestamp())
        canonical = rfc8785.dumps(
            {
                "body": b64(body),
                "integratedTime": integrated_time,
                "logID": self.rekor_id.hex(),
                "logIndex": int(log_index),
            }
        )
        set_signature = self.rekor_key.sign(canonical, ec.ECDSA(hashes.SHA256()))

        log_entry = rekor_v1.TransparencyLogEntry(
            log_index=str(log_index),
            log_id=common_v1.LogId(key_id=b64(self.rekor_id)),
            kind_version=rekor_v1.KindVersion(kind="dsse", version="0.0.1"),
            integrated_time=str(integrated_time),
            inclusion_promise=rekor_v1.InclusionPromise(signed_entry_timestamp=b64(set_signature)),
            inclusion_proof=rekor_v1.InclusionProof(
                log_index=str(log_index),
                root_hash=b64(root_hash),
                tree_size=str(tree_size),
                hashes=[],
                checkpoint=rekor_v1.Checkpoint(envelope=checkpoint),
            ),
            canonicalized_body=b64(body),
        )

        inner = bundle_v1.Bundle(
            media_type="application/vnd.dev.sigstore.bundle+json;version=0.3",
            verification_material=bundle_v1.VerificationMaterial(
                certificate=common_v1.X509Certificate(
                    raw_bytes=b64(leaf.public_bytes(serialization.Encoding.DER))
                ),
                tlog_entries=[log_entry],
                timestamp_verification_data=bundle_v1.TimestampVerificationData(
                    rfc3161_timestamps=[]
                ),
            ),
            dsse_envelope=IntotoEnvelope(
                payload=b64(statement),
                payload_type=payload_type,
                signatures=[IntotoSignature(sig=b64(signature))],
            ),
        )
        return Bundle(inner)

    def _pkey(self, key: ec.EllipticCurvePrivateKey) -> trustroot_v1.PublicKey:
        return trustroot_v1.PublicKey(
            raw_bytes=b64(
                key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            key_details=common_v1.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
            valid_for=trustroot_v1.TimeRange(
                start=self.now - timedelta(days=1), end=self.now + timedelta(days=365)
            ),
        )

    def trusted_root(self) -> TrustedRoot:
        """Build the trusted root that anchors the demo signatures."""
        now = self.now
        tlog = trustroot_v1.TransparencyLogInstance(
            base_url="https://rekor.demo.invalid",
            hash_algorithm=common_v1.HashAlgorithm.SHA2_256,
            public_key=self._pkey(self.rekor_key),
            log_id=trustroot_v1.LogId(key_id=b64(self.rekor_id)),
            checkpoint_key_id=trustroot_v1.LogId(key_id=b64(self.rekor_id)),
            operator="demo",
        )
        ctlog = trustroot_v1.TransparencyLogInstance(
            base_url="https://ct.demo.invalid",
            hash_algorithm=common_v1.HashAlgorithm.SHA2_256,
            public_key=self._pkey(self.ct_key),
            log_id=trustroot_v1.LogId(key_id=b64(self.ct_id)),
            checkpoint_key_id=trustroot_v1.LogId(key_id=b64(self.ct_id)),
            operator="demo",
        )
        ca = trustroot_v1.CertificateAuthority(
            subject=trustroot_v1.DistinguishedName(organization="demo", common_name="demo-root"),
            uri="https://ca.demo.invalid",
            cert_chain=trustroot_v1.X509CertificateChain(
                certificates=[
                    common_v1.X509Certificate(
                        raw_bytes=b64(self.ca_cert.public_bytes(serialization.Encoding.DER))
                    )
                ]
            ),
            valid_for=trustroot_v1.TimeRange(
                start=now - timedelta(days=1), end=now + timedelta(days=365)
            ),
            operator="demo",
        )
        return TrustedRoot(
            trustroot_v1.TrustedRoot(
                media_type="application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                tlogs=[tlog],
                certificate_authorities=[ca],
                ctlogs=[ctlog],
                timestamp_authorities=[],
            )
        )


def main() -> None:
    """Generate the fixtures under `test/assets/release-matrix-demo`."""
    authority = DemoAuthority()
    leaf = authority.build_leaf()

    OUT.mkdir(parents=True, exist_ok=True)
    bundles: dict[str, Bundle] = {}
    for name, payload in ARTIFACTS.items():
        path = OUT / name
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        bundle = authority.sign_artifact(leaf, name, digest)
        bundles[name] = bundle
        attestation = Attestation.from_bundle(bundle)
        (OUT / f"{name}.publish.attestation").write_text(attestation.model_dump_json())

    # Make exactly one evidence set incomplete: reuse the Linux wheel's
    # (valid) attestation as the universal wheel's evidence. A single signed
    # attestation must never be accepted for a different artifact.
    universal = "demo_project-1.2.3-py3-none-any.whl"
    linux = "demo_project-1.2.3-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    (OUT / f"{universal}.publish.attestation").write_text(
        (OUT / f"{linux}.publish.attestation").read_text()
    )

    (OUT / "trusted_root.json").write_text(
        authority.trusted_root()._inner.model_dump_json(by_alias=True)  # noqa: SLF001
    )

    matrix = {
        "version": 1,
        "name": "demo-project",
        "release": "1.2.3",
        "targets": [
            {"platform": "any"},
            {"platform": "manylinux_2_17_x86_64"},
            {
                "platform": "win_amd64",
                "reason": "Windows wheel is not produced for this demo release",
            },
            {"platform": None},
        ],
    }
    (OUT / "matrix.json").write_text(json.dumps(matrix, indent=2) + "\n")

    verifier = Verifier(trusted_root=authority.trusted_root())
    identity = policy.Identity(identity=IDENTITY)
    for bundle in bundles.values():
        verifier.verify_dsse(bundle, identity)


if __name__ == "__main__":
    main()
