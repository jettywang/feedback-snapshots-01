"""Generate the fictional, locally-signed release identity samples.

The samples under this directory are *fictional*: their certificates are
self-signed and their transparency log entries are placeholders. They exist
to exercise the local approval-record workflow without requiring network
access, and must never be treated as real Sigstore provenance.

Run from the repository root:

    .venv/bin/python examples/release-identity/generate_samples.py
"""

from __future__ import annotations

import base64
import json
import zipfile
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography import x509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sigstore.dsse import DigestSet, StatementBuilder, Subject
from sigstore.verify import policy

from pypi_attestations import (
    Attestation,
    AttestationType,
    AuditLog,
    Channel,
    Distribution,
    Envelope,
    GitHubPublisher,
    Period,
    ReleaseRegistry,
    Repository,
    VerificationMaterial,
)

HERE = Path(__file__).parent

# ---------------------------------------------------------------------------
# Fictional identities
# ---------------------------------------------------------------------------

CURRENT_WORKFLOW = "release.yml"
LEGACY_WORKFLOW = "legacy-release.yml"
CURRENT_TAG = "v1.0.0"
LEGACY_TAG = "v0.9.0"

CURRENT_TIME = datetime(2025, 6, 1, 12, 0, tzinfo=UTC)
LEGACY_TIME = datetime(2024, 1, 15, 12, 0, tzinfo=UTC)


def _wheel(path: Path, name: str, version: str) -> None:
    """Write a tiny but structurally valid wheel."""
    info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{name}/__init__.py", f'__version__ = "{version}"\n')
        zf.writestr(
            f"{info}/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        zf.writestr(
            f"{info}/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )


def _certificate(
    *,
    workflow: str,
    tag: str,
    signing_time: datetime,
    private_key: ec.EllipticCurvePrivateKey,
    run_id: str,
) -> x509.Certificate:
    """Build a self-signed certificate carrying Fulcio-style OIDC claims."""
    build_config = (
        f"https://github.com/acme/widgets/.github/workflows/{workflow}@refs/tags/{tag}"
    )
    source_digest = sha256(b"acme/widgets-source-tree").hexdigest()

    def claim(oid: x509.ObjectIdentifier, value: str) -> x509.UnrecognizedExtension:
        return x509.UnrecognizedExtension(oid, asn1.encode_der(value))

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "sigstore.dev")])
        )
        .public_key(private_key.public_key())
        .serial_number(int(sha256(build_config.encode()).hexdigest()[:16], 16))
        .not_valid_before(signing_time - timedelta(minutes=1))
        .not_valid_after(signing_time + timedelta(minutes=9))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(build_config)]),
            critical=False,
        )
        .add_extension(
            claim(policy._OIDC_ISSUER_V2_OID, "https://token.actions.githubusercontent.com"),
            critical=False,
        )
        .add_extension(claim(policy._OIDC_BUILD_SIGNER_URI_OID, build_config), critical=False)
        .add_extension(claim(policy._OIDC_BUILD_SIGNER_DIGEST_OID, source_digest), critical=False)
        .add_extension(claim(policy._OIDC_RUNNER_ENVIRONMENT_OID, "github-hosted"), critical=False)
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_URI_OID, "https://github.com/acme/widgets"),
            critical=False,
        )
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_DIGEST_OID, source_digest), critical=False
        )
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_REF_OID, f"refs/tags/{tag}"), critical=False
        )
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_IDENTIFIER_OID, "112233445"), critical=False
        )
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_OWNER_URI_OID, "https://github.com/acme"),
            critical=False,
        )
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_OWNER_IDENTIFIER_OID, "556677"), critical=False
        )
        .add_extension(claim(policy._OIDC_BUILD_CONFIG_URI_OID, build_config), critical=False)
        .add_extension(claim(policy._OIDC_BUILD_CONFIG_DIGEST_OID, source_digest), critical=False)
        .add_extension(claim(policy._OIDC_BUILD_TRIGGER_OID, "release"), critical=False)
        .add_extension(
            claim(
                policy._OIDC_RUN_INVOCATION_URI_OID,
                f"https://github.com/acme/widgets/actions/runs/{run_id}/attempts/1",
            ),
            critical=False,
        )
        .add_extension(
            claim(policy._OIDC_SOURCE_REPOSITORY_VISIBILITY_OID, "public"), critical=False
        )
    )
    return builder.sign(private_key, hashes.SHA256())


def _pae(statement: bytes) -> bytes:
    payload_type = "application/vnd.in-toto+json"
    pae = f"DSSEv1 {len(payload_type)} {payload_type} ".encode()
    return pae + b" ".join([str(len(statement)).encode(), statement])


def _attestation(
    *,
    dist: Distribution,
    workflow: str,
    tag: str,
    signing_time: datetime,
    run_id: str,
) -> Attestation:
    """Create a locally-signed, fictional PEP 740 attestation."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    certificate = _certificate(
        workflow=workflow,
        tag=tag,
        signing_time=signing_time,
        private_key=private_key,
        run_id=run_id,
    )

    statement = (
        StatementBuilder()
        .subjects([Subject(name=dist.name, digest=DigestSet(root={"sha256": dist.digest}))])
        .predicate_type(AttestationType.PYPI_PUBLISH_V1)
        .build()
    )
    statement_bytes = statement._inner.model_dump_json(by_alias=True).encode()  # noqa: SLF001
    signature = private_key.sign(_pae(statement_bytes), ec.ECDSA(hashes.SHA256()))

    certificate_der = certificate.public_bytes(serialization.Encoding.DER)

    # A placeholder Rekor v1-style entry. It is internally consistent enough
    # for the local signature check, but it is not a real log entry.
    log_entry = {
        "logIndex": "000000001",
        "logId": {"keyId": "ZmljdGlvbmFsLWludGVncml0eS1sb2cta2V5"},
        "kindVersion": {"kind": "dsse", "version": "0.0.1"},
        "integratedTime": str(int(signing_time.timestamp())),
        "inclusionPromise": {"signedEntryTimestamp": base64.b64encode(b"fictional").decode()},
        "inclusionProof": {
            "logIndex": "000000001",
            "rootHash": base64.b64encode(sha256(statement_bytes).digest()).decode(),
            "treeSize": "1",
            "hashes": [],
            "checkpoint": {"envelope": "fictional sigstore checkpoint\n"},
        },
        "canonicalizedBody": base64.b64encode(
            json.dumps(
                {
                    "apiVersion": "0.0.1",
                    "kind": "dsse",
                    "spec": {
                        "payloadHash": {
                            "algorithm": "sha256",
                            "value": sha256(statement_bytes).hexdigest(),
                        }
                    },
                },
                sort_keys=True,
            ).encode()
        ).decode(),
    }

    return Attestation(
        version=1,
        verification_material=VerificationMaterial(
            certificate=base64.b64encode(certificate_der),
            transparency_entries=[log_entry],
        ),
        envelope=Envelope(
            statement=base64.b64encode(statement_bytes),
            signature=base64.b64encode(signature),
        ),
    )


def _registry() -> ReleaseRegistry:
    """Build the fictional approval registry."""
    return ReleaseRegistry(
        repositories=[
            Repository(
                identifier="acme/widgets",
                periods={
                    # The old workflow was retired at the end of this period.
                    "legacy-workflow": Period(
                        start=datetime(2023, 1, 1, tzinfo=UTC),
                        end=datetime(2024, 6, 30, 23, 59, 59, tzinfo=UTC),
                    ),
                    # The new pipeline is still open-ended.
                    "new-pipeline": Period(start=datetime(2025, 1, 1, tzinfo=UTC)),
                },
                approvals=[
                    {
                        "period": "legacy-workflow",
                        "channel": Channel.RELEASE,
                        "publisher": GitHubPublisher(
                            repository="acme/widgets", workflow=LEGACY_WORKFLOW
                        ),
                        "note": "Retired old workflow; retained for historical verification.",
                    },
                    {
                        "period": "new-pipeline",
                        "channel": Channel.RELEASE,
                        "publisher": GitHubPublisher(
                            repository="acme/widgets", workflow=CURRENT_WORKFLOW
                        ),
                        "note": "Current release pipeline.",
                    },
                    {
                        "period": "new-pipeline",
                        "channel": Channel.PRERELEASE,
                        "status": "pending",
                        "publisher": GitHubPublisher(
                            repository="acme/widgets", workflow=LEGACY_WORKFLOW
                        ),
                        "note": "Old workflow requested prerelease access; awaiting review.",
                    },
                ],
            )
        ]
    )


def main() -> None:
    """Write the sample artifacts, attestations, registry, and archive."""
    # Sample A: a release from the current pipeline.
    current_whl = HERE / "widgets-1.0.0-py3-none-any.whl"
    _wheel(current_whl, "widgets", "1.0.0")
    current_dist = Distribution.from_file(current_whl)
    current_attestation = _attestation(
        dist=current_dist,
        workflow=CURRENT_WORKFLOW,
        tag=CURRENT_TAG,
        signing_time=CURRENT_TIME,
        run_id="7000000001",
    )
    Path(f"{current_whl}.publish.attestation").write_text(
        current_attestation.model_dump_json(indent=2) + "\n"
    )

    # Sample B: an archived release from the retired old workflow.
    legacy_whl = HERE / "widgets-0.9.0-py3-none-any.whl"
    _wheel(legacy_whl, "widgets", "0.9.0")
    legacy_dist = Distribution.from_file(legacy_whl)
    legacy_attestation = _attestation(
        dist=legacy_dist,
        workflow=LEGACY_WORKFLOW,
        tag=LEGACY_TAG,
        signing_time=LEGACY_TIME,
        run_id="6000000002",
    )
    Path(f"{legacy_whl}.publish.attestation").write_text(
        legacy_attestation.model_dump_json(indent=2) + "\n"
    )

    registry = _registry()
    registry.to_file(HERE / "release-registry.json")

    # Record an archived proof for the retired workflow. The evaluation
    # deliberately uses a fixed "now" after the legacy period ended.
    audit = AuditLog()
    evaluation = registry.evaluate(
        legacy_attestation,
        legacy_dist,
        repository="acme/widgets",
        channel=Channel.RELEASE,
        now=datetime(2026, 11, 29, tzinfo=UTC),
    )
    audit.record(
        evaluation,
        legacy_attestation,
        recorded_at=datetime(2026, 11, 29, 9, 0, tzinfo=UTC),
    )
    audit.to_file(HERE / "archive.json")

    print(f"Wrote {current_whl.name} and its attestation")
    print(f"Wrote {legacy_whl.name} and its attestation")
    print("Wrote release-registry.json")
    print("Wrote archive.json")


if __name__ == "__main__":
    main()
