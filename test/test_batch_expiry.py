"""Batch expiry experiment.

Simulates a long-running batch attestation run whose ephemeral credentials
expire mid-batch. A stand-in signer with a pinned validity window emits both
expiry states (`ExpiredCertificate` and `ExpiredIdentity`), and the produced
file manifests are checked before and after re-confirmation:

* files completed before the expiry point keep their original issuer identity;
* files pending at the expiry point are left unattested, with a recognizable
  failure reason;
* files attested after renewal belong to the renewed identity;
* every issued attestation still corresponds to its original file.
"""

from datetime import UTC, datetime
from pathlib import Path

import pypi_attestations._impl as impl
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore.dsse import Statement
from sigstore.dsse import _sign as dsse_sign
from sigstore.models import Bundle
from sigstore.sign import ExpiredCertificate, ExpiredIdentity

_HERE = Path(__file__).parent
_ASSETS = _HERE / "assets"

# A real transparency log entry reused as-is; the experiment never contacts
# any external service, so the entry is only needed to satisfy the model.
_LOG_ENTRY = Bundle.from_json(
    (_ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz.sigstore").read_bytes()
).log_entry

# The signer's validity window is pinned: every certificate issued by the
# stand-in signer below expires exactly at this moment.
_NOT_VALID_AFTER = datetime(2026, 1, 1, 0, 10, tzinfo=UTC)

_BATCH_FILES = [
    _ASSETS / "pypi_attestation_models-0.0.4a2.tar.gz",
    _ASSETS / "gitlab_oidc_project-0.0.3.tar.gz",
    _ASSETS / "gcb_attestation_test-0.0.0.tar.gz",
    _ASSETS / "rfc8785-0.1.2-py3-none-any.whl",
]


def _self_signed_certificate(
    identity: str, key: ec.EllipticCurvePrivateKey, not_valid_after: datetime
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(not_valid_after)
        .sign(key, hashes.SHA256())
    )


class StubSigner:
    """Stand-in for `sigstore.sign.Signer` with a pinned validity window.

    Like the real signer, it refuses to issue once its validity window is
    exhausted, raising the configured expiry error. The window is pinned by
    construction: the certificate carries a fixed `not_valid_after`, and the
    number of operations before expiry is fixed per instance.
    """

    def __init__(self, identity: str, remaining_uses: int, expiry_error: Exception) -> None:
        self.identity = identity
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.certificate = _self_signed_certificate(identity, self._key, _NOT_VALID_AFTER)
        self._remaining_uses = remaining_uses
        self._expiry_error = expiry_error

    def sign_dsse(self, stmt: Statement) -> Bundle:
        if self._remaining_uses <= 0:
            raise self._expiry_error
        self._remaining_uses -= 1
        envelope = dsse_sign(self._key, stmt)
        return Bundle._from_parts(cert=self.certificate, content=envelope, log_entry=_LOG_ENTRY)


def run_batch(
    files: list[Path], signer: StubSigner
) -> tuple[dict[str, impl.Attestation], list[str], str | None]:
    """Attest each file in order, stopping at the first expiry.

    Returns the issued attestations, the pending filenames, and the failure
    reason (if any).
    """
    issued: dict[str, impl.Attestation] = {}
    pending: list[str] = []
    failure: str | None = None
    for path in files:
        if failure is not None:
            pending.append(path.name)
            continue
        try:
            issued[path.name] = impl.Attestation.sign(signer, impl.Distribution.from_file(path))
        except impl.AttestationError as e:
            failure = str(e)
            pending.append(path.name)
    return issued, pending, failure


def attestation_identity(attestation: impl.Attestation) -> str:
    cert = x509.load_der_x509_certificate(attestation.verification_material.certificate)
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def attestation_matches_file(attestation: impl.Attestation, path: Path) -> bool:
    dist = impl.Distribution.from_file(path)
    subjects = attestation.statement["subject"]
    return (
        len(subjects) == 1
        and subjects[0]["name"] == dist.name
        and subjects[0]["digest"]["sha256"] == dist.digest
    )


def manifest_of(issued: dict[str, impl.Attestation]) -> dict[str, str]:
    return {name: attestation_identity(att) for name, att in issued.items()}


def test_batch_expiry_completed_files_keep_original_identity() -> None:
    # First run: the signer expires after exactly two files.
    gen1 = StubSigner("batch-bot/gen-1", remaining_uses=2, expiry_error=ExpiredCertificate())
    assert gen1.certificate.not_valid_after_utc == _NOT_VALID_AFTER

    issued, pending, failure = run_batch(_BATCH_FILES, gen1)

    # First-run manifest: two files attested under the original identity,
    # the rest left pending with a recognizable expiry reason.
    first_manifest = manifest_of(issued)
    assert first_manifest == {
        _BATCH_FILES[0].name: "batch-bot/gen-1",
        _BATCH_FILES[1].name: "batch-bot/gen-1",
    }
    assert pending == [_BATCH_FILES[2].name, _BATCH_FILES[3].name]
    assert failure is not None and "certificate" in failure

    # Before resuming, re-confirm every issued attestation still corresponds
    # to its original file.
    for name, attestation in issued.items():
        assert attestation_matches_file(attestation, _ASSETS / name)

    # Resume the pending files under a renewed identity.
    gen2 = StubSigner(
        "batch-bot/gen-2", remaining_uses=len(pending), expiry_error=ExpiredCertificate()
    )
    resumed, still_pending, resume_failure = run_batch([_ASSETS / n for n in pending], gen2)
    assert resume_failure is None
    assert still_pending == []

    # Final manifest: completed files keep the original identity, files
    # attested after renewal belong to the renewed identity, and every file
    # is accounted for exactly once.
    final_manifest = first_manifest | manifest_of(resumed)
    assert final_manifest == {
        _BATCH_FILES[0].name: "batch-bot/gen-1",
        _BATCH_FILES[1].name: "batch-bot/gen-1",
        _BATCH_FILES[2].name: "batch-bot/gen-2",
        _BATCH_FILES[3].name: "batch-bot/gen-2",
    }
    assert set(final_manifest) == {path.name for path in _BATCH_FILES}
    for name, attestation in (issued | resumed).items():
        assert attestation_matches_file(attestation, _ASSETS / name)


def test_batch_expiry_causes_remain_distinguishable() -> None:
    files = _BATCH_FILES[:2]

    cert_expired = StubSigner(
        "batch-bot/gen-1", remaining_uses=0, expiry_error=ExpiredCertificate()
    )
    issued_cert, pending_cert, failure_cert = run_batch(files, cert_expired)

    identity_expired = StubSigner(
        "batch-bot/gen-1", remaining_uses=0, expiry_error=ExpiredIdentity()
    )
    issued_id, pending_id, failure_id = run_batch(files, identity_expired)

    # Nothing is issued in either case, and everything stays pending.
    assert issued_cert == {} and issued_id == {}
    assert pending_cert == pending_id == [path.name for path in files]

    # The two expiry states surface distinct, recognizable reasons.
    assert failure_cert is not None and "certificate" in failure_cert
    assert failure_id is not None and "identity" in failure_id
    assert failure_cert != failure_id


def test_expiry_errors_keep_original_cause() -> None:
    dist = impl.Distribution.from_file(_BATCH_FILES[0])

    cert_expired = StubSigner(
        "batch-bot/gen-1", remaining_uses=0, expiry_error=ExpiredCertificate()
    )
    with pytest.raises(impl.AttestationError, match="certificate") as cert_excinfo:
        impl.Attestation.sign(cert_expired, dist)
    assert isinstance(cert_excinfo.value.__cause__, ExpiredCertificate)

    identity_expired = StubSigner(
        "batch-bot/gen-1", remaining_uses=0, expiry_error=ExpiredIdentity()
    )
    with pytest.raises(impl.AttestationError, match="identity") as id_excinfo:
        impl.Attestation.sign(identity_expired, dist)
    assert isinstance(id_excinfo.value.__cause__, ExpiredIdentity)
