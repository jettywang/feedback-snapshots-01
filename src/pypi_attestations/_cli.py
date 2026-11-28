"""Implementation of the CLI for pypi-attestations."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
import typing
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

import sigstore.oidc
import urllib3
from cryptography import x509
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    parse_sdist_filename,
    parse_wheel_filename,
)
from pydantic import ValidationError
from rfc3986 import exceptions, uri_reference, validators
from sigstore.models import Bundle, ClientTrustConfig, InvalidBundle
from sigstore.oidc import IdentityError, IdentityToken, Issuer
from sigstore.sign import SigningContext
from sigstore.verify import policy

from pypi_attestations import Attestation, AttestationError, VerificationError, __version__
from pypi_attestations._impl import (
    CircleCIPublisher,
    ConversionError,
    Distribution,
    GitHubPublisher,
    GitLabPublisher,
    GooglePublisher,
    Provenance,
)
from pypi_attestations._receipt import (
    ReceiptRecorder,
    Segment,
    record_failure,
    record_gap,
    record_read,
    record_success,
    redact_text,
)

if typing.TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable, Iterator
    from typing import NoReturn

    from rfc3986 import URIReference

logging.basicConfig(format="%(message)s", datefmt="[%X]", handlers=[logging.StreamHandler()])
_logger = logging.getLogger(__name__)
_logger.setLevel(logging.INFO)


def _parser() -> argparse.ArgumentParser:
    parent_parser = argparse.ArgumentParser(add_help=False)

    parent_parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Run with additional debug logging; supply multiple times to increase verbosity",
    )

    parser = argparse.ArgumentParser(
        prog="pypi-attestations",
        description="Sign, inspect or verify PEP 740 attestations",
        parents=[parent_parser],
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"pypi-attestations {__version__}",
    )

    subcommands = parser.add_subparsers(
        required=True,
        dest="subcommand",
        metavar="COMMAND",
        help="The operation to perform",
    )

    sign_command = subcommands.add_parser(
        name="sign", help="Sign one or more inputs", parents=[parent_parser]
    )

    sign_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
    )

    sign_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    verify_command = subcommands.add_parser(
        name="verify",
        help="Verify one or more inputs",
        parents=[parent_parser],
    )

    verify_subcommands = verify_command.add_subparsers(
        required=True,
        dest="verification_type",
        metavar="VERIFICATION_TYPE",
        help="The type of verification",
    )
    verify_attestation_command = verify_subcommands.add_parser(
        name="attestation", help="Verify a PEP-740 attestation"
    )

    verify_attestation_command.add_argument(
        "--identity",
        type=str,
        required=True,
        help="Signer identity",
    )

    verify_attestation_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
    )

    verify_attestation_command.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="Disable TUF refresh",
    )

    verify_attestation_command.add_argument(
        "--receipt",
        type=Path,
        metavar="PATH",
        help="Write a shareable JSON receipt of the evidence that was read "
        "to PATH, or to stdout if PATH is '-'",
    )

    verify_attestation_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to sign",
    )

    verify_pypi_command = verify_subcommands.add_parser(name="pypi", help="Verify a PyPI release")

    verify_pypi_command.add_argument(
        "distribution_file",
        metavar="PYPI_FILE",
        type=str,
        help="PyPI file to verify, can be: "
        "(1) a path to a local file, "
        "(2) pypi:$FILE_NAME (e.g. pypi:sampleproject-1.0.0.tar.gz) or "
        "(3) A direct URL to files.pythonhosted.org",
    )

    verify_pypi_command.add_argument(
        "--repository",
        type=str,
        help="URL of the publishing GitHub or GitLab repository",
    )

    verify_pypi_command.add_argument(
        "--gcp-service-account",
        type=str,
        help="Email of the Google Cloud service account",
    )

    verify_pypi_command.add_argument(
        "--circleci-project-id",
        type=str,
        help="CircleCI project ID (UUID)",
    )

    verify_pypi_command.add_argument(
        "--circleci-pipeline-definition-id",
        type=str,
        help="CircleCI pipeline definition ID (UUID)",
    )

    verify_pypi_command.add_argument(
        "--staging",
        action="store_true",
        default=False,
        help="Use the staging environment",
    )

    verify_pypi_command.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="Force use of local files and disable TUF refresh",
    )

    verify_pypi_command.add_argument(
        "--provenance-file",
        type=Path,
        help="Provide the provenance file instead of downloading it from PyPI",
    )

    verify_pypi_command.add_argument(
        "--receipt",
        type=Path,
        metavar="PATH",
        help="Write a shareable JSON receipt of the evidence that was read "
        "to PATH, or to stdout if PATH is '-'",
    )

    inspect_command = subcommands.add_parser(
        name="inspect",
        help="Inspect one or more inputs",
        parents=[parent_parser],
    )

    inspect_command.add_argument(
        "--dump-bytes",
        action="store_true",
        default=False,
        help="Dump the bytes of the signature",
    )

    inspect_command.add_argument(
        "files",
        metavar="FILE",
        type=Path,
        nargs="+",
        help="The file to inspect",
    )

    convert_command = subcommands.add_parser(
        name="convert",
        help="Convert a Sigstore bundle into a PEP 740 attestation",
        parents=[parent_parser],
    )

    convert_command.add_argument(
        "bundle_file",
        metavar="BUNDLE_FILE",
        type=Path,
        help="The Sigstore bundle to convert",
    )

    convert_command.add_argument(
        "--output-file",
        required=True,
        type=Path,
        help="The output file to write the attestation to",
    )
    return parser


def _die(message: str) -> NoReturn:
    """Handle errors and terminate the program with an error code."""
    record_failure(message)
    _logger.error(message)
    raise SystemExit(1)


def _command_line() -> str:
    """Return a shareable representation of the current command line."""
    return redact_text(" ".join(["pypi-attestations", *sys.argv[1:]]))


@contextmanager
def _receipt_context(args: argparse.Namespace) -> Iterator[ReceiptRecorder | None]:
    """Open the optional receipt requested by the user, if any."""
    receipt_path = getattr(args, "receipt", None)
    if receipt_path is None:
        yield None
        return

    recorder = ReceiptRecorder(
        receipt_path,
        command=_command_line(),
        environment={
            "python": platform.python_version(),
            "platform": platform.system(),
            "offline": bool(getattr(args, "offline", False)),
            "staging": bool(getattr(args, "staging", False)),
        },
        tool_version=__version__,
    )
    with recorder:
        yield recorder


def _record_local_read(segment: Segment, path: Path, *, sha256: str, size: int) -> None:
    """Record a file read whose contents were consumed by another reader."""
    record_read(
        segment,
        kind="file",
        location=str(path),
        name=path.name,
        sha256=sha256,
        size=size,
    )


def _record_download_read(
    segment: Segment, url: str, name: str, *, sha256: str, size: int
) -> None:
    """Record a download by its origin URL rather than its temporary path."""
    record_read(
        segment,
        kind="url",
        location=url,
        name=name,
        sha256=sha256,
        size=size,
    )


def _validate_files(files: Iterable[Path], should_exist: bool = True) -> None:
    """Validate that the list of files exists or not.

    This function exits the program if the condition is not met.
    """
    for file_path in files:
        if file_path.is_file() != should_exist:
            if should_exist:
                _die(f"{file_path} is not a file.")
            else:
                _die(f"{file_path} already exists.")


def get_identity_token(args: argparse.Namespace) -> IdentityToken:
    """Generate an Identity Token.

    This method uses the following order of precedence:
    - An ambient credential
    - An OAuth-2 flow
    """
    # Ambient credential detection
    oidc_token = sigstore.oidc.detect_credential()
    if oidc_token is not None:
        return IdentityToken(oidc_token)

    if args.staging:
        trust_config = ClientTrustConfig.staging()
    else:
        trust_config = ClientTrustConfig.production()
    issuer: Issuer = Issuer(trust_config.signing_config.get_oidc_url())
    return issuer.identity_token()


def _download_file(url: str, dest: Path) -> None:
    """Download a file into a given path."""
    try:
        with urllib3.request("GET", url, preload_content=False) as response:
            if response.status >= 400:
                message = f"Error downloading file: {response.status} {response.reason}"
                record_gap("artifact", "download_failed", message, kind="url", location=url)
                _die(message)

            with open(dest, "wb") as f:
                for chunk in response.stream(1024):
                    f.write(chunk)
    except urllib3.exceptions.HTTPError as e:
        message = f"Error downloading file: {e}"
        record_gap("artifact", "download_failed", message, kind="url", location=url)
        _die(message)


def _get_distribution_from_arg(arg: str, offline: bool) -> Distribution:
    """Parse the artifact argument for the `verify pypi` subcommand.

    The argument can be:
    - A pypi: prefixed filename (e.g. pypi:sampleproject-1.0.0.tar.gz)
    - A direct URL to a PyPI-hosted artifact
    - A path to a local file
    """
    if arg.startswith("pypi:") or arg.startswith("https://"):
        if offline:
            record_gap(
                "artifact",
                "offline",
                "The '--offline' option can only be used with local files",
            )
            _die("The '--offline' option can only be used with local files")
        pypi_url = _get_direct_url_from_arg(arg)
        dist_filename = pypi_url.path.split("/")[-1]
        with TemporaryDirectory() as temp_dir:
            dist_path = Path(temp_dir) / dist_filename
            _download_file(url=pypi_url.unsplit(), dest=dist_path)
            dist = Distribution.from_file(dist_path)
            _record_download_read(
                "artifact",
                pypi_url.unsplit(),
                dist_filename,
                sha256=dist.digest,
                size=dist_path.stat().st_size,
            )
    else:
        dist_path = Path(arg)
        if not dist_path.exists():
            record_gap(
                "artifact",
                "missing",
                f"File does not exist: {dist_path}",
                kind="file",
                location=str(dist_path),
            )
            _die(f"File does not exist: {dist_path}")
        dist = Distribution.from_file(dist_path)
        _record_local_read(
            "artifact", dist_path, sha256=dist.digest, size=dist_path.stat().st_size
        )

    return dist


def _get_direct_url_from_arg(arg: str) -> URIReference:
    """Get the URL from the artifact argument for the `verify pypi` subcommand.

    The argument can be:
    - A pypi: prefixed filename (e.g. pypi:sampleproject-1.0.0.tar.gz)
    - A direct URL to a PyPI-hosted artifact
    """
    direct_url = None

    if arg.startswith("pypi:"):
        file_name = arg[5:]
        try:
            if file_name.endswith(".tar.gz") or file_name.endswith(".zip"):
                pkg_name, _ = parse_sdist_filename(file_name)
            elif file_name.endswith(".whl"):
                pkg_name, _, _, _ = parse_wheel_filename(file_name)
            else:
                _die("File should be a wheel (*.whl) or a source distribution (*.zip or *.tar.gz)")
        except (InvalidSdistFilename, InvalidWheelFilename) as e:
            _die(f"Invalid distribution filename: {e}")

        provenance_url = f"https://pypi.org/simple/{pkg_name}"
        response = urllib3.request(
            "GET", provenance_url, headers={"Accept": "application/vnd.pypi.simple.v1+json"}
        )
        if response.status >= 400:
            message = (
                f"Error trying to get information for '{pkg_name}' from PyPI: {response.status}"
            )
            record_gap(
                "artifact", "index_lookup_failed", message, kind="url", location=provenance_url
            )
            _die(message)

        response_json = response.json()
        for file_json in response_json.get("files", []):
            if file_json.get("filename", "") == file_name:
                direct_url = file_json.get("url", "")
                break
        if not direct_url:
            message = f"Could not find the artifact '{file_name}' on PyPI"
            record_gap("artifact", "not_found", message, kind="url", location=provenance_url)
            _die(message)
    else:
        direct_url = arg

    validator = (
        validators.Validator()
        .allow_schemes("https")
        .allow_hosts("files.pythonhosted.org")
        .require_presence_of("scheme", "host")
    )
    try:
        pypi_url = uri_reference(direct_url)
        validator.validate(pypi_url)
    except exceptions.RFC3986Exception as e:
        _die(f"Unsupported/invalid URL: {e}")

    return pypi_url


def _get_provenance_from_pypi(dist: Distribution) -> Provenance:
    """Use PyPI's integrity API to get a distribution's provenance."""
    filename = dist.name
    # Filename is already validated when creating the Distribution object
    if filename.endswith(".tar.gz") or filename.endswith(".zip"):
        name, version = parse_sdist_filename(filename)
    else:
        name, version, _, _ = parse_wheel_filename(filename)

    provenance_url = f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance"
    response = urllib3.request("GET", provenance_url)
    if response.status == 403:
        message = "Access to provenance is temporarily disabled by PyPI administrators"
        record_gap(
            "provenance", "unavailable", message, kind="url", location=provenance_url
        )
        _die(message)
    elif response.status == 404:
        message = f'Provenance for file "{filename}" was not found'
        record_gap("provenance", "not_found", message, kind="url", location=provenance_url)
        _die(message)
    elif response.status != 200:
        message = (
            f"Unexpected error while downloading provenance file from PyPI, Integrity API "
            f"returned status code: {response.status}"
        )
        record_gap("provenance", "http_error", message, kind="url", location=provenance_url)
        _die(message)

    record_read(
        "provenance",
        kind="url",
        location=provenance_url,
        name=f"{filename}.provenance",
        data=response.data,
    )
    try:
        return Provenance.model_validate_json(response.data)
    except ValidationError as validation_error:
        message = f"Invalid provenance: {validation_error}"
        record_gap(
            "provenance", "invalid", message, kind="url", location=provenance_url
        )
        _die(message)


def _check_repository_identity(
    expected_repository_url: str, publisher: GitHubPublisher | GitLabPublisher
) -> None:
    """Check that a repository url matches the given publisher's identity."""
    validator = (
        validators.Validator()
        .allow_schemes("https")
        .allow_hosts("github.com", "gitlab.com")
        .require_presence_of("scheme", "host")
    )
    try:
        expected_uri = uri_reference(expected_repository_url)
        validator.validate(expected_uri)
    except exceptions.RFC3986Exception as e:
        _die(f"Unsupported/invalid URL: {e}")

    actual_host = "github.com" if isinstance(publisher, GitHubPublisher) else "gitlab.com"
    expected_host = expected_uri.host
    if actual_host != expected_host:
        _die(
            f"Verification failed: provenance was signed by a {actual_host} repository, but "
            f"expected a {expected_host} repository"
        )

    actual_repository = publisher.repository
    # '/owner/repo' -> 'owner/repo'
    expected_repository = expected_uri.path.lstrip("/")
    if actual_repository != expected_repository:
        _die(
            f'Verification failed: provenance was signed by repository "{actual_repository}", '
            f'expected "{expected_repository}"'
        )


def _sign(args: argparse.Namespace) -> None:
    """Sign the files passed as argument."""
    try:
        identity = get_identity_token(args)
    except IdentityError as identity_error:
        _die(f"Failed to detect identity: {identity_error}")

    trust_config = ClientTrustConfig.staging() if args.staging else ClientTrustConfig.production()
    # Make sure we use rekor v1 until attestations are compatible with v2
    trust_config.force_tlog_version = 1

    signing_ctx = SigningContext.from_trust_config(trust_config)

    # Validates that every file we want to sign exist but none of their attestations
    _validate_files(args.files, should_exist=True)
    _validate_files(
        (Path(f"{file_path}.publish.attestation") for file_path in args.files),
        should_exist=False,
    )

    with signing_ctx.signer(identity, cache=True) as signer:
        for file_path in args.files:
            _logger.debug(f"Signing {file_path}")

            try:
                dist = Distribution.from_file(file_path)
            except ValidationError as e:
                _die(f"Invalid Python package distribution: {e}")

            try:
                attestation = Attestation.sign(signer, dist)
            except AttestationError as e:
                _die(f"Failed to sign: {e}")

            signature_path = Path(f"{file_path}.publish.attestation")
            signature_path.write_text(attestation.model_dump_json())
            _logger.debug("Attestation for %s saved in %s", file_path, signature_path)


def _inspect(args: argparse.Namespace) -> None:
    """Inspect attestations.

    Warning: The information displayed from the attestations are not verified.
    """
    attestation_files = [f for f in args.files if f.suffix == ".attestation"]
    _validate_files(attestation_files, should_exist=True)
    for file_path in attestation_files:
        try:
            attestation = Attestation.model_validate_json(file_path.read_bytes())
        except ValidationError as validation_error:
            _die(f"Invalid attestation ({file_path}): {validation_error}")

        _logger.info(
            "Warning: The information displayed below are not verified, they are only "
            "displayed. Use the verify command to verify them."
        )

        _logger.info(f"File: {file_path}")
        _logger.info(f"Version: {attestation.version}")

        decoded_statement = json.loads(attestation.envelope.statement.decode())

        _logger.info("Statement:")
        _logger.info(f"\tType: {decoded_statement['_type']}")
        _logger.info("\tSubject:")
        for subject in decoded_statement["subject"]:
            _logger.info(f"\t\t{subject['name']} (digest: {subject['digest']['sha256']})")

        _logger.info(f"\tPredicate type: {decoded_statement['predicateType']}")
        _logger.info(f"\tPredicate: {decoded_statement['predicate']}")

        if args.dump_bytes:
            _logger.info(f"Signature: {attestation.envelope.signature!r}")

        # Verification Material
        verification_material = attestation.verification_material

        # Certificate
        certificate = x509.load_der_x509_certificate(verification_material.certificate)
        _logger.info("Certificate:")
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        _logger.info(
            f"\tSubjects (suitable for `--identity`): {[name.value for name in san.value]}"
        )
        _logger.info(f"\tIssuer: {certificate.issuer.rfc4514_string()}")
        _logger.info(f"\tValidity: {certificate.not_valid_after_utc}")

        # Transparency Log
        _logger.info(
            f"Transparency Log ({len(verification_material.transparency_entries)} entries):"
        )
        for idx, entry in enumerate(verification_material.transparency_entries):
            _logger.info(f"\tLog Index: {entry['logIndex']}")


def _verify_attestation(args: argparse.Namespace) -> None:
    """Verify the files passed as argument."""
    pol = policy.Identity(identity=args.identity)

    # Record any artifact that is missing before the generic validation exits.
    for file_path in args.files:
        if not file_path.is_file():
            record_gap(
                "artifact",
                "missing",
                f"{file_path} is not a file.",
                kind="file",
                location=str(file_path),
            )
    _validate_files(args.files, should_exist=True)

    # artifact -> [attestation1, attestation2, ...]
    files_with_attestations: dict[Path, list[Path]] = defaultdict(list)
    for f in args.files:
        for attestation_file in (Path(f"{f}.publish.attestation"), Path(f"{f}.slsa.attestation")):
            if attestation_file.exists():
                files_with_attestations[f].append(attestation_file)
        if not files_with_attestations[f]:
            record_gap(
                "attestation",
                "missing",
                f"Couldn't find attestations for file {f}",
                kind="file",
                location=str(f),
            )
            _die(f"Couldn't find attestations for file {f}")

    verified_attestations = 0
    recorded_artifacts: set[Path] = set()
    for file_path, attestations in files_with_attestations.items():
        for attestation_path in attestations:
            attestation_bytes = attestation_path.read_bytes()
            record_read(
                "attestation",
                kind="file",
                location=str(attestation_path),
                name=attestation_path.name,
                data=attestation_bytes,
            )
            try:
                attestation = Attestation.model_validate_json(attestation_bytes)
            except ValidationError as validation_error:
                _die(f"Invalid attestation ({attestation_path}): {validation_error}")

            if file_path not in recorded_artifacts:
                try:
                    dist = Distribution.from_file(file_path)
                except ValidationError as e:
                    _die(f"Invalid Python package distribution: {e}")
                _record_local_read(
                    "artifact", file_path, sha256=dist.digest, size=file_path.stat().st_size
                )
                recorded_artifacts.add(file_path)

            try:
                attestation.verify(pol, dist, staging=args.staging, offline=args.offline)
            except VerificationError as verification_error:
                _die(f"Verification failed for {file_path}: {verification_error}")

            verified_attestations += 1
            _logger.info(f"OK: {attestation_path}")

    record_success(
        f"OK: verified {verified_attestations} attestation(s) for "
        f"{len(files_with_attestations)} artifact(s)"
    )


def _verify_pypi(args: argparse.Namespace) -> None:
    """Verify a distribution hosted on PyPI.

    The distribution is downloaded (if needed) and verified. The verification is against
    the provenance file (passed using the `--provenance-file` option, or downloaded
    from PyPI if not provided), and against the repository URL passed by the user
    as a CLI argument.
    """
    dist = _get_distribution_from_arg(args.distribution_file, offline=args.offline)

    if args.provenance_file is None:
        if args.offline:
            record_gap(
                "provenance",
                "offline",
                "The '--offline' option can only be used with local files",
            )
            _die("The '--offline' option can only be used with local files")
        provenance = _get_provenance_from_pypi(dist)
    else:
        if not args.provenance_file.exists():
            record_gap(
                "provenance",
                "missing",
                f"Provenance file does not exist: {args.provenance_file}",
                kind="file",
                location=str(args.provenance_file),
            )
            _die(f"Provenance file does not exist: {args.provenance_file}")
        provenance_bytes = args.provenance_file.read_bytes()
        record_read(
            "provenance",
            kind="file",
            location=str(args.provenance_file),
            name=args.provenance_file.name,
            data=provenance_bytes,
        )
        try:
            provenance = Provenance.model_validate_json(provenance_bytes)
        except ValidationError as validation_error:
            _die(f"Invalid provenance: {validation_error}")

    try:
        for attestation_bundle in provenance.attestation_bundles:
            publisher = attestation_bundle.publisher
            if isinstance(publisher, GooglePublisher):
                if not args.gcp_service_account:
                    _die(
                        "Provenance signed by a Google Cloud account, but no service account "
                        "provided; use '--gcp-service-account'"
                    )
                if publisher.email != args.gcp_service_account:
                    _die(
                        f"Verification failed: provenance was signed by service account "
                        f'"{publisher.email}", expected "{args.gcp_service_account}"'
                    )
            elif isinstance(publisher, CircleCIPublisher):
                if not args.circleci_project_id:
                    _die(
                        "Provenance signed by CircleCI, but no project ID provided; "
                        "use '--circleci-project-id'"
                    )
                if not args.circleci_pipeline_definition_id:
                    _die(
                        "Provenance signed by CircleCI, but no pipeline definition ID provided; "
                        "use '--circleci-pipeline-definition-id'"
                    )
                if publisher.project_id != args.circleci_project_id:
                    _die(
                        f"Verification failed: provenance was signed by CircleCI project "
                        f'"{publisher.project_id}", expected "{args.circleci_project_id}"'
                    )
                if publisher.pipeline_definition_id != args.circleci_pipeline_definition_id:
                    _die(
                        f"Verification failed: provenance was signed by CircleCI pipeline "
                        f'definition "{publisher.pipeline_definition_id}", expected '
                        f'"{args.circleci_pipeline_definition_id}"'
                    )
            else:
                if not args.repository:
                    _die(
                        "Provenance signed by a repository, but no repository URL provided; "
                        "use '--repository'"
                    )
                _check_repository_identity(
                    expected_repository_url=args.repository, publisher=publisher
                )

            policy = publisher._as_policy()  # noqa: SLF001
            for attestation in attestation_bundle.attestations:
                attestation.verify(policy, dist, staging=args.staging, offline=args.offline)
    except VerificationError as verification_error:
        _die(f"Verification failed for {dist.name}: {verification_error}")

    record_success(f"OK: {dist.name}")
    _logger.info(f"OK: {dist.name}")


def _convert(args: argparse.Namespace) -> None:
    """Convert a Sigstore bundle into a PEP 740 attestation."""
    if not args.bundle_file.exists():
        _die(f"Bundle file does not exist: {args.bundle_file}")

    if args.output_file.exists():
        _die(f"Output file already exists: {args.output_file}")

    try:
        sigstore_bundle = Bundle.from_json(args.bundle_file.read_bytes())
        attestation_object = Attestation.from_bundle(sigstore_bundle)
    except (InvalidBundle, json.JSONDecodeError) as e:
        _die(f"Invalid Sigstore bundle: {e}")
    except ConversionError as e:
        _die(f"Failed to convert Sigstore bundle: {e}")

    args.output_file.write_text(attestation_object.model_dump_json())
    _logger.info(f"Converted Sigstore bundle to attestation: {args.output_file}")


def main() -> None:
    """Dispatch the CLI subcommand."""
    parser = _parser()
    args: argparse.Namespace = parser.parse_args()

    if args.verbose >= 1:
        _logger.setLevel("DEBUG")
    if args.verbose >= 2:
        logging.getLogger().setLevel("DEBUG")

    _logger.debug(args)

    args._parser = parser  # noqa: SLF001

    if args.subcommand == "sign":
        _sign(args)
    elif args.subcommand == "verify":
        with _receipt_context(args):
            if args.verification_type == "attestation":
                _verify_attestation(args)
            elif args.verification_type == "pypi":
                _verify_pypi(args)
    elif args.subcommand == "inspect":
        _inspect(args)
    elif args.subcommand == "convert":
        _convert(args)
