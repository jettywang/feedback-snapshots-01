"""Implementation of the CLI for pypi-attestations."""

from __future__ import annotations

import argparse
import json
import logging
import typing
from collections import defaultdict
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
    BundleReport,
    CircleCIPublisher,
    ConversionError,
    Distribution,
    GitHubPublisher,
    GitLabPublisher,
    GooglePublisher,
    Provenance,
    ProvenanceReport,
    Publisher,
)

if typing.TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable
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
        action="append",
        type=str,
        help="URL of an approved publishing GitHub or GitLab repository; "
        "supply once per approved publisher",
    )

    verify_pypi_command.add_argument(
        "--gcp-service-account",
        action="append",
        type=str,
        help="Email of an approved Google Cloud service account; "
        "supply once per approved publisher",
    )

    verify_pypi_command.add_argument(
        "--circleci-project-id",
        action="append",
        type=str,
        help="CircleCI project ID (UUID) of an approved publisher",
    )

    verify_pypi_command.add_argument(
        "--circleci-pipeline-definition-id",
        action="append",
        type=str,
        help="CircleCI pipeline definition ID (UUID) of an approved publisher",
    )

    verify_pypi_command.add_argument(
        "--approve-bundle",
        action="append",
        type=int,
        metavar="INDEX",
        help="Approve the attestation bundle at this zero-based position, "
        "in addition to any publisher selections",
    )

    verify_pypi_command.add_argument(
        "--report-json",
        type=Path,
        metavar="FILE",
        help="Write the per-bundle verification and approval report as JSON",
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
    _logger.error(message)
    raise SystemExit(1)


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
                _die(f"Error downloading file: {response.status} {response.reason}")

            with open(dest, "wb") as f:
                for chunk in response.stream(1024):
                    f.write(chunk)
    except urllib3.exceptions.HTTPError as e:
        _die(f"Error downloading file: {e}")


def _get_distribution_from_arg(arg: str, offline: bool) -> Distribution:
    """Parse the artifact argument for the `verify pypi` subcommand.

    The argument can be:
    - A pypi: prefixed filename (e.g. pypi:sampleproject-1.0.0.tar.gz)
    - A direct URL to a PyPI-hosted artifact
    - A path to a local file
    """
    if arg.startswith("pypi:") or arg.startswith("https://"):
        if offline:
            _die("The '--offline' option can only be used with local files")
        pypi_url = _get_direct_url_from_arg(arg)
        dist_filename = pypi_url.path.split("/")[-1]
        with TemporaryDirectory() as temp_dir:
            dist_path = Path(temp_dir) / dist_filename
            _download_file(url=pypi_url.unsplit(), dest=dist_path)
            dist = Distribution.from_file(dist_path)
    else:
        dist_path = Path(arg)
        if not dist_path.exists():
            _die(f"File does not exist: {dist_path}")
        dist = Distribution.from_file(dist_path)

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
            _die(f"Error trying to get information for '{pkg_name}' from PyPI: {response.status}")

        response_json = response.json()
        for file_json in response_json.get("files", []):
            if file_json.get("filename", "") == file_name:
                direct_url = file_json.get("url", "")
                break
        if not direct_url:
            _die(f"Could not find the artifact '{file_name}' on PyPI")
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
        _die("Access to provenance is temporarily disabled by PyPI administrators")
    elif response.status == 404:
        _die(f'Provenance for file "{filename}" was not found')
    elif response.status != 200:
        _die(
            f"Unexpected error while downloading provenance file from PyPI, Integrity API "
            f"returned status code: {response.status}"
        )

    try:
        return Provenance.model_validate_json(response.data)
    except ValidationError as validation_error:
        _die(f"Invalid provenance: {validation_error}")


def _repository_identity_matches(
    expected_repository_url: str, publisher: GitHubPublisher | GitLabPublisher
) -> tuple[bool, str]:
    """Check whether a repository URL matches the given publisher's identity.

    Returns `(matches, reason)`, where `reason` explains a mismatch.
    """
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
        return (
            False,
            f"provenance was signed by a {actual_host} repository, but "
            f"expected a {expected_host} repository",
        )

    actual_repository = publisher.repository
    # '/owner/repo' -> 'owner/repo'
    expected_repository = expected_uri.path.lstrip("/")
    if actual_repository != expected_repository:
        return (
            False,
            f'provenance was signed by repository "{actual_repository}", '
            f'expected "{expected_repository}"',
        )

    return True, ""


def _approved_publishers(
    args: argparse.Namespace, provenance: Provenance
) -> tuple[list[Publisher], list[str]]:
    """Build the approved publisher identities selected on the command line.

    Returns `(publishers, errors)`. Errors describe selections that were
    supplied with incomplete options, such as a CircleCI project without a
    pipeline definition, or a single-bundle legacy selection that does not
    match the bundle's declared publisher.
    """
    publishers: list[Publisher] = []
    errors: list[str] = []

    repositories = args.repository or []
    service_accounts = args.gcp_service_account or []
    project_ids = args.circleci_project_id or []
    pipeline_ids = args.circleci_pipeline_definition_id or []

    if project_ids and not pipeline_ids:
        errors.append(
            "Provenance signed by CircleCI, but no pipeline definition ID provided; "
            "use '--circleci-pipeline-definition-id'"
        )
    elif pipeline_ids and not project_ids:
        errors.append(
            "Provenance signed by CircleCI, but no project ID provided; "
            "use '--circleci-project-id'"
        )
    else:
        for project_id, pipeline_id in zip(project_ids, pipeline_ids, strict=False):
            publishers.append(
                CircleCIPublisher(
                    project_id=project_id,
                    pipeline_definition_id=pipeline_id,
                )
            )

    for repository in repositories:
        publishers.append(_repository_publisher(repository))

    for service_account in service_accounts:
        publishers.append(GooglePublisher(email=service_account))

    if errors:
        return publishers, errors

    errors.extend(_single_bundle_selection_errors(args, provenance, publishers))

    return publishers, errors


def _single_bundle_selection_errors(
    args: argparse.Namespace, provenance: Provenance, publishers: list[Publisher]
) -> list[str]:
    """Preserve the historical single-bundle selection diagnostics.

    With multiple bundles, approval is per bundle: a bundle whose publisher
    type has no selection option is simply unapproved, and the remaining
    bundles can still be verified and admitted.
    """
    bundles = provenance.attestation_bundles
    if len(bundles) != 1:
        return []

    declared = bundles[0].publisher
    if isinstance(declared, GooglePublisher):
        if not (args.gcp_service_account or []):
            return [
                "Provenance signed by a Google Cloud account, but no service account "
                "provided; use '--gcp-service-account'"
            ]
        selected = args.gcp_service_account[0]
        if declared.email != selected:
            return [
                "Verification failed: provenance was signed by service account "
                f'"{declared.email}", expected "{selected}"'
            ]
        return []

    if isinstance(declared, CircleCIPublisher):
        if not (args.circleci_project_id or []):
            return [
                "Provenance signed by CircleCI, but no project ID provided; "
                "use '--circleci-project-id'"
            ]
        selected_project = args.circleci_project_id[0]
        selected_pipeline = (args.circleci_pipeline_definition_id or [""])[0]
        if declared.project_id != selected_project:
            return [
                "Verification failed: provenance was signed by CircleCI project "
                f'"{declared.project_id}", expected "{selected_project}"'
            ]
        if declared.pipeline_definition_id != selected_pipeline:
            return [
                "Verification failed: provenance was signed by CircleCI pipeline "
                f'definition "{declared.pipeline_definition_id}", expected '
                f'"{selected_pipeline}"'
            ]
        return []

    if isinstance(declared, (GitHubPublisher, GitLabPublisher)):
        if not (args.repository or []):
            return [
                "Provenance signed by a repository, but no repository URL provided; "
                "use '--repository'"
            ]
        for repository_url in args.repository:
            matches, reason = _repository_identity_matches(repository_url, declared)
            if matches:
                return []
        # Preserve the historical diagnostic for the first selection.
        _, reason = _repository_identity_matches(args.repository[0], declared)
        return [f"Verification failed: {reason}"]

    return []


def _repository_publisher(url: str) -> GitHubPublisher | GitLabPublisher:
    """Build a publisher selection from an approved repository URL."""
    validator = (
        validators.Validator()
        .allow_schemes("https")
        .allow_hosts("github.com", "gitlab.com")
        .require_presence_of("scheme", "host")
    )
    try:
        uri = uri_reference(url)
        validator.validate(uri)
    except exceptions.RFC3986Exception as e:
        _die(f"Unsupported/invalid URL: {e}")

    repository = uri.path.lstrip("/")
    if uri.host == "github.com":
        return GitHubPublisher(repository=repository, workflow="")
    return GitLabPublisher(repository=repository, workflow_filepath="")


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

    # Validate that the files exist
    _validate_files(args.files, should_exist=True)

    # artifact -> [attestation1, attestation2, ...]
    files_with_attestations: dict[Path, list[Path]] = defaultdict(list)
    for f in args.files:
        for attestation_file in (Path(f"{f}.publish.attestation"), Path(f"{f}.slsa.attestation")):
            if attestation_file.exists():
                files_with_attestations[f].append(attestation_file)
        if not files_with_attestations[f]:
            _die(f"Couldn't find attestations for file {f}")

    for file_path, attestations in files_with_attestations.items():
        for attestation_path in attestations:
            try:
                attestation = Attestation.model_validate_json(attestation_path.read_bytes())
            except ValidationError as validation_error:
                _die(f"Invalid attestation ({attestation_path}): {validation_error}")

            try:
                dist = Distribution.from_file(file_path)
            except ValidationError as e:
                _die(f"Invalid Python package distribution: {e}")

            try:
                attestation.verify(pol, dist, staging=args.staging, offline=args.offline)
            except VerificationError as verification_error:
                _die(f"Verification failed for {file_path}: {verification_error}")

            _logger.info(f"OK: {attestation_path}")


def _verify_pypi(args: argparse.Namespace) -> None:
    """Verify a distribution hosted on PyPI.

    The distribution is downloaded (if needed) and verified against the
    provenance file (passed using the `--provenance-file` option, or
    downloaded from PyPI if not provided).

    Every attestation bundle is verified independently using its own declared
    publisher. The publisher selection options identify which bundle(s) the
    caller approves for this admission; bundles that were not approved are
    still verified and reported but do not contribute to admission.
    """
    dist = _get_distribution_from_arg(args.distribution_file, offline=args.offline)

    if args.provenance_file is None:
        if args.offline:
            _die("The '--offline' option can only be used with local files")
        provenance = _get_provenance_from_pypi(dist)
    else:
        if not args.provenance_file.exists():
            _die(f"Provenance file does not exist: {args.provenance_file}")
        try:
            provenance = Provenance.model_validate_json(args.provenance_file.read_bytes())
        except ValidationError as validation_error:
            _die(f"Invalid provenance: {validation_error}")

    approved_publishers, selection_errors = _approved_publishers(args, provenance)
    if selection_errors:
        _die("\n".join(selection_errors))

    if not approved_publishers and not args.approve_bundle:
        _die(
            f"Verification failed for {dist.name}: no approved publisher or bundle "
            "was selected"
        )

    try:
        report = provenance.report(
            dist,
            approved_publishers,
            approved_bundles=args.approve_bundle,
            staging=args.staging,
            offline=args.offline,
        )
    except AttestationError as attestation_error:
        _die(str(attestation_error))

    _log_report(report)

    if args.report_json is not None:
        args.report_json.write_text(report.model_dump_json(indent=2))

    if not report.admitted:
        failed = [
            bundle
            for bundle in report.bundles
            if bundle.approved and not bundle.admitted
        ]
        if failed:
            details = "; ".join(
                f"bundle {bundle.index} ({bundle.publisher.kind}) failed verification"
                for bundle in failed
            )
            _die(f"Verification failed for {dist.name}: {details}")
        _die(
            f"Verification failed for {dist.name}: no approved bundle was found "
            f"(selections: {', '.join(report.unmatched_selections) or 'none'})"
        )

    _logger.info(f"OK: {dist.name}")


def _log_report(report: ProvenanceReport) -> None:
    """Log a per-bundle verification and approval report."""
    _logger.info(f"Report for {report.distribution}:")
    _logger.info(f"  approved bundles: {report.approved_bundles or 'none'}")
    if report.approved_publishers:
        _logger.info(
            "  approved publishers: "
            + ", ".join(
                f"{publisher.kind}:{_publisher_detail(publisher)}"
                for publisher in report.approved_publishers
            )
        )
    for bundle in report.bundles:
        _logger.info(
            f"  bundle {bundle.index} ({_publisher_summary(bundle)}): "
            f"verified={bundle.verified} approved={bundle.approved} "
            f"approved_by={bundle.approved_by or 'none'} "
            f"admitted={bundle.admitted}"
        )
        for result in bundle.attestation_results:
            if result.verified:
                _logger.info(
                    f"    attestation {result.index}: verified "
                    f"({result.predicate_type})"
                )
            else:
                _logger.info(f"    attestation {result.index}: failed: {result.error}")
    for selection in report.unmatched_selections:
        _logger.info(f"  unmatched selection: {selection}")
    _logger.info(f"  admitted: {report.admitted}")


def _publisher_summary(bundle: BundleReport) -> str:
    """Summarize a bundle's declared publisher identity."""
    return f"{bundle.publisher.kind} {_publisher_detail(bundle.publisher)}"


def _publisher_detail(publisher: Publisher) -> str:
    """Return the identity detail used in reports."""
    if isinstance(publisher, (GitHubPublisher, GitLabPublisher)):
        return publisher.repository
    if isinstance(publisher, GooglePublisher):
        return publisher.email
    return f"{publisher.project_id}/{publisher.pipeline_definition_id}"


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
        if args.verification_type == "attestation":
            _verify_attestation(args)
        elif args.verification_type == "pypi":
            _verify_pypi(args)
    elif args.subcommand == "inspect":
        _inspect(args)
    elif args.subcommand == "convert":
        _convert(args)
