# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  runlib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  June 27, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Provides a wrapper for any command of the software supply chain.

  The wrapper performs the following tasks which are implemented in this
  library.

    - Record state of material (files the command is executed on)
    - Execute command
      - Capture stdout/stderr/return value of the executed command
    - Record state of product (files after the command was executed)
    - Return Metadata containing a Link object which can be can be signed
      and stored to disk
"""

import contextlib
import glob
import hashlib
import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict

import securesystemslib._gpg
import securesystemslib.exceptions
import securesystemslib.formats
from securesystemslib.signer import Signer

import in_toto.exceptions
import in_toto.settings
from in_toto.formats import _check_hex, _check_str, _check_str_list
from in_toto.models._signer import GPGSigner
from in_toto.models.link import (
    FILENAME_FORMAT,
    FILENAME_FORMAT_SHORT,
    FILENAME_HANDLE_FORMAT,
    UNFINISHED_FILENAME_FORMAT,
    UNFINISHED_FILENAME_FORMAT_GLOB,
    UNFINISHED_HANDLE_FILENAME_FORMAT,
    UNFINISHED_HANDLE_FILENAME_GLOB,
)
from in_toto.models.metadata import Envelope, Metablock, Metadata
from in_toto.models.record import (
    RecordHandle,
    check_record_token,
    make_record_token,
)
from in_toto.resolver import (
    RESOLVER_FOR_URI_SCHEME,
    DirectoryResolver,
    FileResolver,
    OSTreeResolver,
    Resolver,
)

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)


def record_artifacts_as_dict(  # noqa: PLR0913, PLR0917, RUF100
    artifacts,
    exclude_patterns=None,
    base_path=None,
    follow_symlink_dirs=False,
    normalize_line_endings=False,
    lstrip_paths=None,
):
    """
    <Purpose>
      Hashes each file in the passed path list. If the path list contains
      paths to directories the directory tree(s) are traversed.

      The files a link command is executed on are called materials.
      The files that result form a link command execution are called
      products.

      Paths are normalized for matching and storing by left stripping "./"

      NOTE on exclude patterns:
        - Uses PathSpec to compile gitignore-style patterns, making use of the
          GitWildMatchPattern class (registered as 'gitwildmatch')

        - Patterns are checked for match against the full path relative to each
          path passed in the artifacts list

        - If a directory is excluded, all its files and subdirectories are also
          excluded

        - How it differs from .gitignore
              - No need to escape #
              - No ignoring of trailing spaces
              - No general negation with exclamation mark !
              - No special treatment of slash /
              - No special treatment of consecutive asterisks **

        - Exclude patterns are likely to become command line arguments or part of
          a config file.

    <Arguments>
      artifacts:
              A list of file or directory paths used as materials or products for
              the link command.

      exclude_patterns: (optional)
              Artifacts matched by the pattern are excluded from the result.
              Exclude patterns can be passed as argument or specified via
              ARTIFACT_EXCLUDE_PATTERNS setting (see `in_toto.settings`).
              If passed, patterns specified via settings are overridden.

      base_path: (optional)
              Change to base_path and record artifacts relative from there.
              If not passed, current working directory is used as base_path.
              NOTE: The base_path part of the recorded artifact is not included
              in the returned paths.

      follow_symlink_dirs: (optional)
              Follow symlinked dirs if the linked dir exists (default is False).
              The recorded path contains the symlink name, not the resolved name.
              NOTE: This parameter toggles following linked directories only,
              linked files are always recorded, independently of this parameter.
              NOTE: Beware of infinite recursions that can occur if a symlink
              points to a parent directory or itself.

      normalize_line_endings: (optional)
              If True, replaces windows and mac line endings with unix line
              endings before hashing the content of the passed files, for
              cross-platform support.

      lstrip_paths: (optional)
              If a prefix path is passed, the prefix is left stripped from
              the path of every artifact that contains the prefix.

    <Exceptions>
      OSError: cannot change to base path directory.
      ValueError: arguments are malformed.

    <Side Effects>
      Calls functions to generate cryptographic hashes.

    <Returns>
      A dictionary with file paths as keys and the files' hashes as values.

    """
    artifact_hashes = {}

    if not artifacts:
        return artifact_hashes

    if not base_path:
        base_path = in_toto.settings.ARTIFACT_BASE_PATH

    if not exclude_patterns:
        exclude_patterns = in_toto.settings.ARTIFACT_EXCLUDE_PATTERNS

    # Configure resolver with resolver specific arguments
    # FIXME: This should happen closer to the user boundary, where
    # resolver-specific config arguments are passed and global state is managed.
    RESOLVER_FOR_URI_SCHEME[FileResolver.SCHEME] = FileResolver(
        exclude_patterns,
        base_path,
        follow_symlink_dirs,
        normalize_line_endings,
        lstrip_paths,
    )

    # Configure resolver for OSTree
    RESOLVER_FOR_URI_SCHEME[OSTreeResolver.SCHEME] = OSTreeResolver(base_path)

    # Configure resolver for hashing directories as a single entry
    RESOLVER_FOR_URI_SCHEME[DirectoryResolver.SCHEME] = DirectoryResolver(
        exclude_patterns=exclude_patterns,
        follow_symlink_dirs=follow_symlink_dirs,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    # Aggregate artifacts per resolver
    resolver_for_uris = defaultdict(list)
    for artifact in artifacts:
        resolver = Resolver.for_uri(artifact)
        resolver_for_uris[resolver].append(artifact)

    # Hash artifacts in a batch per resolver
    # FIXME: The behavior may change if we hash each artifact individually,
    # because the left-prefix duplicate check in FileResolver only works for the
    # artifacts hashed in one batch.
    for resolver, uris in resolver_for_uris.items():
        artifact_hashes.update(resolver.hash_artifacts(uris))

    # Clear resolvers to not preserve global state change beyond this function.
    # FIXME: This also clears resolver registered elsewhere. For now we
    # assume that we only modify RESOLVER_FOR_URI_SCHEME in this function.
    RESOLVER_FOR_URI_SCHEME.clear()

    return artifact_hashes


def _subprocess_run_duplicate_streams(cmd, timeout):
    """Helper to run subprocess and both print and capture standards streams.

    Caveat:
    * Might behave unexpectedly with interactive commands.
    * Might not duplicate output in real time, if the command buffers it (see
      e.g. `print("foo")` vs. `print("foo", flush=True)`).
    * Possible race condition on Windows when removing temporary files.

    """
    # Use temporary files as targets for child process standard stream redirects
    # They seem to work better (i.e. do not hang) than pipes, when using
    # interactive commands like `vi`.
    stdout_fd, stdout_name = tempfile.mkstemp()
    stderr_fd, stderr_name = tempfile.mkstemp()
    try:
        with (
            open(  # noqa: PLW1514, RUF100
                stdout_name
            ) as stdout_reader,
            os.fdopen(stdout_fd, "w") as stdout_writer,
            open(  # noqa: PLW1514, RUF100
                stderr_name
            ) as stderr_reader,
            os.fdopen(stderr_fd, "w") as stderr_writer,
        ):
            # Store stream results in mutable dict to update it inside nested helper
            streams = {"out": "", "err": ""}

            def _duplicate_streams():
                """Helper to read from child process standard streams, write their
                contents to parent process standard streams, and build up return values
                for outer function.
                """
                # Read until EOF but at most `io.DEFAULT_BUFFER_SIZE` bytes per call.
                # Reading and writing in reasonably sized chunks prevents us from
                # subverting a timeout, due to being busy for too long or indefinitely.
                stdout_part = stdout_reader.read(io.DEFAULT_BUFFER_SIZE)
                stderr_part = stderr_reader.read(io.DEFAULT_BUFFER_SIZE)
                sys.stdout.write(stdout_part)
                sys.stderr.write(stderr_part)
                sys.stdout.flush()
                sys.stderr.flush()
                streams["out"] += stdout_part
                streams["err"] += stderr_part

            # Start child process, writing its standard streams to temporary files
            proc = subprocess.Popen(  # pylint: disable=consider-using-with  # noqa: S603
                cmd,
                stdout=stdout_writer,
                stderr=stderr_writer,
                universal_newlines=True,
            )
            proc_start_time = time.time()

            # Duplicate streams until the process exits (or times out)
            while proc.poll() is None:
                # Time out as Python's `subprocess.run` would do it
                if (
                    timeout is not None
                    and time.time() > proc_start_time + timeout
                ):
                    proc.kill()
                    proc.wait()
                    raise subprocess.TimeoutExpired(cmd, timeout)

                _duplicate_streams()

            # Read/write once more to grab everything that the process wrote between
            # our last read in the loop and exiting, i.e. breaking the loop.
            _duplicate_streams()

    finally:
        # The work is done or was interrupted, the temp files can be removed
        # FIXME: retry failed file removal once to maybe work around #547
        for name in (stdout_name, stderr_name):
            try:
                os.remove(name)
            except PermissionError:  # pragma: no cover
                time.sleep(0.01)
                os.remove(name)

    # Return process exit code and captured streams
    return proc.poll(), streams["out"], streams["err"]


def execute_link(link_cmd_args, record_streams, timeout):
    """
    <Purpose>
      Executes the passed command plus arguments in a subprocess and returns
      the return value of the executed command. If the specified standard output
      and standard error of the command are recorded and also returned to the
      caller.

    <Arguments>
      link_cmd_args:
              A list where the first element is a command and the remaining
              elements are arguments passed to that command.
      record_streams:
              A bool that specifies whether to redirect standard output and
              and standard error to a temporary file which is returned to the
              caller (True) or not (False).

    <Exceptions>
      OSError:
              The given command is not present or non-executable

      subprocess.TimeoutExpired:
              The execution of the given command times.

    <Side Effects>
      Executes passed command in a subprocess and redirects stdout and stderr
      if specified.

    <Returns>
      - A dictionary containing standard output and standard error of the
        executed command, called by-products.
        Note: If record_streams is False, the dict values are empty strings.
      - The return value of the executed command.
    """
    if record_streams:
        return_code, stdout_str, stderr_str = _subprocess_run_duplicate_streams(
            link_cmd_args, timeout=timeout
        )

    else:
        process = subprocess.run(  # noqa: S603
            link_cmd_args,
            check=False,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        stdout_str = stderr_str = ""
        return_code = process.returncode

    return {
        "stdout": stdout_str,
        "stderr": stderr_str,
        "return-value": return_code,
    }


def in_toto_mock(name, link_cmd_args, use_dsse=False):
    """
    <Purpose>
      in_toto_run with defaults
       - Records materials and products in current directory
       - Does not sign resulting link file
       - Stores resulting link file under "<name>.link"

    <Arguments>
      name:
              A unique name to relate mock link metadata with a step or
              inspection defined in the layout.
      link_cmd_args:
              A list where the first element is a command and the remaining
              elements are arguments passed to that command.
      use_dsse (optional):
              A boolean indicating if DSSE should be used to generate metadata.

    <Exceptions>
      None.

    <Side Effects>
      Writes newly created link metadata file to disk using the filename scheme
      from link.FILENAME_FORMAT_SHORT

    <Returns>
      Newly created Metadata object containing a Link object

    """
    link_metadata = in_toto_run(
        name,
        ["."],
        ["."],
        link_cmd_args,
        record_streams=True,
        use_dsse=use_dsse,
    )

    filename = FILENAME_FORMAT_SHORT.format(step_name=name)
    LOG.info("Storing unsigned link metadata to '%s'...", filename)
    link_metadata.dump(filename)
    return link_metadata


def _check_signer(signer):
    if not isinstance(signer, Signer):
        raise ValueError("signer must be a Signer instance")


def _require_signing_arg(signer, gpg_keyid, gpg_use_default):
    if not any([signer, gpg_keyid, gpg_use_default]):
        raise ValueError(
            "Pass either a signer, a gpg keyid or set gpg_use_default to True!"
        )


def in_toto_run(  # noqa: C901, PLR0912, PLR0913, PLR0914, PLR0915, PLR0917, RUF100
    name,
    material_list,
    product_list,
    link_cmd_args,
    record_streams=False,
    gpg_keyid=None,
    gpg_use_default=False,
    gpg_home=None,
    exclude_patterns=None,
    base_path=None,
    compact_json=False,
    record_environment=False,
    normalize_line_endings=False,
    lstrip_paths=None,
    metadata_directory=None,
    use_dsse=False,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
    signer=None,
):
    """Performs a supply chain step or inspection generating link metadata.

  Executes link_cmd_args, recording paths and hashes of files before and after
  command execution (aka. artifacts) in a link metadata file. The metadata is
  signed with the passed signer, a gpg key identified by its ID, or
  the default gpg key. If multiple key arguments are passed, only one key is
  used in above order of precedence. The resulting link file is written to
  ``STEP-NAME.KEYID-PREFIX.link``. If no key argument is passed the link
  metadata is neither signed nor written to disk.

  Arguments:
    name: A unique name to associate link metadata with a step or inspection.

    material_list: A list of artifact paths to be recorded before command
        execution. Directories are traversed recursively.

    product_list: A list of artifact paths to be recorded after command
        execution. Directories are traversed recursively.

    link_cmd_args: A list where the first element is a command and the
        remaining elements are arguments passed to that command.

    record_streams (optional): A boolean indicating if standard output and
        standard error of the link command should be recorded in the link
        metadata in addition to being displayed while the command is executed.

    gpg_keyid (optional): A keyid used to identify a local gpg key used to sign
        the resulting link metadata.

    gpg_use_default (optional): A boolean indicating if the default gpg key
        should be used to sign the resulting link metadata.

    gpg_home (optional): A path to the gpg home directory. If not set the
        default gpg home directory is used.

    exclude_patterns (optional): A list of filename patterns to exclude certain
        files from being recorded as artifacts. See Config docs for details.

    base_path (optional): A path relative to which artifacts are recorded.
        Default is the current working directory.

    compact_json (optional): A boolean indicating if the resulting link
        metadata should be written in the most compact JSON representation.

    record_environment (optional): A boolean indicating if information about
        the environment should be added in the resulting link metadata.

    normalize_line_endings (optional): A boolean indicating if line endings of
        artifacts should be normalized before hashing for cross-platform
        support.

    lstrip_paths (optional): A list of path prefixes used to left-strip
        artifact paths before storing them in the resulting link metadata.

    metadata_directory (optional): A directory path to write the resulting link
        metadata file to. Default destination is the current working directory.

    use_dsse (optional): A boolean indicating if DSSE should be used to
        generate metadata.

    timeout (optional): An integer indicating the max timeout in seconds
        for this command. Default is 10 seconds.

    signer (optional): A securesystemslib Signer instance used to
        sign the resulting link metadata.

  Raises:
    securesystemslib.exceptions.FormatError: Passed arguments are malformed.

    OSError: Cannot change to base path directory.

    securesystemslib.exceptions.StorageError: Cannot hash artifacts.

    PrefixError: Left-stripping artifact paths results in non-unique dict keys.

    subprocess.TimeoutExpired: Link command times out.

    IOError, FileNotFoundError, NotADirectoryError, PermissionError:
        Cannot write link metadata.

    securesystemslib.exceptions.CryptoError, \
            securesystemslib.exceptions.UnsupportedAlgorithmError:
        Signing errors.

    ValueError, OSError, securesystemslib._gpg.exceptions.CommandError, \
            securesystemslib._gpg.exceptions.KeyNotFoundError:
        gpg signing errors.

  Side Effects:
    Reads artifact files from disk.
    Runs link command in subprocess.
    Calls system gpg in a subprocess, if a gpg key argument is passed.
    Writes link metadata file to disk, if any key argument is passed.

  Returns:
    A Metadata object that contains the resulting link object.

  """
    LOG.info("Running '%s'...", name)

    # Check key formats to fail early
    if signer:
        _check_signer(signer)

    if gpg_keyid:
        _check_hex(gpg_keyid)

    if exclude_patterns:
        _check_str_list(exclude_patterns)

    if base_path:
        _check_str(base_path)

    if metadata_directory:
        _check_str(metadata_directory)

    if material_list:
        LOG.info("Recording materials '%s'...", ", ".join(material_list))

    materials_dict = record_artifacts_as_dict(
        material_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    if link_cmd_args:
        _check_str_list(link_cmd_args)
        LOG.info("Running command '%s'...", " ".join(link_cmd_args))
        byproducts = execute_link(link_cmd_args, record_streams, timeout)
    else:
        byproducts = {}

    if product_list:
        _check_str_list(product_list)
        LOG.info("Recording products '%s'...", ", ".join(product_list))

    products_dict = record_artifacts_as_dict(
        product_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    LOG.info("Creating link metadata...")
    environment = {}
    if record_environment:
        environment["workdir"] = os.getcwd().replace("\\", "/")

    link = in_toto.models.link.Link(
        name=name,
        materials=materials_dict,
        products=products_dict,
        command=link_cmd_args,
        byproducts=byproducts,
        environment=environment,
    )

    if use_dsse:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)
    else:
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link, compact_json=compact_json)

    if signer:
        LOG.info("Signing link metadata using passed signer...")

    elif gpg_keyid:
        LOG.info("Signing link metadata using passed GPG keyid...")
        signer = GPGSigner(keyid=gpg_keyid, homedir=gpg_home)

    elif gpg_use_default:
        LOG.info("Signing link metadata using default GPG key ...")
        signer = GPGSigner(keyid=None, homedir=gpg_home)

    # We need the signature's keyid to write the link to keyid infix'ed filename
    if signer:
        signature = link_metadata.create_signature(signer)
        signing_keyid = signature.keyid

        filename = FILENAME_FORMAT.format(step_name=name, keyid=signing_keyid)

        if metadata_directory is not None:
            filename = os.path.join(metadata_directory, filename)

        LOG.info("Storing link metadata to '%s'...", filename)
        link_metadata.dump(filename)

    return link_metadata


def _sha256_bytes(data):
    """Return the lowercase SHA-256 hex digest of passed bytes."""
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    """Return the lowercase SHA-256 hex digest of the file at path."""
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _materials_digest(materials):
    """Return a stable digest over a recorded materials dictionary."""
    canonical = json.dumps(
        materials, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return _sha256_bytes(canonical)


def _atomic_write_bytes(path, data):
    """Atomically write bytes to path.

    Writes to a temporary file in the target directory and replaces the target
    only after the write completed. A failed write does not truncate or
    overwrite an existing file and does not leave a partially written target.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".in-toto-record-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as fp:
            fp.write(data)
            fp.flush()
            os.fsync(fp.fileno())

        os.replace(tmp_path, path)

    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _atomic_dump_metadata(metadata, path):
    """Atomically dump metadata to path and return the exact written bytes.

    Uses the public metadata ``dump`` method, so write failures surface where
    callers expect them, but only replaces the target after the complete
    metadata was written and flushed.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".in-toto-record-", suffix=".tmp"
    )
    os.close(fd)
    try:
        metadata.dump(tmp_path)
        with open(tmp_path, "rb+") as fp:
            os.fsync(fp.fileno())
            data = fp.read()

        os.replace(tmp_path, path)
        return data

    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _metadata_signature_keyids(metadata):
    """Return keyids of all signatures in passed metadata."""
    if isinstance(metadata, Envelope):
        return [signature.keyid for signature in metadata.signatures.values()]

    return [signature["keyid"] for signature in metadata.signatures]


def _get_stop_verification_key(  # noqa: PLR0913
    link_metadata, signer, gpg_keyid, gpg_home, expected_keyid
):
    """Return verification key and keyid for finishing passed metadata.

    If expected_keyid is set, it must match the key used for verification and,
    for default gpg keys, must occur in the metadata's signatures.
    """
    if signer:
        LOG.info("Verifying preliminary link signature using passed signer...")
        keyid = signer.public_key.keyid
        verification_key = signer.public_key.to_dict()
        verification_key["keyid"] = keyid

    elif gpg_keyid:
        LOG.info("Verifying preliminary link signature using passed gpg key...")
        verification_key = securesystemslib._gpg.functions.export_pubkey(  # noqa: SLF001
            gpg_keyid, gpg_home
        )
        keyid = verification_key["keyid"]

    else:  # must be gpg_use_default
        LOG.info(
            "Verifying preliminary link signature using default gpg key..."
        )
        signature_keyids = _metadata_signature_keyids(link_metadata)
        if expected_keyid and expected_keyid in signature_keyids:
            keyid = expected_keyid
        elif not expected_keyid and signature_keyids:
            keyid = signature_keyids[0]
        else:
            raise in_toto.exceptions.RecordIdentityError(
                "The unfinished record was not signed by the signing"
                f" identity bound to the record handle ({expected_keyid})."
            )

        verification_key = securesystemslib._gpg.functions.export_pubkey(  # noqa: SLF001
            keyid, gpg_home
        )

    if expected_keyid and keyid != expected_keyid:
        raise in_toto.exceptions.RecordIdentityError(
            "The record was started with signing identity"
            f" '{expected_keyid}', but stop uses '{keyid}'."
        )

    return verification_key, keyid


def _get_expected_stop_keyid(signer, gpg_keyid, gpg_home):
    """Return the full keyid that will be used to finish a record, if known."""
    if signer:
        return signer.public_key.keyid

    if gpg_keyid:
        return securesystemslib._gpg.functions.export_pubkey(  # noqa: SLF001
            gpg_keyid, gpg_home
        )["keyid"]

    return None


def _coerce_record_handle(value):
    """Return a RecordHandle from a handle, mapping or JSON string."""
    if isinstance(value, RecordHandle):
        return value

    if isinstance(value, str):
        return RecordHandle.from_json(value)

    if isinstance(value, dict):
        return RecordHandle.from_dict(value)

    raise in_toto.exceptions.RecordHandleFormatError(
        "record_handle must be a RecordHandle, a dict, or a JSON object."
    )


def _legacy_unfinished_candidates(step_name):
    """Return legacy unfinished files for step, excluding session records."""
    glob_pattern = UNFINISHED_FILENAME_FORMAT_GLOB.format(
        step_name=glob.escape(step_name), pattern="*"
    )
    pattern = re.compile(
        r"^\." + re.escape(step_name) + r"\.[0-9a-fA-F]{8}\.link-unfinished$"
    )
    return sorted(
        path
        for path in glob.glob(glob_pattern)
        if pattern.match(os.path.basename(path))
    )


def _session_unfinished_candidates(step_name):
    """Return session-specific unfinished files for step."""
    glob_pattern = UNFINISHED_HANDLE_FILENAME_GLOB.format(
        step_name=glob.escape(step_name)
    )
    pattern = re.compile(
        r"^\."
        + re.escape(step_name)
        + r"\.[0-9a-fA-F]{8}\.[A-Za-z0-9_-]{8,128}\.link-unfinished$"
    )
    return sorted(
        path
        for path in glob.glob(glob_pattern)
        if pattern.match(os.path.basename(path))
    )


def _record_handle_completed_path(handle):
    """Return the stable, handle-bound completed link path.

    The session link stays at this path even when ``metadata_directory`` is
    passed, so a persisted handle can always read its completed result on
    retry. ``metadata_directory`` only controls the canonical mirror.
    """
    return handle.completed_path


def _session_completed_path(session_unfinished_path, metadata_directory=None):
    """Return the session completed link path for a session proof path."""
    basename = os.path.basename(session_unfinished_path)
    if not basename.endswith(".link-unfinished"):
        raise ValueError("Not a session unfinished record path")

    filename = basename[: -len("-unfinished")].lstrip(".")
    directory = metadata_directory or os.path.dirname(session_unfinished_path)
    return os.path.join(directory, filename)


def _record_handle_canonical_path(handle, metadata_directory=None):
    """Return the canonical, layout-discoverable link path for a handle.

    The per-session link is the auditable evidence for one build. The
    canonical ``STEP.KEYID.link`` name is also written so that in-toto
    verification and other existing consumers continue to find the result.
    """
    filename = FILENAME_FORMAT.format(
        step_name=handle.step_name, keyid=handle.keyid
    )

    if metadata_directory:
        if not os.path.isabs(metadata_directory):
            metadata_directory = os.path.join(
                handle.workdir, metadata_directory
            )
        return os.path.join(metadata_directory, filename)

    return os.path.join(handle.workdir, filename)


def _verify_handle_proof(handle, link_metadata, signer, gpg_keyid, gpg_home):  # noqa: PLR0913
    """Verify that loaded start or completed metadata belongs to handle."""
    try:
        verification_key, _ = _get_stop_verification_key(
            link_metadata,
            signer,
            gpg_keyid,
            gpg_home,
            handle.keyid,
        )
        link_metadata.verify_signature(verification_key)

    except in_toto.exceptions.RecordIdentityError:
        raise
    except (
        in_toto.exceptions.SignatureVerificationError,
        securesystemslib.exceptions.FormatError,
        securesystemslib.exceptions.VerificationError,
    ) as exc:
        raise in_toto.exceptions.RecordTamperedError(
            "The metadata bound to the record handle does not carry a"
            " valid signature by the expected signing identity."
        ) from exc

    link = link_metadata.get_payload()
    if not isinstance(link, in_toto.models.link.Link):
        raise in_toto.exceptions.RecordTamperedError(
            "The metadata bound to the record handle is not link metadata."
        )

    if link.name != handle.step_name:
        raise in_toto.exceptions.RecordTamperedError(
            "The metadata bound to the record handle is for step"
            f" '{link.name}', expected '{handle.step_name}'."
        )

    if _materials_digest(link.materials) != handle.start_materials_digest:
        raise in_toto.exceptions.RecordTamperedError(
            "The materials bound to the record handle were modified."
        )

    return link


def _mirror_canonical_link(
    handle, completed_path, completed_bytes, metadata_directory=None
):
    """Mirror a completed session link to the canonical step link path.

    Existing in-toto consumers discover links by ``STEP.KEYID.link``. Writing
    that name keeps handle-based records compatible with verification, while
    the session link remains the auditable per-build artifact.
    """
    canonical_path = _record_handle_canonical_path(handle, metadata_directory)
    if os.path.abspath(canonical_path) == os.path.abspath(completed_path):
        return

    LOG.info("Storing link metadata to '%s'...", canonical_path)
    _atomic_write_bytes(canonical_path, completed_bytes)


def _remove_matching_start_proofs(handle, remove_session=True):
    """Remove the session proof and any matching historical start proof.

    The historical proof is removed only when its bytes equal this handle's
    start proof. If it belongs to another concurrent session, it is left
    untouched for that session's record handle.
    """
    legacy_path = UNFINISHED_FILENAME_FORMAT.format(
        step_name=handle.step_name, keyid=handle.keyid
    )

    if remove_session:
        try:
            os.remove(handle.unfinished_path)
        except FileNotFoundError:
            pass
        except OSError:
            LOG.warning(
                "Could not remove stale unfinished record '%s'.",
                handle.unfinished_path,
            )

    try:
        if _sha256_file(legacy_path) == handle.start_digest:
            os.remove(legacy_path)
    except FileNotFoundError:
        pass


def _strip_record_artifacts(artifacts, step_name):
    """Remove in-toto record housekeeping files for retry comparison.

    A finished record removes its unfinished proof. If products were recorded
    from a directory with custom exclude patterns that did not exclude link
    files, that proof may appear in the recorded products. On retry it is gone.
    Ignoring these files only when comparing retry products keeps a successful
    retry from being misreported as a product change, without changing what is
    actually recorded.

    Only files belonging to the passed step name are ignored, so unrelated
    link metadata in the same directory is never treated specially.
    """
    escaped_step = re.escape(step_name)
    record_file = re.compile(
        r"^(?:"
        + escaped_step
        + r"\.[0-9a-fA-F]{8}(?:\.[A-Za-z0-9_-]{8,128})?\.link"
        + r"|\."
        + escaped_step
        + r"\.[0-9a-fA-F]{8}(?:\.[A-Za-z0-9_-]{8,128})?\.link-unfinished"
        + r"|\."
        + escaped_step
        + r"\.[0-9a-fA-F]{8}(?:\.[A-Za-z0-9_-]{8,128})?\.link\.tmp"
        + r"|\.in-toto-record-[A-Za-z0-9_-]+\.tmp)$"
    )

    return {
        name: digest
        for name, digest in artifacts.items()
        if not record_file.match(os.path.basename(name))
    }


def _completed_metadata_for_retry(  # noqa: PLR0913
    handle,
    completed_path,
    product_list,
    gpg_keyid,
    gpg_home,
    exclude_patterns,
    base_path,
    normalize_line_endings,
    lstrip_paths,
    command,
    byproducts,
    environment,
    signer,
):
    """Return the already completed result, or fail if retry would splice.

    A retry may read and return the existing signed result. It may not replace
    the products, command, byproducts, or environment recorded in it.
    """
    LOG.info(
        "Record handle was already completed at '%s'; checking retry...",
        completed_path,
    )
    link_metadata = Metadata.load(completed_path)
    link = _verify_handle_proof(
        handle,
        link_metadata,
        signer,
        gpg_keyid,
        gpg_home,
    )

    if product_list is not None:
        products = record_artifacts_as_dict(
            product_list,
            exclude_patterns=exclude_patterns,
            base_path=base_path,
            follow_symlink_dirs=True,
            normalize_line_endings=normalize_line_endings,
            lstrip_paths=lstrip_paths,
        )
        existing_products = _strip_record_artifacts(
            link.products, handle.step_name
        )
        retry_products = _strip_record_artifacts(products, handle.step_name)
        if retry_products != existing_products:
            raise in_toto.exceptions.RecordAlreadyCompletedError(
                "The record was already completed with different products."
                " A retry may read the completed result, but must not splice"
                " in a different product set."
            )

    for field, value in (
        ("command", command),
        ("byproducts", byproducts),
        ("environment", environment),
    ):
        if value is not None and value != getattr(link, field):
            raise in_toto.exceptions.RecordAlreadyCompletedError(
                f"The record was already completed with a different {field}."
            )

    LOG.info("Returning already completed link metadata '%s'.", completed_path)
    return link_metadata


def _record_handle_uses_workdir(handle):
    """Return True if the handle records artifacts relative to its workdir."""
    return os.path.realpath(handle.artifact_base_path) == os.path.realpath(
        handle.workdir
    )


def _in_toto_record_stop_with_handle(  # noqa: C901, PLR0912, PLR0913, PLR0914, PLR0915
    handle,
    product_list,
    gpg_keyid,
    gpg_home,
    exclude_patterns,
    base_path,
    normalize_line_endings,
    lstrip_paths,
    metadata_directory,
    command,
    byproducts,
    environment,
    signer,
):
    """Finish exactly the record identified by handle."""
    if not isinstance(handle, RecordHandle):
        handle = _coerce_record_handle(handle)

    LOG.info(
        "Stop recording '%s' for record handle '%s'...",
        handle.step_name,
        handle.token,
    )

    current_workdir = os.path.realpath(os.getcwd())
    if (
        _record_handle_uses_workdir(handle)
        and base_path is None
        and current_workdir != os.path.realpath(handle.workdir)
    ):
        raise in_toto.exceptions.RecordWorkingDirectoryError(
            f"Record handle was created in '{handle.workdir}', but stop"
            f" runs in '{current_workdir}'. Pass base_path explicitly to"
            " finish the record from a different working directory."
        )

    artifact_base_path = (
        base_path if base_path is not None else handle.artifact_base_path
    )
    completed_path = _record_handle_completed_path(handle)

    # Identity is checked before touching files, so stopping with a different
    # key cannot consume another functionary's record.
    expected_stop_keyid = _get_expected_stop_keyid(signer, gpg_keyid, gpg_home)
    if expected_stop_keyid is not None and expected_stop_keyid != handle.keyid:
        raise in_toto.exceptions.RecordIdentityError(
            "The record was started with signing identity"
            f" '{handle.keyid}', but stop uses '{expected_stop_keyid}'."
        )

    # A completed record may be safely read again on retry. The unfinished
    # proof is removed only after the completed link has been durably written,
    # so this path also recovers a successful stop whose cleanup was
    # interrupted.
    if os.path.isfile(completed_path):
        link_metadata = _completed_metadata_for_retry(
            handle,
            completed_path,
            product_list,
            gpg_keyid,
            gpg_home,
            exclude_patterns,
            artifact_base_path,
            normalize_line_endings,
            lstrip_paths,
            command,
            byproducts,
            environment,
            signer,
        )
        # A previous completion may have written the session link but failed
        # before mirroring the canonical link. Restore the mirror on retry.
        with open(completed_path, "rb") as fp:
            completed_bytes = fp.read()
        _mirror_canonical_link(
            handle, completed_path, completed_bytes, metadata_directory
        )

        LOG.info(
            "Removing unfinished link metadata '%s'...",
            handle.unfinished_path,
        )
        _remove_matching_start_proofs(handle, remove_session=False)
        return link_metadata

    if not os.path.isfile(handle.unfinished_path):
        raise in_toto.exceptions.RecordNotFoundError(
            "Could not find the unfinished record bound to handle"
            f" '{handle.token}' at '{handle.unfinished_path}'."
        )

    try:
        with open(handle.unfinished_path, "rb") as fp:
            unfinished_data = fp.read()
    except OSError as exc:
        raise in_toto.exceptions.RecordNotFoundError(
            "Could not read the unfinished record bound to handle"
            f" '{handle.token}' at '{handle.unfinished_path}'."
        ) from exc

    if _sha256_bytes(unfinished_data) != handle.start_digest:
        raise in_toto.exceptions.RecordTamperedError(
            "The unfinished record no longer matches the start proof bound"
            " to the record handle. The raw file was left in place for"
            " diagnosis."
        )

    LOG.info(
        "Loading preliminary link metadata '%s'...", handle.unfinished_path
    )
    link_metadata = Metadata.load(handle.unfinished_path)
    link = _verify_handle_proof(
        handle,
        link_metadata,
        signer,
        gpg_keyid,
        gpg_home,
    )

    if product_list:
        LOG.info("Recording products '%s'...", ", ".join(product_list))

    link.products = record_artifacts_as_dict(
        product_list,
        exclude_patterns=exclude_patterns,
        base_path=artifact_base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    if command:
        link.command = command

    if byproducts:
        link.byproducts = byproducts

    if environment:
        link.environment = environment

    if isinstance(link_metadata, Metablock):
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link)
    else:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)

    if signer:
        LOG.info(
            "Updating signature with signer '%.8s...'...",
            signer.public_key.keyid,
        )
    else:  # gpg_keyid or gpg_use_default
        LOG.info("Updating signature with gpg key '%.8s...'...", handle.keyid)
        signer = GPGSigner(keyid=handle.keyid, homedir=gpg_home)

    signature = link_metadata.create_signature(signer)
    if signature.keyid != handle.keyid:
        raise in_toto.exceptions.RecordIdentityError(
            "The completed record would be signed by"
            f" '{signature.keyid}', not by the bound identity"
            f" '{handle.keyid}'."
        )

    LOG.info("Storing link metadata to '%s'...", completed_path)
    completed_bytes = _atomic_dump_metadata(link_metadata, completed_path)
    _mirror_canonical_link(
        handle, completed_path, completed_bytes, metadata_directory
    )

    LOG.info(
        "Removing unfinished link metadata '%s'...", handle.unfinished_path
    )
    _remove_matching_start_proofs(handle)

    return link_metadata


def in_toto_record_start(  # noqa: PLR0913, PLR0917, RUF100
    step_name,
    material_list,
    gpg_keyid=None,
    gpg_use_default=False,
    gpg_home=None,
    exclude_patterns=None,
    base_path=None,
    record_environment=False,
    normalize_line_endings=False,
    lstrip_paths=None,
    use_dsse=False,
    signer=None,
    record_token=None,
):
    """Generates preliminary link metadata and returns a record handle.

  Records paths and hashes of materials in a preliminary link metadata file. The
  metadata is signed with the passed signer, a gpg key identified
  by its ID, or the default gpg key. If multiple key arguments are passed, only
  one key is used in above order of precedence. At least one key argument must
  be passed.

  The returned handle binds the step name, the signing keyid, the exact start
  proof (file digest and materials digest), the artifact working directory,
  and a session token. The session token is used in the handle's unfinished
  and completed file names, so same-named starts signed with the same key get
  distinct records whose materials cannot be mixed up.

  Two unfinished files are written:

    - ``.STEP-NAME.KEYID-PREFIX.TOKEN.link-unfinished``, the session-specific
      file bound to the returned
      :class:`in_toto.models.record.RecordHandle`.
    - ``.STEP-NAME.KEYID-PREFIX.link-unfinished``, the historical file, which
      keeps single-task and step-name-only stop calls compatible. It contains
      the same start proof bytes as the session file.

  Pass the returned handle to ``in_toto_record_stop`` to finish that exact
  record. A caller that passes only a step name keeps the historical
  single-task behavior: stop finishes the proof in the historical file, and
  raises ``RecordAmbiguousError`` if more than one session carries exactly
  that proof (e.g. two starts with identical materials and a deterministic
  signature). A caller-chosen ``record_token`` that is already in use is
  rejected rather than overwriting another session's start proof.

  Arguments:
    step_name: A unique name to associate link metadata with a step.

    material_list: A list of artifact paths to be recorded as materials.
        Directories are traversed recursively.

    gpg_keyid (optional): A keyid used to identify a local gpg key used to sign
        the resulting link metadata.

    gpg_use_default (optional): A boolean indicating if the default gpg key
        should be used to sign the resulting link metadata.

    gpg_home (optional): A path to the gpg home directory. If not set the
        default gpg home directory is used.

    exclude_patterns (optional): A list of filename patterns to exclude certain
        files from being recorded as artifacts. See Config docs for details.

    base_path (optional): A path relative to which artifacts are recorded.
        Default is the current working directory.

    record_environment (optional): A boolean indicating if information about
        the environment should be added in the resulting link metadata.

    normalize_line_endings (optional): A boolean indicating if line endings of
        artifacts should be normalized before hashing for cross-platform
        support.

    lstrip_paths (optional): A list of path prefixes used to left-strip
        artifact paths before storing them in the resulting link metadata.

    use_dsse (optional): A boolean indicating if DSSE should be used to
        generate metadata.

    signer (optional): A securesystemslib Signer instance used to
        sign the resulting link metadata.

    record_token (optional): A caller-chosen session token. It must contain
        8-128 characters of ``A-Za-z0-9_-``. If omitted, a random token is
        generated.

  Raises:
    securesystemslib.exceptions.FormatError: Passed arguments are malformed.

    ValueError: None of signer, gpg_keyid or gpg_use_default=True is
        passed.

    RecordHandleFormatError: Passed record_token is malformed or already in
        use by another unfinished record.

    securesystemslib.exceptions.StorageError: Cannot hash artifacts.

    PrefixError: Left-stripping artifact paths results in non-unique dict keys.

    subprocess.TimeoutExpired: Link command times out.

    IOError, PermissionError:
        Cannot write link metadata.

    securesystemslib.exceptions.CryptoError, \
            securesystemslib.exceptions.UnsupportedAlgorithmError:
        Signing errors.

    ValueError, OSError, securesystemslib._gpg.exceptions.CommandError, \
            securesystemslib._gpg.exceptions.KeyNotFoundError:
        gpg signing errors.

  Side Effects:
    Reads artifact files from disk.
    Calls system gpg in a subprocess, if a gpg key argument is passed.
    Writes the preliminary session and historical link metadata files to disk.

  Returns:
    A :class:`in_toto.models.record.RecordHandle` binding the started record.

  """
    # pylint: disable=too-many-locals

    # Fail if there is no signing key arg at all
    _require_signing_arg(signer, gpg_keyid, gpg_use_default)

    # Check key formats to fail early. Do this before any output, so invalid
    # arguments never leave a partial start proof behind.
    if signer:
        _check_signer(signer)

    if gpg_keyid:
        _check_str(gpg_keyid)

    if exclude_patterns:
        _check_str_list(exclude_patterns)

    if base_path:
        _check_str(base_path)

    token = (
        check_record_token(record_token)
        if record_token is not None
        else make_record_token()
    )

    LOG.info("Start recording '%s'...", step_name)

    if material_list:
        LOG.info("Recording materials '%s'...", ", ".join(material_list))

    materials_dict = record_artifacts_as_dict(
        material_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    LOG.info("Creating preliminary link metadata...")
    environment = {}
    if record_environment:
        environment["workdir"] = os.getcwd().replace("\\", "/")

    link = in_toto.models.link.Link(
        name=step_name,
        materials=materials_dict,
        products={},
        command=[],
        byproducts={},
        environment=environment,
    )

    if use_dsse:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)
    else:
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link)

    if signer:
        LOG.info("Signing link metadata using passed signer...")

    elif gpg_keyid:
        LOG.info("Signing link metadata using passed GPG keyid...")
        signer = GPGSigner(keyid=gpg_keyid, homedir=gpg_home)

    else:  # (gpg_use_default)
        LOG.info("Signing link metadata using default GPG key ...")
        signer = GPGSigner(keyid=None, homedir=gpg_home)

    signature = link_metadata.create_signature(signer)
    # We need the signature's keyid to write the link to keyid infix'ed filename
    signing_keyid = signature.keyid

    unfinished_fn = UNFINISHED_FILENAME_FORMAT.format(
        step_name=step_name, keyid=signing_keyid
    )
    session_fn = UNFINISHED_HANDLE_FILENAME_FORMAT.format(
        step_name=step_name, keyid=signing_keyid, handle=token
    )
    completed_fn = FILENAME_HANDLE_FORMAT.format(
        step_name=step_name, keyid=signing_keyid, handle=token
    )

    if os.path.exists(session_fn):
        raise in_toto.exceptions.RecordHandleFormatError(
            f"An unfinished record already exists at '{session_fn}'. Pass a"
            " different record_token or omit it to generate one."
        )

    LOG.info("Storing preliminary link metadata to '%s'...", session_fn)
    metadata_bytes = _atomic_dump_metadata(link_metadata, session_fn)

    try:
        LOG.info("Storing preliminary link metadata to '%s'...", unfinished_fn)
        _atomic_write_bytes(unfinished_fn, metadata_bytes)
    except BaseException:
        # Do not leave a session proof behind for a failed start.
        with contextlib.suppress(OSError):
            os.remove(session_fn)
        raise

    return RecordHandle(
        step_name=step_name,
        keyid=signing_keyid,
        token=token,
        start_digest=_sha256_bytes(metadata_bytes),
        start_materials_digest=_materials_digest(materials_dict),
        unfinished_path=os.path.abspath(session_fn),
        completed_path=os.path.abspath(completed_fn),
        workdir=os.path.realpath(os.getcwd()),
        artifact_base_path=os.path.realpath(
            base_path if base_path else os.getcwd()
        ),
        use_dsse=bool(use_dsse),
    )


def in_toto_record_stop(  # noqa: C901, PLR0912, PLR0913, PLR0914, PLR0915, PLR0917, RUF100
    step_name=None,
    product_list=None,
    gpg_keyid=None,
    gpg_use_default=False,
    gpg_home=None,
    exclude_patterns=None,
    base_path=None,
    normalize_line_endings=False,
    lstrip_paths=None,
    metadata_directory=None,
    command=None,
    byproducts=None,
    environment=None,
    signer=None,
    record_handle=None,
    handle=None,
):
    """Finalizes preliminary link metadata generated with in_toto_record_start.

  Loads preliminary link metadata file, verifies its signature, and records
  paths and hashes as products, thus finalizing the link metadata. The metadata
  is signed with the passed signer, a gpg key identified by its ID,
  or the default gpg key. If multiple key arguments are passed, only one key is
  used in above order of precedence. At least one key argument must be passed
  and it must be the same as the one used to sign the preliminary link metadata
  file.

  The record to finish can be selected in one of two ways:

    - Pass a :class:`in_toto.models.record.RecordHandle` returned by
      ``in_toto_record_start``, either as the first argument or via the
      ``record_handle`` keyword (``handle`` is accepted as an alias). Stop only
      finishes the exact start proof bound to that handle. Same-named records
      started concurrently do not interfere. The result is written to
      ``.STEP-NAME.KEYID-PREFIX.TOKEN.link`` (and mirrored to the canonical
      ``STEP-NAME.KEYID-PREFIX.link`` so existing verifiers can find it).
    - Pass a ``step_name``. This is the historical single-task behavior and
      uses ``.STEP-NAME.KEYID-PREFIX.link-unfinished``.

  With a record handle, the following outcomes are explicit:

    - Modified unfinished metadata raises ``RecordTamperedError``; the raw
      file is preserved for diagnosis.
    - Finishing with a different signing identity raises
      ``RecordIdentityError``; the unfinished file is preserved.
    - Finishing from a different working directory without passing
      ``base_path`` raises ``RecordWorkingDirectoryError``.
    - Repeating a successful stop returns the already completed, signed
      result if the same products are passed. Passing different products (or
      command/byproducts/environment) raises ``RecordAlreadyCompletedError``
      and never rewrites the completed link.
    - A failed write leaves the unfinished metadata in place and does not
      create or truncate a completed link.

  Use this function together with in_toto_record_start as an alternative to
  in_toto_run, in order to provide evidence for supply chain steps that cannot
  be carried out by a single command.

  Arguments:
    step_name: A unique name to associate link metadata with a step, or a
        RecordHandle to finish a specific record.

    product_list (optional): A list of artifact paths to be recorded as
        products. Directories are traversed recursively.

    gpg_keyid (optional): A keyid used to identify a local gpg key used to sign
        the resulting link metadata.

    gpg_use_default (optional): A boolean indicating if the default gpg key
        should be used to sign the resulting link metadata.

    gpg_home (optional): A path to the gpg home directory. If not set the
        default gpg home directory is used.

    exclude_patterns (optional): A list of filename patterns to exclude certain
        files from being recorded as artifacts.

    base_path (optional): A path relative to which artifacts are recorded.
        Default is the current working directory. For record handles, the
        default is the artifact working directory bound to the handle.

    normalize_line_endings (optional): A boolean indicating if line endings of
        artifacts should be normalized before hashing for cross-platform
        support.

    lstrip_paths (optional): A list of path prefixes used to left-strip
        artifact paths before storing them in the resulting link metadata.

    metadata_directory (optional): A directory path to write the resulting link
        metadata file to. Default destination is the current working directory.
        For record handles, a relative directory is resolved against the
        handle's working directory.

    command (optional): A list consisting of a command and arguments executed
        between in_toto_record_start() and in_toto_record_stop() to capture
        the command ran in the resulting link metadata.

    byproducts (optional): A dictionary that lists byproducts of the link
        command execution. It should have at least the following entries
        "stdout" (str), "stderr" (str), "return-value" (int).

    environment (optional): A dictionary to capture information about
        the environment to be added in the resulting link metadata.

    signer (optional): A securesystemslib Signer instance used to
        sign the resulting link metadata.

    record_handle (optional): A RecordHandle, its dict representation, or its
        JSON representation. Only the bound record is finished.

    handle (optional): Alias for record_handle.

  Raises:
    securesystemslib.exceptions.FormatError: Passed arguments are malformed.

    ValueError: None of gpg_keyid or gpg_use_default=True is
        passed.

    RecordHandleFormatError: The passed record handle is malformed.

    RecordNotFoundError: The unfinished record for the handle was not found.
        Inherits from LinkNotFoundError and FileNotFoundError.

    RecordAmbiguousError: More than one preliminary link was found for a step
        name finished without a handle.

    RecordTamperedError: The unfinished file does not match the handle proof.

    RecordIdentityError: Stop uses a different signing identity than start.

    RecordWorkingDirectoryError: Handle stop runs from another directory
        without an explicit base_path.

    RecordAlreadyCompletedError: Retry would splice different products into
        an already completed link.

    securesystemslib.exceptions.StorageError: Cannot hash artifacts.

    PrefixError: Left-stripping artifact paths results in non-unique dict keys.

    subprocess.TimeoutExpired: Link command times out.

    IOError, FileNotFoundError, NotADirectoryError, PermissionError:
        Cannot write link metadata.

    securesystemslib.exceptions.CryptoError, \
            securesystemslib.exceptions.UnsupportedAlgorithmError:
        Signing errors.

    ValueError, OSError, securesystemslib._gpg.exceptions.CommandError, \
            securesystemslib._gpg.exceptions.KeyNotFoundError:
        gpg signing errors.

  Side Effects:
    Reads preliminary link metadata file from disk.
    Reads artifact files from disk.
    Calls system gpg in a subprocess, if a gpg key argument is passed.
    Writes resulting link metadata file to disk atomically.
    Removes preliminary link metadata file from disk after a successful write.

  Returns:
    The resulting Metadata object (Metablock or Envelope).

  """
    if record_handle is not None and handle is not None:
        raise in_toto.exceptions.RecordHandleFormatError(
            "Pass either record_handle or handle, not both."
        )

    if handle is not None:
        record_handle = handle

    if isinstance(step_name, (RecordHandle, dict)):
        if record_handle is not None:
            raise in_toto.exceptions.RecordHandleFormatError(
                "Pass the record handle either positionally or by keyword,"
                " not both."
            )
        record_handle = step_name
        step_name = None

    if record_handle is not None:
        record_handle = _coerce_record_handle(record_handle)

        if step_name is not None and step_name != record_handle.step_name:
            raise in_toto.exceptions.RecordHandleFormatError(
                "Passed step_name does not match the record handle."
            )

        step_name = record_handle.step_name

    elif not isinstance(step_name, str):
        raise in_toto.exceptions.RecordHandleFormatError(
            "Pass a step name or a record handle."
        )

    LOG.info("Stop recording '%s'...", step_name)

    # Check that we have something to sign and if the formats are right
    _require_signing_arg(signer, gpg_keyid, gpg_use_default)

    if signer:
        _check_signer(signer)

    if gpg_keyid:
        _check_hex(gpg_keyid)

    if exclude_patterns:
        _check_str_list(exclude_patterns)

    if base_path:
        _check_str(base_path)

    if metadata_directory:
        _check_str(metadata_directory)

    if record_handle is not None:
        return _in_toto_record_stop_with_handle(
            record_handle,
            product_list,
            gpg_keyid,
            gpg_home,
            exclude_patterns,
            base_path,
            normalize_line_endings,
            lstrip_paths,
            metadata_directory,
            command,
            byproducts,
            environment,
            signer,
        )

    # Load preliminary link file
    # If we have a signing key we can use the keyid to construct the name
    if signer:
        unfinished_fn = UNFINISHED_FILENAME_FORMAT.format(
            step_name=step_name, keyid=signer.public_key.keyid
        )

    # FIXME: Currently there is no way to know the default GPG key's keyid and
    # so we glob for preliminary link files
    else:
        unfinished_fn_list = _legacy_unfinished_candidates(step_name)

        if not unfinished_fn_list:
            raise in_toto.exceptions.LinkNotFoundError(
                "Could not find a preliminary"
                f" link for step '{step_name}' in the current working directory."
            )

        if len(unfinished_fn_list) > 1:
            raise in_toto.exceptions.RecordAmbiguousError(
                "Found more than one"
                " preliminary links for step '{}' in the current working directory:"
                " {}. We need exactly one to stop recording. Pass the record"
                " handle returned by in_toto_record_start to select one.".format(
                    step_name, ", ".join(unfinished_fn_list)
                )
            )

        unfinished_fn = unfinished_fn_list[0]

    LOG.info("Loading preliminary link metadata '%s'...", unfinished_fn)
    with open(unfinished_fn, "rb") as fp:
        legacy_proof_data = fp.read()

    # A step-name-only stop is compatible with single-task use. If more than
    # one session carries exactly this start proof (for example two starts with
    # identical materials and a deterministic signature), it is impossible to
    # tell which session the caller meant. Refuse instead of guessing.
    matching_sessions = [
        path
        for path in _session_unfinished_candidates(step_name)
        if _sha256_file(path) == _sha256_bytes(legacy_proof_data)
    ]
    if len(matching_sessions) > 1:
        raise in_toto.exceptions.RecordAmbiguousError(
            "Found more than one record for step '{}' with the same start"
            " proof: {}. Pass the record handle returned by"
            " in_toto_record_start to select one.".format(
                step_name, ", ".join(matching_sessions)
            )
        )

    link_metadata = Metadata.load(unfinished_fn)

    # The file must have been signed by the same key
    # If we have a signer we use it for verification as well
    verification_key, keyid = _get_stop_verification_key(
        link_metadata,
        signer,
        gpg_keyid,
        gpg_home,
        expected_keyid=None,
    )
    link_metadata.verify_signature(verification_key)

    LOG.info("Extracting Link from metadata...")
    link = link_metadata.get_payload()

    # Record products if a product path list was passed
    if product_list:
        LOG.info("Recording products '%s'...", ", ".join(product_list))

    link.products = record_artifacts_as_dict(
        product_list,
        exclude_patterns=exclude_patterns,
        base_path=base_path,
        follow_symlink_dirs=True,
        normalize_line_endings=normalize_line_endings,
        lstrip_paths=lstrip_paths,
    )

    if command:
        link.command = command

    if byproducts:
        link.byproducts = byproducts

    if environment:
        link.environment = environment

    if isinstance(link_metadata, Metablock):
        LOG.info("Generating link metadata using Metablock...")
        link_metadata = Metablock(signed=link)
    else:
        LOG.info("Generating link metadata using DSSE...")
        link_metadata = Envelope.from_signable(link)

    if signer:
        LOG.info(
            "Updating signature with signer '%.8s...'...",
            signer.public_key.keyid,
        )

    else:  # gpg_keyid or gpg_use_default
        # In both cases we use the keyid we got from verifying the preliminary
        # link signature above.
        LOG.info("Updating signature with gpg key '%.8s...'...", keyid)
        signer = GPGSigner(keyid=keyid, homedir=gpg_home)

    link_metadata.create_signature(signer)
    fn = FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)

    if metadata_directory is not None:
        fn = os.path.join(metadata_directory, fn)

    LOG.info("Storing link metadata to '%s'...", fn)
    completed_bytes = _atomic_dump_metadata(link_metadata, fn)

    # This legacy stop consumed exactly the session proof with the same bytes.
    # Persist the corresponding session link too, so a backend that saved the
    # start handle can still read the completed result on retry. Other
    # concurrent session proofs are left for their own handles.
    if matching_sessions:
        session_completed = _session_completed_path(matching_sessions[0])
        LOG.info("Storing link metadata to '%s'...", session_completed)
        _atomic_write_bytes(session_completed, completed_bytes)

        LOG.info(
            "Removing unfinished link metadata '%s'...", matching_sessions[0]
        )
        with contextlib.suppress(OSError):
            os.remove(matching_sessions[0])

    LOG.info("Removing unfinished link metadata '%s'...", unfinished_fn)
    os.remove(unfinished_fn)

    return link_metadata


def in_toto_match_products(
    link, paths=None, exclude_patterns=None, lstrip_paths=None
):
    """Check if local artifacts match products in passed link.

    NOTE: Does not check integrity or authenticity of passed link!

    Arguments:
      link: The Link object to match.

    See ``in_toto_run`` for details about arguments, and exceptions that may
    occur while recording artifact hashes.

    Returns:
      A 3-tuple with artifact names that are
      - only in products,
      - not in products,
      - have different hashes.
    """
    if paths is None:
        paths = ["."]

    artifacts = record_artifacts_as_dict(
        paths, exclude_patterns=exclude_patterns, lstrip_paths=lstrip_paths
    )

    artifact_names = artifacts.keys()
    product_names = link.products.keys()

    only_products = product_names - artifact_names
    not_in_products = artifact_names - product_names
    differ = {
        name
        for name in product_names & artifact_names
        if link.products[name] != artifacts[name]
    }

    return only_products, not_in_products, differ
