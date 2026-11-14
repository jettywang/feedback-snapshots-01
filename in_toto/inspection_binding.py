# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  inspection_binding.py

<Purpose>
  Bind inspection inputs to artifacts reported by authenticated step Links
  before an inspection command is executed.

  The binding is an explicit policy, not a sandbox. It answers one question:
  "Does the file that the inspection is about to read have the name, digest
  and recording method that an already verified step Link reports?" It does
  not restrict which files the inspection process may open at runtime.

  Each inspection input is declared in the layout as an ``InspectionInput``
  (see ``in_toto.models.layout``). For every declaration this module:

  1. Requires an exact, normalized artifact name in an authenticated Link's
     materials or products. No implicit path normalization is performed.
  2. Requires the Link artifact to have been recorded as a regular file
     (``record_method: "file"``). Directory and OSTree recordings are
     rejected.
  3. Recomputes the file digest(s) with the algorithms reported by the Link,
     without line-ending normalization, and compares them to the Link's
     digests.
  4. Rejects missing files, symlinks, non-regular files and files that change
     while they are being hashed.

  Every check produces an ``InspectionInputReport`` that records the Link
  identity (step, signing keyids, Link filename and a digest of the signed
  payload) and the observed file evidence.

  Concurrency limit: hashing and process execution are separate operations.
  The binding does not lock, snapshot or otherwise freeze the files. A writer
  with access to the verification directory can replace a file after the
  preflight check and before (or while) the inspection reads it. Callers must
  provide isolation, e.g. a read-only or immutable snapshot of the artifacts,
  exclusive write locks for the duration of the inspection, or a sandbox that
  executes the inspection against the same snapshot that was checked.
"""

import hashlib
import json
import os
import stat as stat_module

import in_toto.exceptions
from in_toto.models.link import FILENAME_FORMAT

_HASH_CHUNK_SIZE = 4096

BINDING_POLICY = {
    "checked": [
        "input name: normalized relative path declared by the inspection",
        "source name: exact artifact key in an authenticated step Link",
        "digest: every hash algorithm reported by that Link",
        "record method: regular file recorded by the file resolver",
    ],
    "not_guaranteed": [
        "The binding does not sandbox or restrict the inspection process.",
        "It does not check undeclared files, directories or environment.",
        "It does not prove what the inspection read at execution time.",
        "It does not verify Link signatures; callers must pass authenticated "
        "Links.",
    ],
    "concurrency": [
        "Hashing and execution are separate operations; no file locks or "
        "snapshots are held.",
        "A concurrent writer can replace a file after the preflight check but "
        "before or during inspection execution.",
        "A stat change observed while hashing is rejected, but a change after "
        "hashing is not detectable here.",
    ],
    "caller_requirements": [
        "Pass only Links that already passed signature and threshold "
        "verification for the layout.",
        "Run the inspection in a private, read-only or snapshot-backed "
        "directory that no concurrent writer can modify.",
        "If files can be written, hold exclusive locks from preflight through "
        "execution or use an immutable mount/sandbox.",
        "Ensure path case and Unicode normalization semantics of the "
        "filesystem match the layout's normalized POSIX paths.",
    ],
}


class InspectionInputReport:
    """Evidence collected while binding one inspection's declared inputs."""

    def __init__(self, inspection_name, base_path=None):
        self.inspection_name = inspection_name
        self.base_path = base_path
        self.status = "rejected"
        self.inputs = []
        self.errors = []

    def to_dict(self):
        """Return a JSON-serializable report dictionary."""
        return {
            "inspection": self.inspection_name,
            "base_path": self.base_path,
            "status": self.status,
            "inputs": self.inputs,
            "errors": self.errors,
            "policy": BINDING_POLICY,
        }

    def dumps(self):
        """Return the report as a sorted JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def declared_digests_of(self, input_name):
        """Return the authenticated Link digests for a matched input.

        Arguments:
          input_name: The inspection view name of the input.

        Raises:
          ValueError: The input is unknown or was not matched.

        """
        for record in self.inputs:
            if record["name"] == input_name and record["status"] == "matched":
                return dict(record["declared_digests"])

        raise ValueError(
            f"No matched input evidence for '{input_name}'. Inspection input"
            " binding must succeed before execution."
        )


def dump_reports(reports, path):
    """Write a list of inspection input reports to a JSON file.

    Arguments:
      reports: A list of ``InspectionInputReport`` objects.
      path: The output path.

    Side Effects:
      Writes the file to disk.
    """
    data = {
        "policy": BINDING_POLICY,
        "inspections": [report.to_dict() for report in reports],
    }
    with open(path, "w", encoding="utf8") as fp:
        json.dump(data, fp, indent=2, sort_keys=True)
        fp.write("\n")


def get_link_keyids(selected_link_keyids, steps_metadata):
    """Extract the signing keyids of the Links used during verification.

    Arguments:
      selected_link_keyids: A dictionary mapping step names to the keyid whose
          Link was selected for rule verification and inspection binding.

      steps_metadata: The dictionary of verified ``Metadata`` objects per step
          and functionary keyid, as returned by
          ``verifylib.verify_link_signature_thresholds``. It is used to
          distinguish Links that were verified in this process from Links that
          only exist on disk.

    Returns:
      A dictionary mapping step names to a list of keyids.
    """
    keyids = {}
    for step_name, selected in selected_link_keyids.items():
        verified_keyids = set(steps_metadata.get(step_name, {}))
        keyids[step_name] = [
            keyid for keyid in selected if keyid in verified_keyids
        ]
    return keyids


def _check_regular_file(path):
    """Open path without following symlinks and return (fd, stat_result).

    Raises InspectionInputError if the path is not a regular file.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise in_toto.exceptions.InspectionInputError(
            f"Cannot open input file '{path}': {e}"
        ) from e

    try:
        file_stat = os.fstat(fd)
        if not stat_module.S_ISREG(file_stat.st_mode):
            raise in_toto.exceptions.InspectionInputError(
                f"Input '{path}' is not a regular file."
            )
    except Exception:
        os.close(fd)
        raise

    return fd, file_stat


def _digest_fileobj(fileobj, algorithm):
    """Return the hex digest of an open binary file object.

    The file object is rewound before reading, so the same object can be used
    consecutively for multiple algorithms.
    """
    fileobj.seek(0)
    digest = hashlib.new(algorithm)
    while True:
        data = fileobj.read(_HASH_CHUNK_SIZE)
        if not data:
            break
        digest.update(data)
    return digest.hexdigest()


def _digest_file(path, algorithms):
    """Hash a regular file with all passed algorithms.

    Returns (digests, stat_before, stat_after). Raises InspectionInputError if
    the file is not regular, cannot be hashed, or changes while hashing.
    """
    fd, stat_before = _check_regular_file(path)

    try:
        with os.fdopen(fd, "rb", closefd=False) as fileobj:
            digests = {
                algorithm: _digest_fileobj(fileobj, algorithm)
                for algorithm in algorithms
            }
        stat_after = os.fstat(fd)
    finally:
        os.close(fd)

    if (
        stat_before.st_ino != stat_after.st_ino
        or stat_before.st_size != stat_after.st_size
        or stat_before.st_mtime_ns != stat_after.st_mtime_ns
    ):
        raise in_toto.exceptions.InspectionInputError(
            f"Input '{path}' changed while it was being hashed."
        )

    return digests, stat_before, stat_after


def _link_keyids(step_name, link_keyids):
    """Return the list of signing keyids for a step, if known."""
    keyids = None
    if link_keyids is not None:
        keyids = link_keyids.get(step_name)

    if keyids is None:
        return []
    if isinstance(keyids, str):
        return [keyids]
    return sorted(keyids)


def _link_identity(step_name, link, keyids):
    """Build a serializable identity record for an authenticated Link."""
    identity = {
        "step": step_name,
        "name": link.name,
        "artifact_type": "link",
        "payload_sha256": hashlib.sha256(link.signable_bytes).hexdigest(),
        "keyids": keyids,
        "filenames": [],
    }
    for keyid in keyids:
        identity["filenames"].append(
            FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)
        )
    if not identity["filenames"]:
        identity["filenames"].append(
            f"{step_name}.link (identity not provided)"
        )
    return identity


def _record_method_error(link_path):
    """Return an error string if the Link key uses a non-file recording method."""
    scheme, sep, _ = link_path.partition(":")
    if sep and scheme in {"dir", "ostree"}:
        return (
            f"Link artifact '{link_path}' was recorded with method"
            f" '{scheme}', not 'file'."
        )
    return None


def _declared_digests(link_artifact, link_path):
    """Return a copy of the Link digest dictionary after basic checks."""
    if not isinstance(link_artifact, dict) or not link_artifact:
        raise in_toto.exceptions.InspectionInputError(
            f"Link artifact '{link_path}' has no digest evidence."
        )

    for algorithm in link_artifact:
        try:
            hashlib.new(algorithm)
        except (TypeError, ValueError) as e:
            raise in_toto.exceptions.InspectionInputError(
                f"Link artifact '{link_path}' uses unsupported hash"
                f" algorithm '{algorithm}'."
            ) from e

    return dict(link_artifact)


def _bind_one(  # noqa: C901, PLR0911
    input_decl, step_links, link_keyids, base_path, layout=None
):
    """Bind a single InspectionInput declaration.

    Returns an evidence record. The record's ``status`` is ``matched`` on
    success and one of the error statuses otherwise; an error message is
    included in the record and returned separately.
    """
    record = {
        "name": input_decl.name,
        "from_step": input_decl.from_step,
        "from_type": input_decl.from_type,
        "link_path": input_decl.link_path,
        "record_method": input_decl.record_method,
        "status": "rejected",
        "link": None,
        "declared_digests": None,
        "observed_digests": None,
        "file": None,
    }

    record_method_error = _record_method_error(input_decl.link_path)
    if record_method_error:
        record["error"] = record_method_error
        return record

    link = step_links.get(input_decl.from_step)
    if link is None:
        known_steps = sorted(step_links)
        hint = f" Known steps: {', '.join(known_steps)}." if known_steps else ""
        if layout is not None:
            hint += f" Layout steps: {', '.join(layout.get_step_name_list())}."
        record["error"] = (
            f"No authenticated Link for source step"
            f" '{input_decl.from_step}'." + hint
        )
        return record

    record["link"] = _link_identity(
        input_decl.from_step,
        link,
        _link_keyids(input_decl.from_step, link_keyids),
    )

    artifacts = getattr(link, input_decl.from_type, None)
    if not isinstance(artifacts, dict):
        record["error"] = (
            f"Authenticated Link for step '{input_decl.from_step}' has no"
            f" '{input_decl.from_type}' artifacts."
        )
        return record

    link_artifact = artifacts.get(input_decl.link_path)
    if link_artifact is None:
        record["error"] = (
            f"Declared link path '{input_decl.link_path}' is not reported in"
            f" {input_decl.from_type} of step '{input_decl.from_step}'. No"
            " implicit path normalization is performed."
        )
        return record

    try:
        declared_digests = _declared_digests(
            link_artifact, input_decl.link_path
        )
    except in_toto.exceptions.InspectionInputError as e:
        record["error"] = str(e)
        return record

    record["declared_digests"] = declared_digests

    disk_path = os.path.join(base_path, *input_decl.name.split("/"))
    record["file"] = {
        "path": input_decl.name,
        "base_path": base_path,
        "resolved_path": disk_path,
    }

    if not os.path.lexists(disk_path):
        record["error"] = f"Declared input file '{input_decl.name}' is missing."
        return record

    try:
        observed_digests, stat_before, _ = _digest_file(
            disk_path, sorted(declared_digests)
        )
    except in_toto.exceptions.InspectionInputError as e:
        record["error"] = str(e)
        return record
    except OSError as e:
        record["error"] = (
            f"Cannot read declared input file '{input_decl.name}': {e}"
        )
        return record

    record["file"].update(
        {
            "size": stat_before.st_size,
            "mtime_ns": stat_before.st_mtime_ns,
            "inode": stat_before.st_ino,
            "mode": oct(stat_before.st_mode),
            "symlink": False,
        }
    )
    record["observed_digests"] = observed_digests

    mismatched = [
        algorithm
        for algorithm, digest in declared_digests.items()
        if observed_digests.get(algorithm) != digest
    ]
    if mismatched:
        record["error"] = (
            f"Digest mismatch for declared input '{input_decl.name}'"
            f" (link path '{input_decl.link_path}'): "
            + ", ".join(sorted(mismatched))
        )
        return record

    record["status"] = "matched"
    return record


def bind_inspection_inputs(
    inspection, step_links, layout=None, link_keyids=None, base_path=None
):
    """Check inspection input declarations against authenticated step Links.

    This function is meant to run before an inspection command is started. It
    does not stop the inspection process from opening other files; it only
    records and enforces the declared input bindings.

    Arguments:
      inspection: An ``Inspection`` object with ``inputs`` declarations.

      step_links: A dictionary of ``Link`` objects per step name. Callers must
          pass only Links that already passed signature and threshold
          verification.

      layout: (optional) The Layout the inspection belongs to. It is used only
          to improve error messages about unknown steps.

      link_keyids: (optional) A dictionary mapping step names to a keyid or a
          list of keyids, used to record the Link identity. Without it the
          report states that the signing keyid was not provided.

      base_path: (optional) Directory relative to which input names are
          resolved. Default is the current working directory, matching the
          inspection execution directory.

    Returns:
      An ``InspectionInputReport`` with status ``bound``, or
      ``no-inputs-declared`` when the inspection has no declarations.

    Raises:
      in_toto.exceptions.InspectionInputError: If any declared input cannot be
          bound. The exception carries the report on its ``report`` attribute
          and the inspection name on ``inspection_name``.
    """
    base_path = os.path.abspath(base_path or os.getcwd())
    report = InspectionInputReport(inspection.name, base_path=base_path)

    if not inspection.inputs:
        report.status = "no-inputs-declared"
        report.errors.append(
            "No inspection inputs were declared. No pre-execution input"
            " binding was performed; files in the verification directory must"
            " not be treated as authenticated inputs."
        )
        return report

    for input_decl in inspection.inputs:
        record = _bind_one(
            input_decl,
            step_links,
            link_keyids,
            base_path=base_path,
            layout=layout,
        )
        report.inputs.append(record)
        if record["status"] != "matched":
            report.errors.append(record["error"])

    if report.errors:
        report.status = "rejected"
        message = (
            f"Inspection input binding failed for '{inspection.name}': "
            + " | ".join(report.errors)
        )
        raise in_toto.exceptions.InspectionInputError(
            message, inspection_name=inspection.name, report=report
        )

    report.status = "bound"
    return report


def recheck_declared_digests(report, base_path=None):
    """Re-hash matched declared inputs immediately before execution.

    Arguments:
      report: A successful ``InspectionInputReport`` returned by
          ``bind_inspection_inputs``.

      base_path: (optional) Directory relative to which input names are
          resolved. Defaults to the report's recorded base path, i.e. the
          directory that was checked originally.

    Raises:
      in_toto.exceptions.InspectionInputError: If a previously matched input
          is now missing, no longer a regular file, or has different digests.
          The report is updated accordingly and attached to the exception.
    """
    if report.status != "bound":
        raise ValueError("Can only recheck a bound inspection input report.")

    for record in report.inputs:
        if record["status"] != "matched":
            continue

        recorded_base_path = report.base_path
        if base_path is not None:
            recorded_base_path = os.path.abspath(base_path)

        input_name = record["name"]
        disk_path = os.path.join(recorded_base_path, *input_name.split("/"))
        record["file"]["resolved_path"] = disk_path

        try:
            observed_digests, stat_before, _ = _digest_file(
                disk_path, sorted(record["declared_digests"])
            )
        except (in_toto.exceptions.InspectionInputError, OSError) as e:
            record["status"] = "rejected"
            record["error"] = f"Recheck before execution failed: {e}"
            report.status = "rejected"
            report.errors.append(record["error"])
            raise in_toto.exceptions.InspectionInputError(
                f"Inspection input binding failed for"
                f" '{report.inspection_name}' immediately before execution:"
                f" {e}",
                inspection_name=report.inspection_name,
                report=report,
            ) from e

        # Keep the preflight evidence unchanged; record the recheck separately
        # so the report shows both observations and their stat identity.
        record["recheck"] = {
            "digests": observed_digests,
            "size": stat_before.st_size,
            "mtime_ns": stat_before.st_mtime_ns,
            "inode": stat_before.st_ino,
            "mode": oct(stat_before.st_mode),
        }

        file = record["file"]
        replaced = (
            file.get("inode") != stat_before.st_ino
            or file.get("size") != stat_before.st_size
            or file.get("mtime_ns") != stat_before.st_mtime_ns
        )

        mismatched = [
            algorithm
            for algorithm, digest in record["declared_digests"].items()
            if observed_digests.get(algorithm) != digest
        ]
        if replaced:
            record["status"] = "rejected"
            record["error"] = (
                f"Declared input '{input_name}' was replaced between the"
                " preflight check and execution, even though its content still"
                " matched. The inspection was not executed."
            )
            report.status = "rejected"
            report.errors.append(record["error"])
            raise in_toto.exceptions.InspectionInputError(
                record["error"],
                inspection_name=report.inspection_name,
                report=report,
            )

        if mismatched:
            record["status"] = "rejected"
            record["error"] = (
                f"Digest mismatch for declared input '{input_name}'"
                " immediately before execution: "
                + ", ".join(sorted(mismatched))
            )
            report.status = "rejected"
            report.errors.append(record["error"])
            raise in_toto.exceptions.InspectionInputError(
                record["error"],
                inspection_name=report.inspection_name,
                report=report,
            )
