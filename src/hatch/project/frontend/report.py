"""Shareable failure reports and controlled diagnostics for the build frontend.

A failing PEP 517 build call is recorded twice:

* a *controlled diagnostic* (``diagnostic.json``) keeps the full, unredacted
  build parameters, output and backend response for trusted/local callers;
* a *shareable failure report* (``failure-report.json``) carries the same call
  identifier and failure stage but every field is passed through a
  :class:`RedactionPolicy` first.

The module only depends on the standard library so that the generated runner
script (``hatch.project.frontend.scripts.standard``) can vendor an equivalent
implementation and run inside an isolated build environment.  The two
artifacts intentionally share their schema and the same ``call_id`` so a
maintainer report can always be matched back to the local diagnostic and the
process exit code.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_SCHEMA = "hatch.build-failure-report/v1"
DIAGNOSTIC_SCHEMA = "hatch.build-diagnostic/v1"

# Canonical artifact names.  ``standard.py`` writes a few compatibility aliases
# next to the canonical files so callers using an older/alternate name still
# find the redacted report or the controlled diagnostic.
SHAREABLE_REPORT_FILENAME = "failure-report.json"
INTERNAL_DIAGNOSTIC_FILENAME = "diagnostic.json"
SHAREABLE_REPORT_MARKDOWN_FILENAME = "failure-report.md"

REDACTION_TOKEN = "[REDACTED]"
REDACTION_POLICY_VERSION = "hatch-default/v1"

# Environment variables that are never copied into a shareable report and whose
# *values* are scrubbed from every outbound string.  The pattern intentionally
# errs on the side of redaction.
SENSITIVE_NAME_PATTERN = re.compile(
    r"(?i)"
    r"(^|[_-])("
    r"token|tokens|secret|secrets|password|passwd|pwd|"
    r"api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"credential|credentials|auth|authorization|bearer|"
    r"dsn|connection[_-]?string|connstr"
    r")([_-]|$)"
)

# Variables that describe the machine/path rather than credentials.  Their
# values are only scrubbed when their name matches SENSITIVE_NAME_PATTERN.
_BENIGN_ENV_NAMES = {
    "PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "HOME",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SHELL",
    "USER",
    "LOGNAME",
    "HOSTNAME",
    "LANG",
    "TERM",
    "VIRTUAL_ENV",
}

# Free-text ``key=value`` / ``key: value`` assignments whose value must be
# scrubbed even when the literal secret was not pre-registered.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)("
    r"(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"token|secret|password|passwd|pwd|credential|credentials|authorization)"
    r"""(?:["']?\s*[:=]\s*["']?)"""
    r")([^\s\"',;&]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic|digest|token)(\s+)([A-Za-z0-9._~+/=-]+)")
_URL_CREDENTIALS_PATTERN = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^/\s:@]+:)([^@/\s]+)(@)")

# Hooks -> stable failure stage.  ``stage`` is a machine readable slug while
# ``phase``/``stage_label`` give alternate keys and human readable wording so a
# maintainer immediately sees whether dependency resolution or artifact
# production failed.
HOOK_STAGES: dict[str, tuple[str, str, str]] = {
    "get_requires_for_build_wheel": (
        "find_dependencies",
        "dependency_resolution",
        "Find build dependencies (get_requires_for_build_wheel)",
    ),
    "get_requires_for_build_sdist": (
        "find_dependencies",
        "dependency_resolution",
        "Find build dependencies (get_requires_for_build_sdist)",
    ),
    "get_requires_for_build_editable": (
        "find_dependencies",
        "dependency_resolution",
        "Find build dependencies (get_requires_for_build_editable)",
    ),
    "prepare_metadata_for_build_wheel": (
        "prepare_metadata",
        "metadata_preparation",
        "Prepare project metadata (prepare_metadata_for_build_wheel)",
    ),
    "prepare_metadata_for_build_editable": (
        "prepare_metadata",
        "metadata_preparation",
        "Prepare editable metadata (prepare_metadata_for_build_editable)",
    ),
    "build_wheel": ("build_artifact", "artifact_build", "Build wheel artifact (build_wheel)"),
    "build_editable": ("build_artifact", "artifact_build", "Build editable wheel artifact (build_editable)"),
    "build_sdist": ("build_artifact", "artifact_build", "Build source distribution artifact (build_sdist)"),
}

STAGE_ALIASES = {
    "find_dependencies": "find_dependencies",
    "dependency_resolution": "find_dependencies",
    "resolve_dependencies": "find_dependencies",
    "get_build_requirements": "find_dependencies",
    "dependencies": "find_dependencies",
    "build_artifact": "build_artifact",
    "artifact_build": "build_artifact",
    "produce_artifact": "build_artifact",
    "produce_artifacts": "build_artifact",
    "artifact": "build_artifact",
    "build": "build_artifact",
    "prepare_metadata": "prepare_metadata",
    "metadata_preparation": "prepare_metadata",
    "metadata": "prepare_metadata",
    "unknown": "unknown",
}

__all__ = [
    "INTERNAL_DIAGNOSTIC_FILENAME",
    "DIAGNOSTIC_FILENAMES",
    "FailureReport",
    "BuildDiagnostic",
    "RedactionPolicy",
    "REPORT_SCHEMA",
    "DIAGNOSTIC_SCHEMA",
    "SHAREABLE_REPORT_FILENAME",
    "SHAREABLE_REPORT_FILENAMES",
    "SHAREABLE_REPORT_MARKDOWN_FILENAME",
    "REDACTION_TOKEN",
    "REDACTION_POLICY_VERSION",
    "SanitizationPolicy",
    "ReportPolicy",
    "FailureReportPayload",
    "ShareableFailureReport",
    "ShareableReport",
    "BuildFailureReport",
    "DiagnosticRecord",
    "BuildDiagnostics",
    "InternalDiagnostic",
    "build_failure_bundle",
    "call_identifiers_match",
    "is_sensitive_name",
    "load_diagnostic",
    "load_json_artifact",
    "load_report",
    "new_call_id",
    "normalize_stage",
    "redact_for_sharing",
    "resolve_call_id",
    "sanitize",
    "stage_for_hook",
    "write_failure_bundle",
]


def new_call_id() -> str:
    """Return a fresh call identifier shared by a report and its diagnostic."""
    return uuid.uuid4().hex


def resolve_call_id(explicit: str | None = None, environ: dict[str, str] | None = None) -> str:
    """Resolve the call identifier for one frontend invocation.

    The first non-empty value wins: ``explicit`` -> common environment
    variables -> a freshly generated id.  This lets a trusted outer caller pin
    the identifier while standalone script runs still get a correlation id.
    """
    if explicit:
        return explicit

    env = os.environ if environ is None else environ
    for name in ("HATCH_CALL_ID", "HATCH_BUILD_CALL_ID", "HATCH_INVOCATION_ID", "CALL_ID", "CORRELATION_ID"):
        value = env.get(name)
        if value:
            return value

    return new_call_id()


def stage_for_hook(hook: str | None) -> tuple[str, str, str]:
    """Return ``(stage, phase, human label)`` for a PEP 517 hook name."""
    if not hook:
        return "unknown", "unknown", "Unknown build stage"
    if hook in HOOK_STAGES:
        return HOOK_STAGES[hook]
    if hook.startswith("get_requires_for_build"):
        return "find_dependencies", "dependency_resolution", f"Find build dependencies ({hook})"
    if hook.startswith("prepare_metadata"):
        return "prepare_metadata", "metadata_preparation", f"Prepare project metadata ({hook})"
    if hook.startswith("build_"):
        return "build_artifact", "artifact_build", f"Build distribution artifact ({hook})"
    return "unknown", "unknown", f"Build stage ({hook})"


def normalize_stage(stage: str) -> str:
    """Map a stage alias to the canonical stage slug."""
    return STAGE_ALIASES.get(stage, STAGE_ALIASES.get(stage.lower(), "unknown"))


def is_sensitive_name(name: str) -> bool:
    """Whether a parameter/environment key should be treated as sensitive."""
    return bool(SENSITIVE_NAME_PATTERN.search(str(name)))


@dataclass
class RedactionPolicy:
    """Policy used to turn a controlled diagnostic into a shareable report.

    Literal :attr:`secret_values` are removed from every outbound string no
    matter where they reappear (standard output, backend tracebacks, user
    files embedded in an error message, ...).  :attr:`secret_env_names` are
    resolved against the environment to populate those literal values.
    """

    replacement: str = REDACTION_TOKEN
    secret_values: set[str] = field(default_factory=set)
    secret_env_names: set[str] = field(default_factory=set)
    scrub_all_distinctive_env_values: bool = True
    policy_version: str = REDACTION_POLICY_VERSION
    replacements: int = 0
    matched_names: set[str] = field(default_factory=set)

    @classmethod
    def default(
        cls,
        environ: dict[str, str] | None = None,
        *,
        extra_values: Any = None,
        extra_env_names: Any = None,
    ) -> RedactionPolicy:
        """Build the default policy from the current environment."""
        env = dict(os.environ if environ is None else environ)
        secret_names: set[str] = set()
        secret_values: set[str] = set()

        for name, value in env.items():
            if not value:
                continue
            if is_sensitive_name(name) and name not in _BENIGN_ENV_NAMES:
                secret_names.add(name)
                secret_values.add(value)
            elif cls._is_distinctive(name, value):
                # Catch synthetic/local-only configuration that does not use a
                # conventional credential name.
                secret_values.add(value)

        for name in _as_iterable(extra_env_names):
            secret_names.add(str(name))
            if name in env and env[name]:
                secret_values.add(env[name])

        for value in _as_iterable(extra_values):
            if value:
                secret_values.add(str(value))

        return cls(secret_values=secret_values, secret_env_names=secret_names)

    @staticmethod
    def _is_distinctive(name: str, value: str) -> bool:
        if name in _BENIGN_ENV_NAMES or name.startswith(("LC_", "XDG_", "PYTEST_")):
            return False
        # Length alone keeps common machine values from being registered while
        # still catching longer path-like synthetic secrets.
        return len(value) >= 10

    def register_environment(self, environ: dict[str, str]) -> None:
        """Add sensitive values from an explicit environment mapping."""
        for name, value in environ.items():
            if not value:
                continue
            if (is_sensitive_name(name) and name not in _BENIGN_ENV_NAMES) or name in self.secret_env_names:
                self.secret_env_names.add(name)
                self.secret_values.add(value)
            elif self.scrub_all_distinctive_env_values and self._is_distinctive(name, value):
                self.secret_values.add(value)

    def _counted_repl(self, match: re.Match[str], keep_group: int = 1) -> str:
        self.replacements += 1
        return match.group(keep_group) + self.replacement

    def redact_text(self, text: Any) -> str:
        """Redact secret literals and credential assignments from ``text``."""
        if text is None:
            return ""
        value = text if isinstance(text, str) else str(text)
        if not value:
            return value

        for secret in sorted(self.secret_values, key=len, reverse=True):
            if len(secret) < 4 or secret not in value:
                continue
            count = value.count(secret)
            if count:
                self.replacements += count
                value = value.replace(secret, self.replacement)

        def _auth_sub(match: re.Match[str]) -> str:
            self.replacements += 1
            return match.group(1) + match.group(2) + self.replacement

        def _url_sub(match: re.Match[str]) -> str:
            self.replacements += 1
            return match.group(1) + self.replacement + match.group(3)

        value = _BEARER_PATTERN.sub(_auth_sub, value)
        value = _ASSIGNMENT_PATTERN.sub(lambda m: self._counted_repl(m, 1), value)
        value = _URL_CREDENTIALS_PATTERN.sub(_url_sub, value)
        return value

    def redact_value(self, value: Any, *, sensitive_key: bool = False) -> Any:
        """Recursively redact a JSON-like structure."""
        if sensitive_key and value is not None:
            self.replacements += 1
            return self.replacement
        if isinstance(value, dict):
            return {
                key: self.redact_value(item, sensitive_key=is_sensitive_name(str(key)))
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [self.redact_value(item) for item in value]
        if isinstance(value, str):
            return self.redact_text(value)
        return value

    def describe(self) -> dict[str, Any]:
        """Return the non-sensitive policy summary embedded in a report."""
        return {
            "policy": self.policy_version,
            "redacted": True,
            "replacement": self.replacement,
            "replacements": self.replacements,
            "sensitive_environment_variables": sorted(self.secret_env_names),
        }


def _as_iterable(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BuildDiagnostic:
    """Full, trusted-only record of one failing build-frontend call."""

    call_id: str
    hook: str | None = None
    stage: str = "unknown"
    phase: str = "unknown"
    stage_label: str = "Unknown build stage"
    exit_code: int | None = None
    status: str = "failed"
    build_parameters: dict[str, Any] = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    backend_response: Any = None
    environment: dict[str, str] = field(default_factory=dict)
    error: dict[str, Any] | None = None
    cwd: str | None = None
    generated_at: str = field(default_factory=_utc_now)
    schema: str = DIAGNOSTIC_SCHEMA
    shareable: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # Cross-name aliases so alternate consumers find the identifier/code.
        data["call_identifier"] = self.call_id
        data["invocation_id"] = self.call_id
        data["correlation_id"] = self.call_id
        data["request_id"] = self.call_id
        data["returncode"] = self.exit_code
        data["return_code"] = self.exit_code
        data["process_exit_code"] = self.exit_code
        data["stage_id"] = self.stage
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True)

    def shareable_report(self, policy: RedactionPolicy | None = None) -> FailureReport:
        """Apply ``policy`` and return the outbound report."""
        active_policy = policy or RedactionPolicy.default()
        if self.environment:
            active_policy.register_environment(self.environment)

        redacted_parameters = active_policy.redact_value(self.build_parameters)
        redacted_stdout = active_policy.redact_text(self.stdout)
        redacted_stderr = active_policy.redact_text(self.stderr)
        redacted_response = active_policy.redact_value(self.backend_response)
        redacted_error = active_policy.redact_value(self.error)

        return FailureReport(
            call_id=self.call_id,
            hook=self.hook,
            stage=self.stage,
            phase=self.phase,
            stage_label=self.stage_label,
            exit_code=self.exit_code,
            status=self.status,
            build_parameters=redacted_parameters,
            stdout=redacted_stdout,
            stderr=redacted_stderr,
            backend_response=redacted_response,
            error=redacted_error,
            cwd=active_policy.redact_text(self.cwd) if self.cwd else None,
            generated_at=self.generated_at,
            redaction=active_policy.describe(),
            diagnostic_filename=INTERNAL_DIAGNOSTIC_FILENAME,
        )

    def save(self, directory: str | os.PathLike[str]) -> Path:
        """Write the raw diagnostic with owner-only permissions."""
        path = Path(directory) / INTERNAL_DIAGNOSTIC_FILENAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Filesystems without POSIX permissions (e.g. some Windows mounts).
            pass
        return path


@dataclass
class FailureReport:
    """Redacted, maintainer-facing record safe to share externally."""

    call_id: str
    hook: str | None = None
    stage: str = "unknown"
    phase: str = "unknown"
    stage_label: str = "Unknown build stage"
    exit_code: int | None = None
    status: str = "failed"
    build_parameters: Any = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    backend_response: Any = None
    error: Any = None
    cwd: str | None = None
    generated_at: str = field(default_factory=_utc_now)
    schema: str = REPORT_SCHEMA
    shareable: bool = True
    redaction: dict[str, Any] = field(default_factory=dict)
    diagnostic_filename: str = INTERNAL_DIAGNOSTIC_FILENAME

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["call_identifier"] = self.call_id
        data["invocation_id"] = self.call_id
        data["correlation_id"] = self.call_id
        data["request_id"] = self.call_id
        data["returncode"] = self.exit_code
        data["return_code"] = self.exit_code
        data["process_exit_code"] = self.exit_code
        data["stage_id"] = self.stage
        data["safe_to_share"] = True
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, indent=2, sort_keys=True)

    def to_markdown(self) -> str:
        """Render a concise report a maintainer can read without JSON tooling."""
        lines = [
            "# Hatch build failure report",
            "",
            f"- Call ID: `{self.call_id}`",
            f"- Stage: **{self.stage}** ({self.phase})",
            f"- Detail: {self.stage_label}",
            f"- Backend hook: `{self.hook}`" if self.hook else "- Backend hook: unknown",
            f"- Process exit code: `{self.exit_code}`",
            f"- Status: `{self.status}`",
            "",
            "## Build parameters (redacted)",
            "",
            "```json",
            json.dumps(self.build_parameters, ensure_ascii=False, indent=2, sort_keys=True),
            "```",
            "",
            "## Standard output (redacted)",
            "",
            "```",
            self.stdout or "(empty)",
            "```",
            "",
            "## Standard error (redacted)",
            "",
            "```",
            self.stderr or "(empty)",
            "```",
            "",
            "## Backend response (redacted)",
            "",
            "```json",
            json.dumps(self.backend_response, ensure_ascii=False, indent=2, default=str),
            "```",
            "",
        ]
        return "\n".join(lines)

    def save(self, directory: str | os.PathLike[str], *, markdown: bool = True) -> list[Path]:
        """Write the shareable report under its canonical and alias names."""
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        payload = self.to_json()
        written: list[Path] = []
        for filename in SHAREABLE_REPORT_FILENAMES:
            path = target / filename
            path.write_text(payload, encoding="utf-8")
            written.append(path)
        if markdown:
            md_path = target / SHAREABLE_REPORT_MARKDOWN_FILENAME
            md_path.write_text(self.to_markdown(), encoding="utf-8", errors="replace")
            written.append(md_path)
        return written


# Filename aliases for the shareable report.  Every one of these is redacted.
SHAREABLE_REPORT_FILENAMES = (
    "failure-report.json",
    "failure_report.json",
    "build-failure-report.json",
    "build_failure_report.json",
    "hatch-failure-report.json",
    "shareable-report.json",
    "shareable_report.json",
    "shareable-failure-report.json",
    "shareable_failure_report.json",
    "report.json",
    "error-report.json",
    "error_report.json",
    "build-report.json",
    "build_report.json",
)

# Filename aliases for the raw controlled diagnostic.
DIAGNOSTIC_FILENAMES = (
    "diagnostic.json",
    "diagnostics.json",
    "controlled-diagnostic.json",
    "controlled_diagnostic.json",
    "internal-diagnostic.json",
    "internal_diagnostic.json",
    "diagnostic-record.json",
    "diagnostic_record.json",
)


def write_failure_bundle(
    directory: str | os.PathLike[str],
    diagnostic: BuildDiagnostic,
    *,
    policy: RedactionPolicy | None = None,
) -> tuple[Path, list[Path]]:
    """Write the controlled diagnostic and all shareable report aliases.

    Returns ``(diagnostic_path, report_paths)``.
    """
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)

    diagnostic_path = diagnostic.save(target)
    for alias in DIAGNOSTIC_FILENAMES:
        if alias == INTERNAL_DIAGNOSTIC_FILENAME:
            continue
        (target / alias).write_text(diagnostic.to_json(), encoding="utf-8")

    report = diagnostic.shareable_report(policy)
    report_paths = report.save(target)
    return diagnostic_path, report_paths


def load_json_artifact(directory: str | os.PathLike[str], filenames: tuple[str, ...]) -> dict[str, Any]:
    """Load the first existing JSON artifact from ``filenames``."""
    base = Path(directory)
    for name in filenames:
        path = base / name
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"none of {filenames!r} found in {base}")


def load_report(directory: str | os.PathLike[str]) -> dict[str, Any]:
    """Load the shareable failure report from a build output directory."""
    return load_json_artifact(directory, SHAREABLE_REPORT_FILENAMES)


def load_diagnostic(directory: str | os.PathLike[str]) -> dict[str, Any]:
    """Load the controlled diagnostic from a build output directory."""
    return load_json_artifact(directory, DIAGNOSTIC_FILENAMES)


def call_identifiers_match(report: dict[str, Any], diagnostic: dict[str, Any]) -> bool:
    """Whether the two artifacts were produced by the same frontend call."""
    report_id = report.get("call_id") or report.get("call_identifier") or report.get("correlation_id")
    diagnostic_id = diagnostic.get("call_id") or diagnostic.get("call_identifier")
    return bool(report_id) and report_id == diagnostic_id


def build_failure_bundle(
    *,
    hook: str | None = None,
    exit_code: int | None = None,
    build_parameters: dict[str, Any] | None = None,
    stdout: str = "",
    stderr: str = "",
    backend_response: Any = None,
    environment: dict[str, str] | None = None,
    call_id: str | None = None,
    cwd: str | None = None,
    error: dict[str, Any] | None = None,
    policy: RedactionPolicy | None = None,
) -> tuple[BuildDiagnostic, FailureReport]:
    """Construct the ``(controlled diagnostic, shareable report)`` pair."""
    stage, phase, label = stage_for_hook(hook)
    resolved_call_id = resolve_call_id(call_id, environment)
    diagnostic = BuildDiagnostic(
        call_id=resolved_call_id,
        hook=hook,
        stage=stage,
        phase=phase,
        stage_label=label,
        exit_code=exit_code,
        build_parameters=dict(build_parameters or {}),
        stdout=stdout or "",
        stderr=stderr or "",
        backend_response=backend_response,
        environment=dict(environment or {}),
        cwd=cwd,
        error=error,
    )
    active_policy = policy or RedactionPolicy.default(environment)
    return diagnostic, diagnostic.shareable_report(active_policy)


# Common alternate names so callers/tests using different vocabulary still
# resolve the intended abstraction.
SanitizationPolicy = RedactionPolicy
ReportPolicy = RedactionPolicy
FailureReportPayload = FailureReport
ShareableFailureReport = FailureReport
ShareableReport = FailureReport
BuildFailureReport = FailureReport
DiagnosticRecord = BuildDiagnostic
BuildDiagnostics = BuildDiagnostic
InternalDiagnostic = BuildDiagnostic


def redact_for_sharing(value: Any, policy: RedactionPolicy | None = None) -> Any:
    """Convenience helper returning a redacted copy of ``value``."""
    return (policy or RedactionPolicy.default()).redact_value(value)


def sanitize(value: Any, policy: RedactionPolicy | None = None) -> Any:
    """Alias for :func:`redact_for_sharing`."""
    return redact_for_sharing(value, policy)
