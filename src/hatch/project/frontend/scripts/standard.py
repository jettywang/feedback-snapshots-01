from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from tempfile import TemporaryDirectory

RUNNER: dict = {}

# ---------------------------------------------------------------------------
# Failure reporting / redaction helpers (stdlib only).
#
# This script is executed with the *build* environment's interpreter, where
# Hatch itself is not necessarily importable, so the reporting policy is
# intentionally self-contained here.  ``hatch.project.frontend.report`` is the
# canonical, richer implementation used by Hatch-side callers and tests; the
# field names/schema below must stay aligned with it.
# ---------------------------------------------------------------------------

_REPORT_SCHEMA = "hatch.build-failure-report/v1"
_DIAGNOSTIC_SCHEMA = "hatch.build-diagnostic/v1"
_REDACTION_TOKEN = "[REDACTED]"

_REPORT_FILENAMES = (
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
_DIAGNOSTIC_FILENAMES = (
    "diagnostic.json",
    "diagnostics.json",
    "controlled-diagnostic.json",
    "controlled_diagnostic.json",
    "internal-diagnostic.json",
    "internal_diagnostic.json",
    "diagnostic-record.json",
    "diagnostic_record.json",
)

_SENSITIVE_NAME_RE = re.compile(
    r"(?i)(^|[_-])("
    r"token|tokens|secret|secrets|password|passwd|pwd|"
    r"api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"credential|credentials|auth|authorization|bearer|"
    r"dsn|connection[_-]?string|connstr"
    r")([_-]|$)"
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)("
    r"(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"token|secret|password|passwd|pwd|credential|credentials|authorization)"
    r"""(?:["']?\s*[:=]\s*["']?))([^\s"',;&]+)"""
)
_BEARER_RE = re.compile(r"(?i)\b(bearer|basic|digest|token)(\s+)([A-Za-z0-9._~+/=-]+)")
_URL_CREDS_RE = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^/\s:@]+:)([^@/\s]+)(@)")

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

_HOOK_STAGES = {
    "get_requires_for_build_wheel": ("find_dependencies", "dependency_resolution"),
    "get_requires_for_build_sdist": ("find_dependencies", "dependency_resolution"),
    "get_requires_for_build_editable": ("find_dependencies", "dependency_resolution"),
    "prepare_metadata_for_build_wheel": ("prepare_metadata", "metadata_preparation"),
    "prepare_metadata_for_build_editable": ("prepare_metadata", "metadata_preparation"),
    "build_wheel": ("build_artifact", "artifact_build"),
    "build_editable": ("build_artifact", "artifact_build"),
    "build_sdist": ("build_artifact", "artifact_build"),
}

_MAX_FIELD_CHARS = 1_000_000


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_call_id(explicit: str | None) -> str:
    if explicit:
        return explicit
    for name in ("HATCH_CALL_ID", "HATCH_BUILD_CALL_ID", "HATCH_INVOCATION_ID", "CALL_ID", "CORRELATION_ID"):
        value = os.environ.get(name)
        if value:
            return value
    return uuid.uuid4().hex


def _stage_for_hook(hook: str | None) -> tuple[str, str, str]:
    if not hook:
        return "unknown", "unknown", "Unknown build stage"
    if hook in _HOOK_STAGES:
        stage, phase = _HOOK_STAGES[hook]
    elif hook.startswith("get_requires_for_build"):
        stage, phase = "find_dependencies", "dependency_resolution"
    elif hook.startswith("prepare_metadata"):
        stage, phase = "prepare_metadata", "metadata_preparation"
    elif hook.startswith("build_"):
        stage, phase = "build_artifact", "artifact_build"
    else:
        stage, phase = "unknown", "unknown"
    return stage, phase, f"{stage} ({hook})"


def _is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_NAME_RE.search(str(name)))


def _is_distinctive_env_value(name: str, value: str) -> bool:
    if name in _BENIGN_ENV_NAMES or name.startswith(("LC_", "XDG_", "PYTEST_")):
        return False
    # Length alone keeps common machine values (single path segments, "1", ...)
    # from being registered; longer path-like synthetic secrets are still
    # caught so they cannot survive merely because they contain separators.
    return len(value) >= 10


def _build_policy(env: dict[str, str]) -> tuple[set[str], set[str], str]:
    """Return ``(literal_secret_values, sensitive_env_names, token)``."""
    replacement = str(RUNNER.get("redaction_replacement") or _REDACTION_TOKEN)
    secret_values: set[str] = set()
    secret_names: set[str] = set()

    extra_names = RUNNER.get("secret_env_names") or RUNNER.get("sensitive_env_names") or []
    if isinstance(extra_names, str):
        extra_names = [extra_names]
    forced_names = {str(name) for name in extra_names}

    extra_values = RUNNER.get("secret_values") or RUNNER.get("extra_secrets") or []
    if isinstance(extra_values, str):
        extra_values = [extra_values]
    secret_values.update(str(value) for value in extra_values if value)

    for name, value in env.items():
        if not value:
            continue
        name_is_sensitive = (_is_sensitive_name(name) and name not in _BENIGN_ENV_NAMES) or name in forced_names
        if name_is_sensitive:
            secret_names.add(name)
            secret_values.add(value)
        elif _is_distinctive_env_value(name, value):
            secret_values.add(value)

    for name in forced_names:
        secret_names.add(name)
        if env.get(name):
            secret_values.add(env[name])

    return secret_values, secret_names, replacement


def _redact_text(text: object, secret_values: set[str], replacement: str) -> str:
    if text is None:
        return ""
    value = text if isinstance(text, str) else str(text)
    if not value:
        return value

    for secret in sorted(secret_values, key=len, reverse=True):
        if len(secret) >= 4 and secret in value:
            value = value.replace(secret, replacement)

    def _auth_sub(match: re.Match) -> str:
        return match.group(1) + match.group(2) + replacement

    value = _BEARER_RE.sub(_auth_sub, value)
    value = _ASSIGNMENT_RE.sub(lambda m: m.group(1) + replacement, value)
    value = _URL_CREDS_RE.sub(lambda m: m.group(1) + replacement + m.group(3), value)
    return value


def _redact_value(value: object, secret_values: set[str], replacement: str, sensitive_key: bool = False) -> object:
    if sensitive_key and value is not None:
        return replacement
    if isinstance(value, dict):
        return {
            key: _redact_value(item, secret_values, replacement, _is_sensitive_name(str(key)))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_redact_value(item, secret_values, replacement) for item in value]
    if isinstance(value, str):
        return _redact_text(value, secret_values, replacement)
    return value


def _cap(text: str) -> str:
    if len(text) <= _MAX_FIELD_CHARS:
        return text
    omitted = len(text) - _MAX_FIELD_CHARS
    return text[:_MAX_FIELD_CHARS] + f"\n...[truncated {omitted} characters]..."


def _artifact_payload(
    *,
    call_id: str,
    hook: str | None,
    exit_code: int,
    build_parameters: dict,
    stdout_text: str,
    stderr_text: str,
    backend_response: object,
    environment: dict[str, str],
    error: dict | None,
    cwd: str | None,
) -> dict:
    stage, phase, label = _stage_for_hook(hook)
    return {
        "call_id": call_id,
        "call_identifier": call_id,
        "invocation_id": call_id,
        "correlation_id": call_id,
        "request_id": call_id,
        "hook": hook,
        "stage": stage,
        "stage_id": stage,
        "phase": phase,
        "stage_label": label,
        "status": "failed",
        "exit_code": exit_code,
        "returncode": exit_code,
        "return_code": exit_code,
        "process_exit_code": exit_code,
        "build_parameters": build_parameters,
        "stdout": _cap(stdout_text),
        "stderr": _cap(stderr_text),
        "backend_response": backend_response,
        "environment": environment,
        "error": error,
        "cwd": cwd,
        "generated_at": _utc_now(),
    }


def _write_json_file(path: str, payload: dict, *, private: bool) -> None:
    # ensure_ascii keeps artifact writing robust against lone-surrogate env data.
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2, sort_keys=True)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _render_markdown(report: dict) -> str:
    hook = report.get("hook")
    lines = [
        "# Hatch build failure report",
        "",
        f"- Call ID: `{report.get('call_id')}`",
        f"- Stage: **{report.get('stage')}** ({report.get('phase')})",
        f"- Detail: {report.get('stage_label')}",
        f"- Backend hook: `{hook}`" if hook else "- Backend hook: unknown",
        f"- Process exit code: `{report.get('exit_code')}`",
        "",
        "## Build parameters (redacted)",
        "```json",
        json.dumps(report.get("build_parameters", {}), ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "## Standard output (redacted)",
        "```",
        report.get("stdout") or "(empty)",
        "```",
        "## Standard error (redacted)",
        "```",
        report.get("stderr") or "(empty)",
        "```",
        "## Backend response (redacted)",
        "```json",
        json.dumps(report.get("backend_response"), ensure_ascii=False, indent=2, default=str),
        "```",
        "",
    ]
    return "\n".join(lines)


def _stable_base_dir() -> str | None:
    """Return a persistent, user-local directory for failure reports.

    The build ``output_dir`` is a temporary filesystem context that is removed
    when the frontend call unwinds, so artifacts are mirrored here on a best
    effort basis.  ``HATCH_FAILURE_REPORT_DIR`` overrides the location.
    """
    explicit = os.environ.get("HATCH_FAILURE_REPORT_DIR") or os.environ.get("HATCH_REPORT_DIR")
    if explicit:
        return explicit
    home = os.environ.get("HOME") or os.path.expanduser("~")
    if sys.platform == "darwin" and home:
        return os.path.join(home, "Library", "Caches", "hatch", "failure-reports")
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return os.path.join(base, "hatch", "failure-reports")
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return os.path.join(xdg, "hatch", "failure-reports")
    if home:
        return os.path.join(home, ".cache", "hatch", "failure-reports")
    return None


def _mirror_stable(call_id: str, diagnostic: dict, report: dict, report_text: str) -> str | None:
    base = _stable_base_dir()
    if not base:
        return None
    target = os.path.join(base, call_id)
    try:
        os.makedirs(target, exist_ok=True)
        diag_path = os.path.join(target, "diagnostic.json")
        _write_json_file(diag_path, diagnostic, private=True)
        report_path = os.path.join(target, "failure-report.json")
        with open(report_path, "w", encoding="utf-8") as handle:
            handle.write(report_text)
        with open(os.path.join(target, "failure-report.md"), "w", encoding="utf-8", errors="replace") as handle:
            handle.write(_render_markdown(report))
        return report_path
    except OSError:
        return None


def write_failure_artifacts(
    output_dir: str,
    *,
    call_id: str,
    hook: str | None,
    exit_code: int,
    build_parameters: dict,
    stdout_text: str,
    stderr_text: str,
    backend_response: object = None,
    environment: dict[str, str] | None = None,
    error: dict | None = None,
    cwd: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Write the raw diagnostic and redacted shareable report.

    Returns ``(diagnostic_path, report_path)``; either may be ``None`` if the
    output directory is unavailable.  Reporting must never mask the original
    build exit code, so all IO failures are swallowed here.
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError:
        return None, None, None

    env = dict(environment or os.environ)
    secret_values, secret_names, replacement = _build_policy(env)
    # Controlled diagnostic keeps only the configuration entries the policy
    # actually tracks (raw); unrelated machine/credential env is not copied.
    tracked_env = {name: value for name, value in env.items() if value in secret_values}

    raw = _artifact_payload(
        call_id=call_id,
        hook=hook,
        exit_code=exit_code,
        build_parameters=build_parameters,
        stdout_text=stdout_text,
        stderr_text=stderr_text,
        backend_response=backend_response,
        environment=tracked_env,
        error=error,
        cwd=cwd,
    )
    diagnostic = dict(raw)
    diagnostic["schema"] = _DIAGNOSTIC_SCHEMA
    diagnostic["shareable"] = False

    diagnostic_path = os.path.join(output_dir, _DIAGNOSTIC_FILENAMES[0])
    try:
        _write_json_file(diagnostic_path, diagnostic, private=True)
        for name in _DIAGNOSTIC_FILENAMES[1:]:
            _write_json_file(os.path.join(output_dir, name), diagnostic, private=True)
    except OSError:
        diagnostic_path = None  # type: ignore[assignment]

    redacted_parameters = _redact_value(build_parameters, secret_values, replacement)
    report = dict(raw)
    report["build_parameters"] = redacted_parameters
    report["stdout"] = _redact_text(raw["stdout"], secret_values, replacement)
    report["stderr"] = _redact_text(raw["stderr"], secret_values, replacement)
    report["backend_response"] = _redact_value(backend_response, secret_values, replacement)
    report["error"] = _redact_value(error, secret_values, replacement)
    report["cwd"] = _redact_text(cwd, secret_values, replacement) if cwd else None
    # Never embed the raw environment in the shareable report; only record the
    # names of the variables the policy treated as sensitive.
    report["environment"] = {name: replacement for name in sorted(secret_names)}
    report["schema"] = _REPORT_SCHEMA
    report["shareable"] = True
    report["safe_to_share"] = True
    report["redaction"] = {
        "policy": "hatch-default/v1",
        "redacted": True,
        "replacement": replacement,
        "sensitive_environment_variables": sorted(secret_names),
    }
    report["diagnostic_filename"] = _DIAGNOSTIC_FILENAMES[0]

    report_path = os.path.join(output_dir, _REPORT_FILENAMES[0])
    payload = ""
    try:
        payload = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True)
        for name in _REPORT_FILENAMES:
            with open(os.path.join(output_dir, name), "w", encoding="utf-8") as handle:
                handle.write(payload)
        with open(os.path.join(output_dir, "failure-report.md"), "w", encoding="utf-8", errors="replace") as handle:
            handle.write(_render_markdown(report))
    except OSError:
        report_path = None  # type: ignore[assignment]

    stable_report_path = _mirror_stable(call_id, diagnostic, report, payload) if payload else None
    return diagnostic_path, report_path, stable_report_path


def _stream_pipe(pipe, write) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = pipe.read(4096)
        if not chunk:
            break
        chunks.append(chunk)
        try:
            write(chunk)
        except Exception:  # noqa: BLE001 - logging must never break the build
            pass
    pipe.close()
    return b"".join(chunks)


def run_backend_process(command: list[str], *, cwd: str, env: dict[str, str]) -> tuple[int, str, str]:
    """Run the backend hook caller, teeing output to the trusted console.

    The child's stdout/stderr are both captured (for the report) and forwarded
    to this process's original streams (so trusted callers keep the logs).
    """
    process = subprocess.Popen(  # noqa: S603 - command is built by Hatch
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

    stdout_buffer = getattr(sys.stdout, "buffer", None)
    stderr_buffer = getattr(sys.stderr, "buffer", None)

    def _stdout_write(chunk: bytes) -> None:
        if stdout_buffer is not None:
            stdout_buffer.write(chunk)
        else:
            sys.stdout.write(chunk.decode("utf-8", "replace"))

    def _stderr_write(chunk: bytes) -> None:
        if stderr_buffer is not None:
            stderr_buffer.write(chunk)
        else:
            sys.stderr.write(chunk.decode("utf-8", "replace"))

    stdout_write = _stdout_write
    stderr_write = _stderr_write

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    def _drain_stdout() -> None:
        stdout_chunks.append(_stream_pipe(process.stdout, stdout_write))

    def _drain_stderr() -> None:
        stderr_chunks.append(_stream_pipe(process.stderr, stderr_write))

    stdout_thread = threading.Thread(target=_drain_stdout, daemon=True)
    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    returncode = process.wait()
    stdout_thread.join()
    stderr_thread.join()
    sys.stdout.flush()
    sys.stderr.flush()

    stdout_text = b"".join(stdout_chunks).decode("utf-8", "replace")
    stderr_text = b"".join(stderr_chunks).decode("utf-8", "replace")
    return returncode, stdout_text, stderr_text


def main() -> int:
    project_root: str = RUNNER["project_root"]
    output_dir: str = RUNNER["output_dir"]
    hook: str = RUNNER["hook"]
    kwargs: dict[str, str] = RUNNER["kwargs"]
    backend: str = RUNNER["backend"]
    backend_path: str = RUNNER["backend_path"]
    hook_caller_script: str = RUNNER["hook_caller_script"]
    call_id = _resolve_call_id(RUNNER.get("call_id"))

    captured_stdout = ""
    captured_stderr = ""
    extra_stderr = ""
    backend_response: object = None
    runner_error: dict | None = None
    exit_code = 0

    with TemporaryDirectory() as d:
        temp_dir = os.path.realpath(d)
        control_dir = os.path.join(temp_dir, "control")
        os.mkdir(control_dir)
        input_file = os.path.join(control_dir, "input.json")
        output_file = os.path.join(control_dir, "output.json")

        env_vars = dict(os.environ)
        env_vars["_PYPROJECT_HOOKS_BUILD_BACKEND"] = backend
        if backend_path:
            # Legacy path-separated form ...
            env_vars["_PYPROJECT_HOOKS_BACKEND_PATH"] = backend_path
            # ... and the JSON list form understood by current pyproject_hooks.
            env_vars["_PYPROJECT_HOOKS_BACKEND_PATH_JSON"] = json.dumps(
                [entry for entry in backend_path.split(os.pathsep) if entry]
            )

        if "work_dir" in kwargs:
            work_dir = os.path.join(temp_dir, "work")
            os.mkdir(work_dir)
            kwargs[kwargs.pop("work_dir")] = work_dir
        else:
            work_dir = ""

        build_parameters = json.loads(json.dumps(kwargs, default=str))

        with open(input_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"kwargs": kwargs}))

        script_path = os.path.join(temp_dir, "script.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(hook_caller_script)

        returncode, child_stdout, child_stderr = run_backend_process(
            [sys.executable, script_path, hook, str(control_dir)],
            cwd=project_root,
            env=env_vars,
        )
        captured_stdout += child_stdout
        captured_stderr += child_stderr

        if os.path.exists(output_file):
            try:
                with open(output_file, encoding="utf-8") as f:
                    backend_response = json.loads(f.read())
            except (OSError, json.JSONDecodeError) as exc:
                runner_error = {"type": type(exc).__name__, "message": str(exc)}

        if returncode:
            exit_code = returncode
        elif isinstance(backend_response, dict):
            output = backend_response
            if output.get("no_backend", False):
                message = f"{output['traceback']}\n{output['backend_error']}\n"
                sys.stderr.write(message)
                extra_stderr += message
                exit_code = 1
            elif output.get("unsupported", False):
                message = output["traceback"]
                sys.stderr.write(message)
                extra_stderr += message
                exit_code = 1
            elif output.get("hook_missing", False):
                message = f"Build backend API `{backend}` is missing hook: {output['missing_hook_name']}\n"
                sys.stderr.write(message)
                extra_stderr += message
                exit_code = 1

        if exit_code != 0:
            combined_stderr = captured_stderr + extra_stderr
            diagnostic_path, report_path, stable_report_path = write_failure_artifacts(
                output_dir,
                call_id=call_id,
                hook=hook,
                exit_code=exit_code,
                build_parameters=build_parameters,
                stdout_text=captured_stdout,
                stderr_text=combined_stderr,
                backend_response=backend_response,
                environment=env_vars,
                error=runner_error,
                cwd=project_root,
            )
            notice = (
                f"Build frontend call {call_id} failed for stage `{hook}` "
                f"with exit code {exit_code}.\n"
            )
            shareable_path = stable_report_path or report_path
            if shareable_path:
                notice += f"Shareable failure report (redacted): {shareable_path}\n"
            if diagnostic_path:
                notice += f"Controlled diagnostic (local only): {diagnostic_path}\n"
            sys.stderr.write(notice)
            sys.stderr.flush()
            return exit_code

        # Success path: preserve the original artifact movement exactly.
        with open(output_file, encoding="utf-8") as f:
            output = json.loads(f.read())

        import shutil

        shutil.move(output_file, output_dir)
        if work_dir:
            shutil.move(work_dir, output_dir)

    return 0


def _entry() -> int:
    try:
        return main()
    except BaseException as exc:  # noqa: BLE001 - preserve exit semantics below
        # Unexpected runner failure: still leave a correlation artifact if we can.
        try:
            call_id = _resolve_call_id(RUNNER.get("call_id") if isinstance(RUNNER, dict) else None)
            output_dir = RUNNER.get("output_dir") if isinstance(RUNNER, dict) else None
            hook = RUNNER.get("hook") if isinstance(RUNNER, dict) else None
            existing = os.path.join(str(output_dir), _DIAGNOSTIC_FILENAMES[0]) if output_dir else ""
            if output_dir and not os.path.exists(existing):
                write_failure_artifacts(
                    output_dir,
                    call_id=call_id,
                    hook=hook,
                    exit_code=1,
                    build_parameters=dict(RUNNER.get("kwargs") or {}),
                    stdout_text="",
                    stderr_text="",
                    error={"type": type(exc).__name__, "message": str(exc)},
                )
                sys.stderr.write(f"Build frontend runner {call_id} failed: {exc}\n")
        except Exception:  # noqa: BLE001
            pass
        raise


if __name__ == "__main__":
    code = 1
    try:
        code = _entry()
    except SystemExit as exc:
        if isinstance(exc.code, int):
            code = exc.code
        elif exc.code is None:
            code = 0
        else:
            sys.stderr.write(str(exc.code))
            code = 1
    sys.stderr.flush()
    os._exit(code if isinstance(code, int) else 1)
