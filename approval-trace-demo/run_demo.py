from __future__ import annotations

import configparser
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
RECORDS = DEMO_DIR / "records"
PLUGIN_ROOT = DEMO_DIR / "plugins"
GATE_DIR = DEMO_DIR / "gate"
SOURCE_A = PLUGIN_ROOT / "source_a"
SOURCE_B = PLUGIN_ROOT / "source_b"
REPO_ROOT = DEMO_DIR.parent
WORK = DEMO_DIR / ".work"
ACTIVE = WORK / "active"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def reset_dirs() -> None:
    if WORK.exists():
        shutil.rmtree(WORK)
    RECORDS.mkdir(parents=True, exist_ok=True)
    for record in RECORDS.iterdir():
        if record.is_file():
            record.unlink()
    WORK.mkdir()
    ACTIVE.symlink_to(SOURCE_A, target_is_directory=True)
    (WORK / "hatch-config.toml").write_text("", encoding="utf-8")


def write_project() -> Path:
    project = WORK / "project"
    package = project / "src" / "demo_approval"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "0.0.0-static"\n', encoding="utf-8")
    (package / "version.py").write_text(
        '''from __future__ import annotations

import hashlib
import json
import os
import sys
import time

path = __file__
try:
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
except OSError:
    digest = None
log_path = os.environ.get("PROBE_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "record": "project-code",
            "event": "version-code-import",
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "time_ns": time.time_ns(),
            "argv": sys.argv,
            "file": path,
            "sha256": digest,
        }, sort_keys=True) + "\\n")

__version__ = "9.8.7"
''',
        encoding="utf-8",
    )

    python_prefix = json.dumps(sys.prefix)
    pyproject = f'''[build-system]
requires = []
build-backend = "hatchling.build"

[project]
name = "approval-demo"
description = "Offline approval sequencing fixture"
requires-python = ">=3.10"
dynamic = ["version"]

[tool.hatch.version]
source = "code"
path = "src/demo_approval/version.py"

[tool.hatch.build.targets.wheel]
packages = ["src/demo_approval"]

[tool.hatch.build.hooks.probe]
scope = "global"
approved_config = "baseline"

[tool.hatch.build.targets.wheel.hooks.probe]
scope = "target-wheel"
approved_config = "baseline"

[tool.hatch.envs.hatch-build]
path = {python_prefix}
installer = "pip"
skip-install = true
'''
    (project / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return project


def resolve_local_entry_point(source_root: Path) -> dict[str, object]:
    dist_infos = list(source_root.glob("*.dist-info"))
    if len(dist_infos) != 1:
        raise RuntimeError(f"Expected one dist-info in {source_root}, got {dist_infos}")
    dist_info = dist_infos[0]
    parser = configparser.ConfigParser()
    parser.read(dist_info / "entry_points.txt", encoding="utf-8")
    value = parser["hatch"]["probe"].strip()
    module = value.split(":", 1)[0].strip()
    module_path = source_root / f"{module}.py"
    if not module_path.is_file():
        module_path = source_root / module / "__init__.py"
    return {
        "module": module,
        "origin": str(module_path),
        "origin_realpath": str(module_path.resolve()),
        "sha256": sha256_file(module_path),
        "dist_name": "probe-recorder",
        "dist_info_path": str(dist_info),
        "dist_info_realpath": str(dist_info.resolve()),
        "dist_info_basename": dist_info.name,
        "entry_points_sha256": sha256_file(dist_info / "entry_points.txt"),
        "metadata_sha256": sha256_file(dist_info / "METADATA"),
        "entry_point_value": value,
    }


def prepare_manifest(project: Path) -> Path:
    with (project / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    scope = {
        "selected_target": "wheel",
        "project_dynamic": pyproject["project"].get("dynamic", []),
        "version_table": pyproject["tool"]["hatch"].get("version", {}),
        "global_build_hooks": pyproject["tool"]["hatch"]["build"].get("hooks", {}),
        "wheel_target_hooks": pyproject["tool"]["hatch"]["build"]["targets"]["wheel"].get("hooks", {}),
    }
    source = resolve_local_entry_point(SOURCE_A)
    version_code = project / "src" / "demo_approval" / "version.py"
    source["pin_fields"] = [
        "module",
        "origin_realpath",
        "sha256",
        "dist_name",
        "dist_info_realpath",
        "dist_info_basename",
        "entry_points_sha256",
        "metadata_sha256",
        "entry_point_value",
    ]
    manifest = {
        "schema": "hatch-approval-demo/v1",
        "decision": "approved-on-first-review; reuse while pinned fields match",
        "selection": {"target": "wheel"},
        "config_scope": scope,
        "config_scope_digest": canonical_digest(scope),
        "entry_points": {"probe": source},
        "project_code": [
            {
                "role": "dynamic-version-code",
                "path": str(version_code),
                "realpath": str(version_code.resolve()),
                "sha256": sha256_file(version_code),
                "executes_python": True,
            }
        ],
        "reconfirm_when": [
            "selected target or target-specific hook table changes",
            "hook name resolves to different entry point, distribution, file digest, or dist metadata",
            "hook configuration or enabled-by-default/environment enablement changes",
            "dynamic version/metadata code path or digest changes",
            "build-system.requires or backend-path changes",
        ],
    }
    manifest_path = RECORDS / "approval-manifest.a.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest_path


def hatch_command(args: list[str]) -> list[str]:
    hatch_bin = Path(sys.executable).with_name("hatch")
    if hatch_bin.is_file():
        return [str(hatch_bin), *args]
    if shutil.which("hatch"):
        return ["hatch", *args]
    direct_args: list[str]
    if args[:2] == ["build", "--target"]:
        direct_args = ["-m", "hatchling", "build", *args[1:]]
    elif args and args[0] == "clean":
        # `hatch clean -t wheel` is Click-invoked build(clean_only=True).
        rest = args[1:]
        target = rest[1] if len(rest) >= 2 and rest[0] in {"-t", "--target"} else "wheel"
        direct_args = ["-m", "hatchling", "build", "--target", target, "--clean-only"]
    else:
        raise RuntimeError(f"No hatch executable and cannot translate {args}")
    return [sys.executable, *direct_args]


def run_case(
    name: str,
    project: Path,
    args: list[str],
    manifest: Path,
    *,
    enforce: bool = False,
    safe_exec: bool = False,
) -> dict[str, object]:
    plugin_log = RECORDS / f"{name}.jsonl"
    gate_log = RECORDS / f"{name}.gate.jsonl"
    console_log = RECORDS / f"{name}.console.txt"
    plugin_log.unlink(missing_ok=True)
    gate_log.unlink(missing_ok=True)
    console_log.unlink(missing_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "NO_COLOR": "1",
            "PROBE_LOG": str(plugin_log),
            "APPROVAL_GATE_LOG": str(gate_log),
            "APPROVAL_MANIFEST": str(manifest),
            "HATCH_CONFIG": str(WORK / "hatch-config.toml"),
            "HATCH_DATA_DIR": str(WORK / "hatch-data"),
            "HATCH_CACHE_DIR": str(WORK / "hatch-cache"),
            "UV_CACHE_DIR": str(WORK / "uv-cache"),
            "UV_PYTHON_DOWNLOADS": "never",
            "PYTHONPATH": os.pathsep.join([str(GATE_DIR), str(ACTIVE)]),
        }
    )
    if enforce:
        env["APPROVAL_ENFORCE"] = "1"
    if safe_exec:
        env["APPROVAL_SAFE_EXEC"] = "1"

    command = hatch_command(args)
    completed = subprocess.run(command, cwd=project, env=env, text=True, capture_output=True, check=False)
    console_log.write_text(
        "$ " + " ".join(command) + "\n\n[stdout]\n" + completed.stdout + "\n[stderr]\n" + completed.stderr,
        encoding="utf-8",
    )
    return {
        "name": name,
        "command": command,
        "args": args,
        "returncode": completed.returncode,
        "plugin_log": str(plugin_log.relative_to(DEMO_DIR)),
        "gate_log": str(gate_log.relative_to(DEMO_DIR)),
        "console_log": str(console_log.relative_to(DEMO_DIR)),
        "enforce": enforce,
        "safe_exec": safe_exec,
    }


def read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def first_event(records: list[dict], event: str) -> dict:
    return next(record for record in records if record.get("event") == event)


def build_comparison() -> dict[str, object]:
    a_records = read_jsonl(RECORDS / "baseline-hooks-only.jsonl")
    b_records = read_jsonl(RECORDS / "switch-b-observed-hooks-only.jsonl")
    a_init = first_event(a_records, "initialize")
    b_init = first_event(b_records, "initialize")
    comparison = {
        "same_plugin_name": "probe",
        "same_entry_point_name": "probe",
        "initialize_callback_args_equal": a_init["callback_args"] == b_init["callback_args"],
        "initialize_callback_args_a": a_init["callback_args"],
        "initialize_callback_args_b": b_init["callback_args"],
        "provenance_fields_in_initialize_callback": False,
        "out_of_band_a": {
            "source_id": a_init["source_id"],
            "module_file": a_init["module_file"],
            "module_sha256": a_init["module_sha256"],
            "pid": a_init["pid"],
        },
        "out_of_band_b": {
            "source_id": b_init["source_id"],
            "module_file": b_init["module_file"],
            "module_sha256": b_init["module_sha256"],
            "pid": b_init["pid"],
        },
        "interpretation": (
            "The lifecycle arguments are identical. Source identity is available only out-of-band from "
            "the loaded class/module, entry-point distribution metadata, or an import-time gate; those "
            "checks happen after import unless the gate intercepts entry-point loading."
        ),
    }
    (RECORDS / "callback-comparison.json").write_text(
        json.dumps(comparison, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return comparison


def main() -> int:
    reset_dirs()
    project = write_project()
    manifest = prepare_manifest(project)
    shutil.copy2(project / "pyproject.toml", RECORDS / "project.pyproject.toml")
    shutil.copy2(project / "src" / "demo_approval" / "version.py", RECORDS / "project.version.py")

    summary: dict[str, object] = {
        "demo_dir": str(DEMO_DIR),
        "work_dir": str(WORK),
        "python": sys.executable,
        "hatch_command": hatch_command(["build", "--target", "wheel"])[0],
        "cases": [],
    }
    cases = summary["cases"]
    assert isinstance(cases, list)

    baseline_cases = [
        ("baseline-normal-build", ["build", "--target", "wheel"]),
        ("baseline-hooks-only", ["build", "--target", "wheel", "--hooks-only"]),
        ("baseline-clean-only", ["clean", "--target", "wheel"]),
        ("gate-safe-allowed-hooks-only", ["build", "--target", "wheel", "--hooks-only"]),
    ]
    for index, (name, args) in enumerate(baseline_cases):
        result = run_case(
            name,
            project,
            args,
            manifest,
            enforce=(name == "gate-safe-allowed-hooks-only"),
            safe_exec=(name == "gate-safe-allowed-hooks-only"),
        )
        cases.append(result)
        if result["returncode"] != 0:
            raise RuntimeError(f"{name} failed with {result['returncode']}; see {result['console_log']}")

    ACTIVE.unlink()
    ACTIVE.symlink_to(SOURCE_B, target_is_directory=True)
    summary["source_switched_after_case"] = baseline_cases[-1][0]

    observed = run_case("switch-b-observed-hooks-only", project, ["build", "--target", "wheel", "--hooks-only"], manifest)
    cases.append(observed)

    blocked = run_case(
        "switch-b-blocked-hooks-only",
        project,
        ["build", "--target", "wheel", "--hooks-only"],
        manifest,
        enforce=True,
    )
    cases.append(blocked)
    if blocked["returncode"] == 0:
        raise RuntimeError("Blocked source-switch case unexpectedly succeeded")

    summary["callback_comparison"] = build_comparison()
    (RECORDS / "run-summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
