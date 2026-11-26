from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

LAB = Path(__file__).resolve().parent
REPO = LAB.parent
POETRY_SRC = REPO / "src"
PYLIBS = LAB / "pylibs"
EVIDENCE = LAB / "evidence"
RUN_ROOT = Path(
    os.environ.get(
        "APPROVAL_RUN_ROOT",
        Path(os.environ.get("TMPDIR", "/tmp")) / "poetry-approval-lab",
    )
)

CASES = [
    {
        "id": "plain-control",
        "project": "plainpkg",
        "profile": None,
        "native": "0",
        "import_name": "plainpkg",
    },
    {
        "id": "hook-direct-false",
        "project": "hookpkg",
        "profile": "direct.toml",
        "native": "0",
        "import_name": "hookpkg",
    },
    {
        "id": "hook-setup-native",
        "project": "hookpkg",
        "profile": "setup-native.toml",
        "native": "1",
        "import_name": "hookpkg",
    },
    {
        "id": "hook-legacy-string",
        "project": "hookpkg",
        "profile": "legacy-string.toml",
        "native": "0",
        "import_name": "hookpkg",
    },
    {
        "id": "hook-existing-setup",
        "project": "hookpkg",
        "profile": "setup-native.toml",
        "native": "0",
        "import_name": "hookpkg",
        "existing_setup": True,
    },
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def prepare_case_source(case: dict[str, str]) -> Path:
    source = LAB / "projects" / case["project"]
    target = RUN_ROOT / "sources" / case["id"]
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "build", "dist"))

    if case["project"] == "hookpkg":
        base = (target / "pyproject.base.toml").read_text(encoding="utf-8")
        profile = (LAB / "profiles" / case["profile"]).read_text(encoding="utf-8")
        (target / "pyproject.toml").write_text(base + profile, encoding="utf-8")
        (target / "pyproject.base.toml").unlink()

        if case.get("existing_setup"):
            (target / "setup.py").write_text(
                """from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone


def record(event):
    log_path = os.environ.get("APPROVAL_EVENT_LOG")
    if not log_path:
        return
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "event": event,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "argv": sys.argv,
            "dunder_name": __name__,
            "cwd": os.getcwd(),
            "when": datetime.now(timezone.utc).isoformat(),
        }, sort_keys=True) + "\\n")


record("existing_setup_py_enter")
from setuptools import setup

setup(name="hookpkg", version="0.1.0", packages=["hookpkg"])
record("existing_setup_py_exit")
""",
                encoding="utf-8",
            )
    return target


def hook_env(case: dict[str, str], event_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(POETRY_SRC), str(PYLIBS), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    env["APPROVAL_EVENT_LOG"] = str(event_path)
    env["APPROVAL_RUNTIME_LOG"] = str(event_path)
    env["APPROVAL_PROFILE"] = case["id"]
    env["APPROVAL_NATIVE"] = case["native"]
    return env


def run_hook(
    calls: list[dict[str, Any]],
    case: dict[str, str],
    context: str,
    phase: str,
    hook: str,
    project_dir: Path,
    work_dir: Path,
    metadata_dir: Path | None = None,
) -> dict[str, Any]:
    event_path = RUN_ROOT / "events" / f"{case['id']}__{context}__{phase}.jsonl"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    if event_path.exists():
        event_path.unlink()

    log_stem = f"{case['id']}__{context}__{phase}"
    stdout_log = EVIDENCE / "logs" / f"{log_stem}.stdout.txt"
    stderr_log = EVIDENCE / "logs" / f"{log_stem}.stderr.txt"
    work_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(LAB / "pep517_worker.py"),
        hook,
        str(project_dir),
        str(work_dir),
    ]
    if metadata_dir is not None:
        command.append(str(metadata_dir))

    completed = subprocess.run(
        command,
        env=hook_env(case, event_path),
        text=True,
        capture_output=True,
        cwd=LAB,
        check=False,
    )
    stdout_log.parent.mkdir(parents=True, exist_ok=True)
    stdout_log.write_text(completed.stdout, encoding="utf-8")
    stderr_log.write_text(completed.stderr, encoding="utf-8")

    result = None
    for line in completed.stdout.splitlines():
        if line.startswith("APPROVAL_RESULT="):
            result = json.loads(line.split("=", 1)[1])["result"]

    events = read_events(event_path)
    record = {
        "case": case["id"],
        "context": context,
        "phase": phase,
        "hook": hook,
        "returncode": completed.returncode,
        "result": result,
        "event_count": len(events),
        "event_names": [event.get("event") for event in events],
        "event_file": str(event_path.relative_to(RUN_ROOT)),
        "stdout_log": str(stdout_log.relative_to(LAB)),
        "stderr_log": str(stderr_log.relative_to(LAB)),
    }
    calls.append(record)
    return record


def build_context(
    calls: list[dict[str, Any]],
    case: dict[str, str],
    context: str,
    project_dir: Path,
) -> dict[str, Path | str | None]:
    outputs = RUN_ROOT / "outputs" / case["id"] / context
    meta_root = RUN_ROOT / "metadata" / case["id"] / context
    for path in (outputs / "sdist", outputs / "wheel", outputs / "editable", meta_root / "wheel", meta_root / "editable"):
        path.mkdir(parents=True, exist_ok=True)

    requires = run_hook(
        calls, case, context, "get_requires", "requires", project_dir, outputs / "requires"
    )

    metadata_parent = meta_root / "wheel"
    metadata = run_hook(
        calls, case, context, "prepare_metadata", "metadata", project_dir, metadata_parent
    )
    dist_info = metadata_parent / str(metadata["result"]) if metadata["returncode"] == 0 else None

    sdist = None
    if context == "direct-source":
        sdist = run_hook(
            calls, case, context, "build_sdist", "sdist", project_dir, outputs / "sdist"
        )

    wheel = run_hook(
        calls,
        case,
        context,
        "build_wheel",
        "wheel",
        project_dir,
        outputs / "wheel",
        dist_info,
    )

    editable_metadata_parent = meta_root / "editable"
    editable_metadata = run_hook(
        calls,
        case,
        context,
        "prepare_editable_metadata",
        "metadata_editable",
        project_dir,
        editable_metadata_parent,
    )
    editable_dist_info = (
        editable_metadata_parent / str(editable_metadata["result"])
        if editable_metadata["returncode"] == 0
        else None
    )
    editable = run_hook(
        calls,
        case,
        context,
        "build_editable",
        "editable",
        project_dir,
        outputs / "editable",
        editable_dist_info,
    )

    def artifact(record: dict[str, Any], directory: Path) -> Path | None:
        if record["returncode"] != 0 or not record.get("result"):
            return None
        path = directory / str(record["result"])
        return path if path.exists() else None

    return {
        "requires_rc": requires["returncode"],
        "metadata_rc": metadata["returncode"],
        "sdist_path": artifact(sdist, outputs / "sdist") if sdist else None,
        "wheel_path": artifact(wheel, outputs / "wheel"),
        "editable_path": artifact(editable, outputs / "editable"),
    }


def copy_artifact(path: Path | None, case_id: str, context: str, kind: str) -> str | None:
    if path is None or not path.exists():
        return None
    target_dir = EVIDENCE / "artifacts" / case_id / context
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{kind}-{path.name}"
    shutil.copy2(path, target)
    return str(target.relative_to(LAB))


def extract_sdist(sdist_path: Path, case_id: str) -> Path:
    target_root = RUN_ROOT / "sdist-sources" / case_id
    if target_root.exists():
        shutil.rmtree(target_root)
    target_root.mkdir(parents=True)
    with tarfile.open(sdist_path, "r:gz") as archive:
        archive.extractall(target_root, filter="data")
    children = [path for path in target_root.iterdir() if path.is_dir()]
    return children[0]


def inspect_archives() -> dict[str, Any]:
    findings: dict[str, Any] = {}
    content_root = EVIDENCE / "archive-content"
    for archive in sorted((EVIDENCE / "artifacts").rglob("*")):
        if archive.is_dir():
            continue
        rel = archive.relative_to(EVIDENCE / "artifacts")
        key = str(rel)
        out_dir = content_root / rel.parent / archive.name
        out_dir.mkdir(parents=True, exist_ok=True)

        if archive.name.endswith(".tar.gz"):
            with tarfile.open(archive, "r:gz") as tf:
                names = sorted(tf.getnames())
            (out_dir / "FILES.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
            top = names[0].split("/")[0] if names else ""
            selected = [
                f"{top}/setup.py",
                f"{top}/build.py",
                f"{top}/pyproject.toml",
                f"{top}/PKG-INFO",
            ]
            excerpts: dict[str, str] = {}
            setup_member_texts: list[str] = []
            with tarfile.open(archive, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.name == f"{top}/setup.py" and member.isfile():
                        file_obj = tf.extractfile(member)
                        if file_obj is not None:
                            setup_member_texts.append(file_obj.read().decode("utf-8", errors="replace"))
                for name in selected:
                    try:
                        member = tf.extractfile(name)
                    except KeyError:
                        continue
                    if member is None:
                        continue
                    data = member.read()
                    (out_dir / Path(name).name).write_bytes(data)
                    excerpts[name] = data.decode("utf-8", errors="replace")[:4000]
            findings[key] = {
                "type": "sdist",
                "sha256": sha256(archive),
                "files": names,
                "has_build_py": any(name.endswith("/build.py") for name in names),
                "has_generated_setup_py": f"{top}/setup.py" in names,
                "setup_py_member_count": names.count(f"{top}/setup.py"),
                "setup_py_has_existing_marker": any(
                    "existing_setup_py_enter" in text for text in setup_member_texts
                ),
                "has_c_source": any(name.endswith(".c") for name in names),
                "setup_imports_build": "from build import *" in excerpts.get(f"{top}/setup.py", ""),
            }
        elif archive.suffix == ".whl":
            with zipfile.ZipFile(archive) as zf:
                names = sorted(zf.namelist())
                excerpts = {}
                for name in names:
                    if name.endswith(".dist-info/WHEEL") or name.endswith(".pth"):
                        data = zf.read(name).decode("utf-8", errors="replace")
                        safe = name.replace("/", "__")
                        (out_dir / safe).write_text(data, encoding="utf-8")
                        excerpts[name] = data
            (out_dir / "FILES.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
            wheel_text = next((value for name, value in excerpts.items() if name.endswith("WHEEL")), "")
            pth_name = next((name for name in excerpts if name.endswith(".pth")), None)
            findings[key] = {
                "type": "wheel",
                "sha256": sha256(archive),
                "files": names,
                "has_native_so": any(name.endswith(".so") or ".so." in name for name in names),
                "has_pth": pth_name is not None,
                "pth_content": excerpts.get(pth_name, "").strip() if pth_name else None,
                "root_is_purelib_false": "Root-Is-Purelib: false" in wheel_text,
                "wheel": wheel_text.strip(),
            }
    write_json(EVIDENCE / "archive-findings.json", findings)
    return findings


def run_python_probe(
    name: str, command_code: str, cwd: Path, pythonpath: list[Path], runtime_log: Path
) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in pythonpath)
    env["APPROVAL_RUNTIME_LOG"] = str(runtime_log)
    completed = subprocess.run(
        [sys.executable, "-c", command_code],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    log_stem = name
    (EVIDENCE / "logs" / f"{log_stem}.stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (EVIDENCE / "logs" / f"{log_stem}.stderr.txt").write_text(completed.stderr, encoding="utf-8")
    result = None
    for line in completed.stdout.splitlines():
        if line.startswith("APPROVAL_RUNTIME_RESULT="):
            result = json.loads(line.split("=", 1)[1])
    return {
        "name": name,
        "returncode": completed.returncode,
        "result": result,
        "runtime_event_count": len(read_events(runtime_log)),
        "stdout_log": f"evidence/logs/{log_stem}.stdout.txt",
        "stderr_log": f"evidence/logs/{log_stem}.stderr.txt",
    }


def verify_runtime(case: dict[str, str], archive_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    probes = []
    import_name = case["import_name"]
    for record in archive_records:
        if record["kind"] not in {"wheel", "editable"} or not record["evidence_path"]:
            continue
        wheel = LAB / record["evidence_path"]
        context = record["context"]
        mode = record["kind"]
        target = RUN_ROOT / "runtime" / case["id"] / context / mode
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        with zipfile.ZipFile(wheel) as zf:
            zf.extractall(target)

        runtime_log = RUN_ROOT / "events" / f"{case['id']}__{context}__{mode}_import.runtime.jsonl"
        code = f"""
import json
import site
import sys
from pathlib import Path
mode = {mode!r}
target = Path({str(target)!r})
if mode == 'editable':
    site.addsitedir(str(target))
else:
    sys.path.insert(0, str(target))
import {import_name}
out = {{'module_file': {import_name}.__file__, 'value': getattr({import_name}, 'VALUE', None)}}
try:
    from {import_name} import _native
    out['native_file'] = _native.__file__
    out['answer'] = _native.answer()
except Exception as exc:
    out['native_error'] = type(exc).__name__ + ': ' + str(exc)
print('APPROVAL_RUNTIME_RESULT=' + json.dumps(out, sort_keys=True))
"""
        probe = run_python_probe(
            f"runtime-{case['id']}-{context}-{mode}",
            code,
            LAB,
            [PYLIBS],
            runtime_log,
        )
        probe.update({"case": case["id"], "context": context, "mode": mode})
        probes.append(probe)
    return probes


def main() -> int:
    if RUN_ROOT.exists():
        shutil.rmtree(RUN_ROOT)
    RUN_ROOT.mkdir(parents=True)
    if EVIDENCE.exists():
        shutil.rmtree(EVIDENCE)
    (EVIDENCE / "logs").mkdir(parents=True)
    (EVIDENCE / "events").mkdir(parents=True)

    identities = []
    calls: list[dict[str, Any]] = []
    archives: list[dict[str, Any]] = []
    runtime_probes: list[dict[str, Any]] = []

    for case in CASES:
        source = prepare_case_source(case)
        for rel in ("pyproject.toml", "build.py", "setup.py", "hookpkg/native.c"):
            path = source / rel
            if path.exists():
                identities.append(
                    {
                        "case": case["id"],
                        "file": rel,
                        "sha256": sha256(path),
                    }
                )

        direct = build_context(calls, case, "direct-source", source)
        sdist_evidence = copy_artifact(direct["sdist_path"], case["id"], "direct-source", "sdist")
        archives.append(
            {"case": case["id"], "context": "direct-source", "kind": "sdist", "evidence_path": sdist_evidence}
        )
        wheel_evidence = copy_artifact(direct["wheel_path"], case["id"], "direct-source", "wheel")
        archives.append(
            {"case": case["id"], "context": "direct-source", "kind": "wheel", "evidence_path": wheel_evidence}
        )
        editable_evidence = copy_artifact(direct["editable_path"], case["id"], "direct-source", "editable")
        archives.append(
            {"case": case["id"], "context": "direct-source", "kind": "editable", "evidence_path": editable_evidence}
        )

        if direct["sdist_path"] is not None:
            rebuilt_source = extract_sdist(Path(direct["sdist_path"]), case["id"])
            rebuilt = build_context(calls, case, "sdist-rebuild", rebuilt_source)
            wheel_evidence = copy_artifact(rebuilt["wheel_path"], case["id"], "sdist-rebuild", "wheel")
            archives.append(
                {"case": case["id"], "context": "sdist-rebuild", "kind": "wheel", "evidence_path": wheel_evidence}
            )
            editable_evidence = copy_artifact(rebuilt["editable_path"], case["id"], "sdist-rebuild", "editable")
            archives.append(
                {"case": case["id"], "context": "sdist-rebuild", "kind": "editable", "evidence_path": editable_evidence}
            )

    findings = inspect_archives()

    for case in CASES:
        case_archives = [item for item in archives if item["case"] == case["id"]]
        runtime_probes.extend(verify_runtime(case, case_archives))

    for event_path in sorted((RUN_ROOT / "events").glob("*.jsonl")):
        shutil.copy2(event_path, EVIDENCE / "events" / event_path.name)

    metadata_evidence = EVIDENCE / "prepared-metadata"
    if (RUN_ROOT / "metadata").exists():
        shutil.copytree(RUN_ROOT / "metadata", metadata_evidence)

    write_json(EVIDENCE / "identities.json", identities)
    write_json(EVIDENCE / "calls.json", calls)
    write_json(EVIDENCE / "archives.json", archives)
    write_json(EVIDENCE / "runtime.json", runtime_probes)
    write_json(
        EVIDENCE / "summary.json",
        {
            "poetry_core_src": str(POETRY_SRC),
            "run_root": str(RUN_ROOT),
            "call_count": len(calls),
            "failed_calls": [call for call in calls if call["returncode"] != 0],
            "failed_runtime": [probe for probe in runtime_probes if probe["returncode"] != 0],
        },
    )

    print(json.dumps({
        "run_root": str(RUN_ROOT),
        "evidence": str(EVIDENCE),
        "calls": len(calls),
        "failed_calls": len([call for call in calls if call["returncode"] != 0]),
        "failed_runtime": len([probe for probe in runtime_probes if probe["returncode"] != 0]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
