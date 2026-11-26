"""Build the two fixture wheels with the LOCAL poetry-core and create the
digest-mismatch control.

Run from the repository root with the prepared venv:

    .venv/bin/python evidence_lab/build_fixtures.py

No network access is needed: builds use --no-isolation and the editable
poetry-core checkout in this workspace.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ROOT / "evidence_lab" / "projects"
DIST = ROOT / "evidence_lab" / "dist"
CONTROL = DIST / "control"

OLD_MARKER = b"pristine-control-value-0001"
NEW_MARKER = b"tampered-control-value-0001"


def build_wheel(project_dir: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "build",
        "--wheel",
        "--no-isolation",
        "--outdir",
        str(out_dir),
        str(project_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"build failed for {project_dir.name}")
    wheels = sorted(out_dir.glob(f"{project_dir.name.replace('-', '_')}-*.whl"))
    if not wheels:
        raise SystemExit(f"no wheel produced for {project_dir.name}")
    return wheels[-1]


def make_mismatch_control(pristine: Path) -> Path:
    CONTROL.mkdir(parents=True, exist_ok=True)
    target = CONTROL / pristine.name
    changed = False
    with zipfile.ZipFile(pristine) as zin, zipfile.ZipFile(target, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename.endswith("evidence_tampered/__init__.py"):
                assert OLD_MARKER in data, "marker not found in control target"
                assert len(OLD_MARKER) == len(NEW_MARKER)
                data = data.replace(OLD_MARKER, NEW_MARKER)
                changed = True
            zout.writestr(info, data)
    if not changed:
        raise SystemExit("control member was never rewritten")
    return target


def main() -> None:
    import poetry.core

    core_path = Path(poetry.core.__file__).resolve()
    print(f"local poetry-core: {poetry.core.__version__} at {core_path}")
    try:
        core_path.relative_to(ROOT)
        print("builder provenance: poetry-core imported from this workspace")
    except ValueError:
        print("WARNING: poetry-core is not imported from this workspace checkout")

    samename = build_wheel(PROJECTS / "evidence_samename", DIST)
    pristine = build_wheel(PROJECTS / "evidence_tampered", DIST)
    control = make_mismatch_control(pristine)

    print("built artifacts (hand only these wheels to wheel_evidence):")
    for path in (samename, pristine, control):
        print(f"  {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
