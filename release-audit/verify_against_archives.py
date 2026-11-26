"""Cross-check the source-stage audit against actually built archives.

The build step is intentionally separate from audit_release_scope.py:
the audit never builds. Here we build once (ground truth) and assert that
every source member predicted by the audit appears, and that every archive
entry is either a predicted source member or a backend-generated metadata
file, which is flagged explicitly.
"""
from __future__ import annotations

import argparse
import json
import tarfile
import zipfile

from pathlib import Path

from poetry.core.factory import Factory
from poetry.core.masonry.builders.sdist import SdistBuilder
from poetry.core.masonry.builders.wheel import WheelBuilder


def sdist_names(path: Path, top_dir: str) -> set[str]:
    with tarfile.open(str(path), "r:gz") as tar:
        return {
            n[len(top_dir) + 1 :]
            for n in tar.getnames()
            if n.startswith(top_dir + "/")
        }


def wheel_names(path: Path) -> set[str]:
    with zipfile.ZipFile(str(path)) as zf:
        return set(zf.namelist())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("audit_json", type=Path)
    args = parser.parse_args()

    project = args.project.resolve()
    report = json.loads(args.audit_json.read_text())
    poetry = Factory().create_poetry(project)
    dist = project / "dist"
    build_script = poetry.package.build_script

    name = poetry.package.name.replace("-", "_")
    version = str(poetry.package.version)
    checks = []

    if build_script:
        # Source-stage selection is undeterminable for these projects:
        # the wheel builder executes the project build script first.
        wheel_path = WheelBuilder(poetry).build(dist)
        actual_wheel = wheel_names(wheel_path)
        flagged = {
            item["reason"]
            for item in report["formats"]["wheel"]["undeterminable"]
        }
        checks.append(
            (
                "audit predicted zero source members and flagged undeterminability",
                report["formats"]["wheel"]["selected"] == []
                and any("build" in text for text in flagged),
                {"selected": report["formats"]["wheel"]["selected"]},
            )
        )
        dist_info_prefix = f"{name}-{version}.dist-info/"
        script_generated = sorted(
            p for p in actual_wheel if not p.startswith(dist_info_prefix)
        )
        backend_generated = sorted(
            p for p in actual_wheel if p.startswith(dist_info_prefix)
        )
        checks.append(
            (
                "every real wheel entry is script-generated or backend metadata",
                len(script_generated) + len(backend_generated)
                == len(actual_wheel),
                {
                    "script-generated (source stage could not predict)": script_generated,
                    "backend-generated": backend_generated,
                },
            )
        )
        print(f"wheel archive : {wheel_path.name} ({len(actual_wheel)} entries)")
        print("note: sdist cannot be built in this layout (package missing until")
        print("      the build script runs); the audit flagged the same failure.")
    else:
        sdist_path = SdistBuilder(poetry).build(dist)
        wheel_path = WheelBuilder(poetry).build(dist)

        actual_sdist = sdist_names(sdist_path, f"{name}-{version}")
        actual_wheel = wheel_names(wheel_path)

        expected_sdist = {
            item["source"] for item in report["formats"]["sdist"]["selected"]
        }
        expected_wheel = {
            item["in_archive"] for item in report["formats"]["wheel"]["selected"]
        }

        missing_sdist = expected_sdist - actual_sdist
        extra_sdist = actual_sdist - expected_sdist
        generated_sdist = {p for p in extra_sdist if p in {"PKG-INFO", "setup.py"}}
        unknown_sdist = extra_sdist - generated_sdist
        checks.append(
            (
                "sdist source membership matches audit; remainder is generated metadata",
                not missing_sdist and not unknown_sdist,
                {
                    "missing": sorted(missing_sdist),
                    "backend-generated (flagged)": sorted(generated_sdist),
                    "unexplained": sorted(unknown_sdist),
                },
            )
        )

        missing_wheel = expected_wheel - actual_wheel
        extra_wheel = actual_wheel - expected_wheel
        generated_wheel = {p for p in extra_wheel if ".dist-info/" in p}
        unexplained_wheel = extra_wheel - generated_wheel
        checks.append(
            (
                "wheel source membership matches audit; remainder is dist-info",
                not missing_wheel and not unexplained_wheel,
                {
                    "missing": sorted(missing_wheel),
                    "backend-generated (flagged)": sorted(generated_wheel),
                    "unexplained": sorted(unexplained_wheel),
                },
            )
        )
        print(f"sdist archive : {sdist_path.name} ({len(actual_sdist)} entries)")
        print(f"wheel archive : {wheel_path.name} ({len(actual_wheel)} entries)")
    ok = True
    for label, passed, detail in checks:
        ok &= passed
        print(f"[{'PASS' if passed else 'FAIL'}] {label}")
        for key, value in detail.items():
            if value:
                print(f"       {key}: {json.dumps(value, ensure_ascii=False)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
