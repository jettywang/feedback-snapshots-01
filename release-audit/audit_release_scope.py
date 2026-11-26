"""Offline release-scope audit built on poetry-core's own selection logic.

Source-stage only:
  * Factory().create_poetry() parses pyproject.toml exactly like the builders.
  * SdistBuilder/WheelBuilder.find_files_to_add() / find_excluded_files()
    return the membership the library itself would use, without ever running
    a build script or writing an archive (Builder.build() is never called).
  * VCS introspection is read-only ("git ls-files/check-ignore"), the same
    call the builders make; no project code is executed.

Outputs, per distribution format (sdist, wheel):
  selected   -> members the library picks, with the deciding rule and the
                predicted in-archive path (relocation visible for wheels),
  excluded   -> files rejected, with the rule that fired,
  generated  -> metadata the backend synthesizes at build time,
  undeterminable -> build-time products the source stage cannot predict.
"""
from __future__ import annotations

import argparse
import json
import sys

from pathlib import Path

from poetry.core.factory import Factory
from poetry.core.masonry.builders.sdist import SdistBuilder
from poetry.core.masonry.builders.wheel import WheelBuilder
from poetry.core.masonry.utils.include import Include
from poetry.core.masonry.utils.package_include import PackageInclude
from poetry.core.vcs import get_vcs

FORMATS = ("sdist", "wheel")
SDIST_EXTRA_REASON = (
    "sdist mandatory member (pyproject.toml/readme/license/script): "
    "SdistBuilder.find_files_to_add()"
)


def _expand(include: Include, project_root: Path) -> set[Path]:
    files: set[Path] = set()
    for element in include.elements:
        if element.is_dir():
            files.update(f for f in element.glob("**/*") if f.is_file())
        else:
            files.add(element)
    return {f.resolve() for f in files}


def _include_reason(include: Include) -> str:
    if isinstance(include, PackageInclude):
        bits = [f"packages entry include={include._include!r}"]
        if include.source is not None:
            bits.append(f"from={include.source!r}")
        if include.target is not None:
            bits.append(f"to={include.target!r} (wheel-only relocation)")
        bits.append(f"formats={include.formats}")
        return ", ".join(bits)
    return (
        f"explicit include path={include._include!r}, formats={include.formats}"
        " (bare string defaults to sdist-only)"
    )


def audit(project: Path) -> dict:
    poetry = Factory().create_poetry(project)
    package = poetry.package
    project_root = poetry.pyproject_path.parent.resolve()

    vcs = get_vcs(project_root)
    vcs_ignored = set(vcs.get_ignored_files()) if vcs else set()

    explicitly_excluded: set[str] = set()
    for pattern in package.exclude:
        for match in project_root.glob(str(pattern)):
            if match.is_file():
                explicitly_excluded.add(match.relative_to(project_root).as_posix())
            else:
                explicitly_excluded.update(
                    f.relative_to(project_root).as_posix()
                    for f in match.glob("**/*")
                    if f.is_file()
                )

    report: dict = {
        "project": str(project_root),
        "package": package.name,
        "version": str(package.version),
        "vcs_detected": vcs is not None,
        "vcs_ignored_files": sorted(vcs_ignored),
        "declared_policy": {
            "packages": poetry.local_config.get("packages", "<auto-discovery>"),
            "include": poetry.local_config.get("include", []),
            "exclude": list(package.exclude),
            "build": poetry.local_config.get("build"),
        },
        "formats": {},
    }

    builder_classes = {"sdist": SdistBuilder, "wheel": WheelBuilder}
    all_disk_files = {
        f.resolve()
        for f in project_root.glob("**/*")
        if f.is_file() and ".git" not in f.relative_to(project_root).parts
    }

    for fmt in FORMATS:
        entry: dict = {
            "selected": [],
            "excluded": [],
            "not_included_by_any_rule": [],
            "generated_metadata": [],
            "undeterminable": [],
        }

        try:
            builder = builder_classes[fmt](poetry)
            chosen = builder.find_files_to_add()
        except (ValueError, RuntimeError) as exc:
            entry["undeterminable"].append(
                {
                    "reason": (
                        "source-stage selection fails: the declared package does "
                        "not exist yet and is expected to be created by the build "
                        "script; its members cannot be enumerated without running it"
                    ),
                    "error": str(exc),
                    "build_script": package.build_script,
                }
            )
            chosen = set()
            builder = None

        if builder is not None:
            origin: dict[Path, str] = {}
            for include in builder._module.includes:
                if include.formats and fmt not in include.formats:
                    continue
                reason = _include_reason(include)
                for file_path in _expand(include, project_root):
                    origin[file_path] = reason

            for include_file in sorted(chosen, key=lambda f: f.path):
                source = include_file.relative_to_project_root().as_posix()
                archive = (
                    include_file.relative_to_target_root().as_posix()
                    if fmt == "wheel"
                    else include_file.relative_to_source_root().as_posix()
                )
                reasons = [
                    origin.get(include_file.path.resolve(), SDIST_EXTRA_REASON)
                ]
                if source in vcs_ignored:
                    reasons.append(
                        "explicit include overrides VCS ignore "
                        "(Builder.find_excluded_files subtracts explicit includes)"
                    )
                entry["selected"].append(
                    {"source": source, "in_archive": archive, "reasons": reasons}
                )

            library_excluded = builder.find_excluded_files(fmt=fmt)
            selected_paths = {item["source"] for item in entry["selected"]}
            for rel in sorted(library_excluded):
                why = []
                if rel in vcs_ignored:
                    why.append(
                        "VCS ignore (.gitignore via git ls-files --others -i)"
                    )
                if rel in explicitly_excluded:
                    why.append("tool.poetry.exclude glob")
                parts = Path(rel).parts
                if "__pycache__" in parts or Path(rel).suffix == ".pyc":
                    why.append("hard-coded rule: __pycache__/*.pyc always excluded")
                entry["excluded"].append(
                    {"path": rel, "reasons": why or ["VCS/exclude"]}
                )

            accounted = selected_paths | set(library_excluded)
            for disk in sorted(all_disk_files):
                rel = disk.relative_to(project_root).as_posix()
                if rel not in accounted:
                    entry["not_included_by_any_rule"].append(rel)
        else:
            entry["not_included_by_any_rule"] = sorted(
                f.relative_to(project_root).as_posix() for f in all_disk_files
            )

        if fmt == "sdist":
            entry["generated_metadata"] = [
                "PKG-INFO (always synthesized from package metadata)",
            ]
            if package.build_should_generate_setup():
                entry["generated_metadata"].append(
                    "setup.py (generated because build.generate-setup-file=true)"
                )
        else:
            dist_info = (
                builder.dist_info
                if builder is not None
                else f"{package.name.replace('-', '_')}-{package.version}.dist-info"
            )
            entry["generated_metadata"] = [
                f"{dist_info}/METADATA",
                f"{dist_info}/WHEEL",
                f"{dist_info}/RECORD",
                f"{dist_info}/entry_points.txt (only if scripts declared)",
                f"{dist_info}/licenses/* (declared license files)",
            ]
            if package.build_script:
                entry["undeterminable"].append(
                    {
                        "reason": (
                            "WheelBuilder._build() executes the project build "
                            "script and copies build/lib{,.platlib} outputs; "
                            "these files do not exist at source stage"
                        ),
                        "build_script": package.build_script,
                        "examples": [
                            "compiled extension modules (*.so/*.pyd)",
                            "packages copied/generated by the script",
                            "platform-specific wheel tag replaces py3-none-any",
                        ],
                    }
                )
            elif builder is not None:
                entry["undeterminable"].append(
                    {
                        "reason": (
                            "no build script: wheel tag is fixed (py3-none-any); "
                            "only dist-info metadata above is generated"
                        )
                    }
                )

        report["formats"][fmt] = entry

    return report


def render(report: dict) -> str:
    lines = [
        f"# Release-scope audit: {report['package']} {report['version']}",
        f"project: {report['project']}",
        f"vcs detected: {report['vcs_detected']}",
        f"vcs ignored: {', '.join(report['vcs_ignored_files']) or '(none)'}",
        f"declared policy: {json.dumps(report['declared_policy'], ensure_ascii=False)}",
    ]
    for fmt in FORMATS:
        entry = report["formats"][fmt]
        lines.append(f"\n== {fmt} ==")
        lines.append(f"-- selected ({len(entry['selected'])}) --")
        for item in entry["selected"]:
            arrow = (
                f" -> {item['in_archive']}"
                if item["in_archive"] != item["source"]
                else ""
            )
            lines.append(f"  + {item['source']}{arrow}")
            for reason in item["reasons"]:
                lines.append(f"      why: {reason}")
        lines.append(f"-- excluded ({len(entry['excluded'])}) --")
        for item in entry["excluded"]:
            lines.append(f"  - {item['path']}  [{'; '.join(item['reasons'])}]")
        lines.append(
            f"-- unreferenced by any rule "
            f"({len(entry['not_included_by_any_rule'])}) --"
        )
        for rel in entry["not_included_by_any_rule"]:
            lines.append(f"  ~ {rel}")
        lines.append("-- generated at build time (not source files) --")
        for rel in entry["generated_metadata"]:
            lines.append(f"  # {rel}")
        lines.append("-- source-stage UNDETERMINABLE --")
        for item in entry["undeterminable"]:
            lines.append(f"  ? {item['reason']}")
            for key, value in item.items():
                if key == "reason":
                    continue
                lines.append(f"      {key}: {value}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("--json", type=Path, dest="json_path")
    args = parser.parse_args()

    report = audit(args.project.resolve())
    print(render(report))
    if args.json_path:
        args.json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
