"""Offline generative regression for membership of generated projects.

Each parameter is a seed.  A plain-named project is written into ``tmp_path``
with one or two source roots, a package of the same name in every root, and a
manifest that combines package-level ``from``/``to`` relocation with explicit
``include`` entries, parent-directory ``exclude`` rules and per-format
``format`` filters.

``ExpectedMembership`` below is a hand written model of the membership rules.
It never asks a builder what it would do.  It only knows the generated files
and the manifest, and it explains which differences between the source archive
and the wheel are permitted by a format filter and which ones would move a
file out of the published range.

For every seed the test builds both archives in-process, then extracts the
source archive, invokes the PEP 517 wheel hook in a subprocess whose only
backend is this checkout on ``PYTHONPATH``, and checks the rebuilt wheel as
well.  A test double that drops the ``to`` relocation proves that a path-only
regression cannot slip through; failures render the seed manifest, the file
layout and the competing rules needed to rebuild a minimal project.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import textwrap
import zipfile

from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import Literal

import pytest

from poetry.core.factory import Factory
from poetry.core.masonry.builders.sdist import SdistBuilder
from poetry.core.masonry.builders.wheel import WheelBuilder


if TYPE_CHECKING:
    from collections.abc import Iterable
    from collections.abc import Mapping

    from pytest_mock import MockerFixture


Format = Literal["sdist", "wheel"]
Formats = tuple[Format, ...]
Profile = Literal["unrelocated", "relocated", "dual", "parent", "formats", "combined"]

DEFAULT_FORMATS: Formats = ("sdist", "wheel")


@cache
def skip_dependency_check_flag() -> tuple[str, ...]:
    """Use the flag only when the installed ``build`` advertises it."""
    result = subprocess.run(
        [sys.executable, "-m", "build", "--help"],
        text=True,
        capture_output=True,
        check=False,
    )
    if "--skip-dependency-check" in result.stdout:
        return ("--skip-dependency-check",)
    return ()


# --------------------------------------------------------------------------- #
# Seed model and generator
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PackageSpec:
    """One ``[[tool.poetry.packages]]`` entry."""

    include: str
    source: str | None = None
    target: str | None = None
    formats: Formats = DEFAULT_FORMATS
    label: str = "packages[0]"

    def manifest_entry(self) -> str:
        fields = [f"include = {_toml(self.include)}"]
        if self.source is not None:
            fields.append(f"from = {_toml(self.source)}")
        if self.target is not None:
            fields.append(f"to = {_toml(self.target)}")
        fields.append(f"format = {_toml(list(self.formats))}")
        return "{ " + ", ".join(fields) + " }"

    def describes(self) -> str:
        where = self.source or "."
        relocation = f" to={self.target}" if self.target else ""
        return f"{self.label}: include={self.include} from={where}{relocation}"


@dataclass(frozen=True)
class IncludeSpec:
    """One ``[[tool.poetry.include]]`` entry."""

    path: str
    formats: Formats = ("sdist",)
    label: str = "include[0]"

    def manifest_entry(self) -> str:
        fields = [f"path = {_toml(self.path)}"]
        if self.formats != ("sdist",):
            fields.append(f"format = {_toml(list(self.formats))}")
        return "{ " + ", ".join(fields) + " }"

    def describes(self) -> str:
        return f"{self.label}: path={self.path} format={'+'.join(self.formats)}"


@dataclass(frozen=True)
class ProjectSpec:
    seed: str
    profile: Profile
    name: str
    version: str
    module: str
    source_left: str
    source_right: str | None
    target_left: str | None
    target_right: str | None
    packages: tuple[PackageSpec, ...]
    exclude: tuple[str, ...]
    include: tuple[IncludeSpec, ...]

    @property
    def source_roots(self) -> tuple[str, ...]:
        if self.source_right is None:
            return (self.source_left,)
        return (self.source_left, self.source_right)

    def rules(self) -> tuple[str, ...]:
        rules = [package.describes() for package in self.packages]
        rules.extend(f"exclude: {pattern}" for pattern in self.exclude)
        rules.extend(item.describes() for item in self.include)
        return tuple(rules)

    def seed_json(self) -> str:
        data: dict[str, Any] = {
            "seed": self.seed,
            "profile": self.profile,
            "name": self.name,
            "version": self.version,
            "packages": [
                {
                    "include": package.include,
                    "from": package.source,
                    "to": package.target,
                    "format": list(package.formats),
                }
                for package in self.packages
            ],
            "exclude": list(self.exclude),
            "include": [
                {"path": item.path, "format": list(item.formats)}
                for item in self.include
            ],
        }
        return json.dumps(data, indent=2, sort_keys=True)


@dataclass(frozen=True)
class GeneratedProject:
    spec: ProjectSpec
    root: Path
    files: Mapping[str, str]

    def manifest(self) -> str:
        lines = [
            "[project]",
            f"name = {_toml(self.spec.name)}",
            f"version = {_toml(self.spec.version)}",
            'description = "Generated membership regression"',
            'requires-python = ">=3.11"',
            'authors = [{ name = "Regression Bot", email = "bot@example.com" }]',
            "",
            "[tool.poetry]",
            "packages = [",
        ]
        lines.extend(
            f"    {package.manifest_entry()}," for package in self.spec.packages
        )
        lines.append("]")
        if self.spec.exclude:
            lines.append(f"exclude = {_toml(list(self.spec.exclude))}")
        if self.spec.include:
            lines.append("include = [")
            lines.extend(
                f"    {include.manifest_entry()}," for include in self.spec.include
            )
            lines.append("]")
        lines.extend(
            [
                "",
                "[tool.poetry.dependencies]",
                'python = "^3.11"',
                "",
                "[build-system]",
                'requires = ["poetry-core>=1.0.0"]',
                'build-backend = "poetry.core.masonry.api"',
                "",
            ]
        )
        return "\n".join(lines)

    def layout(self) -> str:
        lines = []
        for relative, content in sorted(self.files.items()):
            lines.append(f"  {relative}:")
            lines.extend(f"    {line}" for line in content.splitlines())
        return "\n".join(lines)

    def render(self) -> None:
        self.root.mkdir(parents=True)
        for relative, content in self.files.items():
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        (self.root / "pyproject.toml").write_text(self.manifest(), encoding="utf-8")


def _toml(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML leaf: {value!r}")


def _pick(seed: str, key: str, options: tuple[str, ...]) -> str:
    digest = hashlib.sha256(f"{seed}:{key}".encode()).digest()
    return options[int.from_bytes(digest[:4], "big") % len(options)]


def _features(
    *,
    dual: bool = True,
    relocate: bool = True,
    parent: bool = False,
    formats: bool = False,
    explicit_dir: bool = True,
) -> Mapping[str, bool]:
    return {
        "dual": dual,
        "relocate": relocate,
        "parent": parent,
        "formats": formats,
        "explicit_dir": explicit_dir,
    }


FEATURES: Mapping[Profile, Mapping[str, bool]] = {
    "unrelocated": _features(dual=False, relocate=False, parent=False, formats=False),
    "relocated": _features(dual=False, relocate=True, parent=False, formats=False),
    "dual": _features(dual=True, relocate=True, parent=False, formats=False),
    "parent": _features(dual=True, relocate=True, parent=True, formats=False),
    "formats": _features(dual=True, relocate=True, parent=False, formats=True),
    "combined": _features(dual=True, relocate=True, parent=True, formats=True),
}


def generate_project(seed: str, profile: Profile, tmp_path: Path) -> GeneratedProject:
    """Turn a seed into one legal project without touching shared state."""
    features = FEATURES[profile]
    dual = features["dual"]
    relocate = features["relocate"]
    parent = features["parent"]
    formats = features["formats"]
    explicit_dir = features["explicit_dir"]

    name = _pick(
        seed,
        "name",
        ("sample-project", "generated-demo", "membership-regression"),
    )
    module = "shared_pkg"
    source_left = "lib_left"
    source_right = "lib_right" if dual else None
    target_left = (
        _pick(seed, "target-left", ("landing_left", "alpha_landing"))
        if relocate
        else None
    )
    target_right = (
        _pick(seed, "target-right", ("landing_right", "beta_landing"))
        if relocate and dual
        else None
    )

    packages: list[PackageSpec] = [
        PackageSpec(
            include=module,
            source=source_left,
            target=target_left,
            formats=DEFAULT_FORMATS,
            label="packages[0]",
        )
    ]
    if source_right is not None:
        packages.append(
            PackageSpec(
                include=module,
                source=source_right,
                target=target_right,
                formats=DEFAULT_FORMATS,
                label="packages[1]",
            )
        )
    if formats:
        packages.append(
            PackageSpec(
                include="sdist_side_pkg",
                source=source_left,
                formats=("sdist",),
                label="packages[2]",
            )
        )

    exclude: list[str] = ["extras"]
    include: list[IncludeSpec] = [
        IncludeSpec(
            path="extras/notice.txt",
            formats=DEFAULT_FORMATS,
            label="include[0]",
        )
    ]
    if explicit_dir:
        include.append(
            IncludeSpec(
                path="support",
                formats=DEFAULT_FORMATS,
                label="include[1]",
            )
        )
    if parent:
        exclude.extend([f"{source_left}/{module}/data", "docs"])
        include.extend(
            [
                IncludeSpec(
                    path=f"{source_left}/{module}/data/keep.txt",
                    formats=DEFAULT_FORMATS,
                    label="include[2]",
                ),
                IncludeSpec(
                    path="docs/manual.txt",
                    formats=DEFAULT_FORMATS,
                    label="include[3]",
                ),
            ]
        )
    if formats:
        include.extend(
            [
                IncludeSpec(
                    path="extras/wheel_note.txt",
                    formats=("wheel",),
                    label="include[4]",
                ),
                IncludeSpec(
                    path="extras/sdist_note.txt",
                    formats=("sdist",),
                    label="include[5]",
                ),
                IncludeSpec(
                    path="extras/default_note.txt",
                    formats=DEFAULT_FORMATS,
                    label="include[6]",
                ),
            ]
        )

    spec = ProjectSpec(
        seed=seed,
        profile=profile,
        name=name,
        version="1.2.3",
        module=module,
        source_left=source_left,
        source_right=source_right,
        target_left=target_left,
        target_right=target_right,
        packages=tuple(packages),
        exclude=tuple(exclude),
        include=tuple(include),
    )

    files: dict[str, str] = {
        "extras/notice.txt": f"seed={seed}\nexplicit=notice\n",
        # Excluded by the parent rule and never re-included, so it proves the
        # exclusion override only applies to paths an explicit include names.
        "extras/private.txt": f"seed={seed}\npruned=extras/private.txt\n",
    }
    if explicit_dir:
        files["support/notice.txt"] = f"seed={seed}\nexplicit=support/notice.txt\n"
        files["support/notes.txt"] = f"seed={seed}\nexplicit=support/notes.txt\n"
    if parent:
        files["docs/manual.txt"] = f"seed={seed}\nexplicit=docs/manual.txt\n"
        files["docs/dropped.txt"] = f"seed={seed}\nexcluded=docs/dropped.txt\n"
    for root in spec.source_roots:
        prefix = f"{root}/{module}"
        files[f"{prefix}/__init__.py"] = f'VALUE = "{root}"\n'
        files[f"{prefix}/marker.txt"] = f"origin={root}\nseed={seed}\n"
        files[f"{prefix}/data/keep.txt"] = f"keep={root}\n"
        files[f"{prefix}/data/drop.txt"] = f"drop={root}\n"
    if formats:
        prefix = f"{source_left}/sdist_side_pkg"
        files[f"{prefix}/__init__.py"] = 'VALUE = "sdist-only"\n'
        files[f"{prefix}/side.txt"] = f"seed={seed}\nsdist=only\n"
        files["extras/wheel_note.txt"] = f"seed={seed}\nwheel=only\n"
        files["extras/sdist_note.txt"] = f"seed={seed}\nsdist=only\n"
        files["extras/default_note.txt"] = f"seed={seed}\ndefault=sdist\n"

    project = GeneratedProject(spec=spec, root=tmp_path / "project", files=files)
    project.render()
    # Fail at generation time when two rules claim one destination.
    for fmt in ("sdist", "wheel"):
        try:
            analyse(spec, project, fmt)
        except MembershipConflictError as error:
            raise MembershipRegressionError(
                report(project, fmt, (), (), note=f"ambiguous seed: {error}")
            ) from error
    return project


# --------------------------------------------------------------------------- #
# Hand written expectation model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Member:
    source: str
    destination: str
    supplied_by: str
    formats: Formats
    generated: bool = False


@dataclass(frozen=True)
class ExpectedMembership:
    sdist: Mapping[str, Member]
    wheel: Mapping[str, Member]
    only_sdist: frozenset[str]
    only_wheel: frozenset[str]
    pruned: frozenset[str]
    reasons: Mapping[str, str]

    def source_set(self, fmt: Format) -> frozenset[str]:
        members = self.sdist if fmt == "sdist" else self.wheel
        return frozenset(
            member.source for member in members.values() if not member.generated
        )

    def rebuildable_wheel(self) -> Mapping[str, Member]:
        carried = self.source_set("sdist")
        return {
            destination: member
            for destination, member in self.wheel.items()
            if member.source in carried
        }


class MembershipConflictError(ValueError):
    """Two rules want one destination for different source files."""

    def __init__(self, destination: str, previous: Member, current: Member) -> None:
        super().__init__(
            f"{destination} is claimed by {previous.supplied_by}"
            f" ({previous.source}) and {current.supplied_by} ({current.source})"
        )
        self.destination = destination
        self.previous = previous
        self.current = current


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _relative(path: str, root: str) -> str:
    return Path(path).relative_to(root).as_posix()


def _active(fmt: str, formats: Iterable[str]) -> bool:
    return fmt in formats


def analyse(
    spec: ProjectSpec, project: GeneratedProject, fmt: Format
) -> dict[str, Member]:
    """Apply the documented rules for one archive, in declaration order."""
    result: dict[str, Member] = {}

    def add(member: Member) -> None:
        previous = result.get(member.destination)
        if previous is not None and previous.source != member.source:
            raise MembershipConflictError(member.destination, previous, member)
        result[member.destination] = member

    explicit: dict[str, IncludeSpec] = {}
    for item in spec.include:
        if not _active(fmt, item.formats):
            continue
        for source in project.files:
            if _under(source, item.path):
                explicit.setdefault(source, item)

    excluded = {
        source
        for source in project.files
        if any(_under(source, pattern) for pattern in spec.exclude)
    }
    excluded.difference_update(explicit)

    supplied: set[str] = set()
    for package in spec.packages:
        if not _active(fmt, package.formats):
            continue
        if not package.include or any(char in package.include for char in "*?["):
            continue
        source_root = package.source or "."
        root = (
            package.include
            if source_root == "."
            else f"{source_root}/{package.include}"
        )
        for source in project.files:
            if not _under(source, root) or source in excluded:
                continue
            if fmt == "sdist":
                destination = source
            else:
                relative = _relative(source, source_root)
                if package.target is None:
                    destination = relative
                else:
                    destination = f"{package.target}/{relative}"
            add(
                Member(
                    source=source,
                    destination=destination,
                    supplied_by=package.label,
                    formats=package.formats,
                )
            )
            supplied.add(source)

    for source, item in explicit.items():
        if source in supplied:
            # A package include was seen first; the build includes a file once
            # and therefore keeps the package's relocation.
            continue
        add(
            Member(
                source=source,
                destination=source,
                supplied_by=item.label,
                formats=item.formats,
            )
        )

    if fmt == "sdist":
        for source in ("pyproject.toml", "PKG-INFO"):
            add(
                Member(
                    source=source,
                    destination=source,
                    supplied_by="always",
                    formats=DEFAULT_FORMATS,
                    generated=True,
                )
            )
    return result


def expected_membership(project: GeneratedProject) -> ExpectedMembership:
    spec = project.spec
    sdist = analyse(spec, project, "sdist")
    wheel = analyse(spec, project, "wheel")
    sdist_sources = {member.source for member in sdist.values() if not member.generated}
    wheel_sources = {member.source for member in wheel.values()}
    only_sdist = sdist_sources - wheel_sources
    only_wheel = wheel_sources - sdist_sources
    reasons: dict[str, str] = {}
    for source in only_sdist:
        member = next(member for member in sdist.values() if member.source == source)
        reasons[source] = f"{member.supplied_by} applies to {'+'.join(member.formats)}"
    for source in only_wheel:
        member = next(member for member in wheel.values() if member.source == source)
        reasons[source] = f"{member.supplied_by} applies to {'+'.join(member.formats)}"
    explicit: set[str] = set()
    for item in spec.include:
        explicit.update(source for source in project.files if _under(source, item.path))
    excluded = {
        source
        for source in project.files
        if any(_under(source, pattern) for pattern in spec.exclude)
    }
    return ExpectedMembership(
        sdist={**sdist},
        wheel={**wheel},
        only_sdist=frozenset(only_sdist),
        only_wheel=frozenset(only_wheel),
        pruned=frozenset(excluded - explicit),
        reasons=reasons,
    )


# --------------------------------------------------------------------------- #
# Reading built archives and diagnosing divergence
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Archive:
    path: Path
    files: Mapping[str, bytes]

    def text(self, name: str) -> str:
        return self.files[name].decode("utf-8")


def read_sdist(path: Path) -> Archive:
    prefix = f"{path.name.removesuffix('.tar.gz')}/"
    files: dict[str, bytes] = {}
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            assert member.name.startswith(prefix), member.name
            payload = tar.extractfile(member)
            assert payload is not None
            files[member.name.removeprefix(prefix)] = payload.read()
    return Archive(path=path, files=files)


def read_wheel(path: Path) -> Archive:
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as wheel:
        for name in wheel.namelist():
            if name.endswith("/"):
                continue
            files[name] = wheel.read(name)
    return Archive(path=path, files=files)


def wheel_payload(archive: Archive) -> dict[str, bytes]:
    return {
        name: payload
        for name, payload in archive.files.items()
        if ".dist-info/" not in name
    }


class MembershipRegressionError(AssertionError):
    """Raised with a report that is sufficient to rebuild a minimal project."""


def report(
    project: GeneratedProject,
    fmt: Format,
    expected: Iterable[str],
    actual: Iterable[str],
    *,
    note: str | None = None,
) -> str:
    expected_set = set(expected)
    actual_set = set(actual)
    missing = sorted(expected_set - actual_set)
    unexpected = sorted(actual_set - expected_set)
    lines = [
        f"membership regression for seed {project.spec.seed!r} ({fmt})",
        f"profile: {project.spec.profile}",
        "",
        "seed:",
        project.spec.seed_json(),
        "",
        "layout:",
        project.layout(),
        "",
        "competing rules:",
        *(f"  - {rule}" for rule in project.spec.rules()),
        "",
        "minimal project:",
        textwrap.indent(project.manifest(), "  "),
        "",
        f"missing from {fmt}: {missing}",
        f"unexpected in {fmt}: {unexpected}",
        "",
        "reproduce:",
        f"  pytest {Path(__file__).name} -k 'generated and {project.spec.seed}'",
        "  # project root:",
        f"  #   {project.root}",
    ]
    if note:
        lines.extend(["", note])
    return "\n".join(lines)


def assert_members(
    project: GeneratedProject,
    fmt: Format,
    expected: Mapping[str, Member],
    actual: Archive,
    *,
    note: str | None = None,
) -> None:
    actual_names = set(wheel_payload(actual)) if fmt == "wheel" else set(actual.files)
    if actual_names != set(expected):
        raise MembershipRegressionError(
            report(project, fmt, expected, actual_names, note=note)
        )

    for destination, member in expected.items():
        if member.generated:
            continue
        payload = (
            wheel_payload(actual).get(destination)
            if fmt == "wheel"
            else actual.files[destination]
        )
        assert payload is not None
        expected_bytes = project.files[member.source].encode("utf-8")
        if payload != expected_bytes:
            raise MembershipRegressionError(
                report(
                    project,
                    fmt,
                    expected,
                    actual_names,
                    note=(
                        f"content mismatch at {destination!r}: expected bytes of"
                        f" {member.source!r} supplied by {member.supplied_by}"
                    ),
                )
            )


def classify_differences(
    expected: ExpectedMembership,
) -> dict[str, list[tuple[str, str, str]]]:
    """Split per-source differences into allowed and range-changing ones."""
    result: dict[str, list[tuple[str, str, str]]] = {
        "relocation": [],
        "format_filter": [],
        "range_change": [],
    }
    sdist_by_source = {
        member.source: member
        for member in expected.sdist.values()
        if not member.generated
    }
    wheel_by_source = {member.source: member for member in expected.wheel.values()}
    for source, sdist_member in sdist_by_source.items():
        wheel_member = wheel_by_source.get(source)
        if wheel_member is None:
            bucket = (
                "format_filter" if source in expected.only_sdist else "range_change"
            )
            result[bucket].append(
                (
                    source,
                    sdist_member.destination,
                    expected.reasons.get(source, "absent from wheel"),
                )
            )
        elif sdist_member.destination != wheel_member.destination:
            result["relocation"].append(
                (source, sdist_member.destination, wheel_member.destination)
            )
    for source, wheel_member in wheel_by_source.items():
        if source in sdist_by_source:
            continue
        bucket = "format_filter" if source in expected.only_wheel else "range_change"
        result[bucket].append(
            (
                source,
                expected.reasons.get(source, "absent from sdist"),
                wheel_member.destination,
            )
        )
    return result


def scope_changes(
    expected: ExpectedMembership,
    observed_sdist: Iterable[str],
    observed_wheel: Iterable[str],
) -> list[str]:
    """Sources whose publication range changed without a format justification."""
    sdist = set(observed_sdist)
    wheel = set(observed_wheel)
    always = expected.source_set("sdist") & expected.source_set("wheel")
    known = expected.source_set("sdist") | expected.source_set("wheel")
    problems = [
        f"{source!r} is expected in both archives but missing from "
        f"{'sdist' if source not in sdist else 'wheel'}"
        for source in sorted(always)
        if source not in sdist or source not in wheel
    ]
    problems.extend(
        f"{source!r} appears in an archive but no rule scopes it"
        for source in sorted((sdist | wheel) - known)
    )
    return problems


def format_allowed(expected: ExpectedMembership) -> dict[str, str]:
    """The only differences that a per-format rule may introduce."""
    return {
        source: expected.reasons[source]
        for source in sorted(expected.only_sdist | expected.only_wheel)
    }


# --------------------------------------------------------------------------- #
# Building the two routes
# --------------------------------------------------------------------------- #


def build_direct(project: GeneratedProject, fmt: Format) -> Path:
    poetry = Factory().create_poetry(project.root)
    out = project.root / f"dist-{fmt}"
    if fmt == "sdist":
        return SdistBuilder(poetry).build(out)
    return WheelBuilder(poetry).build(out)


class RelocationDroppingWheel(WheelBuilder):
    """Test double that publishes package files at their source-root path.

    It models a regression where ``to`` is parsed but never applied.  The
    double is deliberately kept outside the expectation model so a bug in the
    builder cannot silently rewrite what the test considers correct.
    """

    def _copy_module(self, wheel: zipfile.ZipFile) -> None:
        for include_file in sorted(
            self.find_files_to_add(), key=lambda item: item.path
        ):
            # Ignore ``target_dir`` on purpose.
            self._add_file(
                wheel,
                include_file.path,
                include_file.relative_to_project_root(),
            )


def extract_sdist(archive: Archive, destination: Path) -> Path:
    root: Path | None = None
    for name, payload in archive.files.items():
        if name == "pyproject.toml":
            root = destination
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    assert root is not None
    return root


@cache
def verify_backend_is_checkout(checkout: Path, python_path: str) -> str:
    """Refuse to rebuild against a poetry-core installed somewhere else."""
    env = os.environ.copy()
    env["PYTHONPATH"] = python_path
    env["PYTHONNOUSERSITE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", "import poetry.core; print(poetry.core.__file__)"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    module = result.stdout.strip()
    if result.returncode != 0 or not Path(module).is_relative_to(checkout):
        raise AssertionError(
            "the rebuild subprocess would use a different poetry-core:"
            f" {module or result.stderr.strip()}"
        )
    return module


def build_from_sdist(project: GeneratedProject, sdist: Archive, tmp_path: Path) -> Path:
    """Rebuild with the PEP 517 wheel hook against this checkout only."""
    source_root = extract_sdist(sdist, tmp_path / "extracted")
    out = tmp_path / "rebuilt"
    out.mkdir()

    checkout = Path(__file__).parents[3] / "src"
    env = os.environ.copy()
    python_path = os.pathsep.join([str(checkout), env.get("PYTHONPATH", "")]).rstrip(
        os.pathsep
    )
    verify_backend_is_checkout(checkout, python_path)
    env["PYTHONPATH"] = python_path
    env["PYTHONNOUSERSITE"] = "1"
    env["SOURCE_DATE_EPOCH"] = "0"
    command = [
        sys.executable,
        "-m",
        "build",
        "--wheel",
        "--no-isolation",
        *skip_dependency_check_flag(),
        "--outdir",
        str(out),
        str(source_root),
    ]
    result = subprocess.run(
        command,
        cwd=source_root,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise MembershipRegressionError(
            report(
                project,
                "wheel",
                (),
                (),
                note=(
                    "PEP 517 wheel rebuild failed\n"
                    f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
                ),
            )
        )
    wheels = sorted(out.glob("*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


SEEDS: tuple[tuple[str, Profile], ...] = (
    ("seed-unrelocated-a", "unrelocated"),
    ("seed-relocated-b", "relocated"),
    ("seed-dual-c", "dual"),
    ("seed-dual-d", "dual"),
    ("seed-parent-e", "parent"),
    ("seed-formats-f", "formats"),
    ("seed-formats-g", "formats"),
    ("seed-combined-h", "combined"),
    ("seed-combined-i", "combined"),
)


@pytest.mark.parametrize(("seed", "profile"), SEEDS, ids=[s for s, _ in SEEDS])
def test_generated_seed_is_well_formed(
    seed: str, profile: Profile, tmp_path: Path
) -> None:
    project = generate_project(seed, profile, tmp_path)
    expected = expected_membership(project)

    # Every generated file must be reachable by at least one rule in both
    # archives, or explicitly outside both.  Nothing may be silently dropped.
    known = expected.source_set("sdist") | expected.source_set("wheel")
    unreachable = set(project.files) - known - set(expected.pruned)
    if unreachable:
        raise MembershipRegressionError(
            report(
                project,
                "wheel",
                known | set(expected.pruned),
                known,
                note=f"files covered by no rule: {sorted(unreachable)}",
            )
        )

    # The parent ignore always prunes its unnamed member, and the explicit
    # include for extras/notice.txt must rescue just that file.
    assert "extras/private.txt" in expected.pruned
    assert "extras/notice.txt" in known
    if project.spec.source_left:
        data_root = f"{project.spec.source_left}/{project.spec.module}/data"
        if data_root in project.spec.exclude:
            assert f"{data_root}/drop.txt" in expected.pruned
            assert f"{data_root}/keep.txt" in known

    # Overlapping source roots only make sense when the relocation story is
    # explicit: both packages must use the same include and distinct targets.
    if project.spec.source_right is not None:
        left, right = project.spec.packages[:2]
        assert left.include == right.include
        assert left.source != right.source
        if left.target or right.target:
            assert left.target and right.target
            assert left.target != right.target
        marker = f"{left.include}/marker.txt"
        left_member = next(
            member
            for member in expected.wheel.values()
            if member.source == f"{left.source}/{marker}"
        )
        right_member = next(
            member
            for member in expected.wheel.values()
            if member.source == f"{right.source}/{marker}"
        )
        assert left_member.destination != right_member.destination

    # Format filters must be one-sided and justified.
    for source in expected.only_sdist:
        member = next(item for item in expected.sdist.values() if item.source == source)
        assert "sdist" in member.formats and "wheel" not in member.formats
    for source in expected.only_wheel:
        member = next(item for item in expected.wheel.values() if item.source == source)
        assert "wheel" in member.formats and "sdist" not in member.formats


def test_model_classifies_path_differences(tmp_path: Path) -> None:
    """The model must name why two archives differ, not merely that they do."""
    project = generate_project("seed-combined-h", "combined", tmp_path)
    expected = expected_membership(project)
    differences = classify_differences(expected)

    # Relocation is a path change, never a membership change.
    relocation = set(differences["relocation"])
    assert (
        "lib_left/shared_pkg/marker.txt",
        "lib_left/shared_pkg/marker.txt",
        f"{project.spec.target_left}/shared_pkg/marker.txt",
    ) in relocation
    assert (
        "lib_right/shared_pkg/marker.txt",
        "lib_right/shared_pkg/marker.txt",
        f"{project.spec.target_right}/shared_pkg/marker.txt",
    ) in relocation
    assert all(source in expected.source_set("sdist") for source, _, _ in relocation)
    assert all(source in expected.source_set("wheel") for source, _, _ in relocation)

    # Per-format rules explain every one-sided source.
    allowed = format_allowed(expected)
    assert set(allowed) == set(expected.only_sdist) | set(expected.only_wheel)
    assert "include[4]" in allowed["extras/wheel_note.txt"]
    assert "include[5]" in allowed["extras/sdist_note.txt"]
    assert "packages[2]" in allowed["lib_left/sdist_side_pkg/side.txt"]

    # No format filter may change the publication range of an unscoped file.
    assert differences["range_change"] == []
    assert set(expected.pruned) == {
        "extras/private.txt",
        "docs/dropped.txt",
        "lib_left/shared_pkg/data/drop.txt",
    }
    assert "lib_left/shared_pkg/data/keep.txt" not in expected.pruned
    assert "docs/manual.txt" not in expected.pruned


@pytest.mark.parametrize(
    "profile",
    ["unrelocated", "relocated", "dual", "parent", "formats", "combined"],
)
def test_generated_profiles_cover_the_matrix(profile: Profile, tmp_path: Path) -> None:
    """Guard against the seed matrix silently losing a rule combination."""
    project = generate_project(f"matrix-{profile}", profile, tmp_path)
    packages = project.spec.packages
    includes = project.spec.include

    single_source = profile in {"unrelocated", "relocated"}
    expected_roots = 1 if single_source else 2
    assert len(project.spec.source_roots) == expected_roots
    relocates = any(package.target for package in packages)
    assert relocates == (profile != "unrelocated")
    assert "extras" in project.spec.exclude
    parent_excludes = [
        pattern for pattern in project.spec.exclude if pattern != "extras"
    ]
    assert bool(parent_excludes) == (profile in {"parent", "combined"})
    only_sdist = [item for item in includes if item.formats == ("sdist",)]
    only_wheel = [item for item in includes if item.formats == ("wheel",)]
    assert bool(only_sdist + only_wheel) == (profile in {"formats", "combined"})
    if not single_source:
        # two packages share an include name but live in different roots
        assert packages[0].include == packages[1].include


@pytest.fixture(autouse=True)
def offline_vcs(mocker: MockerFixture) -> None:
    mocker.patch("poetry.core.vcs.git.Git.get_ignored_files", return_value=[])


@pytest.mark.parametrize(("seed", "profile"), SEEDS, ids=[s for s, _ in SEEDS])
def test_generated_membership_both_archives(
    seed: str, profile: Profile, tmp_path: Path
) -> None:
    project = generate_project(seed, profile, tmp_path)
    expected = expected_membership(project)

    sdist = read_sdist(build_direct(project, "sdist"))
    wheel = read_wheel(build_direct(project, "wheel"))

    assert_members(project, "sdist", expected.sdist, sdist)
    assert_members(project, "wheel", expected.wheel, wheel)

    # Format-only sources are the only allowed source-set difference, and
    # each one must be justified by a rule that names the other format.
    sdist_files = set(sdist.files) - {"pyproject.toml", "PKG-INFO"}
    wheel_files = wheel_sources(wheel, expected.wheel)
    sdist_only = sdist_files - wheel_files
    wheel_only = wheel_files - sdist_files
    if sdist_only != set(expected.only_sdist):
        raise MembershipRegressionError(
            report(
                project,
                "sdist",
                expected.only_sdist,
                sdist_only,
                note="unexplained source-only members in the source archive",
            )
        )
    if wheel_only != set(expected.only_wheel):
        raise MembershipRegressionError(
            report(
                project,
                "wheel",
                expected.only_wheel,
                wheel_only,
                note="unexplained source-only members in the wheel",
            )
        )
    for source, reason in format_allowed(expected).items():
        assert reason
        assert source in sdist_files or source in wheel_files

    # Range changes would be visible as a source present in both archive
    # formats with an unexplained destination, or a path that appears only
    # because no rule scoped it to the other format.
    problems = scope_changes(expected, sdist_files, wheel_files)
    problems += [
        f"{source!r}: {old} -> {new}"
        for source, old, new in classify_differences(expected)["range_change"]
    ]
    if problems:
        raise MembershipRegressionError(
            report(
                project,
                "wheel",
                expected.source_set("sdist") & expected.source_set("wheel"),
                wheel_files,
                note="publication range changed:\n" + "\n".join(problems),
            )
        )

    # Same-named files from different source roots must stay distinguishable.
    origins = marker_origins(project, wheel)
    if origins != set(project.spec.source_roots):
        raise MembershipRegressionError(
            report(
                project,
                "wheel",
                project.spec.source_roots,
                origins,
                note="same-named marker files lost their source-root origin",
            )
        )


@pytest.mark.parametrize(("seed", "profile"), SEEDS, ids=[s for s, _ in SEEDS])
def test_generated_membership_rebuilt_from_sdist(
    seed: str, profile: Profile, tmp_path: Path
) -> None:
    project = generate_project(seed, profile, tmp_path)
    expected = expected_membership(project)

    sdist = read_sdist(build_direct(project, "sdist"))
    rebuilt = read_wheel(build_from_sdist(project, sdist, tmp_path))

    assert_members(project, "wheel", expected.rebuildable_wheel(), rebuilt)
    origins = marker_origins(project, rebuilt)
    if origins != set(project.spec.source_roots):
        raise MembershipRegressionError(
            report(
                project,
                "wheel",
                project.spec.source_roots,
                origins,
                note="rebuilt wheel lost the origin of same-named marker files",
            )
        )

    # A wheel-only rule cannot survive a rebuild from an archive that never
    # contained the source; that is a format-scoped loss, not a range change.
    lost = set(expected.wheel) - set(expected.rebuildable_wheel())
    for destination in lost:
        member = expected.wheel[destination]
        assert member.source in expected.only_wheel
        assert "wheel" in member.formats and "sdist" not in member.formats
    assert lost == {
        destination
        for destination, member in expected.wheel.items()
        if member.source in expected.only_wheel
    }


def marker_origins(project: GeneratedProject, wheel: Archive) -> set[str]:
    origins: set[str] = set()
    for destination, member in expected_membership(project).wheel.items():
        if Path(member.source).name != "marker.txt":
            continue
        origins.add(wheel.text(destination).split("origin=", 1)[1].split("\n", 1)[0])
    return origins


def wheel_sources(archive: Archive, expected: Mapping[str, Member]) -> set[str]:
    """Map rebuilt destinations back to the source files the model expects."""
    sources: set[str] = set()
    for destination in wheel_payload(archive):
        member = expected.get(destination)
        if member is None:
            raise AssertionError(f"unmodelled wheel destination: {destination!r}")
        sources.add(member.source)
    return sources


def test_missing_relocation_is_detected(tmp_path: Path) -> None:
    seed: str = "seed-combined-h"
    profile: Profile = "combined"
    project = generate_project(seed, profile, tmp_path)
    expected = expected_membership(project)

    sdist = read_sdist(build_direct(project, "sdist"))
    assert sdist.files  # the source archive is the stable half of the seed

    poetry = Factory().create_poetry(project.root)
    broken = read_wheel(
        RelocationDroppingWheel(poetry).build(project.root / "dist-lossy")
    )

    # The double publishes the package under its source-root path instead of
    # the declared landing zone.
    assert any(name.startswith(f"{project.spec.source_left}/") for name in broken.files)
    assert not any(
        name.startswith(f"{project.spec.target_left}/") for name in broken.files
    )

    with pytest.raises(MembershipRegressionError) as error:
        assert_members(project, "wheel", expected.wheel, broken)
    message = str(error.value)
    # The report alone must be enough to rebuild a minimal legal project.
    assert f"seed {seed!r}" in message
    assert '"seed": "seed-combined-h"' in message
    assert '"profile": "combined"' in message
    assert "missing from wheel" in message
    assert "unexpected in wheel" in message
    assert "layout:" in message
    assert "competing rules:" in message
    assert "minimal project:" in message
    assert project.spec.target_left is not None
    assert project.spec.target_left in message
    assert f"include={project.spec.module}" in message
    assert "exclude: docs" in message
    assert "path=docs/manual.txt" in message
