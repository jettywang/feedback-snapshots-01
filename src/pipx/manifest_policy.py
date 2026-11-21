from __future__ import annotations

__lazy_modules__ = [
    "collections",
    "packaging.markers",
    "packaging.requirements",
    "packaging.utils",
    "packaging.version",
    "pipx.constants",
    "pipx.result",
    "pipx.util",
    "re",
    "tomllib",
]

import re
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from packaging.markers import Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pipx.constants import EXIT_CODE_OK, ExitCode
from pipx.result import (
    JsonValue,
    OperationData,
    OperationError,
    OperationResult,
    OutputLevel,
    OutputMessage,
    OutputStream,
)
from pipx.util import PipxError

if TYPE_CHECKING:
    from collections.abc import Sequence

_POLICY_VERSION: Final[str] = "1"
_SHA256: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyPackage:
    """One exact package pin that a policy intent approves.

    :ivar name: the normalized package name.
    :ivar version: the exact version the intent approves.
    :ivar sha256: the SHA-256 of an approved artifact, or None when the policy pins only the version.
    """

    name: str
    version: str
    sha256: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyIntent:
    """One local approval: the lock a tool may install and the packages it may contain.

    :ivar id: the identifier reported for the intent.
    :ivar environment: the manifest tool the intent approves.
    :ivar approval: the provenance the lock must declare, such as a review identifier.
    :ivar lock_name: the lock file name the intent is bound to, or None for any lock of the tool.
    :ivar packages: the exact packages the intent approves.
    """

    id: str
    environment: str
    approval: str
    lock_name: str | None
    packages: tuple[PolicyPackage, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Policy:
    """A local approval policy, read from an explicit TOML file.

    :ivar path: the resolved path of the policy file.
    :ivar intents: the approvals the policy grants.
    """

    path: Path
    intents: tuple[PolicyIntent, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class LockTool:
    """A manifest tool whose lock the policy must check.

    :ivar environment: the tool's environment name.
    :ivar package: the tool's package requirement, as the manifest declares it, including extras.
    :ivar package_name: the normalized name of the main package.
    :ivar lock_file: the tool's lock file, or None when the tool declares none.
    """

    environment: str
    package: str
    package_name: str
    lock_file: Path | None


@dataclass(frozen=True, slots=True, kw_only=True)
class VerificationProblem:
    """One reason a lock failed policy verification.

    :ivar code: the code that scripts key on.
    :ivar message: the description of the problem for people.
    """

    code: str
    message: str


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedTool(OperationData):
    """The policy verdict for one manifest tool.

    :ivar environment: the tool's environment name.
    :ivar lock: the lock file that was checked, or None when the tool declares none.
    :ivar intent: the policy intent the lock was matched to, or None.
    :ivar approval: the approval source the lock declares, or None.
    :ivar source: the tool the lock names as its generator, when it names one.
    :ivar packages: the selected packages of the lock, as ``name==version`` strings.
    :ivar pending_review: dependencies present in the lock but absent from the intent.
    :ivar missing: approved packages absent from the lock.
    :ivar status: ``verified``, ``needs_review`` or ``failed``.
    :ivar problems: the reasons the lock failed, empty when it passed.
    """

    environment: str
    lock: str | None
    intent: str | None
    approval: str | None
    source: str | None
    packages: tuple[str, ...]
    pending_review: tuple[str, ...]
    missing: tuple[str, ...]
    status: str
    problems: tuple[VerificationProblem, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the verdict as JSON-ready data, with each problem as a plain object.

        :returns: the fields of the verdict.
        """
        # asdict runs the nested dataclasses through to plain dicts, which the envelope can serialize
        data: Final[dict[str, JsonValue]] = cast("dict[str, JsonValue]", asdict(self))
        data["problems"] = [{"code": problem.code, "message": problem.message} for problem in self.problems]
        return data


@dataclass(frozen=True, slots=True, kw_only=True)
class ManifestVerificationData(OperationData):
    """Result data of the read-only policy stage of ``manifest sync``.

    :ivar tools: the verdict for each manifest tool.
    """

    tools: tuple[VerifiedTool, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class _LockedDependency:
    name: str
    marker: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class _LockPackage:
    name: str
    version: str
    marker: str | None
    hashes: tuple[str, ...]
    dependencies: tuple[_LockedDependency, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class _LockContents:
    lock_version: str
    approval: str | None
    generated_by: str | None
    default_groups: tuple[str, ...]
    packages: tuple[_LockPackage, ...]




class _VerificationError(Exception):
    def __init__(self, problem: VerificationProblem) -> None:
        self.problem: Final[VerificationProblem] = problem
        super().__init__(problem.message)


def load_policy(path: Path) -> Policy:
    """Read and validate a local approval policy.

    :param path: the path given on the command line.
    :returns: the parsed policy.
    :raises PipxError: when the policy is missing, unreadable or does not match the policy schema.
    """
    resolved: Final[Path] = path.expanduser().resolve()
    try:
        with resolved.open("rb") as policy_file:
            data: Final[dict[str, object]] = tomllib.load(policy_file)
    except FileNotFoundError as error:
        msg = f"Policy does not exist: {resolved}"
        raise PipxError(msg) from error
    except (OSError, tomllib.TOMLDecodeError) as error:
        msg = f"Cannot read policy {resolved}: {error}"
        raise PipxError(msg) from error

    if unknown := sorted(set(data) - {"version", "intent"}):
        msg = f"Unknown policy {'key' if len(unknown) == 1 else 'keys'}: {', '.join(unknown)}"
        raise PipxError(msg)
    if data.get("version") != _POLICY_VERSION:
        msg = f'Policy version must be "{_POLICY_VERSION}".'
        raise PipxError(msg)
    raw_intents: Final[object] = data.get("intent")
    if not isinstance(raw_intents, list) or not raw_intents:
        msg = "Policy intent must be a non-empty array of tables."
        raise PipxError(msg)

    intents: Final[tuple[PolicyIntent, ...]] = tuple(_parse_intent(raw_intent) for raw_intent in raw_intents)
    intent_ids: Final[Counter[str]] = Counter(intent.id for intent in intents)
    if duplicates := sorted(intent_id for intent_id, count in intent_ids.items() if count > 1):
        msg = f"Policy intent IDs must be unique: {', '.join(duplicates)}"
        raise PipxError(msg)
    return Policy(path=resolved, intents=intents)


def _parse_intent(raw: object) -> PolicyIntent:
    if not isinstance(raw, dict):
        msg = "Each policy intent must be a table."
        raise PipxError(msg)
    if unknown := sorted(set(raw) - {"id", "environment", "approval", "lock", "packages", "hashes"}):
        msg = f"Unknown policy intent {'key' if len(unknown) == 1 else 'keys'}: {', '.join(unknown)}"
        raise PipxError(msg)
    intent_id: Final[str] = _required_string(raw, "id", "Policy intent")
    environment: Final[str] = _required_string(raw, "environment", f"Policy intent {intent_id}")
    if environment != canonicalize_name(environment):
        msg = f"Policy intent {intent_id} environment must be normalized: {environment}"
        raise PipxError(msg)
    approval: Final[str] = _required_string(raw, "approval", f"Policy intent {intent_id}")
    lock_name: Final[str | None] = _parse_lock_name(raw, intent_id)
    packages: Final[tuple[PolicyPackage, ...]] = _parse_packages(raw, intent_id)
    return PolicyIntent(
        id=intent_id,
        environment=environment,
        approval=approval,
        lock_name=lock_name,
        packages=packages,
    )


def _required_string(raw: dict[str, object], key: str, context: str) -> str:
    value: Final[object] = raw.get(key)
    if not isinstance(value, str) or not value:
        msg = f"{context} {key} must be a non-empty string."
        raise PipxError(msg)
    return value


def _parse_lock_name(raw: dict[str, object], intent_id: str) -> str | None:
    value: Final[object] = raw.get("lock")
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        msg = f"Policy intent {intent_id} lock must be a non-empty path string."
        raise PipxError(msg)
    return Path(value).name


def _parse_packages(raw: dict[str, object], intent_id: str) -> tuple[PolicyPackage, ...]:
    raw_packages: Final[object] = raw.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages or not all(
        isinstance(package, str) and package for package in raw_packages
    ):
        msg = f"Policy intent {intent_id} packages must be non-empty requirement strings."
        raise PipxError(msg)
    raw_hashes: Final[object] = raw.get("hashes", {})
    if not isinstance(raw_hashes, dict):
        msg = f"Policy intent {intent_id} hashes must be a table."
        raise PipxError(msg)

    packages: Final[list[PolicyPackage]] = []
    for text in raw_packages:
        name, version = _parse_pin(text, intent_id)
        if any(package.name == name for package in packages):
            msg = f"Policy intent {intent_id} pins {name} more than once."
            raise PipxError(msg)
        packages.append(PolicyPackage(name=name, version=version, sha256=None))
    hashes: Final[dict[str, object]] = {canonicalize_name(name): digest for name, digest in raw_hashes.items()}
    names: Final[set[str]] = {package.name for package in packages}
    if unknown := sorted(set(hashes) - names):
        msg = f"Policy intent {intent_id} hashes name packages the intent does not pin: {', '.join(unknown)}"
        raise PipxError(msg)
    hashed: Final[list[PolicyPackage]] = []
    for package in packages:
        digest: Final[object] = hashes.get(package.name)
        if digest is None:
            hashed.append(package)
            continue
        if not isinstance(digest, str) or _SHA256.fullmatch(digest.lower()) is None:
            msg = f"Policy intent {intent_id} hash for {package.name} must be a SHA-256 hex digest."
            raise PipxError(msg)
        hashed.append(PolicyPackage(name=package.name, version=package.version, sha256=digest.lower()))
    return tuple(hashed)


def _parse_pin(text: str, intent_id: str) -> tuple[str, str]:
    try:
        requirement: Final[Requirement] = Requirement(text)
    except InvalidRequirement:
        msg = f"Policy intent {intent_id} has an invalid package pin: {text}"
        raise PipxError(msg) from None
    pins: Final[list[object]] = list(requirement.specifier)
    if (
        requirement.url is not None
        or requirement.marker is not None
        or requirement.extras
        or len(pins) != 1
        or pins[0].operator != "=="
        or pins[0].version.endswith(".*")
    ):
        msg = f"Policy intent {intent_id} must pin exactly one version: {text}"
        raise PipxError(msg)
    return canonicalize_name(requirement.name), pins[0].version


def verify_tools(tools: Sequence[LockTool], policy_file: Path) -> OperationResult[ManifestVerificationData]:
    """Check each manifest tool's lock against a local approval policy, without changing any state.

    :param tools: the manifest tools, including those that declare no lock.
    :param policy_file: the local policy to check against.
    :returns: a result whose data names the intent of each lock and any dependency left for review.
    :raises PipxError: when the policy itself cannot be read or validated.
    """
    policy: Final[Policy] = load_policy(policy_file)
    verdicts: Final[list[VerifiedTool]] = []
    messages: Final[list[OutputMessage]] = []
    errors: Final[list[OperationError]] = []
    for tool in tools:
        verdict: Final[VerifiedTool] = _verify_tool(tool, policy)
        verdicts.append(verdict)
        messages.extend(_verdict_messages(verdict))
        # a lock held for review fails the gate by design, so it must also appear in errors for a script to see it
        errors.extend(_verdict_errors(verdict))
    return OperationResult(
        command=("manifest", "sync"),
        data=ManifestVerificationData(tools=tuple(verdicts)),
        messages=tuple(messages),
        exit_code=ExitCode(1) if errors else EXIT_CODE_OK,
        errors=tuple(errors),
        # a run where every tool passed reports success; a review stop is not a success even if another tool passed
        succeeded=bool(verdicts) and not errors,
    )


def _verdict_errors(verdict: VerifiedTool) -> list[OperationError]:
    # a lock held for review is not failed, so a plain error would stop a caller from retrying the same input
    code: Final[str] = "manifest_review_pending" if verdict.status == "needs_review" else "manifest_verification_failed"
    return [
        OperationError(
            code=code,
            message=problem.message,
            environment=verdict.environment,
        )
        for problem in verdict.problems
    ]


def _verify_tool(tool: LockTool, policy: Policy) -> VerifiedTool:
    if tool.lock_file is None:
        return _failed_tool(
            tool,
            intent=None,
            approval=None,
            problem=VerificationProblem(
                code="lock_not_declared",
                message="no lock is declared; policy verification requires every tool to name a lock",
            ),
        )
    try:
        lock: Final[_LockContents] = _read_lock(tool.lock_file)
        intent: Final[PolicyIntent] = _match_intent(tool, policy)
        return _check_lock(tool, lock, intent)
    except _VerificationError as error:
        return _failed_tool(
            tool,
            intent=None,
            approval=None,
            problem=error.problem,
        )


def _read_lock(lock_file: Path) -> _LockContents:
    resolved: Final[Path] = lock_file.expanduser().resolve()
    try:
        with resolved.open("rb") as opened:
            data: Final[dict[str, object]] = tomllib.load(opened)
    except FileNotFoundError as error:
        msg = f"lock file {lock_file} does not exist"
        raise _VerificationError(VerificationProblem(code="lock_unreadable", message=msg)) from error
    except OSError as error:
        msg = f"cannot read lock file {lock_file}: {error}"
        raise _VerificationError(VerificationProblem(code="lock_unreadable", message=msg)) from error
    except tomllib.TOMLDecodeError as error:
        msg = f"lock file {lock_file} is not valid TOML: {error}"
        raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg)) from error

    lock_version: Final[object] = data.get("lock-version")
    if not isinstance(lock_version, str):
        msg = f"lock file {lock_file} has no lock-version"
        raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
    try:
        parsed_version: Final[Version] = Version(lock_version)
    except InvalidVersion as error:
        msg = f"lock file {lock_file} has an invalid lock-version {lock_version!r}"
        raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg)) from error
    if parsed_version.major != 1:
        msg = f"lock file {lock_file} uses unsupported lock-version {lock_version}; pipx policy checks read version 1"
        raise _VerificationError(VerificationProblem(code="lock_unsupported_version", message=msg))

    packages: Final[tuple[_LockPackage, ...]] = _read_lock_packages(lock_file, data.get("packages"))
    default_groups: Final[tuple[str, ...]] = _read_string_list(
        lock_file, "default-groups", data.get("default-groups", [])
    )
    return _LockContents(
        lock_version=lock_version,
        approval=_read_lock_approval(data),
        generated_by=_read_generated_by(data),
        default_groups=default_groups,
        packages=packages,
    )


def _read_lock_packages(lock_file: Path, raw_packages: object) -> tuple[_LockPackage, ...]:
    if not isinstance(raw_packages, list):
        msg = f"lock file {lock_file} has no packages array"
        raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
    packages: Final[list[_LockPackage]] = []
    for raw_package in raw_packages:
        if not isinstance(raw_package, dict):
            msg = f"lock file {lock_file} has a package that is not a table"
            raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
        name: Final[object] = raw_package.get("name")
        version: Final[object] = raw_package.get("version")
        marker: Final[object] = raw_package.get("marker")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            msg = f"lock file {lock_file} has a package without a name or version"
            raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
        if marker is not None and not isinstance(marker, str):
            msg = f"lock file {lock_file} has a non-string marker for {name}"
            raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
        try:
            Version(version)
        except InvalidVersion as error:
            msg = f"lock file {lock_file} has an invalid version {version!r} for {name}"
            raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg)) from error
        packages.append(
            _LockPackage(
                name=canonicalize_name(name),
                version=version,
                marker=marker,
                hashes=_read_package_hashes(raw_package),
                dependencies=_read_package_dependencies(lock_file, raw_package),
            )
        )
    return tuple(packages)


def _read_package_dependencies(
    lock_file: Path, raw_package: dict[str, object]
) -> tuple[_LockedDependency, ...]:
    raw_dependencies: Final[object] = raw_package.get("dependencies", [])
    if not isinstance(raw_dependencies, list):
        msg = f"lock file {lock_file} has non-array dependencies for {raw_package.get('name')}"
        raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
    dependencies: Final[list[_LockedDependency]] = []
    for raw_dependency in raw_dependencies:
        if not isinstance(raw_dependency, dict) or not isinstance(name := raw_dependency.get("name"), str) or not name:
            msg = f"lock file {lock_file} has a dependency without a name for {raw_package.get('name')}"
            raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
        marker: Final[object] = raw_dependency.get("marker")
        if marker is not None and not isinstance(marker, str):
            msg = f"lock file {lock_file} has a non-string dependency marker for {name}"
            raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
        dependencies.append(_LockedDependency(name=canonicalize_name(name), marker=marker))
    return tuple(dependencies)


def _read_package_hashes(raw_package: dict[str, object]) -> tuple[str, ...]:
    digests: Final[list[str]] = []
    artifacts: Final[list[object]] = [raw_package.get("sdist"), *(raw_package.get("wheels") or [])]
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        hashes: Final[object] = artifact.get("hashes")
        if isinstance(hashes, dict) and isinstance(digest := hashes.get("sha256"), str):
            digests.append(digest.lower())
    return tuple(digests)


def _read_string_list(lock_file: Path, key: str, raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) and item for item in raw):
        msg = f"lock file {lock_file} {key} must be non-empty strings"
        raise _VerificationError(VerificationProblem(code="lock_malformed", message=msg))
    return tuple(raw)


def _read_lock_approval(data: dict[str, object]) -> str | None:
    # only the review provenance counts; created-by names the generator and can never stand in for an approval
    tool_data: Final[object] = data.get("tool")
    if isinstance(tool_data, dict) and isinstance(pipx_data := tool_data.get("pipx"), dict):
        approval: Final[object] = pipx_data.get("approval")
        if isinstance(approval, str) and approval:
            return approval
    return None


def _read_generated_by(data: dict[str, object]) -> str | None:
    created_by: Final[object] = data.get("created-by")
    return created_by if isinstance(created_by, str) and created_by else None


def _match_intent(tool: LockTool, policy: Policy) -> PolicyIntent:
    candidates: Final[list[PolicyIntent]] = [
        intent for intent in policy.intents if intent.environment == tool.environment
    ]
    if tool.lock_file is not None:
        named: Final[list[PolicyIntent]] = [
            intent for intent in candidates if intent.lock_name == tool.lock_file.name
        ]
        candidates = named or [intent for intent in candidates if intent.lock_name is None]
    if not candidates:
        msg = f"no policy intent approves tool {tool.environment}"
        raise _VerificationError(VerificationProblem(code="manifest_intent_missing", message=msg))
    if len(candidates) > 1:
        msg = f"policy intents {', '.join(intent.id for intent in candidates)} all match tool {tool.environment}"
        raise _VerificationError(VerificationProblem(code="manifest_intent_ambiguous", message=msg))
    return candidates[0]


def _check_lock(tool: LockTool, lock: _LockContents, intent: PolicyIntent) -> VerifiedTool:
    environment: Final[dict[str, str | list[str]]] = _marker_environment(tool, lock)
    selected: Final[tuple[_LockPackage, ...]] = _select_packages(lock, environment)
    by_name: Final[dict[str, _LockPackage]] = _index_packages(selected)
    problems: Final[list[VerificationProblem]] = []
    problems.extend(_dependency_problems(lock, selected, by_name, environment))

    if lock.approval is None:
        problems.append(
            VerificationProblem(
                code="approval_source_missing",
                message=f"lock declares no approval source; expected {intent.approval!r} for intent {intent.id}",
            )
        )
    elif lock.approval != intent.approval:
        problems.append(
            VerificationProblem(
                code="approval_source_mismatch",
                message=(
                    f"lock approval source {lock.approval!r} does not match "
                    f"intent {intent.id} ({intent.approval!r})"
                ),
            )
        )

    requirement: Final[Requirement] = Requirement(tool.package)
    main_package: Final[_LockPackage | None] = by_name.get(tool.package_name)
    if main_package is None:
        problems.append(
            VerificationProblem(
                code="lock_incomplete",
                message=f"lock does not contain {tool.package_name}",
            )
        )
    else:
        try:
            satisfies: Final[bool] = requirement.specifier.contains(main_package.version, prereleases=True)
        except InvalidVersion:
            satisfies = False
        if not satisfies:
            problems.append(
                VerificationProblem(
                    code="stale_lock",
                    message=f"lock has {tool.package_name} {main_package.version}, which does not satisfy "
                    f"{tool.package}",
                )
            )

    # a lock is only as trustworthy as the source it came from; an intent that names a lock must see that exact file
    if intent.lock_name is not None and tool.lock_file is not None and intent.lock_name != tool.lock_file.name:
        problems.append(
            VerificationProblem(
                code="lock_name_mismatch",
                message=f"intent {intent.id} approves {intent.lock_name}, not {tool.lock_file.name}",
            )
        )

    intent_names: Final[set[str]] = {package.name for package in intent.packages}
    pending_review: Final[tuple[str, ...]] = tuple(sorted(name for name in by_name if name not in intent_names))
    if pending_review:
        problems.append(
            VerificationProblem(
                code="lock_unreviewed_dependency",
                message=f"dependencies pending human review: {', '.join(pending_review)}",
            )
        )

    # only demand the approved packages this environment would select; an approved package that a platform marker
    # leaves out is legitimately absent from the lock
    missing: Final[tuple[str, ...]] = tuple(
        sorted(
            name
            for name in intent_names
            if name not in by_name and not _selected_out(lock, name, environment)
        )
    )
    if missing:
        problems.append(
            VerificationProblem(
                code="lock_incomplete",
                message=f"lock is missing approved packages: {', '.join(missing)}",
            )
        )

    for approved in intent.packages:
        locked: Final[_LockPackage | None] = by_name.get(approved.name)
        if locked is None:
            continue
        if locked.version != approved.version:
            try:
                older: Final[bool] = Version(locked.version) < Version(approved.version)
            except InvalidVersion:
                older = False
            code: Final[str] = "stale_lock" if older else "lock_version_unapproved"
            problems.append(
                VerificationProblem(
                    code=code,
                    message=f"lock has {approved.name} {locked.version}, but intent {intent.id} approves "
                    f"{approved.version}",
                )
            )
        if approved.sha256 is not None and approved.sha256 not in locked.hashes:
            problems.append(
                VerificationProblem(
                    code="lock_artifact_mismatch",
                    message=f"lock has no {approved.name} artifact with the SHA-256 approved by intent {intent.id}",
                )
            )

    return VerifiedTool(
        environment=tool.environment,
        lock=str(tool.lock_file),
        intent=intent.id,
        approval=lock.approval,
        source=lock.generated_by,
        packages=tuple(f"{package.name}=={package.version}" for package in selected),
        pending_review=pending_review,
        missing=missing,
        status=_status(problems),
        problems=tuple(problems),
    )


def _status(problems: Sequence[VerificationProblem]) -> str:
    if not problems:
        return "verified"
    # a lock that is otherwise approved but carries an extra dependency is held for review rather than silently
    # installed, while still telling the reviewer exactly which package to look at
    if all(problem.code == "lock_unreviewed_dependency" for problem in problems):
        return "needs_review"
    return "failed"


def _dependency_problems(
    lock: _LockContents,
    selected: Sequence[_LockPackage],
    by_name: dict[str, _LockPackage],
    environment: dict[str, str | list[str]],
) -> list[VerificationProblem]:
    # PEP 751 dependencies are resolved by name, not pinned by version, so a satisfied direct dependency can still
    # pull a package that neither the lock's provenance nor the intent names; leaving it to the installer would
    # bypass the policy gate
    problems: Final[list[VerificationProblem]] = []
    pending: Final[list[str]] = [package.name for package in selected]
    reached: Final[set[str]] = set()
    for package in selected:
        reached.add(package.name)
    while pending:
        package: Final[_LockPackage] = by_name[pending.pop()]
        for dependency in package.dependencies:
            # a Python-conditional dependency may or may not be installed, so it is not required in the lock; if it
            # is there, it is reviewed with the rest
            if dependency.marker is not None and _python_dependent(dependency.marker):
                if dependency.name in by_name and dependency.name not in reached:
                    reached.add(dependency.name)
                    pending.append(dependency.name)
                continue
            if dependency.marker is not None and not _marker_matches(
                dependency.marker, f"{package.name}'s dependency {dependency.name}", environment
            ):
                continue
            if dependency.name in reached:
                continue
            reached.add(dependency.name)
            if dependency.name in by_name:
                pending.append(dependency.name)
            elif not any(candidate.name == dependency.name for candidate in lock.packages):
                problems.append(
                    VerificationProblem(
                        code="lock_incomplete",
                        message=f"{package.name} depends on {dependency.name}, which the lock does not contain",
                    )
                )
            else:
                problems.append(
                    VerificationProblem(
                        code="lock_incomplete",
                        message=f"{package.name} depends on {dependency.name}, which the lock does not select "
                        "for this environment",
                    )
                )
    return problems


def _selected_out(lock: _LockContents, name: str, environment: dict[str, str | list[str]]) -> bool:
    # a declared package with a marker this platform does not match was intentionally left out of the selection
    return any(
        package.name == name
        and package.marker is not None
        and not _python_dependent(package.marker)
        and not _marker_matches(package.marker, f"{package.name} {package.version}", environment)
        for package in lock.packages
    )


def _marker_environment(tool: LockTool, lock: _LockContents) -> dict[str, str | list[str]]:
    requirement: Final[Requirement] = Requirement(tool.package)
    return default_environment() | {
        "dependency_groups": list(lock.default_groups or (tool.environment,)),
        "extras": sorted(canonicalize_name(extra) for extra in requirement.extras),
        "extra": "",
    }


def _marker_matches(marker: str, subject: str, environment: dict[str, str | list[str]]) -> bool:
    try:
        return Marker(marker).evaluate(environment)
    except Exception as error:  # ruff:ignore[blind-except]  # packaging raises names outside its documented errors
        msg = f"cannot evaluate the marker of {subject}: {error}"
        raise _VerificationError(VerificationProblem(code="lock_marker_unknown", message=msg)) from error


def _python_dependent(marker: str) -> bool:
    # verification runs on pipx's interpreter, which need not be the one the environment will use, so a package that
    # may be selected by its Python version is treated as selected: an unreviewed package must never slip past the
    # gate, even when the difference would only make the lock over-report
    return "python_version" in marker or "python_full_version" in marker


def _select_packages(
    lock: _LockContents, environment: dict[str, str | list[str]]
) -> tuple[_LockPackage, ...]:
    return tuple(
        package
        for package in lock.packages
        if package.marker is None
        or _python_dependent(package.marker)
        or _marker_matches(package.marker, f"{package.name} {package.version}", environment)
    )


def _index_packages(selected: Sequence[_LockPackage]) -> dict[str, _LockPackage]:
    indexed: Final[dict[str, _LockPackage]] = {}
    for package in selected:
        if (existing := indexed.get(package.name)) is not None and existing.version != package.version:
            msg = (
                f"lock selects {package.name} {existing.version} and {package.version} for the same environment"
            )
            raise _VerificationError(VerificationProblem(code="lock_ambiguous", message=msg))
        indexed[package.name] = package
    return indexed


def _failed_tool(
    tool: LockTool,
    *,
    intent: str | None,
    approval: str | None,
    problem: VerificationProblem,
) -> VerifiedTool:
    return VerifiedTool(
        environment=tool.environment,
        lock=str(tool.lock_file) if tool.lock_file is not None else None,
        intent=intent,
        approval=approval,
        source=None,
        packages=(),
        pending_review=(),
        missing=(),
        status="failed",
        problems=(problem,),
    )


def _verdict_messages(verdict: VerifiedTool) -> list[OutputMessage]:
    if verdict.status == "verified":
        return [
            OutputMessage(
                text=f"{verdict.environment}: lock {verdict.lock} verified against intent {verdict.intent} "
                f"({verdict.approval})"
            )
        ]
    heading: Final[str] = "needs human review" if verdict.status == "needs_review" else "policy verification failed"
    return [
        OutputMessage(
            text=f"{verdict.environment}: {heading}: {problem.message}",
            stream=OutputStream.STDERR,
            level=OutputLevel.ERROR,
        )
        for problem in verdict.problems
    ]


__all__ = [
    "LockTool",
    "ManifestVerificationData",
    "Policy",
    "PolicyIntent",
    "PolicyPackage",
    "VerificationProblem",
    "VerifiedTool",
    "load_policy",
    "verify_tools",
]
