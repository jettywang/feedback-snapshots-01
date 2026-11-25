"""Recoverable, content-bound state for dependency-set switches.

A shared lockfile path is only a mutable cache.  It must never be treated as
proof that an environment was switched.  This module keeps:

* content-addressed copies of generated candidate locks;
* a target/options/input/base-result binding for every candidate;
* an append-only record of generated, apply-started, interrupted and verified
  transitions; and
* recovery decisions that prefer the trusted archived candidate or the last
  verified result over whatever currently occupies a shared lock path.

The module is intentionally filesystem-only and does not invoke Hatch, uv or
pip.  Callers perform the actual installation and report the result back.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from hatch.env.lock import LockGenerationState
    from hatch.env.plugin.interface import EnvironmentInterface

SCHEMA_VERSION = 1

STATE_GENERATED = "generated"
STATE_APPLY_STARTED = "apply_started"
STATE_VERIFIED = "verified"
STATE_APPLY_INTERRUPTED = "apply_interrupted"
STATE_APPLY_FAILED = "apply_failed"

ACTION_START_VERIFIED = "start_verified_result"
ACTION_RESUME_CANDIDATE = "resume_candidate"
ACTION_REGENERATE_CANDIDATE = "regenerate_candidate"
ACTION_NO_VERIFIED_RESULT = "no_verified_result"
ACTION_VERIFIED_RESULT_UNAVAILABLE = "verified_result_unavailable"

SHARED_INTACT = "intact"
SHARED_MISSING = "missing"
SHARED_FOREIGN_TARGET = "foreign_target"
SHARED_FOREIGN_WRITE = "foreign_write"
SHARED_SAME_CONTENT_FOREIGN_WRITE = "same_content_foreign_write"

RESUMABLE_PHASES = {
    STATE_GENERATED,
    STATE_APPLY_STARTED,
    STATE_APPLY_INTERRUPTED,
    STATE_APPLY_FAILED,
}


class SwitchStateError(RuntimeError):
    """Base class for switch-state errors."""


class InvalidStateError(SwitchStateError):
    """Raised when persisted state or an artifact cannot be trusted."""


class CandidateBindingError(SwitchStateError):
    """Raised when a candidate does not match the requested recovery binding."""


class LockVerificationError(SwitchStateError):
    """Raised when an applied lock cannot be verified in the environment."""


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def json_value(value: Any) -> Any:
    """Convert common Python values to deterministic JSON-compatible data."""
    if hasattr(value, "to_dict"):
        value = value.to_dict()

    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): json_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def canonical_json(value: Any) -> bytes:
    return json.dumps(json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json(value)).hexdigest()


def digest_bytes(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def digest_file(path: Path | str) -> str:
    digest = sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _coerce_dataclass(cls: type[Any], value: Any) -> Any:
    if value is None:
        return cls()
    if isinstance(value, cls):
        return value
    if isinstance(value, Mapping):
        known = {name for name in cls.__dataclass_fields__}
        return cls(**{key: item for key, item in value.items() if key in known})
    msg = f"Expected {cls.__name__}, mapping, or None; got {type(value).__name__}"
    raise TypeError(msg)


@dataclass(frozen=True)
class TargetRef:
    """The environment/install target a switch belongs to."""

    id: str
    name: str
    root: str
    env_path: str | None = None
    python: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        name: str,
        root: Path | str,
        *,
        env_path: Path | str | None = None,
        python: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        target_id: str | None = None,
    ) -> TargetRef:
        root_path = Path(root).expanduser().resolve()
        env_path_str = None if env_path is None else str(Path(env_path).expanduser().resolve())
        metadata_dict = dict(metadata or {})
        if target_id is None:
            raw_id = canonical_digest(
                {
                    "name": name,
                    "root": str(root_path),
                    "env_path": env_path_str,
                    "python": python,
                    "metadata": metadata_dict,
                }
            ).split(":", 1)[1][:16]
            target_id = f"target_{raw_id}"

        return cls(
            id=target_id,
            name=name,
            root=str(root_path),
            env_path=env_path_str,
            python=python,
            metadata=metadata_dict,
        )

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass(frozen=True)
class SwitchOptions:
    """Options that change how a candidate lock is generated or applied."""

    switch_set: str | None = None
    locker: str | None = None
    locked: bool = True
    upgrade: bool = False
    extras: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()
    arguments: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass(frozen=True)
class LockInputs:
    """Dependency/input binding for a generated lock candidate."""

    dependencies: tuple[str, ...] = ()
    layered: bool = False
    lock_extras: tuple[str, ...] = ()
    lock_groups: tuple[str, ...] = ()
    input_hashes: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass(frozen=True)
class DependencyOwnership:
    """Attribution for the dependencies recorded in a verified result."""

    owner_id: str
    owner_name: str
    switch_set: str | None
    kind: str
    dependencies: tuple[str, ...]
    lock_inputs: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass(frozen=True)
class InstallationResult:
    """A receipt for an installation that actually passed verification."""

    result_id: str
    target_id: str
    status: str
    verified_at: str
    verifier: str
    lock_hash: str
    lock_artifact: str
    installation_fingerprint: str
    ownership: dict[str, Any]
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass
class LockCandidate:
    candidate_id: str
    target_id: str
    phase: str
    lock_path: str
    artifact_path: str
    lock_hash: str
    options: dict[str, Any]
    lock_inputs: dict[str, Any]
    ownership: dict[str, Any]
    base_result_id: str | None
    base_result_binding: dict[str, Any] | None
    created_at: str
    updated_at: str
    attempts: int = 0
    last_error: str | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> LockCandidate:
        known = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in data.items() if key in known})

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass(frozen=True)
class StartupPlan:
    action: str
    target_id: str
    reason: str
    result_id: str | None = None
    result_path: str | None = None
    ownership: dict[str, Any] | None = None
    installation_fingerprint: str | None = None
    verified_at: str | None = None
    shared_lock_path: str | None = None
    shared_lock_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


@dataclass(frozen=True)
class RecoveryPlan:
    action: str
    target_id: str
    reason: str
    candidate_id: str | None = None
    candidate_phase: str | None = None
    trusted_lock_path: str | None = None
    lock_hash: str | None = None
    base_result_id: str | None = None
    attempts: int | None = None
    shared_lock_path: str | None = None
    shared_lock_status: str | None = None
    shared_lock_owner_id: str | None = None
    shared_lock_owner_name: str | None = None
    shared_lock_hash: str | None = None
    fallback_result_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return json_value(asdict(self))


def lock_inputs_from_generation_state(state: LockGenerationState) -> LockInputs:
    """Convert Hatch's computed lock inputs into the recovery binding."""
    return LockInputs(
        dependencies=tuple(state.dependencies),
        layered=state.layered,
        lock_extras=tuple(state.lock_extras),
        lock_groups=tuple(state.lock_groups),
    )


def target_for_environment(environment: EnvironmentInterface) -> TargetRef:
    """Build the stable target binding for a Hatch environment."""
    config = getattr(environment, "config", {}) or {}
    env_path = getattr(environment, "virtual_env_path", None)
    return TargetRef.create(
        environment.name,
        environment.root,
        env_path=env_path,
        python=config.get("python"),
        metadata={
            "plugin": getattr(environment, "PLUGIN_NAME", environment.__class__.__name__),
            "locked": bool(getattr(environment, "locked", False)),
            "installer": config.get("installer"),
        },
    )


def options_for_environment(
    environment: EnvironmentInterface,
    *,
    upgrade: bool = False,
    upgrade_packages: tuple[str, ...] = (),
    switch_set: str | None = None,
    deps_override: list[str] | None = None,
) -> SwitchOptions:
    """Build the option binding for a Hatch lock/apply request."""
    config = getattr(environment, "config", {}) or {}
    return SwitchOptions(
        switch_set=switch_set,
        locker=config.get("locker"),
        locked=bool(getattr(environment, "locked", False)),
        upgrade=upgrade,
        extras=tuple(getattr(environment, "features", ())),
        groups=tuple(getattr(environment, "dependency_groups", ())),
        metadata={
            "upgrade_packages": tuple(upgrade_packages),
            "deps_override": None if deps_override is None else tuple(deps_override),
        },
    )


def record_generation_for_environment(
    environment: EnvironmentInterface,
    lock_path: Path | str,
    *,
    generation_state: LockGenerationState,
    upgrade: bool = False,
    upgrade_packages: tuple[str, ...] = (),
    switch_set: str | None = None,
    deps_override: list[str] | None = None,
) -> LockCandidate:
    """Archive a generated Hatch lock and bind it to its target/inputs."""
    path = Path(lock_path)
    store = SwitchStateStore.for_project(environment.root)
    return store.record_generated(
        target=target_for_environment(environment),
        lock_content=path.read_bytes(),
        lock_path=path,
        options=options_for_environment(
            environment,
            upgrade=upgrade,
            upgrade_packages=upgrade_packages,
            switch_set=switch_set,
            deps_override=deps_override,
        ),
        lock_inputs=lock_inputs_from_generation_state(generation_state),
    )


class SwitchStateStore:
    """Filesystem-backed switch journal and recovery planner."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.state_path = self.directory / "state.json"
        self.journal_path = self.directory / "journal.jsonl"
        self.artifact_dir = self.directory / "locks"
        self.lock_path = self.directory / "store.lock"
        import threading

        self._thread_lock = threading.RLock()

    @classmethod
    def for_project(cls, project_root: Path | str) -> SwitchStateStore:
        return cls(Path(project_root) / ".hatch" / "switch-state")

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Acquire an in-process and cross-process exclusive lock."""
        with self._thread_lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._ensure_gitignore()
            handle = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                if os.name == "nt":  # pragma: no cover - Windows locking
                    msvcrt = __import__("msvcrt")
                    msvcrt.locking(handle, msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle, fcntl.LOCK_EX)
                yield
            finally:
                try:
                    if os.name == "nt":  # pragma: no cover
                        msvcrt = __import__("msvcrt")
                        os.lseek(handle, 0, os.SEEK_SET)
                        msvcrt.locking(handle, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(handle)

    def list_events(self) -> list[dict[str, Any]]:
        if not self.journal_path.is_file():
            return []
        events: list[dict[str, Any]] = []
        for line_number, line in enumerate(self.journal_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                msg = f"Invalid switch journal line {line_number}: {exc}"
                raise InvalidStateError(msg) from exc
        return events

    def read_state(self) -> dict[str, Any]:
        with self.locked():
            return self._load_state()

    def get_candidate(self, candidate_id: str) -> LockCandidate:
        with self.locked():
            state = self._load_state()
            for target in state["targets"].values():
                candidate = target["candidates"].get(candidate_id)
                if candidate is not None:
                    return LockCandidate.from_dict(candidate)
        raise CandidateBindingError(f"Unknown switch candidate: {candidate_id}")

    def startup_plan(self, target: TargetRef | str, *, record_decision: bool = True) -> StartupPlan:
        target_id = target.id if isinstance(target, TargetRef) else target
        with self.locked():
            state = self._load_state()
            target_state = state["targets"].get(target_id)
            if target_state is None or not target_state.get("active_result_id"):
                plan = StartupPlan(
                    action=ACTION_NO_VERIFIED_RESULT,
                    target_id=target_id,
                    reason="target has no verified installation result",
                )
            else:
                result_id = target_state["active_result_id"]
                result = target_state["results"].get(result_id)
                if result is None:
                    plan = StartupPlan(
                        action=ACTION_VERIFIED_RESULT_UNAVAILABLE,
                        target_id=target_id,
                        result_id=result_id,
                        reason="active result receipt is missing from state",
                    )
                else:
                    artifact = Path(result["lock_artifact"])
                    if not artifact.is_file() or digest_file(artifact) != result["lock_hash"]:
                        plan = StartupPlan(
                            action=ACTION_VERIFIED_RESULT_UNAVAILABLE,
                            target_id=target_id,
                            result_id=result_id,
                            reason="archived result lock is missing or fails its SHA-256 binding",
                            ownership=result.get("ownership"),
                            installation_fingerprint=result.get("installation_fingerprint"),
                            verified_at=result.get("verified_at"),
                        )
                    else:
                        shared_path = None
                        shared_status = None
                        candidate_id = target_state.get("last_verified_candidate_id")
                        candidate = target_state["candidates"].get(candidate_id) if candidate_id else None
                        if candidate is not None:
                            shared_path = candidate["lock_path"]
                            shared_status = self._inspect_shared_lock(state, candidate)["status"]

                        plan = StartupPlan(
                            action=ACTION_START_VERIFIED,
                            target_id=target_id,
                            result_id=result_id,
                            result_path=str(artifact),
                            reason="target is bound to its last verification-passed result",
                            ownership=result.get("ownership"),
                            installation_fingerprint=result.get("installation_fingerprint"),
                            verified_at=result.get("verified_at"),
                            shared_lock_path=shared_path,
                            shared_lock_status=shared_status,
                        )

            if record_decision:
                self._record_decision(state, "startup", plan.to_dict())
            return plan

    def restore_verified_result(self, target: TargetRef | str, destination: Path | str | None = None) -> Path:
        """Return the trusted lock for the active result, optionally restoring it."""
        plan = self.startup_plan(target, record_decision=False)
        if plan.action != ACTION_START_VERIFIED or not plan.result_path:
            raise InvalidStateError(plan.reason)

        source = Path(plan.result_path)
        if destination is None:
            return source

        output = Path(destination)
        output.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        digest = digest_bytes(data)
        with self.locked():
            state = self._load_state()
            result = self._find_active_result(state, plan.target_id)
            if result is None or digest != result["lock_hash"]:
                msg = "Refusing to restore a result whose lock binding is invalid"
                raise InvalidStateError(msg)
            self._atomic_write_bytes(output, data)
        return output

    def record_generated(
        self,
        *,
        target: TargetRef | Mapping[str, Any] | str,
        lock_content: bytes | str,
        lock_path: Path | str,
        options: SwitchOptions | Mapping[str, Any] | None = None,
        lock_inputs: LockInputs | Mapping[str, Any] | None = None,
        base_result: InstallationResult | Mapping[str, Any] | str | None = "auto",
        created_at: str | None = None,
    ) -> LockCandidate:
        target_ref = self._coerce_target(target)
        switch_options = _coerce_dataclass(SwitchOptions, options)
        inputs = _coerce_dataclass(LockInputs, lock_inputs)
        lock_bytes = lock_content.encode("utf-8") if isinstance(lock_content, str) else lock_content

        lock_hash = digest_bytes(lock_bytes)
        artifact_rel = Path("locks") / f"pylock.{lock_hash.split(':', 1)[1]}.toml"
        artifact_path = self.directory / artifact_rel
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        if not artifact_path.is_file():
            self._atomic_write_bytes(artifact_path, lock_bytes)
        elif digest_file(artifact_path) != lock_hash:
            msg = f"Content-addressed artifact collision: {artifact_path}"
            raise InvalidStateError(msg)

        ownership = DependencyOwnership(
            owner_id=target_ref.id,
            owner_name=target_ref.name,
            switch_set=switch_options.switch_set,
            kind="hatch-environment",
            dependencies=tuple(inputs.dependencies),
            lock_inputs=inputs.to_dict(),
        ).to_dict()

        advertised_path = str(Path(lock_path).expanduser().resolve())
        now = created_at or utc_now()

        with self.locked():
            state = self._load_state()
            target_state = self._ensure_target(state, target_ref)

            base_result_data, base_binding = self._resolve_base_result(state, target_state, base_result)
            base_result_id = None if base_result_data is None else base_result_data["result_id"]

            binding = {
                "target": target_ref.to_dict(),
                "lock_path": advertised_path,
                "options": switch_options.to_dict(),
                "lock_inputs": inputs.to_dict(),
                "base_result": base_binding,
                "lock_hash": lock_hash,
            }
            candidate_id = "cand_" + canonical_digest(binding).split(":", 1)[1][:20]

            existing = target_state["candidates"].get(candidate_id)
            if existing is not None:
                if existing["lock_hash"] != lock_hash:
                    msg = f"Candidate identity collision for {candidate_id}"
                    raise InvalidStateError(msg)
                candidate = existing
                if candidate["phase"] != STATE_VERIFIED:
                    target_state["pending_candidate_id"] = candidate_id
            else:
                candidate = {
                    "candidate_id": candidate_id,
                    "target_id": target_ref.id,
                    "phase": STATE_GENERATED,
                    "lock_path": advertised_path,
                    "artifact_path": str(artifact_path),
                    "lock_hash": lock_hash,
                    "options": switch_options.to_dict(),
                    "lock_inputs": inputs.to_dict(),
                    "ownership": ownership,
                    "base_result_id": base_result_id,
                    "base_result_binding": base_binding,
                    "created_at": now,
                    "updated_at": now,
                    "attempts": 0,
                    "last_error": None,
                }
                target_state["candidates"][candidate_id] = candidate
                target_state["pending_candidate_id"] = candidate_id

            path_record = {
                "path": advertised_path,
                "target_id": target_ref.id,
                "target_name": target_ref.name,
                "candidate_id": candidate_id,
                "lock_hash": lock_hash,
                "observed_at": now,
            }
            state["lock_paths"][advertised_path] = path_record

            event = {
                "at": now,
                "type": "candidate_generated",
                "target": target_ref.to_dict(),
                "target_id": target_ref.id,
                "candidate_id": candidate_id,
                "phase": candidate["phase"],
                "lock_hash": lock_hash,
                "shared_lock_path": advertised_path,
                "artifact_path": str(artifact_path),
                "candidate": candidate,
                "lock_path_record": path_record,
            }
            self._commit_event(state, event)
            return LockCandidate.from_dict(candidate)

    def record_lock_path_write(self, candidate_id: str, *, at: str | None = None) -> LockCandidate:
        """Record that a candidate's bytes were written to its shared lock path."""
        now = at or utc_now()
        with self.locked():
            state = self._load_state()
            _, candidate = self._find_candidate(state, candidate_id)
            lock_path = Path(candidate["lock_path"])
            if not lock_path.is_file() or digest_file(lock_path) != candidate["lock_hash"]:
                msg = f"Shared lock path does not contain candidate {candidate_id}"
                raise InvalidStateError(msg)

            record = {
                "path": candidate["lock_path"],
                "target_id": candidate["target_id"],
                "target_name": state["targets"][candidate["target_id"]]["target"].get("name"),
                "candidate_id": candidate_id,
                "lock_hash": candidate["lock_hash"],
                "observed_at": now,
            }
            state["lock_paths"][candidate["lock_path"]] = record
            event = {
                "type": "lock_path_written",
                "at": now,
                "target_id": candidate["target_id"],
                "candidate_id": candidate_id,
                "phase": candidate["phase"],
                "shared_lock_path": candidate["lock_path"],
                "lock_hash": candidate["lock_hash"],
                "lock_path_record": record,
            }
            self._commit_event(state, event)
            return LockCandidate.from_dict(candidate)

    def begin_apply(self, candidate_id: str, *, at: str | None = None) -> LockCandidate:
        now = at or utc_now()
        with self.locked():
            state = self._load_state()
            target_state, candidate = self._find_candidate(state, candidate_id)
            artifact = Path(candidate["artifact_path"])
            if not artifact.is_file() or digest_file(artifact) != candidate["lock_hash"]:
                msg = f"Candidate artifact is missing or corrupted: {candidate_id}"
                raise InvalidStateError(msg)

            candidate["phase"] = STATE_APPLY_STARTED
            candidate["attempts"] = int(candidate.get("attempts", 0)) + 1
            candidate["last_error"] = None
            candidate["updated_at"] = now
            target_state["pending_candidate_id"] = candidate_id

            event = {
                "type": "apply_started",
                "at": now,
                "target_id": candidate["target_id"],
                "candidate_id": candidate_id,
                "phase": STATE_APPLY_STARTED,
                "attempt": candidate["attempts"],
                "artifact_path": candidate["artifact_path"],
                "shared_lock_path": candidate["lock_path"],
            }
            self._commit_event(state, event)
            return LockCandidate.from_dict(candidate)

    def record_apply_failure(
        self,
        candidate_id: str,
        error: BaseException | str,
        *,
        interrupted: bool = False,
        evidence: Mapping[str, Any] | None = None,
        at: str | None = None,
    ) -> LockCandidate:
        now = at or utc_now()
        phase = STATE_APPLY_INTERRUPTED if interrupted else STATE_APPLY_FAILED
        message = str(error)
        with self.locked():
            state = self._load_state()
            _, candidate = self._find_candidate(state, candidate_id)
            candidate["phase"] = phase
            candidate["last_error"] = message
            candidate["updated_at"] = now

            event = {
                "type": "apply_interrupted" if interrupted else "apply_failed",
                "at": now,
                "target_id": candidate["target_id"],
                "candidate_id": candidate_id,
                "phase": phase,
                "error": message,
                "evidence": json_value(evidence or {}),
            }
            self._commit_event(state, event)
            return LockCandidate.from_dict(candidate)

    def record_verification_passed(
        self,
        candidate_id: str,
        *,
        verifier: str,
        installation_fingerprint: Mapping[str, Any] | str,
        evidence: Mapping[str, Any] | None = None,
        result_id: str | None = None,
        at: str | None = None,
    ) -> InstallationResult:
        now = at or utc_now()
        fingerprint = (
            installation_fingerprint
            if isinstance(installation_fingerprint, str)
            else canonical_digest(installation_fingerprint)
        )

        with self.locked():
            state = self._load_state()
            target_state, candidate = self._find_candidate(state, candidate_id)
            artifact = Path(candidate["artifact_path"])
            if not artifact.is_file() or digest_file(artifact) != candidate["lock_hash"]:
                msg = f"Cannot verify candidate with invalid artifact: {candidate_id}"
                raise InvalidStateError(msg)

            if result_id is None:
                result_id = (
                    "res_"
                    + canonical_digest(
                        {
                            "target_id": candidate["target_id"],
                            "lock_hash": candidate["lock_hash"],
                            "installation_fingerprint": fingerprint,
                            "ownership": candidate["ownership"],
                        }
                    ).split(":", 1)[1][:20]
                )

            result = InstallationResult(
                result_id=result_id,
                target_id=candidate["target_id"],
                status=STATE_VERIFIED,
                verified_at=now,
                verifier=verifier,
                lock_hash=candidate["lock_hash"],
                lock_artifact=candidate["artifact_path"],
                installation_fingerprint=fingerprint,
                ownership=candidate["ownership"],
                evidence=dict(evidence or {}),
            ).to_dict()

            candidate["phase"] = STATE_VERIFIED
            candidate["updated_at"] = now
            target_state["results"][result_id] = result
            target_state["active_result_id"] = result_id
            target_state["last_verified_candidate_id"] = candidate_id
            target_state["pending_candidate_id"] = None

            event = {
                "type": "verification_passed",
                "at": now,
                "target_id": candidate["target_id"],
                "candidate_id": candidate_id,
                "result_id": result_id,
                "phase": STATE_VERIFIED,
                "installation_fingerprint": fingerprint,
                "result": result,
            }
            self._commit_event(state, event)
            return InstallationResult(
                **{key: value for key, value in result.items() if key in InstallationResult.__dataclass_fields__}
            )

    def verify_and_record(
        self,
        candidate_id: str,
        verifier: Callable[[Path], Mapping[str, Any] | bool | None],
        *,
        verifier_name: str | None = None,
    ) -> InstallationResult:
        candidate = self.get_candidate(candidate_id)
        outcome = verifier(Path(candidate.artifact_path))
        if outcome is False or outcome is None:
            self.record_apply_failure(candidate_id, "post-apply verification failed")
            msg = f"Verification failed for candidate {candidate_id}"
            raise InvalidStateError(msg)

        if outcome is True:
            fingerprint = canonical_digest({"verified": True, "candidate": candidate_id})
            evidence: Mapping[str, Any] = {"verified": True}
        else:
            evidence = outcome
            fingerprint_value = outcome.get("installation_fingerprint", outcome)
            fingerprint = (
                fingerprint_value if isinstance(fingerprint_value, str) else canonical_digest(fingerprint_value)
            )

        return self.record_verification_passed(
            candidate_id,
            verifier=verifier_name or str(getattr(verifier, "__name__", "callable-verifier")),
            installation_fingerprint=fingerprint,
            evidence=evidence,
        )

    def retry_plan(
        self,
        target: TargetRef | str,
        *,
        candidate_id: str | None = None,
        options: SwitchOptions | Mapping[str, Any] | None = None,
        lock_inputs: LockInputs | Mapping[str, Any] | None = None,
        record_decision: bool = True,
    ) -> RecoveryPlan:
        target_id = target.id if isinstance(target, TargetRef) else target
        expected_options = _coerce_dataclass(SwitchOptions, options).to_dict() if options is not None else None
        expected_inputs = _coerce_dataclass(LockInputs, lock_inputs).to_dict() if lock_inputs is not None else None

        with self.locked():
            state = self._load_state()
            target_state = state["targets"].get(target_id)
            active_result_id = None if target_state is None else target_state.get("active_result_id")
            fallback = active_result_id

            selected_id = candidate_id
            if selected_id is None and target_state is not None:
                selected_id = target_state.get("pending_candidate_id")

            if target_state is None or not selected_id:
                plan = RecoveryPlan(
                    action=ACTION_REGENERATE_CANDIDATE,
                    target_id=target_id,
                    reason="no interrupted or pending candidate is bound to this target",
                    fallback_result_id=fallback,
                )
            else:
                candidate = target_state["candidates"].get(selected_id)
                if candidate is None:
                    plan = RecoveryPlan(
                        action=ACTION_REGENERATE_CANDIDATE,
                        target_id=target_id,
                        reason=f"pending candidate receipt is missing: {selected_id}",
                        fallback_result_id=fallback,
                    )
                else:
                    mismatch = self._binding_mismatch(
                        target_state,
                        candidate,
                        expected_options=expected_options,
                        expected_inputs=expected_inputs,
                        active_result_id=active_result_id,
                    )
                    artifact = Path(candidate["artifact_path"])
                    artifact_valid = artifact.is_file() and digest_file(artifact) == candidate["lock_hash"]

                    if mismatch:
                        reason = mismatch
                    elif candidate["phase"] not in RESUMABLE_PHASES:
                        reason = f"candidate phase `{candidate['phase']}` is not resumable"
                    elif not artifact_valid:
                        reason = "archived candidate lock is missing or fails its hash binding"
                    else:
                        shared = self._inspect_shared_lock(state, candidate)
                        plan = RecoveryPlan(
                            action=ACTION_RESUME_CANDIDATE,
                            target_id=target_id,
                            reason=(
                                "retry the content-addressed archived candidate; "
                                "do not infer identity from the shared lock path"
                            ),
                            candidate_id=candidate["candidate_id"],
                            candidate_phase=candidate["phase"],
                            trusted_lock_path=candidate["artifact_path"],
                            lock_hash=candidate["lock_hash"],
                            base_result_id=candidate.get("base_result_id"),
                            attempts=candidate.get("attempts", 0),
                            shared_lock_path=candidate["lock_path"],
                            shared_lock_status=shared["status"],
                            shared_lock_owner_id=shared.get("owner_id"),
                            shared_lock_owner_name=shared.get("owner_name"),
                            shared_lock_hash=shared.get("current_hash"),
                            fallback_result_id=fallback,
                        )
                        if record_decision:
                            self._record_decision(state, "retry", plan.to_dict())
                        return plan

                    plan = RecoveryPlan(
                        action=ACTION_REGENERATE_CANDIDATE,
                        target_id=target_id,
                        reason=reason,
                        candidate_id=candidate.get("candidate_id"),
                        candidate_phase=candidate.get("phase"),
                        lock_hash=candidate.get("lock_hash"),
                        base_result_id=candidate.get("base_result_id"),
                        attempts=candidate.get("attempts"),
                        shared_lock_path=candidate.get("lock_path"),
                        fallback_result_id=fallback,
                    )

            if record_decision:
                self._record_decision(state, "retry", plan.to_dict())
            return plan

    def shared_lock_conflicts(self) -> list[dict[str, Any]]:
        with self.locked():
            state = self._load_state()
            owners: dict[str, dict[str, Any]] = {}
            for target_id, target_state in state["targets"].items():
                target_name = target_state.get("target", {}).get("name", target_id)
                for candidate in target_state["candidates"].values():
                    path = str(Path(candidate["lock_path"]).expanduser().resolve())
                    entry = owners.setdefault(path, {"lock_path": path, "targets": {}})
                    entry["targets"][target_id] = target_name

            conflicts = []
            for entry in owners.values():
                if len(entry["targets"]) > 1:
                    conflicts.append(
                        {
                            "lock_path": entry["lock_path"],
                            "target_ids": sorted(entry["targets"]),
                            "target_names": [entry["targets"][tid] for tid in sorted(entry["targets"])],
                        }
                    )
            return conflicts

    def export_evidence(self) -> dict[str, Any]:
        with self.locked():
            state = self._load_state()
        return {
            "schema_version": SCHEMA_VERSION,
            "state": state,
            "events": self.list_events(),
            "shared_lock_conflicts": self.shared_lock_conflicts(),
        }

    def _binding_mismatch(
        self,
        target_state: Mapping[str, Any],
        candidate: Mapping[str, Any],
        *,
        expected_options: Mapping[str, Any] | None,
        expected_inputs: Mapping[str, Any] | None,
        active_result_id: str | None,
    ) -> str | None:
        if candidate["target_id"] != target_state["target"]["id"]:
            return "candidate is bound to a different target"
        if expected_options is not None and canonical_digest(candidate["options"]) != canonical_digest(
            expected_options
        ):
            return "requested options do not match candidate binding"
        if expected_inputs is not None and canonical_digest(candidate["lock_inputs"]) != canonical_digest(
            expected_inputs
        ):
            return "requested lock inputs do not match candidate binding"

        base_id = candidate.get("base_result_id")
        if base_id != active_result_id:
            return "candidate's last verified base result is no longer the active result"

        base_binding = candidate.get("base_result_binding")
        if base_id is not None and base_binding is not None:
            result = target_state["results"].get(base_id)
            if result is None:
                return "candidate's bound base result receipt is missing"
            current_binding = {
                "result_id": result["result_id"],
                "lock_hash": result["lock_hash"],
                "installation_fingerprint": result["installation_fingerprint"],
            }
            if canonical_digest(current_binding) != canonical_digest(base_binding):
                return "active base result does not match candidate's result binding"
        return None

    def _inspect_shared_lock(self, state: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
        shared_path = Path(candidate["lock_path"])
        absolute = str(shared_path.expanduser().resolve())
        recorded = state["lock_paths"].get(absolute)
        if not shared_path.is_file():
            return {"status": SHARED_MISSING, "current_hash": None, "owner_id": None, "owner_name": None}

        current_hash = digest_file(shared_path)
        owner_id = None if recorded is None else recorded.get("target_id")
        owner_name = None if recorded is None else recorded.get("target_name")

        if current_hash == candidate["lock_hash"]:
            if owner_id is not None and owner_id != candidate["target_id"]:
                status = SHARED_SAME_CONTENT_FOREIGN_WRITE
            else:
                status = SHARED_INTACT
        elif recorded is not None and recorded.get("lock_hash") == current_hash:
            status = SHARED_FOREIGN_TARGET if owner_id != candidate["target_id"] else "modified_same_target"
        else:
            status = SHARED_FOREIGN_WRITE

        return {
            "status": status,
            "current_hash": current_hash,
            "owner_id": owner_id,
            "owner_name": owner_name,
        }

    def _resolve_base_result(
        self,
        state: dict[str, Any],
        target_state: dict[str, Any],
        base_result: InstallationResult | Mapping[str, Any] | str | None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if base_result is None:
            return None, None
        if isinstance(base_result, str) and base_result == "auto":
            result_id = target_state.get("active_result_id")
            if not result_id:
                return None, None
            result = target_state["results"][result_id]
        elif isinstance(base_result, str):
            result = target_state["results"].get(base_result)
            if result is None:
                msg = f"Unknown base installation result: {base_result}"
                raise CandidateBindingError(msg)
        elif isinstance(base_result, InstallationResult):
            result = base_result.to_dict()
            target_state["results"][result["result_id"]] = result
        elif isinstance(base_result, Mapping):
            result = json_value(base_result)
            result_id = result.get("result_id")
            if not result_id:
                msg = "A mapping base_result must contain result_id"
                raise CandidateBindingError(msg)
            target_state["results"][result_id] = result
        else:
            msg = "base_result must be 'auto', None, a result ID, result or mapping"
            raise TypeError(msg)

        binding = {
            "result_id": result["result_id"],
            "lock_hash": result["lock_hash"],
            "installation_fingerprint": result["installation_fingerprint"],
        }
        return result, binding

    def _coerce_target(self, target: TargetRef | Mapping[str, Any] | str) -> TargetRef:
        if isinstance(target, TargetRef):
            return target
        if isinstance(target, str):
            msg = "Target ID strings are only valid for recovery lookups; generation requires a TargetRef"
            raise TypeError(msg)
        if isinstance(target, Mapping):
            data = dict(target)
            if "root" in data and "name" in data and "id" not in data:
                return TargetRef.create(**data)
            return TargetRef(**{key: value for key, value in data.items() if key in TargetRef.__dataclass_fields__})
        msg = f"Unsupported target type: {type(target).__name__}"
        raise TypeError(msg)

    def _ensure_target(self, state: dict[str, Any], target: TargetRef) -> dict[str, Any]:
        target_state = state["targets"].get(target.id)
        if target_state is None:
            target_state = {
                "target": target.to_dict(),
                "active_result_id": None,
                "pending_candidate_id": None,
                "last_verified_candidate_id": None,
                "candidates": {},
                "results": {},
            }
            state["targets"][target.id] = target_state
        else:
            target_state["target"] = target.to_dict()
        return target_state

    def _find_candidate(self, state: dict[str, Any], candidate_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        for target_state in state["targets"].values():
            candidate = target_state["candidates"].get(candidate_id)
            if candidate is not None:
                return target_state, candidate
        raise CandidateBindingError(f"Unknown switch candidate: {candidate_id}")

    def _find_active_result(self, state: dict[str, Any], target_id: str) -> dict[str, Any] | None:
        target_state = state["targets"].get(target_id)
        if target_state is None:
            return None
        result_id = target_state.get("active_result_id")
        if not result_id:
            return None
        return target_state["results"].get(result_id)

    def _initial_state(self) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "sequence": 0, "targets": {}, "lock_paths": {}}

    def _load_state(self) -> dict[str, Any]:
        if self.state_path.is_file():
            try:
                state = json.loads(self.state_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                state = self._replay_journal()
            else:
                if state.get("schema_version") != SCHEMA_VERSION:
                    msg = f"Unsupported switch state schema: {state.get('schema_version')!r}"
                    raise InvalidStateError(msg)
                return state
        elif self.journal_path.is_file():
            return self._replay_journal()
        return self._initial_state()

    def _replay_journal(self) -> dict[str, Any]:
        state = self._initial_state()
        for event in self.list_events():
            self._reduce_event(state, event)
        self._write_state(state)
        return state

    def _commit_event(self, state: dict[str, Any], event: dict[str, Any]) -> None:
        event["seq"] = int(state.get("sequence", 0)) + 1
        self._reduce_event(state, event)
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        with self.journal_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._write_state(state)

    def _record_decision(self, state: dict[str, Any], kind: str, decision: dict[str, Any]) -> None:
        event = {
            "type": "recovery_decision",
            "at": utc_now(),
            "decision_kind": kind,
            "action": decision.get("action"),
            "target_id": decision.get("target_id"),
            "candidate_id": decision.get("candidate_id"),
            "decision": decision,
        }
        self._commit_event(state, event)

    def _reduce_event(self, state: dict[str, Any], event: Mapping[str, Any]) -> None:
        event_type = event.get("type")
        state["sequence"] = max(int(state.get("sequence", 0)), int(event.get("seq", 0)))

        if event_type == "candidate_generated":
            candidate = event["candidate"]
            target_id = event["target_id"]
            target_state = state["targets"].setdefault(
                target_id,
                {
                    "target": event.get("target", {"id": target_id, "name": event.get("target_name", target_id)}),
                    "active_result_id": None,
                    "pending_candidate_id": None,
                    "last_verified_candidate_id": None,
                    "candidates": {},
                    "results": {},
                },
            )
            target_state["candidates"][candidate["candidate_id"]] = candidate
            if candidate.get("phase") != STATE_VERIFIED:
                target_state["pending_candidate_id"] = candidate["candidate_id"]
            state["lock_paths"][event["shared_lock_path"]] = event["lock_path_record"]

        elif event_type == "lock_path_written":
            state["lock_paths"][event["shared_lock_path"]] = event["lock_path_record"]

        elif event_type == "apply_started":
            _, candidate = self._find_candidate(state, event["candidate_id"])
            candidate["phase"] = STATE_APPLY_STARTED
            candidate["attempts"] = event["attempt"]
            candidate["updated_at"] = event["at"]
            target_state, _ = self._find_candidate(state, event["candidate_id"])
            target_state["pending_candidate_id"] = event["candidate_id"]

        elif event_type in {"apply_interrupted", "apply_failed"}:
            _, candidate = self._find_candidate(state, event["candidate_id"])
            candidate["phase"] = event["phase"]
            candidate["last_error"] = event.get("error")
            candidate["updated_at"] = event["at"]

        elif event_type == "verification_passed":
            result = event["result"]
            target_state, candidate = self._find_candidate(state, event["candidate_id"])
            candidate["phase"] = STATE_VERIFIED
            candidate["updated_at"] = event["at"]
            target_state["results"][result["result_id"]] = result
            target_state["active_result_id"] = result["result_id"]
            target_state["last_verified_candidate_id"] = event["candidate_id"]
            target_state["pending_candidate_id"] = None

        elif event_type == "recovery_decision":
            return

    def _ensure_gitignore(self) -> None:
        gitignore = self.directory / ".gitignore"
        if not gitignore.is_file():
            self._atomic_write_text(gitignore, "# Automatically created by Hatch\n*\n")

    def _write_state(self, state: Mapping[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._atomic_write_text(self.state_path, json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True))

    @staticmethod
    def _atomic_write_bytes(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        try:
            with temporary.open("wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    @classmethod
    def _atomic_write_text(cls, path: Path, text: str) -> None:
        cls._atomic_write_bytes(path, text.encode("utf-8"))
