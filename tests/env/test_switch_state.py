from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from hatch.env.switch_state import (
    ACTION_REGENERATE_CANDIDATE,
    ACTION_RESUME_CANDIDATE,
    ACTION_START_VERIFIED,
    LockInputs,
    SwitchOptions,
    SwitchStateStore,
    TargetRef,
    canonical_digest,
    digest_file,
)
from hatch.utils.toml import load_toml_data

if TYPE_CHECKING:
    from collections.abc import Mapping


class InstallationInterrupted(RuntimeError):
    """Synthetic power/process failure during package application."""


class SyntheticEnvironment:
    """A tiny install prefix whose contents stand in for a virtualenv."""

    def __init__(self, name: str, root: Path) -> None:
        self.name = name
        self.workdir = root / "work"
        self.target = TargetRef.create(
            name,
            self.workdir,
            env_path=root / "venvs" / name,
            metadata={"synthetic": True},
        )
        self.prefix = root / "installed" / name
        self.receipt = self.prefix / "installed.json"

    def read_installed(self) -> dict[str, str]:
        if not self.receipt.is_file():
            return {}
        return json.loads(self.receipt.read_text(encoding="utf-8"))

    def fingerprint(self) -> str:
        return canonical_digest({"target": self.target.id, "packages": self.read_installed()})

    def apply_lock(self, lock_path: Path, *, fail_during_apply: bool = False) -> None:
        packages = parse_synthetic_lock(lock_path.read_text(encoding="utf-8"))
        self.prefix.mkdir(parents=True, exist_ok=True)

        if fail_during_apply:
            first_package = next(iter(packages))
            self._write_installed({first_package: packages[first_package]})
            raise InstallationInterrupted(f"synthetic abort after installing {first_package}")

        self._write_installed(dict(packages))

    def verify_lock(self, lock_path: Path) -> dict[str, object]:
        expected = parse_synthetic_lock(lock_path.read_text(encoding="utf-8"))
        installed = self.read_installed()
        if installed != expected:
            msg = f"{self.name}: installed packages {installed!r} do not match {expected!r}"
            raise AssertionError(msg)
        return {"packages": installed, "installation_fingerprint": self.fingerprint()}

    def _write_installed(self, packages: Mapping[str, str]) -> None:
        self.receipt.parent.mkdir(parents=True, exist_ok=True)
        self.receipt.write_text(json.dumps(dict(packages), sort_keys=True), encoding="utf-8")


def render_synthetic_lock(switch_set: str, packages: Mapping[str, str]) -> str:
    lines = [
        'lock-version = "1"',
        f'switch-set = "{switch_set}"',
        "",
    ]
    for name, version in sorted(packages.items()):
        lines.append("[[packages]]")
        lines.append(f'name = "{name}"')
        lines.append(f'version = "{version}"')
        lines.append("")
    return "\n".join(lines)


def parse_synthetic_lock(content: str) -> dict[str, str]:
    data = load_toml_data(content)
    packages = {item["name"]: item["version"] for item in data["packages"]}
    return dict(sorted(packages.items()))


def run_two_environment_evidence(root: Path) -> dict[str, object]:
    workdir = root / "work"
    workdir.mkdir(parents=True, exist_ok=True)
    shared_lock_path = workdir / "pylock.toml"
    store = SwitchStateStore(root / ".hatch" / "switch-state")

    daily = SyntheticEnvironment("daily", root)
    approved = SyntheticEnvironment("approved-patches", root)

    daily_packages = {"alpha": "1.0.0", "daily-only": "1.2.0"}
    approved_base_packages = {"alpha": "1.0.1", "patch-only": "2.0.0"}
    approved_next_packages = {"alpha": "1.0.2", "patch-only": "2.0.1"}

    def generate(
        env: SyntheticEnvironment,
        switch_set: str,
        packages: Mapping[str, str],
        *,
        at: str,
        base_result: str | None = None,
    ):
        content = render_synthetic_lock(switch_set, packages)
        shared_lock_path.write_text(content, encoding="utf-8")
        options = SwitchOptions(switch_set=switch_set, locker="synthetic")
        inputs = LockInputs(dependencies=tuple(f"{name}=={version}" for name, version in packages.items()))
        return store.record_generated(
            target=env.target,
            lock_content=content,
            lock_path=shared_lock_path,
            options=options,
            lock_inputs=inputs,
            base_result=base_result,
            created_at=at,
        )

    def verify(candidate, env: SyntheticEnvironment, result_id: str, at: str):
        evidence = env.verify_lock(Path(candidate.artifact_path))
        return store.record_verification_passed(
            candidate.candidate_id,
            verifier="synthetic-exact-package-map-v1",
            installation_fingerprint=env.fingerprint(),
            evidence=evidence,
            result_id=result_id,
            at=at,
        )

    daily_candidate = generate(daily, "daily", daily_packages, at="2026-11-26T00:00:01+00:00")
    store.begin_apply(daily_candidate.candidate_id, at="2026-11-26T00:00:02+00:00")
    daily.apply_lock(Path(daily_candidate.artifact_path))
    daily_result = verify(daily_candidate, daily, "result-daily-v1", "2026-11-26T00:00:03+00:00")

    approved_base_candidate = generate(
        approved, "approved-patches", approved_base_packages, at="2026-11-26T00:00:04+00:00"
    )
    store.begin_apply(approved_base_candidate.candidate_id, at="2026-11-26T00:00:05+00:00")
    approved.apply_lock(Path(approved_base_candidate.artifact_path))
    approved_base_result = verify(approved_base_candidate, approved, "result-approved-v1", "2026-11-26T00:00:06+00:00")

    next_options = SwitchOptions(switch_set="approved-patches", locker="synthetic")
    next_inputs = LockInputs(
        dependencies=tuple(f"{name}=={version}" for name, version in approved_next_packages.items())
    )
    next_candidate = generate(
        approved,
        "approved-patches",
        approved_next_packages,
        at="2026-11-26T00:00:07+00:00",
        base_result=approved_base_result.result_id,
    )

    started = store.begin_apply(next_candidate.candidate_id, at="2026-11-26T00:00:08+00:00")
    partial_install_after_abort: dict[str, str] = {}
    try:
        approved.apply_lock(Path(started.artifact_path), fail_during_apply=True)
    except InstallationInterrupted as exc:
        partial_install_after_abort = approved.read_installed()
        interrupted = store.record_apply_failure(
            next_candidate.candidate_id,
            exc,
            interrupted=True,
            evidence={"partial_install": partial_install_after_abort},
            at="2026-11-26T00:00:09+00:00",
        )
    else:  # pragma: no cover - test fixture must abort
        msg = "synthetic installation did not abort"
        raise AssertionError(msg)

    state_after_abort = store.read_state()
    assert state_after_abort["targets"][approved.target.id]["active_result_id"] == "result-approved-v1"
    assert state_after_abort["targets"][approved.target.id]["pending_candidate_id"] == next_candidate.candidate_id

    old_env_startup = store.startup_plan(daily.target)
    retry_before_foreign_write = store.retry_plan(
        approved.target,
        options=next_options,
        lock_inputs=next_inputs,
    )

    # The other environment rewrites the accidentally shared path with its own
    # already-verified daily lock.  The approved candidate remains archived.
    shared_lock_path.write_text(render_synthetic_lock("daily", daily_packages), encoding="utf-8")
    store.record_lock_path_write(daily_candidate.candidate_id, at="2026-11-26T00:00:10+00:00")

    retry_after_foreign_write = store.retry_plan(
        approved.target,
        options=next_options,
        lock_inputs=next_inputs,
    )
    restored_daily_lock = store.restore_verified_result(daily.target, root / "restored" / "pylock.daily.toml")

    retry_started = store.begin_apply(next_candidate.candidate_id, at="2026-11-26T00:00:11+00:00")
    approved.apply_lock(Path(retry_started.artifact_path))
    approved_next_result = verify(next_candidate, approved, "result-approved-v2", "2026-11-26T00:00:12+00:00")
    approved_startup_after_retry = store.startup_plan(approved.target)

    state = store.read_state()
    journal_states = [
        {
            "seq": event["seq"],
            "at": event["at"],
            "event": event["type"],
            "state": event.get("phase") or event.get("action"),
            "target": event.get("target_id"),
            "candidate": event.get("candidate_id"),
            "result": event.get("result_id"),
            "attempt": event.get("attempt"),
        }
        for event in store.list_events()
        if event["type"] in {"candidate_generated", "apply_started", "apply_interrupted", "verification_passed"}
    ]

    evidence = {
        "shared_lock_path": str(shared_lock_path),
        "shared_lock_now_hash": digest_file(shared_lock_path),
        "daily_lock_hash": daily_candidate.lock_hash,
        "approved_next_hash": next_candidate.lock_hash,
        "shared_lock_conflicts": store.shared_lock_conflicts(),
        "actual_approved_install_after_abort": partial_install_after_abort,
        "actual_approved_install_after_retry": approved.read_installed(),
        "old_environment_startup": old_env_startup.to_dict(),
        "retry_before_foreign_write": retry_before_foreign_write.to_dict(),
        "retry_after_foreign_write": retry_after_foreign_write.to_dict(),
        "restored_daily_lock": str(restored_daily_lock),
        "approved_startup_after_retry": approved_startup_after_retry.to_dict(),
        "final_active_results": {
            "daily": state["targets"][daily.target.id]["active_result_id"],
            "approved": state["targets"][approved.target.id]["active_result_id"],
        },
        "journal_states": journal_states,
    }

    assert daily_result.result_id == "result-daily-v1"
    assert approved_base_result.result_id == "result-approved-v1"
    assert interrupted.phase == "apply_interrupted"
    assert interrupted.attempts == 1
    assert partial_install_after_abort == {"alpha": "1.0.2"}

    assert old_env_startup.action == ACTION_START_VERIFIED
    assert old_env_startup.result_id == "result-daily-v1"
    assert old_env_startup.ownership is not None
    assert old_env_startup.ownership["owner_name"] == "daily"
    assert old_env_startup.ownership["switch_set"] == "daily"
    assert "daily-only==1.2.0" in old_env_startup.ownership["dependencies"]
    assert old_env_startup.shared_lock_status == "foreign_target"

    assert retry_before_foreign_write.action == ACTION_RESUME_CANDIDATE
    assert retry_before_foreign_write.candidate_id == next_candidate.candidate_id
    assert retry_before_foreign_write.shared_lock_status == "intact"

    assert retry_after_foreign_write.action == ACTION_RESUME_CANDIDATE
    assert retry_after_foreign_write.candidate_id == next_candidate.candidate_id
    assert retry_after_foreign_write.trusted_lock_path == next_candidate.artifact_path
    assert retry_after_foreign_write.shared_lock_status == "foreign_target"
    assert retry_after_foreign_write.shared_lock_owner_id == daily.target.id
    assert retry_after_foreign_write.shared_lock_hash == daily_candidate.lock_hash
    assert digest_file(Path(retry_after_foreign_write.trusted_lock_path)) == next_candidate.lock_hash

    assert digest_file(restored_daily_lock) == daily_candidate.lock_hash
    assert parse_synthetic_lock(restored_daily_lock.read_text(encoding="utf-8")) == daily_packages

    assert retry_started.attempts == 2
    assert retry_started.phase == "apply_started"
    assert approved_next_result.result_id == "result-approved-v2"
    assert approved_startup_after_retry.action == ACTION_START_VERIFIED
    assert approved_startup_after_retry.result_id == "result-approved-v2"
    assert state["targets"][approved.target.id]["pending_candidate_id"] is None
    assert digest_file(shared_lock_path) == daily_candidate.lock_hash

    assert any(
        entry["lock_path"] == str(shared_lock_path.resolve())
        and set(entry["target_ids"]) == {daily.target.id, approved.target.id}
        for entry in evidence["shared_lock_conflicts"]
    )

    generated = [item for item in journal_states if item["event"] == "candidate_generated"]
    applying = [item for item in journal_states if item["event"] == "apply_started"]
    verified = [item for item in journal_states if item["event"] == "verification_passed"]
    assert generated and applying and verified
    next_generated = next(item for item in generated if item["candidate"] == next_candidate.candidate_id)
    next_apply_first = next(
        item for item in applying if item["candidate"] == next_candidate.candidate_id and item["attempt"] == 1
    )
    next_verified = next(item for item in verified if item["result"] == "result-approved-v2")
    assert next_generated["seq"] < next_apply_first["seq"] < next_verified["seq"]
    assert next_generated["state"] == "generated"
    assert next_apply_first["state"] == "apply_started"
    assert next_verified["state"] == "verified"

    return evidence


def test_two_synthetic_environments_sharing_lock_recover_to_bound_results(tmp_path: Path) -> None:
    evidence = run_two_environment_evidence(tmp_path)
    print("\nSWITCH_RECOVERY_EVIDENCE=" + json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True))

    # A new store object must recover the same state from state.json/journal.
    reopened = SwitchStateStore(tmp_path / ".hatch" / "switch-state")
    recovered = reopened.retry_plan(
        TargetRef.create(
            "approved-patches",
            tmp_path / "work",
            env_path=tmp_path / "venvs" / "approved-patches",
            metadata={"synthetic": True},
        ),
        record_decision=False,
    )
    assert recovered.action == ACTION_REGENERATE_CANDIDATE
    assert "no interrupted or pending candidate" in recovered.reason
    assert (
        reopened.startup_plan(
            TargetRef.create(
                "approved-patches",
                tmp_path / "work",
                env_path=tmp_path / "venvs" / "approved-patches",
                metadata={"synthetic": True},
            ),
            record_decision=False,
        ).result_id
        == "result-approved-v2"
    )


def test_retry_rejects_binding_drift_and_missing_artifact(tmp_path: Path) -> None:
    store = SwitchStateStore(tmp_path / "state")
    target = TargetRef.create("synthetic", tmp_path)
    shared_lock = tmp_path / "pylock.toml"
    shared_lock.write_text("a==1.0.0\n", encoding="utf-8")
    options = SwitchOptions(switch_set="daily", locker="synthetic")
    inputs = LockInputs(dependencies=("a==1.0.0",))
    candidate = store.record_generated(
        target=target,
        lock_content="a==1.0.0\n",
        lock_path=shared_lock,
        options=options,
        lock_inputs=inputs,
        base_result=None,
    )

    matching = store.retry_plan(target, options=options, lock_inputs=inputs, record_decision=False)
    assert matching.action == ACTION_RESUME_CANDIDATE
    assert matching.candidate_id == candidate.candidate_id

    changed_options = store.retry_plan(
        target,
        options=SwitchOptions(switch_set="approved", locker="synthetic"),
        lock_inputs=inputs,
        record_decision=False,
    )
    assert changed_options.action == "regenerate_candidate"
    assert "options do not match" in changed_options.reason

    changed_inputs = store.retry_plan(
        target,
        options=options,
        lock_inputs=LockInputs(dependencies=("a==2.0.0",)),
        record_decision=False,
    )
    assert changed_inputs.action == "regenerate_candidate"
    assert "lock inputs do not match" in changed_inputs.reason

    Path(candidate.artifact_path).unlink()
    missing_artifact = store.retry_plan(target, options=options, lock_inputs=inputs, record_decision=False)
    assert missing_artifact.action == "regenerate_candidate"
    assert "archived candidate lock is missing" in missing_artifact.reason


def test_startup_detects_tampered_result_and_replays_journal(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    store = SwitchStateStore(state_dir)
    target = TargetRef.create("synthetic", tmp_path)
    lock_path = tmp_path / "pylock.toml"
    candidate = store.record_generated(
        target=target,
        lock_content="a==1.0.0\n",
        lock_path=lock_path,
        base_result=None,
    )
    store.begin_apply(candidate.candidate_id)
    store.record_verification_passed(
        candidate.candidate_id,
        verifier="test",
        installation_fingerprint={"packages": {"a": "1.0.0"}},
        result_id="result-1",
    )

    startup = store.startup_plan(target, record_decision=False)
    assert startup.action == ACTION_START_VERIFIED
    assert startup.result_id == "result-1"

    Path(startup.result_path).write_text("a==9.9.9\n", encoding="utf-8")
    tampered = store.startup_plan(target, record_decision=False)
    assert tampered.action == "verified_result_unavailable"

    # Restore the content-addressed artifact, then lose the atomic snapshot.
    original = store.get_candidate(candidate.candidate_id)
    Path(original.artifact_path).write_text("a==1.0.0\n", encoding="utf-8")
    store.state_path.unlink()
    replayed = SwitchStateStore(state_dir).startup_plan(target, record_decision=False)
    assert replayed.action == ACTION_START_VERIFIED
    assert replayed.result_id == "result-1"


def test_hatch_environment_adapter_records_generation(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from hatch.env.lock import LockGenerationState
    from hatch.env.switch_state import (
        SwitchStateStore,
        record_generation_for_environment,
    )

    lock_path = tmp_path / "pylock.toml"
    lock_path.write_text('lock-version = "1"\n', encoding="utf-8")
    environment = SimpleNamespace(
        name="default",
        root=tmp_path,
        virtual_env_path=tmp_path / ".venv",
        config={"python": "3.12", "installer": "uv", "locker": "uv"},
        features=("security",),
        dependency_groups=("dev",),
        locked=True,
        PLUGIN_NAME="virtual",
    )
    generation_state = LockGenerationState(
        dependencies=["requests==2.32.0"],
        layered=True,
        lock_extras=("security",),
        lock_groups=("dev",),
    )

    candidate = record_generation_for_environment(
        environment,
        lock_path,
        generation_state=generation_state,
        upgrade_packages=("requests",),
    )

    store = SwitchStateStore.for_project(tmp_path)
    plan = store.retry_plan(
        candidate.target_id,
        options={
            "switch_set": None,
            "locker": "uv",
            "locked": True,
            "upgrade": False,
            "extras": ["security"],
            "groups": ["dev"],
            "arguments": [],
            "metadata": {
                "upgrade_packages": ["requests"],
                "deps_override": None,
            },
        },
        lock_inputs={
            "dependencies": ["requests==2.32.0"],
            "layered": True,
            "lock_extras": ["security"],
            "lock_groups": ["dev"],
            "input_hashes": {},
            "metadata": {},
        },
        record_decision=False,
    )
    assert plan.action == ACTION_RESUME_CANDIDATE
    assert plan.candidate_id == candidate.candidate_id


def _simple_hatch_environment(tmp_path: Path):
    from types import SimpleNamespace

    return SimpleNamespace(
        name="default",
        root=tmp_path,
        virtual_env_path=tmp_path / ".venv",
        config={},
        features=(),
        dependency_groups=(),
        locked=True,
    )


def test_apply_lockfile_wrapper_uses_archived_candidate_after_foreign_write(tmp_path: Path, monkeypatch) -> None:
    import hatch.env.lock as lock_module
    from hatch.env.switch_state import target_for_environment

    environment = _simple_hatch_environment(tmp_path)
    shared_lock = tmp_path / "pylock.toml"
    shared_lock.write_text("approved candidate\n", encoding="utf-8")
    store = SwitchStateStore.for_project(tmp_path)
    target = target_for_environment(environment)
    candidate = store.record_generated(
        target=target,
        lock_content="approved candidate\n",
        lock_path=shared_lock,
        base_result=None,
    )

    # Another environment now owns the shared path.
    shared_lock.write_text("daily lock from another target\n", encoding="utf-8")

    applied_paths: list[Path] = []

    def fake_apply(_environment, path):
        applied_paths.append(Path(path))

    monkeypatch.setattr(lock_module, "apply_lock_with_locker", fake_apply)
    monkeypatch.setattr(
        lock_module,
        "verify_applied_lock",
        lambda _environment, path: (True, {"path": str(path)}, {"packages": {"alpha": "1.0.2"}}),
    )

    lock_module.apply_lockfile_to_environment(environment, shared_lock)

    assert applied_paths == [Path(candidate.artifact_path)]
    updated = store.get_candidate(candidate.candidate_id)
    assert updated.phase == "verified"
    assert updated.attempts == 1
    assert store.startup_plan(target, record_decision=False).result_id is not None


def test_apply_lockfile_wrapper_records_keyboard_interrupt(tmp_path: Path, monkeypatch) -> None:
    import hatch.env.lock as lock_module
    from hatch.env.switch_state import target_for_environment

    environment = _simple_hatch_environment(tmp_path)
    shared_lock = tmp_path / "pylock.toml"
    shared_lock.write_text("first\n", encoding="utf-8")
    store = SwitchStateStore.for_project(tmp_path)
    target = target_for_environment(environment)
    first = store.record_generated(
        target=target,
        lock_content="first\n",
        lock_path=shared_lock,
        base_result=None,
    )
    store.begin_apply(first.candidate_id)
    store.record_verification_passed(
        first.candidate_id, verifier="test", installation_fingerprint={"v": 1}, result_id="result-1"
    )

    shared_lock.write_text("second\n", encoding="utf-8")
    second = store.record_generated(target=target, lock_content="second\n", lock_path=shared_lock, base_result="auto")

    def interrupt(_environment, _path):
        raise KeyboardInterrupt

    monkeypatch.setattr(lock_module, "apply_lock_with_locker", interrupt)

    with pytest.raises(KeyboardInterrupt):
        lock_module.apply_lockfile_to_environment(environment, shared_lock)

    interrupted = store.get_candidate(second.candidate_id)
    assert interrupted.phase == "apply_interrupted"
    assert interrupted.attempts == 1
    assert store.read_state()["targets"][target.id]["active_result_id"] == "result-1"
