"""Pre-release validation preflight and enforcement evidence.

Adds a *policy* layer on top of the existing ``Validator`` rules. Preflight
(dry-run) and runtime enforcement share one evaluation engine and the very
same validator objects, so a release decision is based on exactly the rules
that will later run.

Key ideas
---------
* Per-environment rollout: one environment can stay in ``warn`` mode while
  another already uses ``enforce``.
* Non destructive preflight: it evaluates isolated copies, so defaults/casts
  and failure fallbacks never touch the caller's settings.
* Runtime-dependent candidates: values that only exist once the runtime is
  known (e.g. ``@format``/``@get`` lazy values) are reported as ``pending``
  ("to be checked") instead of pass/fail.
* Enforcement evidence: a structured report records the ruleset version and
  digest, the runtime decision and, on failure, the approved values that the
  application can still read.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import warnings
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any
from typing import Iterable
from typing import Sequence

from dynaconf.loaders.base import SourceMetadata
from dynaconf.nodes import DataDict
from dynaconf.utils import ensure_a_list
from dynaconf.utils import find_the_correct_casing
from dynaconf.utils import upperfy
from dynaconf.utils.functional import empty
from dynaconf.utils.parse_conf import Lazy
from dynaconf.validator import ValidationError
from dynaconf.validator import Validator

VALID_MODES = ("off", "warn", "enforce")
VALID_FAILURES = ("raise", "fallback", "warn")

PASSED = "passed"
FAILED = "failed"
PENDING = "pending"
SKIPPED = "skipped"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Rule signature / versioning
# ---------------------------------------------------------------------------


def _normalize(value: Any) -> Any:
    """Turn rule values into something json serializable and stable."""
    if isinstance(value, type):
        return f"type:{value.__qualname__}"
    if callable(value):
        return f"callable:{getattr(value, '__qualname__', repr(value))}"
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_normalize(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _validator_signature(validator: Validator) -> dict:
    if getattr(validator, "validators", None):
        return {
            "kind": type(validator).__name__,
            "validators": [
                _validator_signature(item) for item in validator.validators
            ],
        }
    return {
        "kind": type(validator).__name__,
        "names": [str(name) for name in validator.names],
        "must_exist": validator.must_exist,
        "operations": {
            key: _normalize(value)
            for key, value in validator.operations.items()
        },
        "envs": list(validator.envs) if validator.envs else None,
        "when": (
            _validator_signature(validator.when) if validator.when else None
        ),
        "condition": _normalize(validator.condition),
        "default": _normalize(validator.default),
        "items_validators": [
            _validator_signature(item)
            for item in validator.items_validators
        ],
        "description": validator.description,
    }


def build_ruleset(validators: Iterable[Validator], version: str = "") -> dict:
    """Return the canonical description and digest of a rule set."""
    signatures = [_validator_signature(v) for v in validators]
    payload = json.dumps(
        signatures, sort_keys=True, default=str, separators=(",", ":")
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {
        "version": version or "auto",
        "digest": digest,
        "short_digest": digest[:12],
        "count": len(signatures),
        "rules": signatures,
    }


def ruleset_label(ruleset_data: dict) -> str:
    version = ruleset_data.get("version", "auto")
    short = ruleset_data.get("short_digest", "")
    return f"{version}+{short}" if short else version


# ---------------------------------------------------------------------------
# Policy object
# ---------------------------------------------------------------------------


@dataclass
class ValidationPolicy:
    """Rollout policy for validators.

    :param modes: mapping of environment name to ``off``/``warn``/``enforce``
        (matched case-insensitively).
    :param default_mode: mode for environments missing from ``modes``.
    :param version: human readable ruleset version (e.g. ``"2026.11"``).
    :param approved: inline approved values keyed by environment.
    :param approved_file: JSON file holding approved values + approval meta.
    :param runtime_dependent: extra key names that must be reported as
        ``pending`` during preflight because they depend on runtime state.
    :param evidence_file: optional path where evidence JSON is written.
    :param on_failure: what enforcement does when validation fails:
        ``"fallback"`` (use approved values and continue), ``"warn"`` or
        ``"raise"``.
    """

    modes: dict[str, str] = field(default_factory=dict)
    default_mode: str = "warn"
    version: str = ""
    approved: dict[str, dict] = field(default_factory=dict)
    approved_file: str | Path | None = None
    runtime_dependent: list[str] = field(default_factory=list)
    evidence_file: str | Path | None = None
    on_failure: str = "fallback"

    approval_meta: dict = field(default_factory=dict, init=False)

    def __post_init__(self):
        self.modes = {
            str(env).upper(): str(mode).lower()
            for env, mode in (self.modes or {}).items()
        }
        for env, mode in self.modes.items():
            if mode not in VALID_MODES:
                raise ValueError(
                    f"invalid validation mode {mode!r} for env {env!r}; "
                    f"expected one of {VALID_MODES}"
                )
        self.default_mode = str(self.default_mode).lower()
        if self.default_mode not in VALID_MODES:
            raise ValueError(
                f"invalid default_mode {self.default_mode!r}; "
                f"expected one of {VALID_MODES}"
            )
        self.on_failure = str(self.on_failure).lower()
        if self.on_failure not in VALID_FAILURES:
            raise ValueError(
                f"invalid on_failure {self.on_failure!r}; "
                f"expected one of {VALID_FAILURES}"
            )
        self.runtime_dependent = [
            upperfy(name) for name in (self.runtime_dependent or [])
        ]
        self.approved = {
            str(env).upper(): dict(values)
            for env, values in (self.approved or {}).items()
        }
        self._load_approved_file()

    def _load_approved_file(self):
        if not self.approved_file:
            return
        path = Path(self.approved_file)
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:  # pragma: no cover - defensive
            warnings.warn(
                f"[dynaconf validation] could not read approved file "
                f"{path}: {e}",
                RuntimeWarning,
                stacklevel=2,
            )
            return
        self.approval_meta = {
            "approved_at": data.get("approved_at"),
            "ruleset": data.get("ruleset") or {},
            "source": str(path),
        }
        for env, values in (data.get("environments") or {}).items():
            self.approved.setdefault(str(env).upper(), dict(values))

    def mode_for(self, env: str | None) -> str:
        if env is None:
            return self.default_mode
        return self.modes.get(str(env).upper(), self.default_mode)

    def approved_for(self, env: str | None) -> dict:
        if env is None:
            return {}
        return dict(self.approved.get(str(env).upper(), {}))

    def copy(self) -> ValidationPolicy:
        return copy.deepcopy(self)


def as_policy(value: Any) -> ValidationPolicy | None:
    if value is None:
        return None
    if isinstance(value, ValidationPolicy):
        return value
    if isinstance(value, dict):
        return ValidationPolicy(**value)
    raise TypeError(
        "validation_policy must be a ValidationPolicy or a dict, "
        f"got {type(value)!r}"
    )


# ---------------------------------------------------------------------------
# Runtime-dependent detection
# ---------------------------------------------------------------------------


def _raw_get(settings: Any, dotted_name: str) -> Any:
    """Get a raw (non evaluated) value, bypassing lazy evaluation."""
    current = getattr(getattr(settings, "__core__", None), "store", settings)
    for part in dotted_name.split("."):
        if isinstance(current, dict):
            key = find_the_correct_casing(part, tuple(current.keys()))
            if key is None or key not in current:
                return empty
            if isinstance(current, DataDict):
                current = current.get(key, bypass_eval=True)
            else:
                current = current[key]
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return empty
        else:
            return current
    return current


LAZY_TOKENS = ("@format", "@jinja", "@get", "@read_file")


def _contains_lazy(value: Any) -> bool:
    if isinstance(value, Lazy):
        return True
    if isinstance(value, str):
        return any(token in value for token in LAZY_TOKENS)
    if isinstance(value, dict):
        return any(_contains_lazy(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_lazy(v) for v in value)
    return False


def _raw_source_value(settings: Any, dotted_name: str) -> Any:
    """Look up a value in the *source* data recorded by the loaders.

    Unlike the settings store this is not evaluated, so it still shows
    ``@format``/``@get`` markers after the runtime resolved them.
    """
    sources = getattr(settings, "loaded_by_loaders", None) or {}
    parts = dotted_name.split(".")
    for data in sources.values():
        current: Any = data
        for part in parts:
            if isinstance(current, dict):
                key = find_the_correct_casing(part, tuple(current.keys()))
                if key is None or key not in current:
                    current = empty
                    break
                current = current[key]
            else:
                current = empty
                break
        if current is not empty:
            return current
    return empty


def leaf_validators(validators: Iterable[Validator]) -> Iterable[Validator]:
    for validator in validators:
        inner = getattr(validator, "validators", None)
        if inner:
            yield from leaf_validators(inner)
        else:
            yield validator


def validator_names(validator: Validator) -> list[str]:
    return [str(name) for name in validator.names]


def applies_to_env(validator: Validator, env: str) -> bool:
    if not validator.envs:
        return True
    return any(
        str(item).upper() == str(env).upper() for item in validator.envs
    )


def explicit_runtime_dependent(policy: ValidationPolicy | None) -> set[str]:
    """Names the policy explicitly declares as runtime dependent."""
    return set(policy.runtime_dependent) if policy else set()


def runtime_dependent_names(
    settings: Any,
    validators: Sequence[Validator],
    policy: ValidationPolicy | None = None,
) -> set[str]:
    """Names whose rule cannot be decided without the running application.

    Used by preflight: lazy values (``@format``/``@get``/``@jinja``) and names
    explicitly declared on the policy are reported as pending there.
    """
    names: set[str] = set()
    explicit = explicit_runtime_dependent(policy)
    for validator in leaf_validators(validators):
        for name in validator_names(validator):
            if upperfy(name) in explicit:
                names.add(name)
                continue
            raw = _raw_get(settings, name)
            source = _raw_source_value(settings, name)
            if _contains_lazy(raw) or _contains_lazy(source):
                names.add(name)
                continue
            if raw is empty and _contains_lazy(validator.default):
                names.add(name)
    return names


# ---------------------------------------------------------------------------
# Shared rule evaluation engine (preflight AND runtime)
# ---------------------------------------------------------------------------


def _result(name: str, status: str, message: str, validator: Any) -> dict:
    return {
        "name": name,
        "status": status,
        "message": message,
        "rule": repr(validator),
    }


def _clone_validator(validator: Validator) -> Validator:
    """Shallow copy a validator, isolating the mutable ``when`` chain.

    ``Validator.validate`` mutates ``when.envs`` and ``messages``, so copies
    must not share those nested objects between environments.
    """
    proxy = copy.copy(validator)
    proxy.messages = dict(validator.messages)
    inner = getattr(validator, "validators", None)
    if inner is not None:
        proxy.validators = tuple(_clone_validator(item) for item in inner)
        return proxy
    proxy.operations = dict(validator.operations)
    proxy.items_validators = [
        _clone_validator(item) for item in validator.items_validators
    ]
    if validator.when is not None:
        proxy.when = _clone_validator(validator.when)
    return proxy


def _validate_one(
    validator: Validator, settings: Any, env: str, name: str
) -> dict:
    """Evaluate one name with an isolated copy restricted to ``env``."""
    proxy = _clone_validator(validator)
    proxy.names = (name,)
    proxy.envs = (env,)
    try:
        # do not forward ``only``: it would also filter the ``when`` chain and
        # change the semantics compared to a plain validate() call.
        proxy.validate(settings, only_current_env=True)
    except ValidationError as e:
        return _result(name, FAILED, str(e), validator)
    return _result(name, PASSED, "", validator)


def _when_state(
    validator: Validator,
    settings: Any,
    env: str,
    pending: set[str],
) -> str:
    """Whether the ``when`` precondition holds: active/inactive/pending."""
    when = validator.when
    if when is None:
        return "active"
    when_names = set()
    for leaf in leaf_validators([when]):
        when_names.update(validator_names(leaf))
    if when_names & pending:
        return "pending"
    proxy = _clone_validator(when)
    proxy.envs = (env,)
    try:
        proxy.validate(settings, only_current_env=True)
    except ValidationError:
        return "inactive"
    return "active"


def _failed_names(validator: Validator, message: str) -> list[str]:
    names = validator_names(validator)
    lowered = message.lower()
    matched = [name for name in names if name.lower() in lowered]
    return matched or names


def _select_names(
    names: Iterable[str],
    only: Sequence[str] | None,
    exclude: Sequence[str] | None,
) -> list[str]:
    selected = []
    for name in names:
        if only and not any(name.startswith(sub) for sub in only):
            continue
        if exclude and any(name.startswith(sub) for sub in exclude):
            continue
        selected.append(name)
    return selected


def evaluate_environment(
    settings: Any,
    validators: Sequence[Validator],
    env: str,
    pending: Iterable[str] = (),
    only: str | Sequence[str] | None = None,
    exclude: str | Sequence[str] | None = None,
) -> dict:
    """Run *the same rules* against one environment without raising."""
    env = str(env).upper()
    pending = set(pending)
    only_list = ensure_a_list(only) or None
    exclude_list = ensure_a_list(exclude) or None
    results: list[dict] = []

    for validator in validators:
        inner = getattr(validator, "validators", None)
        if inner:
            combined_names: list[str] = []
            for leaf in leaf_validators([validator]):
                if applies_to_env(leaf, env):
                    combined_names.extend(validator_names(leaf))
            if not combined_names:
                continue
            waiting = {n for n in combined_names if n in pending}
            for name in waiting:
                results.append(
                    _result(
                        name,
                        PENDING,
                        "depends on runtime state; awaiting proof",
                        validator,
                    )
                )
            if len(waiting) == len(set(combined_names)):
                continue
            proxy = _clone_validator(validator)
            proxy.validators = tuple(
                _leaf_for_env(item, env) for item in validator.validators
            )
            try:
                proxy.validate(settings, only_current_env=True)
            except ValidationError as e:
                failed = set(_failed_names(validator, str(e)))
                for name in failed - waiting:
                    results.append(_result(name, FAILED, str(e), validator))
                for name in set(combined_names) - failed - waiting:
                    results.append(_result(name, PASSED, "", validator))
            else:
                for name in set(combined_names) - waiting:
                    results.append(_result(name, PASSED, "", validator))
            continue

        if not applies_to_env(validator, env):
            continue

        names = _select_names(
            validator_names(validator), only_list, exclude_list
        )
        waiting = {n for n in names if n in pending}
        when_state = _when_state(validator, settings, env, pending)
        for name in names:
            if name in waiting:
                results.append(
                    _result(
                        name,
                        PENDING,
                        "depends on runtime state; awaiting proof",
                        validator,
                    )
                )
            elif when_state == "inactive":
                results.append(
                    _result(
                        name,
                        SKIPPED,
                        "validation skipped: `when` precondition not met",
                        validator,
                    )
                )
            else:
                results.append(_validate_one(validator, settings, env, name))
    return summarize(env, results)


def _leaf_for_env(validator: Validator, env: str) -> Validator:
    proxy = _clone_validator(validator)
    proxy.names = tuple(validator_names(validator))
    proxy.envs = (env,)
    return proxy


def summarize(env: str, results: list[dict]) -> dict:
    failed = [r for r in results if r["status"] == FAILED]
    pending = [r for r in results if r["status"] == PENDING]
    skipped = [r for r in results if r["status"] == SKIPPED]
    if failed:
        outcome = "failed"
    elif pending:
        outcome = "pending"
    else:
        outcome = "passed"
    return {
        "env": str(env),
        "outcome": outcome,
        "results": results,
        "failed": [r["name"] for r in failed],
        "pending": [r["name"] for r in pending],
        "skipped": [r["name"] for r in skipped],
    }


def decide(mode: str, outcome: str, kind: str) -> str:
    if kind == "preflight":
        if outcome == "failed":
            return "would-block" if mode == "enforce" else "would-warn"
        if outcome == "pending":
            return "needs-runtime-check"
        if mode == "off":
            return "disabled"
        return "would-pass"
    if mode == "off":
        return "disabled"
    if outcome == "passed":
        return "enforced-pass" if mode == "enforce" else "warned-pass"
    if outcome == "pending":
        return "needs-runtime-check"
    return "warned-fail" if mode == "warn" else "enforcement-failed"


# ---------------------------------------------------------------------------
# Environment views
# ---------------------------------------------------------------------------


def _same_env(settings: Any, env: str) -> bool:
    current = str(getattr(settings, "current_env", "")).upper()
    return current == str(env).upper()


def _view_for(settings: Any, env: str) -> Any:
    if _same_env(settings, env) or not hasattr(settings, "from_env"):
        return settings
    return settings.from_env(env)


def _isolated(settings: Any, env: str) -> Any:
    """Return a disposable copy of the settings focused on ``env``."""
    view = _view_for(settings, env)
    view.current_env  # ensure the view is configured before copying
    return copy.deepcopy(view)


def _collect_values(
    view: Any,
    validators: Sequence[Validator],
    env: str,
    pending: Iterable[str],
    only: str | Sequence[str] | None = None,
    exclude: str | Sequence[str] | None = None,
) -> dict:
    pending = set(pending)
    only_list = ensure_a_list(only) or None
    exclude_list = ensure_a_list(exclude) or None
    values: dict[str, Any] = {}
    for validator in leaf_validators(validators):
        if not applies_to_env(validator, env):
            continue
        names = _select_names(
            validator_names(validator), only_list, exclude_list
        )
        for name in names:
            if name in pending:
                continue
            raw = _raw_get(view, name)
            source = _raw_source_value(view, name)
            if raw is empty or _contains_lazy(raw) or _contains_lazy(source):
                continue
            values[upperfy(name)] = view.get(name, empty)
    return values


def _target_envs(settings: Any, policy: ValidationPolicy, envs) -> list[str]:
    if envs:
        return [str(env).upper() for env in ensure_a_list(envs)]
    if policy.modes:
        return list(policy.modes)
    return [str(getattr(settings, "current_env", "main")).upper()]


def _declared_envs(
    settings: Any, validators: Sequence[Validator]
) -> list[str]:
    declared: list[str] = []
    for validator in leaf_validators(validators):
        if not validator.envs:
            continue
        for env in validator.envs:
            env = str(env).upper()
            if env not in declared:
                declared.append(env)
    current = str(getattr(settings, "current_env", "main")).upper()
    if current not in declared:
        declared.insert(0, current)
    return declared


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def preflight(
    settings: Any,
    policy: ValidationPolicy | None = None,
    envs: str | Sequence[str] | None = None,
    validators: Sequence[Validator] | None = None,
    only: str | Sequence[str] | None = None,
    exclude: str | Sequence[str] | None = None,
) -> dict:
    """Evaluate validators for ``envs`` without touching ``settings``.

    Returns evidence with the ruleset version/digest, per-environment
    decision, pending runtime candidates and the approved values usable if
    enforcement failed.
    """
    policy = as_policy(policy) if policy is not None else None
    if policy is None:
        policy = getattr(settings, "validation_policy", None)
        policy = policy or ValidationPolicy(default_mode="warn")

    rules = list(validators or getattr(settings, "validators", []))
    rule_data = build_ruleset(rules, version=policy.version)
    targets = _target_envs(settings, policy, envs)

    environments: dict[str, dict] = {}
    approvals: dict[str, dict] = {}
    for env in targets:
        isolated = _isolated(settings, env)
        # NOTE: reuse the original validator objects. A deepcopy of settings
        # would deepcopy the ``empty`` sentinel used by Validator internals,
        # breaking its ``is empty`` checks. Rules are never mutated here.
        internal_rules = rules
        pending = runtime_dependent_names(isolated, internal_rules, policy)
        report = evaluate_environment(
            isolated,
            internal_rules,
            env,
            pending=pending,
            only=only,
            exclude=exclude,
        )
        mode = policy.mode_for(env)
        fallback = policy.approved_for(env)
        fallback_source = "approved"
        if not fallback and report["outcome"] != "failed":
            fallback = _collect_values(
                isolated, internal_rules, env, pending, only, exclude
            )
            fallback_source = "candidate"
        report.update(
            {
                "mode": mode,
                "decision": decide(mode, report["outcome"], "preflight"),
                "runtime_dependent": sorted(pending),
                "fallback": fallback,
                "fallback_source": fallback_source,
                "ruleset": ruleset_label(rule_data),
            }
        )
        environments[env] = report
        if report["outcome"] in ("passed", "pending"):
            approvals[env] = fallback

    evidence = {
        "kind": "preflight",
        "generated_at": _now(),
        "current_env": str(getattr(settings, "current_env", "main")).upper(),
        "ruleset": rule_data,
        "ruleset_label": ruleset_label(rule_data),
        "modes": dict(policy.modes),
        "default_mode": policy.default_mode,
        "approval": approval_summary(policy, rule_data),
        "environments": environments,
        "fallback": {
            env: report["fallback"] for env, report in environments.items()
        },
        "candidate_approvals": approvals,
    }
    maybe_write_evidence(policy, evidence)
    return evidence


def approval_summary(policy: ValidationPolicy, rule_data: dict) -> dict:
    meta = policy.approval_meta or {}
    approved_ruleset = meta.get("ruleset") or {}
    approved_digest = approved_ruleset.get("digest")
    return {
        "recorded": bool(policy.approved),
        "approved_at": meta.get("approved_at"),
        "ruleset_version": approved_ruleset.get("version"),
        "ruleset_digest": approved_digest,
        "matches_current_ruleset": (
            approved_digest == rule_data["digest"]
            if approved_digest
            else None
        ),
        "source": meta.get("source"),
    }


# ---------------------------------------------------------------------------
# Runtime enforcement
# ---------------------------------------------------------------------------


def _apply_fallback(settings: Any, env: str, values: dict) -> None:
    metadata = SourceMetadata("validation_policy", "approved", env.lower())
    for key, value in values.items():
        settings.set(
            key,
            value,
            loader_identifier=metadata,
            validate=False,
            dotted_lookup=True,
        )


def _warn(message: str) -> None:
    warnings.warn(message, RuntimeWarning, stacklevel=3)


def _errors_text(reports: dict) -> str:
    return "; ".join(
        str(item["message"])
        for report in reports.values()
        for item in report["results"]
        if item["status"] == FAILED
    )


def enforce(
    settings: Any,
    policy: ValidationPolicy,
    validators: Sequence[Validator] | None = None,
    write_evidence: bool = True,
    only: str | Sequence[str] | None = None,
    exclude: str | Sequence[str] | None = None,
    only_current_env: bool = False,
) -> dict:
    """Apply the environment policy at runtime using the preflight engine.

    Enforcement is decided by the environment the application runs in: its
    mode decides whether failures block, warn or are ignored. Other declared
    environments are evaluated too, and are reported as ``blocked`` when they
    are already in ``enforce`` and fail, but they never change the values of
    the running environment.
    """
    policy = as_policy(policy)
    assert policy is not None
    current = str(getattr(settings, "current_env", "main")).upper()
    mode = policy.mode_for(current)
    rules = list(validators or getattr(settings, "validators", []))
    rule_data = build_ruleset(rules, version=policy.version)

    if only_current_env:
        targets = [current]
    else:
        targets = _declared_envs(settings, rules)
        if current in targets:
            targets.remove(current)
        targets.insert(0, current)

    reports: dict[str, dict] = {}
    pending_by_env: dict[str, list[str]] = {}
    decisions: dict[str, str] = {}
    if mode == "off":
        # `off` disables validation for this process entirely
        targets = [current]
    for env in targets:
        view = settings if env == current else _isolated(settings, env)
        # At runtime lazy values resolve, so only explicitly declared
        # runtime-dependent names stay "to be checked".
        pending = explicit_runtime_dependent(policy)
        pending_by_env[env] = sorted(pending)
        reports[env] = evaluate_environment(
            view,
            rules,
            env,
            pending=pending,
            only=only,
            exclude=exclude,
        )
        decisions[env] = decide(
            policy.mode_for(env), reports[env]["outcome"], "runtime"
        )

    outcome = reports[current]["outcome"]
    decision = decisions[current]
    fallback: dict[str, Any] = {}
    raised = False
    blocked: dict[str, dict] = {}

    if outcome == "failed" and mode == "enforce":
        approval = policy.approved_for(current)
        if policy.on_failure == "fallback" and approval:
            _apply_fallback(settings, current, approval)
            fallback = approval
            decision = "enforcement-failed-fallback"
            _warn(
                f"[dynaconf validation] enforcement failed for env {current};"
                f" continuing with approved values: "
                f"{', '.join(sorted(approval))}"
            )
        elif policy.on_failure == "warn":
            decision = "enforcement-failed-warned"
            _warn(
                f"[dynaconf validation] enforcement failed for env {current}:"
                f" {_errors_text({current: reports[current]})}"
            )
        else:
            raised = True
    elif outcome == "failed":
        _warn(
            f"[dynaconf validation] validation failed in warn mode for env "
            f"{current}: {_errors_text({current: reports[current]})}"
        )

    for env, report in reports.items():
        if env == current or report["outcome"] != "failed":
            continue
        env_mode = policy.mode_for(env)
        if env_mode == "enforce":
            blocked[env] = {
                "failed": report["failed"],
                "approved_available": policy.approved_for(env),
            }
            _warn(
                f"[dynaconf validation] env {env} is enforced and would "
                f"block: {', '.join(report['failed'])}"
            )
        elif env_mode == "warn":
            _warn(
                f"[dynaconf validation] env {env} validation failed "
                f"(warn mode): {_errors_text({env: report})}"
            )

    fallback_source = "approved"
    if outcome == "passed" and mode != "off":
        fallback = policy.approved_for(current)
        if not fallback:
            fallback = _collect_values(
                settings,
                rules,
                current,
                pending_by_env.get(current, []),
                only,
                exclude,
            )
            fallback_source = "runtime"

    evidence = {
        "kind": "runtime",
        "generated_at": _now(),
        "current_env": current,
        "ruleset": rule_data,
        "ruleset_label": ruleset_label(rule_data),
        "modes": dict(policy.modes),
        "default_mode": policy.default_mode,
        "approval": approval_summary(policy, rule_data),
        "environment": current,
        "mode": mode,
        "decision": decision,
        "outcome": outcome,
        "results": reports[current]["results"],
        "failed": reports[current]["failed"],
        "pending": reports[current]["pending"],
        "skipped": reports[current].get("skipped", []),
        "declared_runtime_dependent": pending_by_env.get(current, []),
        "environments": {
            env: {
                "mode": policy.mode_for(env),
                "decision": decisions[env],
                "outcome": report["outcome"],
                "failed": report["failed"],
                "pending": report["pending"],
                "skipped": report.get("skipped", []),
            }
            for env, report in reports.items()
        },
        "fallback": fallback,
        "fallback_source": fallback_source if fallback else None,
        "blocked": blocked,
        "approved_available": policy.approved_for(current),
    }
    if write_evidence:
        maybe_write_evidence(policy, evidence)
    core = getattr(settings, "__core__", None)
    if core is not None:
        core.config.last_validation_evidence = evidence

    if raised:
        raise ValidationError(
            _errors_text({current: reports[current]}) or "validation failed"
        )
    return evidence


# ---------------------------------------------------------------------------
# Evidence persistence / rendering
# ---------------------------------------------------------------------------


def maybe_write_evidence(policy: ValidationPolicy, evidence: dict) -> None:
    if not policy.evidence_file:
        return
    path = Path(policy.evidence_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(evidence, indent=2, default=str) + "\n", encoding="utf-8"
    )


def format_evidence(evidence: dict) -> str:
    """Human readable evidence: version, decision and fallback config."""
    rule_data = evidence.get("ruleset") or {}
    lines = [
        "Dynaconf validation evidence",
        f"  kind: {evidence.get('kind')}",
        f"  ruleset version: {ruleset_label(rule_data)}",
        f"  ruleset digest: {rule_data.get('digest')}",
        f"  rules count: {rule_data.get('count')}",
        f"  generated at: {evidence.get('generated_at')}",
        f"  current env: {evidence.get('current_env')}",
    ]
    approval = evidence.get("approval") or {}
    lines.append(
        "  approval: recorded={recorded} matches_ruleset={matches}".format(
            recorded=approval.get("recorded"),
            matches=approval.get("matches_current_ruleset"),
        )
    )
    modes = evidence.get("modes") or {}
    if modes:
        lines.append(
            "  modes: "
            + ", ".join(f"{env}={mode}" for env, mode in modes.items())
        )

    if evidence.get("kind") == "runtime":
        lines.append(
            "  runtime decision: mode={mode} decision={decision} "
            "outcome={outcome}".format(
                mode=evidence.get("mode"),
                decision=evidence.get("decision"),
                outcome=evidence.get("outcome"),
            )
        )
        lines.extend(format_results(evidence.get("results") or [], "  "))
        lines.extend(
            format_fallback(
                evidence.get("fallback") or {},
                evidence.get("environment"),
                evidence.get("fallback_source"),
            )
        )
        for env, report in (evidence.get("environments") or {}).items():
            if env == evidence.get("environment"):
                continue
            lines.append(
                f"  [{env}] outcome={report.get('outcome')} "
                f"failed={report.get('failed')}"
            )
    else:
        for env, report in (evidence.get("environments") or {}).items():
            lines.append(
                f"  [{env}] mode={report.get('mode')} "
                f"decision={report.get('decision')} "
                f"outcome={report.get('outcome')}"
            )
            lines.extend(format_results(report.get("results") or [], "    "))
            pending = report.get("pending") or []
            if pending:
                lines.append(
                    "    awaiting runtime: " + ", ".join(sorted(pending))
                )
            lines.extend(
                format_fallback(
                    report.get("fallback") or {},
                    env,
                    report.get("fallback_source"),
                )
            )
    return "\n".join(lines)


def format_results(results: list[dict], indent: str) -> list[str]:
    if not results:
        return []
    lines = [f"{indent}rules:"]
    for item in results:
        detail = f" - {item['message']}" if item.get("message") else ""
        lines.append(f"{indent}  - {item['name']}: {item['status']}{detail}")
    return lines


def format_fallback(
    fallback: dict, env: str | None, source: str | None = None
) -> list[str]:
    if not fallback:
        return []
    label = f" ({source})" if source else ""
    lines = [f"  fallback config for {str(env).upper()}{label}:"]
    for key, value in sorted(fallback.items()):
        lines.append(f"    {key} = {value!r}")
    return lines


# ---------------------------------------------------------------------------
# Approval recording
# ---------------------------------------------------------------------------


def record_approval(
    settings: Any,
    policy: ValidationPolicy,
    envs: str | Sequence[str] | None = None,
    validators: Sequence[Validator] | None = None,
) -> dict:
    """Freeze currently passing values as the approved snapshot.

    The snapshot stores the ruleset version/digest, so the approval is
    auditable and enforcement can detect rule changes.
    """
    policy = as_policy(policy)
    assert policy is not None
    evidence = preflight(
        settings, policy=policy, envs=envs, validators=validators
    )
    failing = [
        env
        for env, report in evidence["environments"].items()
        if report["outcome"] == "failed"
    ]
    if failing:
        raise ValidationError(
            "cannot approve environments with failing validators: "
            + ", ".join(failing)
        )

    candidate = evidence.get("candidate_approvals") or {}
    if not candidate:
        candidate = {
            env: report["fallback"]
            for env, report in evidence["environments"].items()
        }
    policy.approved.update(candidate)
    policy.approval_meta = {
        "approved_at": _now(),
        "ruleset": {
            "version": evidence["ruleset"]["version"],
            "digest": evidence["ruleset"]["digest"],
        },
        "source": str(policy.approved_file) if policy.approved_file else None,
    }

    if policy.approved_file:
        path = Path(policy.approved_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format": 1,
            "approved_at": policy.approval_meta["approved_at"],
            "ruleset": policy.approval_meta["ruleset"],
            "environments": policy.approved,
        }
        path.write_text(
            json.dumps(payload, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    evidence["approval"] = approval_summary(policy, evidence["ruleset"])
    evidence["approved"] = policy.approved
    maybe_write_evidence(policy, evidence)
    return evidence
