from __future__ import annotations

import json
import warnings

import pytest

from dynaconf import Dynaconf
from dynaconf import ValidationError
from dynaconf import ValidationPolicy
from dynaconf import Validator
from dynaconf.validation_policy import build_ruleset
from dynaconf.validation_policy import format_evidence
from dynaconf.validation_policy import ruleset_label

pytestmark = pytest.mark.usefixtures("no_deprecations")

SETTINGS = """
[development]
PAYMENT_KEY = "dev-test-key-001"
DB_POOL = 5
[production]
PAYMENT_KEY = "prod-live-key-001"
DB_POOL = 20
"""


def make_settings(
    tmp_path, mode_dev="warn", mode_prod="warn", env=None, **kwargs
):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(SETTINGS, encoding="utf-8")
    validators = [
        Validator(
            "PAYMENT_KEY",
            must_exist=True,
            len_min=12,
            env=["development", "production"],
        ),
        Validator(
            "PAYMENT_KEY",
            condition=lambda v: "weak" not in v,
            env="production",
        ),
        Validator("DB_POOL", is_type_of=int, gte=10, env="production"),
    ]
    policy = ValidationPolicy(
        modes={"development": mode_dev, "production": mode_prod},
        version="2026.11",
        **kwargs,
    )
    return (
        Dynaconf(
            settings_files=[str(settings_file)],
            environments=True,
            env=env or "development",
            validators=validators,
            validation_policy=policy,
        ),
        policy,
    )


def test_same_key_different_values_per_env(tmp_path):
    settings, _ = make_settings(tmp_path)
    report = settings.preflight(envs=["development", "production"])
    assert report["environments"]["DEVELOPMENT"]["outcome"] == "passed"
    assert report["environments"]["DEVELOPMENT"]["fallback"] == {
        "PAYMENT_KEY": "dev-test-key-001"
    }
    assert report["environments"]["PRODUCTION"]["fallback"] == {
        "PAYMENT_KEY": "prod-live-key-001",
        "DB_POOL": 20,
    }


def test_preflight_does_not_mutate_settings(tmp_path):
    settings, _ = make_settings(tmp_path)
    before = dict(settings.as_dict())
    settings.preflight(envs=["development", "production"])
    after = dict(settings.as_dict())
    assert before == after


def test_preflight_and_enforcement_share_rules(tmp_path):
    settings, policy = make_settings(tmp_path)
    preflight = settings.preflight(envs=["production"])
    report = preflight["environments"]["PRODUCTION"]
    assert report["decision"] == "would-pass"
    runtime = settings.validate_settings(only_current_env=True)
    assert runtime["ruleset"]["digest"] == preflight["ruleset"]["digest"]
    assert runtime["outcome"] == report["outcome"]


def test_rule_version_changes_with_rules(tmp_path):
    settings, _ = make_settings(tmp_path)
    base = build_ruleset(settings.validators)
    changed = build_ruleset(
        [*settings.validators, Validator("NEW_KEY", must_exist=True)]
    )
    assert base["digest"] != changed["digest"]
    assert base["short_digest"] != changed["short_digest"]
    assert ruleset_label(base) == f"auto+{base['short_digest']}"


def test_runtime_dependent_candidate_is_pending(tmp_path):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(
        """
[development]
HOST = "dev.example"
SECRET_KEY = "@format {this.HOST}-token"
[production]
HOST = "prod.example"
SECRET_KEY = "@format {this.HOST}-token"
""",
        encoding="utf-8",
    )
    settings = Dynaconf(
        settings_files=[str(settings_file)],
        environments=True,
        validators=[Validator("SECRET_KEY", must_exist=True)],
        validation_policy=ValidationPolicy(
            modes={"development": "warn", "production": "warn"},
        ),
    )
    report = settings.preflight(envs=["development"])
    env_report = report["environments"]["DEVELOPMENT"]
    assert env_report["outcome"] == "pending"
    assert env_report["decision"] == "needs-runtime-check"
    assert "SECRET_KEY" in env_report["pending"]
    # it is explicitly "to be checked", not silently accepted
    assert env_report["fallback"] == {}


def test_warn_mode_does_not_block_startup(tmp_path):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(
        """
[development]
PAYMENT_KEY = "dev-test-key-001"
[production]
PAYMENT_KEY = "prod-live-key-with-weak"
""",
        encoding="utf-8",
    )
    settings = Dynaconf(
        settings_files=[str(settings_file)],
        environments=True,
        validators=[
            Validator(
                "PAYMENT_KEY",
                condition=lambda v: "weak" not in v,
                env="production",
            )
        ],
        validation_policy=ValidationPolicy(
            modes={"development": "warn", "production": "warn"},
        ),
    )
    with pytest.warns(RuntimeWarning):
        settings.validate_settings()
    assert settings.PAYMENT_KEY == "dev-test-key-001"


def test_enforce_blocks_and_fallback_keeps_approved_values(tmp_path):
    settings, policy = make_settings(
        tmp_path, mode_dev="warn", mode_prod="enforce", env="production"
    )
    settings.approve(envs=["development", "production"])
    approved = policy.approved.copy()

    # Simulate drift: the production key becomes weak after approval.
    settings.set(
        "PAYMENT_KEY",
        "prod-live-key-with-weak",
        loader_identifier="drift",
    )

    policy.on_failure = "raise"
    with pytest.raises(ValidationError):
        settings.validate_settings()

    policy.on_failure = "fallback"
    with pytest.warns(RuntimeWarning):
        evidence = settings.validate_settings()
    assert evidence["decision"] == "enforcement-failed-fallback"
    assert evidence["fallback"] == approved["PRODUCTION"]
    assert settings.PAYMENT_KEY == approved["PRODUCTION"]["PAYMENT_KEY"]
    assert evidence["approval"]["matches_current_ruleset"] is True


def test_approval_is_bound_to_ruleset_version(tmp_path):
    settings, policy = make_settings(tmp_path)
    settings.approve(envs=["production"])
    assert policy.approval_meta["ruleset"]["version"] == "2026.11"
    assert policy.approval_meta["ruleset"]["digest"]

    # Add a rule; approval is no longer valid for the new ruleset.
    settings.validators.register(Validator("EXTRA", must_exist=True))
    report = settings.preflight(envs=["production"])
    assert report["approval"]["matches_current_ruleset"] is False


def test_approve_rejects_failing_envs(tmp_path):
    settings, policy = make_settings(
        tmp_path, mode_dev="warn", env="production"
    )
    settings.set(
        "PAYMENT_KEY",
        "prod-live-key-with-weak",
        loader_identifier="drift",
    )
    with pytest.raises(ValidationError) as exc:
        settings.approve(envs=["production"])
    assert "PRODUCTION" in str(exc.value)


def test_approval_file_round_trip(tmp_path):
    approved_file = tmp_path / "approved.json"
    evidence_file = tmp_path / "evidence.json"
    settings, policy = make_settings(
        tmp_path,
        approved_file=str(approved_file),
        evidence_file=str(evidence_file),
    )
    settings.approve(envs=["development", "production"])
    payload = json.loads(approved_file.read_text(encoding="utf-8"))
    assert payload["format"] == 1
    assert payload["ruleset"]["version"] == "2026.11"
    assert payload["environments"]["PRODUCTION"]["DB_POOL"] == 20

    # Reload into a fresh policy, as a new process would do.
    reloaded = ValidationPolicy(
        approved_file=str(approved_file),
        modes={"development": "warn", "production": "enforce"},
    )
    assert reloaded.approved_for("production")["PAYMENT_KEY"] == (
        "prod-live-key-001"
    )
    assert reloaded.approval_meta["ruleset"]["version"] == "2026.11"

    evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
    assert evidence["kind"] == "preflight"


def test_runtime_resolves_lazy_but_explicit_names_stay_pending(tmp_path):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(
        """
[development]
HOST = "dev.example"
SECRET_KEY = "@format {this.HOST}-token"
[production]
HOST = "prod.example"
SECRET_KEY = "@format {this.HOST}-token"
""",
        encoding="utf-8",
    )
    settings = Dynaconf(
        settings_files=[str(settings_file)],
        environments=True,
        validators=[Validator("SECRET_KEY", must_exist=True, len_min=8)],
        validation_policy=ValidationPolicy(
            modes={"development": "enforce", "production": "warn"},
            version="2026.11",
            runtime_dependent=["HOST"],
        ),
    )
    # preflight reports the lazy value as pending
    report = settings.preflight(envs=["development"])
    assert report["environments"]["DEVELOPMENT"]["outcome"] == "pending"
    # runtime resolves the lazy value and validates it for real
    evidence = settings.validate_settings(only_current_env=True)
    assert evidence["outcome"] == "passed"
    assert evidence["pending"] == []
    assert evidence["results"][0]["name"] == "SECRET_KEY"
    # explicitly declared names are still reported as to be checked
    assert "HOST" in evidence["declared_runtime_dependent"]


def test_format_evidence_shows_version_decision_and_fallback(tmp_path):
    settings, policy = make_settings(
        tmp_path, mode_dev="warn", mode_prod="enforce", env="production"
    )
    settings.approve(envs=["development", "production"])
    settings.set(
        "PAYMENT_KEY",
        "prod-live-key-with-weak",
        loader_identifier="drift",
    )
    policy.on_failure = "fallback"
    evidence = settings.validate_settings()
    text = format_evidence(evidence)
    assert "ruleset version: 2026.11+" in text
    assert "runtime decision: mode=enforce decision=enforcement-failed" in text
    assert "fallback config for PRODUCTION (approved):" in text
    assert "PAYMENT_KEY = 'prod-live-key-001'" in text


def test_legacy_validators_are_reused(tmp_path):
    settings, policy = make_settings(tmp_path, mode_prod="warn")
    # The very same Validator objects registered the old way are used.
    assert settings.validators
    settings.preflight(envs=["production"])
    assert settings.validators.validate_all(raise_error=False) == []


def test_declared_envs_warn_does_not_bleed_into_current_env(tmp_path):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(
        """
[development]
PAYMENT_KEY = "dev-test-key-001"
[production]
PAYMENT_KEY = "prod-live-key-with-weak"
""",
        encoding="utf-8",
    )
    settings = Dynaconf(
        settings_files=[str(settings_file)],
        environments=True,
        env="development",
        validators=[
            Validator(
                "PAYMENT_KEY",
                condition=lambda v: "weak" not in v,
                env="production",
            )
        ],
        validation_policy=ValidationPolicy(
            modes={"development": "warn", "production": "enforce"},
            version="2026.11",
        ),
    )
    # Current env is development (warn): production failure only warns.
    with pytest.warns(RuntimeWarning) as caught:
        evidence = settings.validate_settings()
    messages = [str(item.message) for item in caught]
    assert any("PRODUCTION is enforced" in m for m in messages)
    assert evidence["environment"] == "DEVELOPMENT"
    assert evidence["decision"] == "warned-pass"
    assert (
        evidence["environments"]["PRODUCTION"]["outcome"] == "failed"
    )
    assert settings.PAYMENT_KEY == "dev-test-key-001"


def test_invalid_policy_mode_is_rejected():
    with pytest.raises(ValueError):
        ValidationPolicy(modes={"production": "silent"})


def test_policy_accepts_dict_on_settings(tmp_path):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(SETTINGS, encoding="utf-8")
    settings = Dynaconf(
        settings_files=[str(settings_file)],
        environments=True,
        validators=[Validator("DB_POOL", gte=1)],
        validation_policy={
            "modes": {"development": "warn", "production": "enforce"},
            "version": "v-dict",
        },
    )
    assert settings.validation_policy.version == "v-dict"
    assert settings.validation_policy.mode_for("production") == "enforce"


def test_off_mode_ignores_failures(tmp_path):
    settings, _ = make_settings(tmp_path, mode_dev="off", mode_prod="off")
    settings.set(
        "PAYMENT_KEY",
        "prod-live-key-with-weak",
        loader_identifier="drift",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        evidence = settings.validate_settings(only_current_env=True)
    assert evidence["mode"] == "off"
    assert evidence["decision"] == "disabled"


def test_when_precondition_is_reported_as_skipped(tmp_path):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(
        """
[development]
E = "no"
[production]
E = "yes"
""",
        encoding="utf-8",
    )
    settings = Dynaconf(
        settings_files=[str(settings_file)],
        environments=True,
        validators=[
            Validator(
                "D",
                must_exist=True,
                when=Validator("E", eq="yes"),
            )
        ],
        validation_policy=ValidationPolicy(
            modes={"development": "warn", "production": "warn"},
        ),
    )
    report = settings.preflight(envs=["development"])
    env_report = report["environments"]["DEVELOPMENT"]
    assert env_report["outcome"] == "passed"
    assert env_report["skipped"] == ["D"]
    assert env_report["results"][0]["status"] == "skipped"

    prod = settings.preflight(envs=["production"])["environments"][
        "PRODUCTION"
    ]
    assert prod["outcome"] == "failed"
    assert "D" in prod["failed"]


def test_combined_validators_are_evaluated(tmp_path):
    settings = Dynaconf(
        environments=True,
        validators=[
            Validator("B", must_exist=True) | Validator("C", must_exist=True)
        ],
        validation_policy=ValidationPolicy(modes={"development": "warn"}),
        B=1,
    )
    report = settings.preflight(envs=["development"])
    assert report["environments"]["DEVELOPMENT"]["outcome"] == "passed"
