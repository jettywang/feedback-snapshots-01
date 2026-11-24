"""Same key, different values per environment: warn -> preflight -> enforce.

Run with: python app.py
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

from dynaconf import Dynaconf
from dynaconf import ValidationError
from dynaconf import ValidationPolicy
from dynaconf import Validator
from dynaconf.validation_policy import format_evidence

HERE = Path(__file__).parent
APPROVED = HERE / "approved.json"
if APPROVED.exists():  # start from a clean snapshot each run
    APPROVED.unlink()

validators = [
    Validator(
        "PAYMENT_KEY",
        must_exist=True,
        len_min=12,
        env=["development", "production"],
    ),
    Validator(
        "PAYMENT_KEY",
        condition=lambda value: "weak" not in value,
        env="production",
    ),
    Validator("DB_POOL", is_type_of=int, gte=10, env="production"),
]


def make_settings(env="development"):
    policy = ValidationPolicy(
        modes={"development": "warn", "production": "warn"},
        version="2026.11",
        approved_file=APPROVED,
    )
    return Dynaconf(
        settings_files=[str(HERE / "settings.toml")],
        environments=True,
        env=env,
        validators=validators,
        validation_policy=policy,
    )


# 1. Warn mode: the production value is weak, startup only warns.
risky = make_settings(env="production")
risky.set(
    "PAYMENT_KEY", "prod-live-key-with-weak", loader_identifier="drift"
)
with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    risky.validate_settings()
warning_text = " ".join(str(item.message) for item in caught)
assert "validation failed in warn mode for env PRODUCTION" in warning_text
assert risky.PAYMENT_KEY == "prod-live-key-with-weak"  # still readable
print("warn mode:", warning_text)

# Preflight on the same config shows it would fail, without touching it.
risky_report = risky.preflight(envs=["production"])
assert risky_report["environments"]["PRODUCTION"]["decision"] == "would-warn"
assert risky_report["environments"]["PRODUCTION"]["outcome"] == "failed"
assert risky.PAYMENT_KEY == "prod-live-key-with-weak"

# 2. The same key has different values per environment (the good config).
settings = make_settings()
assert settings.PAYMENT_KEY == "dev-test-key-001"
print("same key, development:", settings.PAYMENT_KEY)
print("same key, production: ", settings.from_env("production").PAYMENT_KEY)
report = settings.preflight(envs=["development", "production"])
assert report["environments"]["DEVELOPMENT"]["decision"] == "would-pass"
assert report["environments"]["PRODUCTION"]["decision"] == "would-pass"
assert report["environments"]["DEVELOPMENT"]["fallback"] == {
    "PAYMENT_KEY": "dev-test-key-001"
}
assert report["environments"]["PRODUCTION"]["fallback"] == {
    "PAYMENT_KEY": "prod-live-key-001",
    "DB_POOL": 20,
}
print(format_evidence(report))
print("preflight ruleset:", report["ruleset_label"])

# 3. Approve the values that are known to be good.
approved = settings.approve(envs=["development", "production"])
assert json.loads(APPROVED.read_text())["ruleset"]["version"] == "2026.11"
assert approved["approved"]["PRODUCTION"]["PAYMENT_KEY"] == (
    "prod-live-key-001"
)

# 4. Flip production to enforce, then simulate a risky drift after approval.
settings.validation_policy.modes["PRODUCTION"] = "enforce"
prod_settings = settings.from_env("production")
prod_settings.validation_policy.on_failure = "raise"
prod_settings.set(
    "PAYMENT_KEY", "prod-live-key-with-weak", loader_identifier="drift"
)
try:
    prod_settings.validate_settings()
except ValidationError as exc:
    print("enforce mode blocked:", exc)
else:  # pragma: no cover
    raise AssertionError("enforcement should have blocked")

# 5. With fallback, the approved value stays readable after the failure.
prod_settings.validation_policy.on_failure = "fallback"
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    evidence = prod_settings.validate_settings()
assert evidence["decision"] == "enforcement-failed-fallback"
assert evidence["ruleset"]["version"] == "2026.11"
assert evidence["approval"]["matches_current_ruleset"] is True
assert prod_settings.PAYMENT_KEY == "prod-live-key-001"
assert evidence["fallback"]["PAYMENT_KEY"] == "prod-live-key-001"
print(format_evidence(evidence))

# 6. Changing the rules invalidates the approval for the new ruleset.
prod_settings.validators.register(
    Validator("DB_POOL", lte=10, env="production")
)
new_report = prod_settings.preflight(envs=["production"])
assert new_report["approval"]["matches_current_ruleset"] is False
print(
    "ruleset changed, approval matches:",
    new_report["approval"]["matches_current_ruleset"],
)

print("validation policy rollout example: OK")
