"""
Shared (redacted) view for ``inspect_settings`` and debug diagnostics.

Scenario: on-call attaches inspect output to a ticket. The shared view must
keep sources, override order and identifiers but never disclose restricted
values or fields computed from them (nested leaves, merged history entries,
lazy/interpolated dependencies). Authorized callers still get the full
loading history through the default API.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from textwrap import dedent

import pytest

from dynaconf import Dynaconf
from dynaconf.cli import main as cli_main
from dynaconf.utils.inspect import builtin_dumpers
from dynaconf.utils.inspect import get_debug_info
from dynaconf.utils.inspect import get_history
from dynaconf.utils.inspect import get_shared_report
from dynaconf.utils.inspect import inspect_settings
from dynaconf.utils.inspect import REDACTED
from dynaconf.utils.inspect import redact_report
from dynaconf.utils.inspect import RedactionPolicy
from dynaconf.utils.inspect import shared_view
from dynaconf.vendor.click.testing import CliRunner

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "shared_inspect"

# Synthetic literals used by the on-disk fixtures. They are not real secrets.
FIXTURE_SECRETS = [
    "FIXTURE-PLACEHOLDER-pass-alpha-0001",
    "FIXTURE-PLACEHOLDER-token-alpha-0002",
    "FIXTURE-PLACEHOLDER-dbpass-alpha-0003",
    "FIXTURE-PLACEHOLDER-pass-beta-0004",
    "FIXTURE-PLACEHOLDER-dbpass-beta-0005",
    "FIXTURE-PLACEHOLDER-listpass-beta-0006",
    "FIXTURE-PLACEHOLDER-billing-0007",
]


def create_file(filename, data: str):
    filename = Path(filename)
    filename.parent.mkdir(parents=True, exist_ok=True)
    filename.write_text(dedent(data))
    return filename


def assert_no_secrets(blob: str, secrets) -> None:
    leaked = [secret for secret in secrets if secret in blob]
    assert not leaked, (
        f"restricted literals leaked into shared output: {leaked}"
    )


def source_sequence(report: dict):
    return [
        (entry.get("loader"), entry.get("identifier"), entry.get("env"))
        for entry in report["history"]
    ]


@pytest.fixture
def ticket_settings(tmp_path, monkeypatch):
    """A rich loading trace with restricted placeholders and override paths."""
    monkeypatch.setenv("DYNACONF_OPS_TOKEN", "FIXTURE-PLACEHOLDER-env-0009")

    file_a = create_file(
        tmp_path / "ticket_a.toml",
        """\
        NORMAL = "alpha-normal"
        PASSWORD = "pass-alpha-0001"
        API_TOKEN = "token-alpha-0002"
        GREETING = "@format hello {this.NORMAL}"
        DSN = "@format postgres://{this.DB.USER}:{this.DB.PASSWORD}@h/db"

        [DB]
        HOST = "alpha-db.internal"
        USER = "alpha_user"
        PASSWORD = "dbpass-alpha-0003"
        """,
    )
    file_b = create_file(
        tmp_path / "ticket_b.toml",
        """\
        NORMAL = "beta-normal"
        PASSWORD = "pass-beta-0004"

        [DB]
        dynaconf_merge = true
        PASSWORD = "dbpass-beta-0005"
        """,
    )

    settings = Dynaconf(settings_file=[file_a, file_b])
    # Sensitive key is rotated/reset after loading; older history entries
    # still carry the previous generations of the value.
    settings.set("PASSWORD", "rotated-pass-reset-0008")
    return settings


@pytest.fixture
def secret_literals():
    return [
        "pass-alpha-0001",
        "token-alpha-0002",
        "dbpass-alpha-0003",
        "pass-beta-0004",
        "dbpass-beta-0005",
        "rotated-pass-reset-0008",
        "FIXTURE-PLACEHOLDER-env-0009",
    ]


# ---------------------------------------------------------------------------
# Full vs shared view
# ---------------------------------------------------------------------------


def test_full_view_keeps_complete_history(ticket_settings, secret_literals):
    """Authorized callers get values and the complete loading history."""
    report = inspect_settings(ticket_settings)
    blob = json.dumps(report, default=str)

    assert "rotated-pass-reset-0008" in blob
    assert "pass-alpha-0001" in blob
    assert "dbpass-beta-0005" in blob
    assert len(report["history"]) > 1


def test_shared_view_masks_restricted_values(ticket_settings, secret_literals):
    report = inspect_settings(ticket_settings, shared=True)
    blob = json.dumps(report, default=str)

    assert_no_secrets(blob, secret_literals)
    # conventional sensitive names are detected automatically
    assert report["current"]["PASSWORD"] == REDACTED
    assert report["current"]["API_TOKEN"] == REDACTED
    assert report["current"]["OPS_TOKEN"] == REDACTED


def test_shared_view_accepts_public_alias(ticket_settings, secret_literals):
    report = inspect_settings(ticket_settings, public=True)
    assert_no_secrets(json.dumps(report, default=str), secret_literals)

    report2 = inspect_settings(ticket_settings, redact=True)
    assert_no_secrets(json.dumps(report2, default=str), secret_literals)


def test_reveal_restores_full_view(ticket_settings, secret_literals):
    report = inspect_settings(
        ticket_settings, shared=True, reveal_secrets=True
    )
    assert "rotated-pass-reset-0008" in json.dumps(report, default=str)


# ---------------------------------------------------------------------------
# Sources, override order and identifiers are preserved
# ---------------------------------------------------------------------------


def test_shared_view_preserves_sources_and_order(ticket_settings):
    full = inspect_settings(ticket_settings)
    shared = inspect_settings(ticket_settings, shared=True)

    assert len(shared["history"]) == len(full["history"])
    assert source_sequence(shared) == source_sequence(full)

    # metadata fields stay available for cross-referencing sources
    for entry in shared["history"]:
        assert "loader" in entry
        assert "identifier" in entry
        assert "env" in entry
        assert "merged" in entry

    identifiers = [str(e["identifier"]) for e in shared["history"]]
    assert any("ticket_a.toml" in identifier for identifier in identifiers)
    assert any("ticket_b.toml" in identifier for identifier in identifiers)


def test_shared_history_keeps_override_order(tmp_path):
    file_a = create_file(tmp_path / "a.toml", 'PASSWORD = "from-a-secret"')
    file_b = create_file(tmp_path / "b.toml", 'PASSWORD = "from-b-secret"')
    settings = Dynaconf(settings_file=[file_a, file_b])

    full = get_history(settings, "PASSWORD")
    shared = get_history(settings, "PASSWORD", shared=True)

    assert [e["identifier"] for e in shared] == [
        e["identifier"] for e in full
    ]
    assert all(e["value"] == REDACTED for e in shared)
    assert [e["value"] for e in full] == ["from-a-secret", "from-b-secret"]


# ---------------------------------------------------------------------------
# Precise lookup for normal fields; nested/merge/lazy rules
# ---------------------------------------------------------------------------


def test_normal_field_precise_lookup(ticket_settings):
    report = inspect_settings(ticket_settings, key="NORMAL", shared=True)
    assert report["current"] == "beta-normal"
    # new-first order: override (beta) then base (alpha)
    assert [entry["value"] for entry in report["history"]] == [
        "beta-normal",
        "alpha-normal",
    ]
    assert all(entry["identifier"] for entry in report["history"])

    nested = inspect_settings(ticket_settings, key="DB.HOST", shared=True)
    assert nested["current"] == "alpha-db.internal"


def test_nested_restricted_leaf_is_masked_but_siblings_keep_working(
    ticket_settings, secret_literals
):
    report = inspect_settings(ticket_settings, shared=True)
    db = report["current"]["DB"]

    assert db["HOST"] == "alpha-db.internal"
    assert db["USER"] == "alpha_user"
    assert db["PASSWORD"] == REDACTED
    assert_no_secrets(json.dumps(db, default=str), secret_literals)


def test_merged_structures_are_scrubbed(tmp_path):
    file_a = create_file(
        tmp_path / "a.toml",
        """\
        [DB]
        HOST = "h.internal"
        PASSWORD = "merge-pass-a"
        """,
    )
    file_b = create_file(
        tmp_path / "b.toml",
        """\
        [DB]
        dynaconf_merge = true
        PASSWORD = "merge-pass-b"
        """,
    )
    settings = Dynaconf(settings_file=[file_a, file_b])
    report = inspect_settings(settings, shared=True)

    assert report["current"]["DB"]["HOST"] == "h.internal"
    assert report["current"]["DB"]["PASSWORD"] == REDACTED
    blob = json.dumps(report, default=str)
    assert "merge-pass-a" not in blob
    assert "merge-pass-b" not in blob
    assert any(entry.get("merged") is True for entry in report["history"])


def test_lazy_field_derived_from_secret_is_redacted(ticket_settings):
    full = inspect_settings(ticket_settings, key="DSN")
    assert "dbpass-beta-0005" in str(full["current"])

    shared = inspect_settings(ticket_settings, key="DSN", shared=True)
    assert shared["current"] == REDACTED
    assert all(entry["value"] == REDACTED for entry in shared["history"])
    assert "dbpass" not in json.dumps(shared, default=str)

    # a lazy field derived only from a normal key stays fully visible
    greeting = inspect_settings(
        ticket_settings, key="GREETING", shared=True
    )
    assert greeting["current"] == "hello beta-normal"


def test_lazy_reference_dependency_detection():
    policy = RedactionPolicy(["PASSWORD"])
    refs = policy.find_referenced_paths(
        "@format postgres://u:{this.PASSWORD}@{this.DB.HOST}/db"
    )
    assert ("PASSWORD",) in refs
    assert ("DB", "HOST") in refs
    assert policy._references_restricted("{this.PASSWORD}") is True
    assert policy._references_restricted("{this.NORMAL}") is False


# ---------------------------------------------------------------------------
# Explicit innocuous restricted keys and settings-declared policy
# ---------------------------------------------------------------------------


def test_explicit_restricted_key_with_innocuous_name():
    settings = Dynaconf(BILLING_CODE="billing-secret-xyz", VISIBLE="ok")
    report = inspect_settings(
        settings, shared=True, restricted_keys=["BILLING_CODE"]
    )
    assert report["current"]["BILLING_CODE"] == REDACTED
    assert report["current"]["VISIBLE"] == "ok"
    assert "billing-secret-xyz" not in json.dumps(report, default=str)


def test_dotted_restricted_path():
    settings = Dynaconf(
        OUTER={"TOKEN_LIKE": "x", "INNOCUOUS": "keep"},
        CREDENTIALS={"API_KEY": "abcdef123456"},
    )
    report = inspect_settings(
        settings,
        shared=True,
        detect_named=False,
        restricted_keys=["CREDENTIALS.API_KEY"],
    )
    assert report["current"]["CREDENTIALS"]["API_KEY"] == REDACTED
    assert report["current"]["OUTER"]["INNOCUOUS"] == "keep"
    # detection disabled: TOKEN_LIKE name is not auto-restricted
    assert report["current"]["OUTER"]["TOKEN_LIKE"] == "x"


def test_policy_from_settings_configures_keys(tmp_path):
    policy_file = FIXTURES_DIR / "policy.toml"
    settings = Dynaconf(settings_file=[policy_file])
    policy = RedactionPolicy.from_settings(settings)
    report = inspect_settings(settings, policy=policy)
    assert report["current"]["BILLING_CODE"] == REDACTED
    assert report["current"]["VISIBLE"] == "visible-value"
    assert "FIXTURE-PLACEHOLDER-billing-0007" not in json.dumps(
        report, default=str
    )


# ---------------------------------------------------------------------------
# Debug/diagnostics
# ---------------------------------------------------------------------------


def test_debug_info_shared_verbosity_two(ticket_settings, secret_literals):
    full = get_debug_info(ticket_settings, verbosity=2)
    assert "pass-alpha-0001" in json.dumps(full, default=str)

    shared = get_debug_info(ticket_settings, verbosity=2, shared=True)
    blob = json.dumps(shared, default=str)
    assert_no_secrets(blob, secret_literals)

    # diagnostic structure and source identity survive
    assert len(shared["history"]) == len(full["history"])
    assert [h["identifier"] for h in shared["history"]] == [
        h["identifier"] for h in full["history"]
    ]
    assert "versions" in shared and "dynaconf" in shared["versions"]


def test_debug_info_shared_key(ticket_settings):
    shared = get_debug_info(
        ticket_settings, key="DB.PASSWORD", shared=True
    )
    blob = json.dumps(shared, default=str)
    assert "dbpass-beta-0005" not in blob
    assert shared["current"]["DB.PASSWORD"] == REDACTED


# ---------------------------------------------------------------------------
# Human report vs structured export
# ---------------------------------------------------------------------------


def _dump(report, fmt):
    stream = io.StringIO()
    builtin_dumpers[fmt](report, stream)
    return stream.getvalue()


def test_human_and_structured_exports_agree(ticket_settings, secret_literals):
    report = inspect_settings(ticket_settings, shared=True)

    json_text = _dump(report, "json")
    yaml_text = _dump(report, "yaml")

    assert_no_secrets(json_text, secret_literals)
    assert_no_secrets(yaml_text, secret_literals)

    structured = json.loads(json_text)
    assert source_sequence(structured) == source_sequence(report)

    # the same placeholder marker is visible in both renderings
    assert REDACTED in json_text
    assert "*" in yaml_text

    # normal values survive both formats
    assert "beta-normal" in json_text
    assert "beta-normal" in yaml_text
    assert "alpha-db.internal" in json_text
    assert "alpha-db.internal" in yaml_text


def test_static_fixture_files_compare_cleanly():
    settings = Dynaconf(
        settings_file=[
            FIXTURES_DIR / "ticket_a.toml",
            FIXTURES_DIR / "ticket_b.toml",
        ]
    )
    report = get_shared_report(settings)

    json_text = json.dumps(report, default=str, indent=2)
    yaml_text = _dump(report, "yaml")

    assert_no_secrets(json_text, FIXTURE_SECRETS)
    assert_no_secrets(yaml_text, FIXTURE_SECRETS)

    # normal fields are precisely recoverable from the structured export
    structured = json.loads(json_text)
    assert structured["current"]["NORMAL"] == "beta-normal"
    assert structured["current"]["DB"]["HOST"] == "alpha-db.internal"
    assert structured["current"]["GREETING"] == "hello beta-normal"
    assert structured["current"]["DSN"] == REDACTED


# ---------------------------------------------------------------------------
# Standalone helpers / aliases
# ---------------------------------------------------------------------------


def test_redact_report_helper():
    raw = {
        "current": {"PASSWORD": "helper-secret-1234", "NAME": "ok"},
        "history": [
            {
                "loader": "toml",
                "identifier": "x.toml",
                "env": "default",
                "merged": False,
                "value": {"PASSWORD": "helper-secret-1234", "NAME": "ok"},
            }
        ],
    }
    redacted = redact_report(raw, restricted_keys=["PASSWORD"])
    assert redacted["current"]["PASSWORD"] == REDACTED
    assert redacted["current"]["NAME"] == "ok"
    assert (
        redacted["history"][0]["value"]["PASSWORD"] == REDACTED
    )
    assert "helper-secret-1234" not in json.dumps(redacted)


def test_shared_view_dispatches_on_dict_and_settings(ticket_settings):
    from_dict = shared_view(
        {"PASSWORD": "dict-secret-zzzz", "OK": 1},
        restricted_keys=["PASSWORD"],
    )
    assert from_dict["PASSWORD"] == REDACTED
    assert from_dict["OK"] == 1

    from_settings = shared_view(ticket_settings)
    assert "pass-alpha-0001" not in json.dumps(from_settings, default=str)


def test_custom_marker_is_honored(ticket_settings):
    report = inspect_settings(
        ticket_settings, shared=True, redaction_text="[REDACTED]"
    )
    assert report["current"]["PASSWORD"] == "[REDACTED]"
    assert "[REDACTED]" in json.dumps(report, default=str)


def test_shared_view_does_not_mutate_settings(ticket_settings):
    inspect_settings(ticket_settings, shared=True)
    get_debug_info(ticket_settings, verbosity=2, shared=True)

    # the live/authorized view is completely unaffected
    assert ticket_settings.PASSWORD == "rotated-pass-reset-0008"
    full = inspect_settings(ticket_settings)
    assert "pass-alpha-0001" in json.dumps(full, default=str)
    assert "rotated-pass-reset-0008" in json.dumps(full, default=str)


def test_drop_mode_removes_restricted_entries():
    settings = Dynaconf(
        PASSWORD="drop-secret-1", DB={"TOKEN": "drop-tok-2", "HOST": "h"}
    )
    report = inspect_settings(settings, shared=True, on_restricted="drop")
    assert "PASSWORD" not in report["current"]
    assert report["current"]["DB"] == {"HOST": "h"}


def test_debug_validator_default_secret_is_scrubbed():
    from dynaconf.validator import Validator

    settings = Dynaconf(
        validators=[
            Validator(
                "WEBHOOK_SECRET", default="val-default-secret-9"
            )
        ]
    )
    full = get_debug_info(settings, verbosity=2)
    assert "val-default-secret-9" in json.dumps(full, default=str)

    shared = get_debug_info(settings, 2, None, True)
    blob = json.dumps(shared, default=str)
    assert "val-default-secret-9" not in blob


def test_dotted_dunder_override_paths(monkeypatch):
    monkeypatch.setenv("DYNACONF_CACHE__ACCESS_TOKEN", "dotted-env-token-aaa")
    settings = Dynaconf()
    settings.set("SERVICES__BILLING__API_KEY", "dotted-set-key-bbb")

    report = inspect_settings(settings, shared=True)
    blob = json.dumps(report, default=str)
    assert "dotted-env-token-aaa" not in blob
    assert "dotted-set-key-bbb" not in blob
    assert report["current"]["CACHE"]["ACCESS_TOKEN"] == REDACTED
    assert (
        report["current"]["SERVICES"]["BILLING"]["API_KEY"] == REDACTED
    )

    # explicit dunder path specs normalize the same way
    explicit = inspect_settings(
        settings,
        shared=True,
        detect_named=False,
        restricted_keys=["SERVICES__BILLING__API_KEY"],
    )
    assert (
        "dotted-set-key-bbb"
        not in json.dumps(explicit, default=str)
    )


def test_view_alias_styles():
    settings = Dynaconf(PASSWORD="alias-secret-1", NAME="n")
    for kwargs in (
        {"view": "public"},
        {"audience": "ticket"},
        {"redact_secrets": True},
        {"mask_secrets": True},
        {"shareable": True},
    ):
        report = inspect_settings(settings, **kwargs)
        assert "alias-secret-1" not in json.dumps(report, default=str), kwargs

    # authorized/full aliases keep the value
    full = inspect_settings(settings, view="authorized")
    assert "alias-secret-1" in json.dumps(full, default=str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_inspect_shared_flag(tmp_path):
    instance_name = "shared_inspect_cli_instance"
    setting_file = create_file(
        tmp_path / "settings.toml",
        'PASSWORD = "cli-secret-aaaa"\nNORMAL = "cli-normal"\n',
    )
    create_file(
        tmp_path / f"{instance_name}.py",
        f"""\
        from dynaconf import Dynaconf
        settings = Dynaconf(settings_file={str(setting_file)!r})
        """,
    )

    runner = CliRunner()
    result = runner.invoke(
        cli_main,
        [
            "-i",
            f"{instance_name}.settings",
            "inspect",
            "--shared",
            "-f",
            "json",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert "cli-secret-aaaa" not in result.output
    assert "cli-normal" in result.output
    assert "********" in result.output

    # default CLI output remains complete for authorized operators
    full = runner.invoke(
        cli_main,
        [
            "-i",
            f"{instance_name}.settings",
            "inspect",
            "-f",
            "json",
        ],
        catch_exceptions=False,
    )
    assert "cli-secret-aaaa" in full.output
