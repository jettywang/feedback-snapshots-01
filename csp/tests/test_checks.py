from django.test.utils import override_settings

from csp.checks import (
    check_django_csp_lt_4_0,
    check_exclude_url_prefixes_is_not_string,
    check_policy_size_settings,
    migrate_settings,
)
from csp.constants import NONCE


@override_settings(
    CSP_REPORT_PERCENTAGE=0.25,
    CSP_EXCLUDE_URL_PREFIXES=["/admin/"],
    CSP_REPORT_ONLY=False,
    CSP_DEFAULT_SRC=["'self'", "example.com"],
)
def test_migrate_settings() -> None:
    config, report_only = migrate_settings()
    assert config == {
        "REPORT_PERCENTAGE": 25.0,
        "EXCLUDE_URL_PREFIXES": ["/admin/"],
        "DIRECTIVES": {"default-src": ["'self'", "example.com"]},
    }
    assert report_only is False


@override_settings(
    CSP_REPORT_ONLY=True,
    CSP_DEFAULT_SRC=["'self'", "example.com"],
    CSP_SCRIPT_SRC=["'self'", "example.com", "'unsafe-inline'"],
    CSP_INCLUDE_NONCE_IN=["script-src"],
)
def test_migrate_settings_report_only() -> None:
    config, report_only = migrate_settings()
    assert config == {
        "DIRECTIVES": {
            "default-src": ["'self'", "example.com"],
            "script-src": ["'self'", "example.com", "'unsafe-inline'", NONCE],
        }
    }
    assert report_only is True


@override_settings(
    CSP_DEFAULT_SRC=["'self'", "example.com"],
)
def test_check_django_csp_lt_4_0() -> None:
    errors = check_django_csp_lt_4_0(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E001"
    assert "update your settings to use the new format" in error.msg


def test_check_django_csp_lt_4_0_no_config() -> None:
    assert check_django_csp_lt_4_0(None) == []


@override_settings(
    CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_is_not_string() -> None:
    errors = check_exclude_url_prefixes_is_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY settings must be a list or tuple."


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"EXCLUDE_URL_PREFIXES": "/admin/"},
)
def test_check_exclude_url_prefixes_ro_is_not_string() -> None:
    errors = check_exclude_url_prefixes_is_not_string(None)
    assert len(errors) == 1
    error = errors[0]
    assert error.id == "csp.E002"
    assert error.msg == "EXCLUDE_URL_PREFIXES in CONTENT_SECURITY_POLICY_REPORT_ONLY settings must be a list or tuple."


def test_check_policy_size_settings_valid() -> None:
    with override_settings(
        CONTENT_SECURITY_POLICY={
            "POLICY_SIZE_LIMIT": 1024,
            "ON_POLICY_TOO_LONG": "fallback",
            "FALLBACK_DIRECTIVES": {"default-src": ["'none'"]},
        }
    ):
        assert check_policy_size_settings(None) == []


def test_check_policy_size_settings_defaults() -> None:
    with override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"]}}):
        assert check_policy_size_settings(None) == []


@override_settings(CONTENT_SECURITY_POLICY={"POLICY_SIZE_LIMIT": "1024"})
def test_check_policy_size_limit_must_be_int() -> None:
    errors = check_policy_size_settings(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E003"


@override_settings(CONTENT_SECURITY_POLICY={"POLICY_SIZE_LIMIT": 0})
def test_check_policy_size_limit_must_be_positive() -> None:
    errors = check_policy_size_settings(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E003"


@override_settings(CONTENT_SECURITY_POLICY={"ON_POLICY_TOO_LONG": "explode"})
def test_check_on_policy_too_long_unknown_action() -> None:
    errors = check_policy_size_settings(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E004"


@override_settings(
    CONTENT_SECURITY_POLICY={
        "ON_POLICY_TOO_LONG": "fallback",
        "POLICY_SIZE_LIMIT": 1024,
    }
)
def test_check_fallback_required_for_fallback_action() -> None:
    errors = check_policy_size_settings(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E005"


@override_settings(
    CONTENT_SECURITY_POLICY={
        "ON_POLICY_TOO_LONG": "fallback",
        "FALLBACK_DIRECTIVES": {"not-a-real-directive": ["example.com"]},
    }
)
def test_check_fallback_unknown_directive() -> None:
    errors = check_policy_size_settings(None)
    assert len(errors) == 1
    assert errors[0].id == "csp.E005"
    assert "not-a-real-directive" in errors[0].msg


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "POLICY_SIZE_LIMIT": 10,
        "ON_POLICY_TOO_LONG": "explode",
    }
)
def test_check_policy_size_settings_report_only() -> None:
    errors = check_policy_size_settings(None)
    assert [error.id for error in errors] == ["csp.E004"]
