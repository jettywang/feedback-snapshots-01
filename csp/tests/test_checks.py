from django.test.utils import override_settings

from csp.checks import check_django_csp_lt_4_0, check_exclude_url_prefixes_is_not_string, migrate_settings
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


@override_settings(
    CSP_POLICY_APPROVALS=[
        {
            "id": "AP-1",
            "site": "shop.example",
            "directive": "img-src",
            "source": "cdn.partner.example",
            "scope": ["/checkout/"],
        }
    ]
)
def test_check_policy_approvals_valid() -> None:
    from csp.checks import check_policy_approvals

    assert check_policy_approvals(None) == []


@override_settings(
    CSP_POLICY_APPROVALS=[
        {"id": "AP-1", "site": "shop.example", "directive": "img-src", "source": "cdn.partner.example"},
        {"id": "AP-1", "site": "shop.example", "directive": "img-src", "source": "cdn2.partner.example"},
    ]
)
def test_check_policy_approvals_duplicate_id() -> None:
    from csp.checks import check_policy_approvals

    errors = check_policy_approvals(None)
    assert [error.id for error in errors] == ["csp.E004"]
    assert "duplicate approval_id" in errors[0].msg


@override_settings(CSP_POLICY_APPROVALS=[{"site": "shop.example", "directive": "img-src", "source": "cdn.partner.example"}])
def test_check_policy_approvals_missing_id() -> None:
    from csp.checks import check_policy_approvals

    errors = check_policy_approvals(None)
    assert [error.id for error in errors] == ["csp.E004"]


@override_settings(CSP_POLICY_APPROVALS="not-a-table")
def test_check_policy_approvals_not_a_table() -> None:
    from csp.checks import check_policy_approvals

    errors = check_policy_approvals(None)
    assert [error.id for error in errors] == ["csp.E003"]
