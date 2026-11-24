from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
)
from django.template import Context, Template, engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONE, SELF
from csp.exceptions import CSPNonceError, CSPPolicyTooLongError
from csp.middleware import CheckableLazyObject, CSPMiddleware
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()


def test_checkable_lazy_object() -> None:
    def generate_value() -> str:
        return "generated"

    lazy = CheckableLazyObject(generate_value)

    # Before wrapped object is initiated, lazy is falsy
    assert bool(lazy) is False

    # After str(lazy) calls generate_value, lazy is truthy
    assert str(lazy) == "generated"
    assert bool(lazy) is True


def test_add_header() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["example.com"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_both_headers() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": {"example.com"}}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": {SELF}}},
)
def test_directives_configured_as_sets() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


def test_exempt() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_exempt", True)
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": ["/inlines-r-us"]})
def test_exclude() -> None:
    request = rf.get("/inlines-r-us/foo")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(
    CONTENT_SECURITY_POLICY=None,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response
    assert HEADER_REPORT_ONLY in response
    assert response[HEADER_REPORT_ONLY] == "default-src 'self'"


def test_dont_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    response[HEADER] = "default-src example.com"
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_config() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_config", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_update() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_update", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self' example.com"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_use_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_replace", {"img-src": ["bar.com"]})
    mw.process_response(request, response)
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


@override_settings(DEBUG=True)
def test_debug_errors_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseServerError()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(DEBUG=True)
def test_debug_notfound_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseNotFound()
    mw.process_response(request, response)
    assert HEADER not in response


def test_nonce_created_when_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    mw.process_response(request, response)
    assert nonce in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


def test_nonce_is_false_before_access_and_true_after() -> None:
    request = rf.get("/")
    mw.process_request(request)
    assert bool(getattr(request, "csp_nonce")) is False
    nonce = str(getattr(request, "csp_nonce"))
    assert bool(getattr(request, "csp_nonce")) is True

    response = HttpResponse()
    mw.process_response(request, response)
    assert bool(getattr(request, "csp_nonce")) is True
    assert getattr(request, "csp_nonce") == nonce


def test_nonce_conditional_in_django_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = Template(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_django_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = Template("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_nonce_conditional_in_jinja2_template() -> None:
    """An unset nonce is Falsy in a template context"""

    template = engines["jinja2"].from_string(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    rendered_unset = template.render(context).strip()
    assert rendered_unset == "The CSP nonce is not set."

    nonce = str(getattr(request, "csp_nonce"))
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_jinja2_template() -> None:
    """Reading a nonce in a template context generates the nonce"""

    template = engines["jinja2"].from_string("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert bool(nonce) is False
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_no_nonce_when_not_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = HttpResponse()
    mw.process_response(request, response)
    assert "nonce-" not in response[HEADER]
    assert response[HEADER] == "default-src 'self'"


def test_nonce_regenerated_on_new_request() -> None:
    request1 = rf.get("/")
    request2 = rf.get("/")
    mw.process_request(request1)
    mw.process_request(request2)
    nonce1 = str(getattr(request1, "csp_nonce"))
    nonce2 = str(getattr(request2, "csp_nonce"))
    assert nonce1 != nonce2

    response1 = HttpResponse()
    response2 = HttpResponse()
    mw.process_response(request1, response1)
    mw.process_response(request2, response2)
    assert nonce1 not in response2[HEADER]
    assert nonce2 not in response1[HEADER]


def test_no_nonce_access_after_middleware_is_attribute_error() -> None:
    # Test `CSPNonceError` is raised when accessing an unset nonce after the response has been processed.
    request = rf.get("/")
    mw.process_request(request)
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", True)) is False
    with pytest.raises(CSPNonceError):
        str(getattr(request, "csp_nonce"))


def test_set_nonce_access_after_middleware_is_ok() -> None:
    # Test accessing a set nonce after the response has been processed is OK.
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", False)) is True
    assert str(getattr(request, "csp_nonce")) == nonce


# --- Policy size budget ---------------------------------------------------


def test_policy_size_limit_exact_fit() -> None:
    # The default test policy ("default-src 'self'") is exactly 18 bytes.
    settings_dict = {
        "CONTENT_SECURITY_POLICY": {
            "POLICY_SIZE_LIMIT": 18,
            "DIRECTIVES": {"default-src": [SELF]},
        }
    }
    with override_settings(**settings_dict):
        request = rf.get("/")
        resp = HttpResponse()
        mw.process_response(request, resp)
    assert resp[HEADER] == "default-src 'self'"
    assert len(resp[HEADER].encode()) == 18


def test_policy_size_limit_too_long_raises() -> None:
    settings_dict = {
        "CONTENT_SECURITY_POLICY": {
            "POLICY_SIZE_LIMIT": 17,
            "DIRECTIVES": {"default-src": [SELF]},
        }
    }
    with override_settings(**settings_dict):
        request = rf.get("/")
        resp = HttpResponse()
        with pytest.raises(CSPPolicyTooLongError) as exc_info:
            mw.process_response(request, resp)
    # A too-long policy must never be partially written.
    assert HEADER not in resp
    error = exc_info.value
    assert error.header == HEADER
    assert error.limit == 17
    assert error.policy_size == 18
    assert error.policy == "default-src 'self'"
    assert error.offending_directive == "default-src"
    assert "default-src" in str(error)


def test_policy_size_limit_offending_directive_diagnostic() -> None:
    settings_dict = {
        "CONTENT_SECURITY_POLICY": {
            "POLICY_SIZE_LIMIT": 18,
            "DIRECTIVES": {"default-src": [SELF], "img-src": ["example.com"]},
        }
    }
    with override_settings(**settings_dict):
        request = rf.get("/")
        resp = HttpResponse()
        with pytest.raises(CSPPolicyTooLongError) as exc_info:
            mw.process_response(request, resp)
    assert exc_info.value.offending_directive == "img-src"
    assert HEADER not in resp


@override_settings(
    CONTENT_SECURITY_POLICY={
        "POLICY_SIZE_LIMIT": 18,
        "ON_POLICY_TOO_LONG": "fallback",
        "DIRECTIVES": {"default-src": [SELF], "img-src": ["example.com"]},
        "FALLBACK_DIRECTIVES": {"default-src": [NONE]},
    }
)
def test_policy_size_limit_fallback_delivers_complete_policy() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    mw.process_response(request, resp)
    assert HEADER in resp
    assert resp[HEADER] == "default-src 'none'"
    assert len(resp[HEADER].encode()) <= 18


@override_settings(
    CONTENT_SECURITY_POLICY={
        "POLICY_SIZE_LIMIT": 10,
        "ON_POLICY_TOO_LONG": "fallback",
        "FALLBACK_DIRECTIVES": {"default-src": ["a-very-long-fallback.example.com"]},
    }
)
def test_policy_size_limit_fallback_that_does_not_fit_raises() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    with pytest.raises(CSPPolicyTooLongError):
        mw.process_response(request, resp)
    assert HEADER not in resp


@override_settings(
    CONTENT_SECURITY_POLICY={
        "POLICY_SIZE_LIMIT": 17,
        "ON_POLICY_TOO_LONG": "fallback",
    }
)
def test_policy_size_limit_misconfigured_fallback_raises() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    with pytest.raises(CSPPolicyTooLongError):
        mw.process_response(request, resp)
    assert HEADER not in resp


def test_pre_existing_header_is_kept_when_policy_too_long() -> None:
    approved = "default-src 'none'"
    settings_dict = {
        "CONTENT_SECURITY_POLICY": {
            "POLICY_SIZE_LIMIT": 5,
            "DIRECTIVES": {"default-src": [SELF]},
        }
    }
    with override_settings(**settings_dict):
        request = rf.get("/")
        resp = HttpResponse()
        resp[HEADER] = approved
        # Must not raise: the already-present header is treated as approved.
        mw.process_response(request, resp)
    assert resp[HEADER] == approved


def test_separate_limits_for_enforced_and_report_only() -> None:
    settings_dict = {
        "CONTENT_SECURITY_POLICY": {
            "POLICY_SIZE_LIMIT": 18,
            "DIRECTIVES": {"default-src": [SELF]},
        },
        "CONTENT_SECURITY_POLICY_REPORT_ONLY": {
            "POLICY_SIZE_LIMIT": 17,
            "DIRECTIVES": {"default-src": [SELF]},
        },
    }
    with override_settings(**settings_dict):
        request = rf.get("/")
        resp = HttpResponse()
        with pytest.raises(CSPPolicyTooLongError) as exc_info:
            mw.process_response(request, resp)
    # The enforced header was written before the report-only one overflowed.
    assert exc_info.value.header == HEADER_REPORT_ONLY
    assert resp[HEADER] == "default-src 'self'"
    assert HEADER_REPORT_ONLY not in resp


def test_view_update_overflow_diagnostic() -> None:
    settings_dict = {
        "CONTENT_SECURITY_POLICY": {
            "POLICY_SIZE_LIMIT": 18,
            "DIRECTIVES": {"default-src": [SELF]},
        }
    }
    with override_settings(**settings_dict):
        request = rf.get("/")
        resp = HttpResponse()
        setattr(resp, "_csp_update", {"img-src": ["example.com"]})
        with pytest.raises(CSPPolicyTooLongError) as exc_info:
            mw.process_response(request, resp)
    assert exc_info.value.offending_directive == "img-src"
    assert "img-src example.com" in exc_info.value.policy
    assert HEADER not in resp


@override_settings(
    CONTENT_SECURITY_POLICY={
        "POLICY_SIZE_LIMIT": 100,
        "DIRECTIVES": {"default-src": [SELF], "img-src": ["example.com"]},
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "POLICY_SIZE_LIMIT": 100,
        "DIRECTIVES": {"default-src": [SELF]},
    },
)
def test_full_response_with_default_view_update_and_report_header() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    setattr(resp, "_csp_update", {"script-src": ["cdn.example.com"]})
    mw.process_response(request, resp)
    enforced_parts = dict(part.split(" ", 1) for part in resp[HEADER].split("; "))
    assert enforced_parts["default-src"] == "'self'"
    assert enforced_parts["img-src"] == "example.com"
    assert enforced_parts["script-src"] == "cdn.example.com"
    assert resp[HEADER_REPORT_ONLY] == "default-src 'self'"
    assert len(resp[HEADER].encode()) <= 100
    assert len(resp[HEADER_REPORT_ONLY].encode()) <= 100
