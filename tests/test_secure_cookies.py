"""Strict, security-sensitive reading of authentication cookies.

The legacy dict-like ``request.cookies`` view stays available for preference
and UI cookies.  Authentication cookies go through the secure reader, which
must distinguish a definite value, a missing cookie, an ambiguous duplicate
and the case where the raw WSGI source can no longer be reconstructed.
"""

import pytest

from webob import CookieReadResult, CookieReadStatus, Request, Response
from webob.cookies import SecureCookieReader

AUTH = "session"


def _make_request(header):
    req = Request.blank("/")
    req.environ["HTTP_COOKIE"] = header
    return req


def test_present_single_value_is_definite():
    req = _make_request("session=legit; theme=dark")
    result = req.read_secure_cookie(AUTH)

    assert result.status is CookieReadStatus.PRESENT
    assert result.value == "legit"
    assert result.values == ("legit",)
    assert result.is_definite
    assert result.from_wsgi_input is True


def test_missing_cookie_is_reported_not_collapsed():
    req = _make_request("theme=dark")
    result = req.read_secure_cookie(AUTH)

    assert result.status is CookieReadStatus.MISSING
    assert result.value is None
    assert result.values == ()
    assert result.is_missing


def test_duplicate_cookie_is_ambiguous_and_keeps_every_value():
    # An attacker appends a second value; the dict view would surface it.
    req = _make_request("session=legit; theme=dark; session=evil")
    result = req.read_secure_cookie(AUTH)

    assert result.status is CookieReadStatus.AMBIGUOUS
    assert result.is_ambiguous
    assert result.values == ("legit", "evil")
    # No single value may be trusted for a security decision.
    assert result.value is None
    assert result.is_definite is False


def test_legacy_mapping_still_returns_last_value_for_non_auth_field():
    req = _make_request("session=legit; theme=dark; session=evil")

    # The old interface is unchanged and directly comparable.
    assert req.cookies["theme"] == "dark"
    assert req.cookies["session"] == "evil"
    assert dict(req.cookies) == {"session": "evil", "theme": "dark"}


def test_reader_rejects_a_naive_last_value_implementation():
    # A reader built only from the collapsed dict cannot see the duplicate.
    req = _make_request("session=legit; session=evil")

    dict_only_value = req.cookies.get(AUTH)
    secure = req.read_secure_cookie(AUTH)

    assert dict_only_value == "evil"  # what the naive implementation returns
    assert secure.status is CookieReadStatus.AMBIGUOUS
    assert secure.values == ("legit", "evil")
    assert secure.value != dict_only_value


def test_observation_names_its_request_revision():
    req = _make_request("session=legit")
    first = req.read_secure_cookie(AUTH)

    assert isinstance(first, CookieReadResult)
    assert first.generation == 0
    assert first.from_wsgi_input is True
    assert first.header_fingerprint == "session=legit"

    # Re-parsing the same untouched request reproduces the same observation.
    again = req.read_secure_cookie(AUTH)
    assert again.generation == first.generation
    assert again.header_fingerprint == first.header_fingerprint
    assert again.status is first.status


def test_copy_does_not_reuse_a_stale_ambiguous_verdict():
    original = _make_request("session=legit; session=evil")
    ambiguous = original.read_secure_cookie(AUTH)
    assert ambiguous.status is CookieReadStatus.AMBIGUOUS

    derived = original.copy()
    copied = derived.read_secure_cookie(AUTH)

    # The derived request is a distinct revision, not the raw WSGI entry...
    assert copied.generation > ambiguous.generation
    assert copied.from_wsgi_input is False
    # ...and it independently re-derives the ambiguity instead of inheriting.
    assert copied.status is CookieReadStatus.AMBIGUOUS
    assert copied.values == ("legit", "evil")


def test_wholesale_cookie_replacement_resets_to_a_definite_source():
    original = _make_request("session=legit; session=evil; theme=dark")
    derived = original.copy()

    # The application updates the whole cookie view through the normal setter.
    derived.cookies = {"session": "fresh", "theme": "light"}
    result = derived.read_secure_cookie(AUTH)

    assert result.status is CookieReadStatus.PRESENT
    assert result.value == "fresh"
    assert result.from_wsgi_input is False
    assert result.generation > original.read_secure_cookie(AUTH).generation
    # The legacy, non-auth field is directly comparable.
    assert derived.cookies["theme"] == "light"


def test_point_edit_makes_the_wsgi_source_unknown():
    req = _make_request("session=legit; theme=dark")
    req.cookies["theme"] = "blue"  # ordinary preference edit via mapping

    result = req.read_secure_cookie(AUTH)
    assert result.status is CookieReadStatus.SOURCE_UNKNOWN
    assert result.source_unknown
    assert result.value is None
    assert result.values == ()
    assert result.from_wsgi_input is False


def test_delete_and_clear_also_invalidate_the_source():
    req = _make_request("session=legit; theme=dark")
    del req.cookies["theme"]
    status = req.read_secure_cookie(AUTH).status
    assert status is CookieReadStatus.SOURCE_UNKNOWN

    other = _make_request("session=legit")
    other.cookies.clear()
    status = other.read_secure_cookie(AUTH).status
    assert status is CookieReadStatus.SOURCE_UNKNOWN


def test_response_set_cookie_is_not_request_evidence():
    req = _make_request("session=legit")
    response = Response()
    response.set_cookie("session", "set-on-response")

    # Emitting a Set-Cookie happens on the response boundary and cannot change
    # what the application observed on the received request.
    observed = req.read_secure_cookie(AUTH)
    assert observed.status is CookieReadStatus.PRESENT
    assert observed.value == "legit"
    assert response.headers.getall("Set-Cookie") == [
        "session=set-on-response; Path=/"
    ]


def test_next_request_is_observed_independently():
    first = _make_request("session=legit; session=evil")
    assert first.read_secure_cookie(AUTH).status is CookieReadStatus.AMBIGUOUS

    Response().set_cookie("session", "rotated")  # does not feed the next read

    next_request = _make_request("session=next")
    observed = next_request.read_secure_cookie(AUTH)
    assert observed.status is CookieReadStatus.PRESENT
    assert observed.value == "next"
    assert observed.from_wsgi_input is True
    assert observed.generation == 0


def test_full_lifecycle_records_each_phase():
    # Phase 1: initial read of an in-memory request carrying synthetic values.
    req = _make_request("session=legit; theme=dark; session=evil")
    initial = req.read_secure_cookie(AUTH)
    assert initial.status is CookieReadStatus.AMBIGUOUS
    assert initial.from_wsgi_input is True

    # Phase 2: copy, then replace the whole cookie list.
    derived = req.copy()
    derived.cookies = {"session": "fresh", "theme": "light"}
    replaced = derived.read_secure_cookie(AUTH)
    assert replaced.status is CookieReadStatus.PRESENT
    assert replaced.value == "fresh"
    assert replaced.from_wsgi_input is False

    # Phase 3: a response is emitted; the following request is read afresh.
    response = Response()
    response.set_cookie("session", "rotated")
    following = _make_request("session=following")
    after_response = following.read_secure_cookie(AUTH)
    assert after_response.status is CookieReadStatus.PRESENT
    assert after_response.value == "following"
    assert after_response.from_wsgi_input is True

    # Each phase names a distinct, auditable request revision.
    assert initial.generation != replaced.generation
    assert replaced.header_fingerprint != after_response.header_fingerprint


def test_reader_for_a_configured_auth_cookie_set():
    req = _make_request("session=legit; csrf=abc; theme=dark")
    reader = SecureCookieReader(req.environ, ("session", "csrf", "missing"))
    readings = reader.read_auth_cookies()

    assert set(readings) == {"session", "csrf", "missing"}
    assert readings["session"].status is CookieReadStatus.PRESENT
    assert readings["csrf"].value == "abc"
    assert readings["missing"].status is CookieReadStatus.MISSING
    # Non-auth cookies are simply not part of the secure view.
    assert "theme" not in readings


def test_request_exposes_reader_factory():
    req = _make_request("session=legit")
    reader = req.secure_cookie_reader(("session",))
    result = reader.read("session")
    assert result.status is CookieReadStatus.PRESENT
    assert result.value == "legit"


def test_out_of_band_header_replacement_is_treated_as_new_source():
    req = _make_request("session=legit")
    assert req.read_secure_cookie(AUTH).from_wsgi_input is True

    req.environ["HTTP_COOKIE"] = "session=rewritten"
    result = req.read_secure_cookie(AUTH)

    assert result.status is CookieReadStatus.PRESENT
    assert result.value == "rewritten"
    assert result.from_wsgi_input is False


@pytest.mark.parametrize(
    "header,expected",
    [
        ("", CookieReadStatus.MISSING),
        ("other=1", CookieReadStatus.MISSING),
        ("session=a", CookieReadStatus.PRESENT),
        ("session=a; session=b", CookieReadStatus.AMBIGUOUS),
        ("session=a; x=1; session=b; session=c", CookieReadStatus.AMBIGUOUS),
    ],
)
def test_status_matrix(header, expected):
    assert _make_request(header).read_secure_cookie(AUTH).status is expected
