"""Client-side contract tests for login cookie issuance and logout.

The application keeps a legacy login page at ``/login`` and has moved the
new page to a separate mount point, ``/portal``.  A client therefore holds
identity cookies in two distinct scopes that the application itself
declares:

* a host-only ``session`` cookie scoped to ``/login`` (the legacy page),
  and
* a Domain-scoped ``session`` cookie scoped to ``example.com``/``/portal``
  (the new page).

These tests drive a real :class:`http.cookiejar.CookieJar` (the same
cookie storage semantics a browser uses) through the application's
responses entirely in-process.  No socket is opened.  They check that:

* issuance and the redirect to the new mount point populate both scopes,
* the targeted update of domain/path is observable browser-side,
* logout revokes identity in *both* declared scopes, including when the
  revocation arrives as an expired ``Set-Cookie`` tombstone (which must
  not be mistaken for a cookie that is still sent back),
* ordinary business preferences and other scopes the application did not
  approve for cleanup are left untouched, and
* WebOb's own request reading agrees with the jar once the same jar is
  replayed against the relevant mount points.

Two deliberately broken logout implementations are exercised to pin the
contract: one that only deletes the *current path*, and one that only
matches on the cookie *name* and drops the Domain attribute.  Each test
reports which scope still carries an identity while confirming the
preference value survives.
"""

from email.message import Message
from http.cookiejar import CookieJar
from urllib.parse import urljoin
from urllib.request import Request as URLRequest

import pytest

from webob import Request, Response, exc
from webob.dec import wsgify

HOST = "example.com"
BASE_URL = "http://" + HOST

AUTH_COOKIE = "session"
PREFS_COOKIE = "prefs"
PREFS_VALUE = "dark-mode"
CONTROL_COOKIE = "sso_id"
CONTROL_VALUE = "partner-session"

# The two identity scopes the application explicitly asks to revoke.
LEGACY_SCOPE = {"path": "/login", "domain": None}
PORTAL_SCOPE = {"path": "/portal", "domain": HOST}
AUTH_SCOPES = (LEGACY_SCOPE, PORTAL_SCOPE)

LEGACY_LOGIN_PATH = "/login"
NEW_LOGIN_PATH = "/portal/login"
LOGOUT_PATH = "/login/logout"
LOGOUT_LANDING_PATH = "/login/bye"
CONTROL_ISSUANCE_PATH = "/sso/entry"

# Inspection endpoints living under each relevant mount point.
LEGACY_CHECK_PATH = "/login/whoami"
PORTAL_CHECK_PATH = "/portal/whoami"
PREFS_CHECK_PATH = "/app/whoami"
CONTROL_CHECK_PATH = "/sso/whoami"

EXPIRED = "Wed, 31-Dec-97 23:59:59 GMT"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def make_app(logout_mode="correct"):
    """Build the WSGI application with selectable logout behaviour."""

    @wsgify
    def application(req):
        path = req.path

        # Legacy login page: issues the host-only session, sets a business
        # preference, and redirects the client to the new mount point.
        if path == LEGACY_LOGIN_PATH and req.method == "POST":
            resp = exc.HTTPFound(location=NEW_LOGIN_PATH)
            resp.set_cookie(
                AUTH_COOKIE, "legacy-token", path=LEGACY_SCOPE["path"]
            )
            resp.set_cookie(PREFS_COOKIE, PREFS_VALUE, path="/app")
            return resp

        # The legacy page itself does not mint a session on GET.
        if path == LEGACY_LOGIN_PATH:
            return Response("legacy login page")

        # New mount point: the targeted update moves identity into the
        # Domain-scoped /portal cookie.  Reached via the redirect above.
        if path == NEW_LOGIN_PATH:
            resp = Response("new login page")
            resp.set_cookie(
                AUTH_COOKIE,
                "new-token",
                path=PORTAL_SCOPE["path"],
                domain=PORTAL_SCOPE["domain"],
            )
            return resp

        # Another scope that logout is not authorised to touch.
        if path == CONTROL_ISSUANCE_PATH:
            resp = Response("partner entry")
            resp.set_cookie(CONTROL_COOKIE, CONTROL_VALUE, path="/sso")
            return resp

        if path == LOGOUT_PATH and req.method == "POST":
            return _logout_response(req, logout_mode)

        if path == LOGOUT_LANDING_PATH:
            return Response("signed out")

        if path.endswith("/whoami"):
            # Echo what WebOb actually reads from the replayed Cookie header.
            return Response(json={"path": path, "cookies": dict(req.cookies)})

        raise exc.HTTPNotFound

    return application


def _logout_response(req, mode):
    resp = exc.HTTPFound(location=LOGOUT_LANDING_PATH)

    if mode == "correct":
        # Revoke every identity scope the application itself declared.
        for scope in AUTH_SCOPES:
            resp.delete_cookie(
                AUTH_COOKIE, path=scope["path"], domain=scope["domain"]
            )
        return resp

    if mode == "current_path_only":
        # Bug: only delete at the logout request's own path.  Neither
        # declared identity scope lives at this path, so both survive.
        resp.delete_cookie(AUTH_COOKIE, path=req.path)
        return resp

    if mode == "name_only":
        # Bug: match on cookie name only and omit the Domain attribute,
        # so the Domain-scoped portal cookie cannot be matched or removed.
        resp.delete_cookie(AUTH_COOKIE, path=LEGACY_SCOPE["path"])
        resp.delete_cookie(AUTH_COOKIE, path=PORTAL_SCOPE["path"])
        return resp

    raise ValueError("unknown logout mode: %r" % mode)


class _JarResponse:
    """Adapt a WebOb response to the object CookieJar.extract_cookies wants."""

    def __init__(self, response):
        message = Message()
        for header in response.headers.getall("Set-Cookie"):
            message.add_header("Set-Cookie", header)
        self._message = message

    def info(self):
        return self._message


class InProcessBrowser:
    """Minimal browser: one shared cookie jar, follows redirects in-process."""

    def __init__(self, application):
        self.application = application
        self.jar = CookieJar()

    def open(self, path, method="GET"):
        url = urljoin(BASE_URL, path)
        history = []

        for _ in range(10):
            cookie_request = URLRequest(url, method=method)
            self.jar.add_cookie_header(cookie_request)
            cookie_header = cookie_request.get_header("Cookie", default="")

            request = Request.blank(url)
            request.method = method
            if cookie_header:
                request.headers["Cookie"] = cookie_header

            response = request.get_response(self.application)
            self.jar.extract_cookies(_JarResponse(response), cookie_request)
            history.append(response)

            if response.status_code not in REDIRECT_STATUSES:
                break
            url = urljoin(url, response.headers["Location"])
            method = "GET"

        return history

    def cookie_header_for(self, path):
        """What the browser would send for a path, without hitting the app."""
        request = URLRequest(urljoin(BASE_URL, path))
        self.jar.add_cookie_header(request)
        return request.get_header("Cookie", default="")

    def stored(self, name, path, domain_specified):
        matches = [
            cookie
            for cookie in self.jar
            if cookie.name == name
            and cookie.path == path
            and cookie.domain_specified == domain_specified
        ]
        assert len(matches) == 1, (name, path, domain_specified, matches)
        return matches[0]

    def whoami(self, path):
        response = self.open(path)[-1]
        assert response.status_code == 200
        return response.json["cookies"]


def _issue_full_login(browser):
    history = browser.open(LEGACY_LOGIN_PATH, method="POST")
    return history


def _issue_control_scope(browser):
    browser.open(CONTROL_ISSUANCE_PATH)


def test_legacy_issuance_redirects_to_new_mount_point():
    browser = InProcessBrowser(make_app())

    history = _issue_full_login(browser)

    assert [response.status_code for response in history] == [302, 200]
    assert history[0].headers["Location"] == urljoin(BASE_URL, NEW_LOGIN_PATH)
    assert history[-1].text == "new login page"


def test_issuance_populates_both_declared_scopes_with_browser_semantics():
    browser = InProcessBrowser(make_app())

    _issue_full_login(browser)

    legacy = browser.stored(
        AUTH_COOKIE, LEGACY_SCOPE["path"], domain_specified=False
    )
    portal = browser.stored(
        AUTH_COOKIE, PORTAL_SCOPE["path"], domain_specified=True
    )

    assert legacy.value == "legacy-token"
    assert legacy.domain == HOST  # host-only: no leading dot
    assert portal.value == "new-token"
    assert portal.domain == "." + HOST  # Domain-scoped
    assert portal.path == PORTAL_SCOPE["path"]

    # The preference issued alongside login is ordinary business state.
    prefs = browser.stored(PREFS_COOKIE, "/app", domain_specified=False)
    assert prefs.value == PREFS_VALUE


def test_cookies_are_only_sent_to_their_own_scope():
    browser = InProcessBrowser(make_app())

    _issue_full_login(browser)

    assert browser.cookie_header_for(LEGACY_CHECK_PATH) == (
        AUTH_COOKIE + "=legacy-token"
    )
    assert browser.cookie_header_for(PORTAL_CHECK_PATH) == (
        AUTH_COOKIE + "=new-token"
    )
    # Neither session leaks to an unrelated path.
    assert browser.cookie_header_for("/elsewhere") == ""
    # The preference stays isolated under its own path too.
    assert browser.cookie_header_for(PREFS_CHECK_PATH) == (
        PREFS_COOKIE + "=" + PREFS_VALUE
    )


def test_webob_reads_the_same_identity_the_jar_replays():
    browser = InProcessBrowser(make_app())

    _issue_full_login(browser)

    assert browser.whoami(LEGACY_CHECK_PATH) == {
        AUTH_COOKIE: "legacy-token"
    }
    assert browser.whoami(PORTAL_CHECK_PATH) == {AUTH_COOKIE: "new-token"}
    assert browser.whoami(PREFS_CHECK_PATH) == {PREFS_COOKIE: PREFS_VALUE}


def test_unapproved_scope_is_verified_by_a_control_request():
    browser = InProcessBrowser(make_app())

    _issue_full_login(browser)
    _issue_control_scope(browser)

    control = browser.stored(CONTROL_COOKIE, "/sso", domain_specified=False)
    assert control.value == CONTROL_VALUE
    # A request under the unapproved scope carries its own identity and
    # neither of the login sessions.
    cookies = browser.whoami(CONTROL_CHECK_PATH)
    assert cookies == {CONTROL_COOKIE: CONTROL_VALUE}


def test_correct_logout_revokes_both_scopes_and_keeps_preferences():
    browser = InProcessBrowser(make_app())

    _issue_full_login(browser)
    _issue_control_scope(browser)

    history = browser.open(LOGOUT_PATH, method="POST")
    assert [response.status_code for response in history] == [302, 200]
    assert history[0].headers["Location"] == urljoin(
        BASE_URL, LOGOUT_LANDING_PATH
    )

    set_cookies = history[0].headers.getall("Set-Cookie")
    assert len(set_cookies) == 2

    # Both tombstones target the exact scope the session was issued for.
    legacy_tombstone, portal_tombstone = sorted(
        set_cookies, key=lambda header: "Domain" in header
    )
    assert legacy_tombstone == (
        AUTH_COOKIE
        + "=; Max-Age=0; Path=/login; expires="
        + EXPIRED
    )
    assert portal_tombstone == (
        AUTH_COOKIE
        + "=; Domain="
        + HOST
        + "; Max-Age=0; Path=/portal; expires="
        + EXPIRED
    )

    # Expired deletion must not leave a cookie that is still sent back.
    remaining = {cookie.name for cookie in browser.jar}
    assert AUTH_COOKIE not in remaining
    assert browser.cookie_header_for(LEGACY_CHECK_PATH) == ""
    assert browser.cookie_header_for(PORTAL_CHECK_PATH) == ""

    # WebOb's request reading agrees: no identity at either mount point.
    assert browser.whoami(LEGACY_CHECK_PATH) == {}
    assert browser.whoami(PORTAL_CHECK_PATH) == {}

    # Ordinary preferences and the unapproved scope are untouched.
    assert browser.whoami(PREFS_CHECK_PATH) == {PREFS_COOKIE: PREFS_VALUE}
    assert browser.whoami(CONTROL_CHECK_PATH) == {
        CONTROL_COOKIE: CONTROL_VALUE
    }
    prefs = browser.stored(PREFS_COOKIE, "/app", domain_specified=False)
    assert prefs.value == PREFS_VALUE


@pytest.mark.parametrize(
    ("mode", "surviving_paths"),
    [
        # Only deleting the current path misses both issued scopes.
        ("current_path_only", ["/login", "/portal"]),
        # Matching on name only (no Domain) cannot touch the portal cookie.
        ("name_only", ["/portal"]),
    ],
)
def test_broken_logouts_leave_an_identifiable_scope_with_preferences_intact(
    mode, surviving_paths
):
    browser = InProcessBrowser(make_app(logout_mode=mode))

    _issue_full_login(browser)
    _issue_control_scope(browser)

    browser.open(LOGOUT_PATH, method="POST")

    legacy_alive = bool(browser.cookie_header_for(LEGACY_CHECK_PATH))
    portal_alive = bool(browser.cookie_header_for(PORTAL_CHECK_PATH))
    survivors = []
    if legacy_alive:
        survivors.append("/login")
    if portal_alive:
        survivors.append("/portal")

    assert survivors == surviving_paths

    # WebOb confirms the retained identity at the mount point(s).
    if legacy_alive:
        assert browser.whoami(LEGACY_CHECK_PATH) == {
            AUTH_COOKIE: "legacy-token"
        }
    else:
        assert browser.whoami(LEGACY_CHECK_PATH) == {}
    if portal_alive:
        assert browser.whoami(PORTAL_CHECK_PATH) == {
            AUTH_COOKIE: "new-token"
        }
    else:
        assert browser.whoami(PORTAL_CHECK_PATH) == {}

    # Business preference and the unapproved control scope stay in place.
    assert browser.whoami(PREFS_CHECK_PATH) == {PREFS_COOKIE: PREFS_VALUE}
    assert browser.whoami(CONTROL_CHECK_PATH) == {
        CONTROL_COOKIE: CONTROL_VALUE
    }
