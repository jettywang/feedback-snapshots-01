import io

import pytest

from webob.request import Request
from webob.response import Response
from webob.trustedproxy import (
    ExternalAddress,
    IncompleteAttestationFields,
    IncompleteProxyAttestation,
    MissingAttestation,
    ProxyAttestation,
    TrustedProxyPolicy,
    UntrustedProxySource,
)

# The integrator-approved chain of managed proxies, outermost first.
POLICY = TrustedProxyPolicy(require=("edge-proxy", "internal-proxy"))


def mounted_environ(attestations=(), policy=POLICY):
    """
    The WSGI adapter's view of a request: the application mounted at the
    subpath ``/mount``, plus the synthetic confirmation result the WSGI
    server places into the environ for the proxy hops it confirmed.
    """
    environ = {
        "REQUEST_METHOD": "GET",
        "SCRIPT_NAME": "/mount",
        "PATH_INFO": "/login",
        "QUERY_STRING": "next=/account",
        "SERVER_NAME": "appserver.internal",
        "SERVER_PORT": "8080",
        "HTTP_HOST": "appserver.internal:8080",
        "wsgi.url_scheme": "http",
        "wsgi.version": (1, 0),
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }

    if attestations:
        environ[TrustedProxyPolicy.attestations_environ_key] = tuple(attestations)

    if policy is not None:
        environ[TrustedProxyPolicy.policy_environ_key] = policy

    return environ


def full_chain():
    return (
        ProxyAttestation(
            "edge-proxy",
            scheme="https",
            host="public.example.com",
            prefix="/app",
        ),
        ProxyAttestation(
            "internal-proxy",
            scheme="http",
            host="internal-hop.example",
            prefix="/internal",
        ),
    )


def call_app(app, environ):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = dict(headers)

    body = b"".join(app(environ, start_response))
    captured["body"] = body

    return captured


def login_app(environ, start_response):
    """The mounted application: issues an absolute return address."""
    req = Request(environ)
    resp = Response(status=302, location="welcome")
    return resp(environ, start_response)


def refusing_app(environ, start_response):
    """The application explicitly refuses incomplete public links."""
    req = Request(environ)

    try:
        resp = Response(status=302, location="welcome")
        return resp(environ, start_response)
    except IncompleteProxyAttestation as exc:
        resp = Response(
            status=503,
            body=("refused to generate public link: %s" % exc.category).encode(),
        )
        return resp(environ, start_response)


class TestDirectConnection:
    """No attestations: a plain direct connection uses the local origin."""

    def test_request_url_uses_local_origin(self):
        req = Request(mounted_environ())
        view = req.external_view()

        assert view.address == ExternalAddress(
            scheme="http",
            host="appserver.internal:8080",
            prefix="",
            source="local",
        )
        assert view.host_url == "http://appserver.internal:8080"
        assert view.application_url == "http://appserver.internal:8080/mount"
        assert view.url == "http://appserver.internal:8080/mount/login?next=/account"

    def test_internal_routing_unchanged(self):
        req = Request(mounted_environ())
        req.external_view().url

        assert req.script_name == "/mount"
        assert req.path_info == "/login"
        assert req.url == "http://appserver.internal:8080/mount/login?next=/account"

    def test_location_uses_local_origin(self):
        result = call_app(login_app, mounted_environ())

        assert result["status"] == "302 Found"
        assert (
            result["headers"]["Location"]
            == "http://appserver.internal:8080/mount/welcome"
        )


class TestCompleteTwoLevelProxy:
    """Both managed proxies attested: the public address comes from the edge."""

    def test_request_url_uses_outermost_attestation(self):
        req = Request(mounted_environ(full_chain()))
        view = req.external_view()

        assert view.address.source == "edge-proxy"
        assert view.host_url == "https://public.example.com"
        assert view.application_url == "https://public.example.com/app/mount"
        assert view.url == "https://public.example.com/app/mount/login?next=/account"

    def test_fields_never_mixed_across_hops(self):
        req = Request(mounted_environ(full_chain()))
        url = req.external_view().url

        # Nothing in the public URL may come from the second hop or the
        # local origin: fields only combine within one approved
        # attestation.
        assert "internal-hop.example" not in url
        assert "/internal" not in url
        assert "appserver.internal" not in url

    def test_internal_routing_unchanged(self):
        req = Request(mounted_environ(full_chain()))
        req.external_view().url

        assert req.script_name == "/mount"
        assert req.path_info == "/login"

    def test_request_copy_preserves_view(self):
        req = Request(mounted_environ(full_chain()))
        copy = req.copy()

        assert copy.path_info == "/login"
        assert copy.script_name == "/mount"
        assert copy.external_view().url == req.external_view().url
        assert copy.external_view().address.source == "edge-proxy"

    def test_location_uses_external_address(self):
        result = call_app(login_app, mounted_environ(full_chain()))

        assert result["status"] == "302 Found"
        assert (
            result["headers"]["Location"]
            == "https://public.example.com/app/mount/welcome"
        )


class TestMissingSecondLevelAttestation:
    """The second proxy hop lost its evidence: no new public address."""

    def environ(self):
        return mounted_environ(full_chain()[:1])

    def test_view_resolution_refused(self):
        req = Request(self.environ())
        view = req.external_view()

        with pytest.raises(MissingAttestation) as excinfo:
            view.url

        assert excinfo.value.category == "missing-attestation"
        assert isinstance(excinfo.value, IncompleteProxyAttestation)

    def test_internal_routing_unchanged(self):
        req = Request(self.environ())

        with pytest.raises(MissingAttestation):
            req.external_view().url

        assert req.script_name == "/mount"
        assert req.path_info == "/login"
        # The local request URL is still the local origin only.
        assert req.url == "http://appserver.internal:8080/mount/login?next=/account"

    def test_application_explicitly_refuses(self):
        result = call_app(refusing_app, self.environ())

        assert result["status"] == "503 Service Unavailable"
        assert result["body"] == (
            b"refused to generate public link: missing-attestation"
        )
        assert "Location" not in result["headers"]

    def test_location_conversion_raises_without_evidence(self):
        req = Request(self.environ())
        resp = Response(status=302, location="welcome")

        with pytest.raises(MissingAttestation):
            Response._make_location_absolute(req.environ, resp.location)


class TestPolicyDiagnostics:
    def test_untrusted_source_rejected(self):
        attestations = (
            ProxyAttestation(
                "rogue-proxy", scheme="https", host="evil.example", prefix="/"
            ),
            full_chain()[1],
        )
        req = Request(mounted_environ(attestations))

        with pytest.raises(UntrustedProxySource) as excinfo:
            req.external_view().url

        assert excinfo.value.category == "untrusted-proxy-source"

    def test_incomplete_fields_rejected(self):
        attestations = (
            ProxyAttestation("edge-proxy", scheme="https", host="public.example.com"),
            full_chain()[1],
        )
        req = Request(mounted_environ(attestations))

        with pytest.raises(IncompleteAttestationFields) as excinfo:
            req.external_view().url

        assert excinfo.value.category == "incomplete-attestation-fields"

    def test_extra_unexpected_hop_rejected(self):
        attestations = (
            ProxyAttestation(
                "unknown-proxy", scheme="https", host="x.example", prefix="/"
            ),
        ) + full_chain()
        req = Request(mounted_environ(attestations))

        with pytest.raises(UntrustedProxySource):
            req.external_view().url

    def test_view_requires_a_policy(self):
        req = Request(mounted_environ(policy=None))

        with pytest.raises(ValueError):
            req.external_view()

    def test_policy_passed_explicitly(self):
        req = Request(mounted_environ(full_chain(), policy=None))

        assert (
            req.external_view(POLICY).url
            == "https://public.example.com/app/mount/login?next=/account"
        )

    def test_location_without_policy_keeps_local_semantics(self):
        environ = mounted_environ(full_chain(), policy=None)

        assert (
            Response._make_location_absolute(environ, "welcome")
            == "http://appserver.internal:8080/mount/welcome"
        )
