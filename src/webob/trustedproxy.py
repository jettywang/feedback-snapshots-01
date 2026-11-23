"""
Trusted external address support.

When a WSGI application runs behind one or more managed proxies, the
public address of a request (its scheme, host, and any path prefix the
proxy adds) differs from the address the WSGI server reports locally.
Guessing that public address from raw request headers is unsafe: clients
can forge ``Forwarded``/``X-Forwarded-*`` headers unless a proxy they
cannot bypass overwrites them.

This module implements an *optional* trusted external address view.  The
WSGI server (or the adapter in front of the application) is the only
component that knows which proxy hops actually forwarded a request, so
it confirms each hop by placing a synthetic confirmation result -- a
tuple of :class:`ProxyAttestation` objects, outermost hop first -- into
``environ['webob.trusted_proxy.attestations']``.  The integrator
supplies a :class:`TrustedProxyPolicy` describing the attestation
sources it approved, and uses :class:`TrustedExternalView` (via
``Request.external_view()``) to read the public scheme, host, and
prefix.

The scheme, host, and prefix of a public URL are always taken from a
*single* approved attestation (or, for direct connections, from the
local WSGI origin); fields from different hops are never mixed.  If the
confirmation result is incomplete -- a hop is missing, an unexpected
source shows up, or the selected attestation lacks fields -- resolution
fails with :class:`IncompleteProxyAttestation` (see its subclasses for
the diagnostic categories) so the application can explicitly refuse to
generate public links.

Internal routing is unaffected: ``SCRIPT_NAME``/``PATH_INFO`` always
keep their local meaning, and the external prefix only appears in the
URLs produced by the view.  Because both the attestations and the
policy live in the environ, ``Request.copy()`` preserves the view, and
``Response``'s relative-``Location`` resolution honours the policy
stored under ``environ['webob.trusted_proxy.policy']``.
"""

from urllib.parse import quote as url_quote

from webob.util import bytes_

__all__ = [
    "ExternalAddress",
    "IncompleteAttestationFields",
    "IncompleteProxyAttestation",
    "MissingAttestation",
    "ProxyAttestation",
    "TrustedExternalView",
    "TrustedProxyPolicy",
    "UntrustedProxySource",
]

PATH_SAFE = "/~!$&'()*+,;=:@"


class IncompleteProxyAttestation(Exception):
    """
    The proxy confirmation result did not yield a complete, approved
    external address.

    The application may catch this to explicitly refuse generating
    public links for the request.  ``category`` is a stable diagnostic
    category string; subclasses refine it.
    """

    category = "incomplete-proxy-attestation"


class MissingAttestation(IncompleteProxyAttestation):
    """A proxy hop of the approved chain is missing its attestation."""

    category = "missing-attestation"


class UntrustedProxySource(IncompleteProxyAttestation):
    """An attestation comes from a source the policy did not approve."""

    category = "untrusted-proxy-source"


class IncompleteAttestationFields(IncompleteProxyAttestation):
    """The selected attestation lacks scheme, host, or prefix."""

    category = "incomplete-attestation-fields"


class ProxyAttestation:
    """
    A single proxy hop's externally visible address, confirmed by the
    WSGI server.

    ``source`` identifies which managed proxy the server confirmed (the
    integrator approves sources through the policy).  ``scheme``,
    ``host``, and ``prefix`` belong together: they describe the address
    at which *this* hop exposed the application, and may only be used
    together.
    """

    def __init__(self, source, scheme=None, host=None, prefix=None):
        self.source = source
        self.scheme = scheme
        self.host = host
        self.prefix = prefix

    @property
    def complete(self):
        return (
            self.scheme is not None
            and self.host is not None
            and self.prefix is not None
        )

    def __repr__(self):
        return "%s(source=%r, scheme=%r, host=%r, prefix=%r)" % (
            type(self).__name__,
            self.source,
            self.scheme,
            self.host,
            self.prefix,
        )


class ExternalAddress:
    """
    A resolved public address.

    All fields come from a single source: either one approved
    attestation, or the local WSGI origin (``source == "local"``).
    """

    def __init__(self, scheme, host, prefix="", source="local"):
        self.scheme = scheme
        self.host = host
        self.prefix = prefix
        self.source = source

    @classmethod
    def local(cls, environ):
        """The address of a direct connection, from the local origin."""
        scheme = environ.get("wsgi.url_scheme", "http")
        host = environ.get("HTTP_HOST")

        if host is None:
            host = environ.get("SERVER_NAME", "localhost")
            port = environ.get("SERVER_PORT")
            default_port = "443" if scheme == "https" else "80"

            if port and port != default_port:
                host = "%s:%s" % (host, port)

        return cls(scheme=scheme, host=host, prefix="", source="local")

    @property
    def host_url(self):
        return "%s://%s" % (self.scheme, self.host)

    @property
    def quoted_prefix(self):
        return url_quote(bytes_(self.prefix), PATH_SAFE)

    def __eq__(self, other):
        if not isinstance(other, ExternalAddress):
            return NotImplemented

        return (
            self.scheme == other.scheme
            and self.host == other.host
            and self.prefix == other.prefix
            and self.source == other.source
        )

    def __repr__(self):
        return "%s(scheme=%r, host=%r, prefix=%r, source=%r)" % (
            type(self).__name__,
            self.scheme,
            self.host,
            self.prefix,
            self.source,
        )


class TrustedProxyPolicy:
    """
    Integrator-supplied policy deciding the trusted external address.

    ``require`` is the approved chain of attestation sources, outermost
    proxy first.  A request with no attestations at all is a direct
    connection and resolves to the local origin.  A request whose
    attestation chain does not exactly match ``require`` -- a hop lost
    its evidence, or an unexpected source appears -- raises
    :class:`IncompleteProxyAttestation`.

    The public scheme, host, and prefix are taken from the outermost
    approved attestation only; they are never combined with fields from
    another hop.
    """

    attestations_environ_key = "webob.trusted_proxy.attestations"
    policy_environ_key = "webob.trusted_proxy.policy"

    def __init__(self, require=()):
        self.require = tuple(require)

    @classmethod
    def from_environ(cls, environ):
        """The policy the integrator stored in the environ, if any."""
        return environ.get(cls.policy_environ_key)

    def attestations(self, environ):
        """The synthetic confirmation result placed by the WSGI server."""
        return tuple(environ.get(self.attestations_environ_key) or ())

    def resolve(self, environ):
        """
        Resolve the trusted external address for a request environ.

        Returns an :class:`ExternalAddress`; raises a subclass of
        :class:`IncompleteProxyAttestation` when the confirmation result
        is incomplete or does not match the approved chain.
        """
        attestations = self.attestations(environ)

        if not attestations:
            return ExternalAddress.local(environ)

        required = self.require

        if len(attestations) < len(required):
            raise MissingAttestation(
                "proxy attestation chain is incomplete: expected %d "
                "attested hop(s) %r, got %d"
                % (len(required), required, len(attestations))
            )

        if len(attestations) > len(required):
            raise UntrustedProxySource(
                "proxy attestation chain is longer than the approved "
                "chain %r" % (required,)
            )

        for attestation, source in zip(attestations, required):
            if attestation.source != source:
                raise UntrustedProxySource(
                    "proxy attestation source %r is not the approved "
                    "source %r" % (attestation.source, source)
                )

        outermost = attestations[0]

        if not outermost.complete:
            raise IncompleteAttestationFields(
                "attestation from %r does not confirm scheme, host, and "
                "prefix together" % (outermost.source,)
            )

        return ExternalAddress(
            scheme=outermost.scheme,
            host=outermost.host,
            prefix=outermost.prefix,
            source=outermost.source,
        )

    def request_uri(self, environ):
        """
        The full external request URI, mirroring the semantics of
        ``wsgiref.util.request_uri`` against the trusted address.
        """
        address = self.resolve(environ)
        url = address.host_url + address.quoted_prefix

        script_name = bytes_(environ.get("SCRIPT_NAME", "/"))
        path_info = bytes_(environ.get("PATH_INFO", ""))

        url += url_quote(script_name, PATH_SAFE)
        qpath_info = url_quote(path_info, PATH_SAFE)

        if "SCRIPT_NAME" not in environ:
            url += qpath_info[1:]
        else:
            url += qpath_info

        return url


class TrustedExternalView:
    """
    The trusted external address view of a request.

    Created via ``Request.external_view()``; see
    :class:`TrustedProxyPolicy` for how the address is resolved.  Every
    property resolves lazily and may raise
    :class:`IncompleteProxyAttestation`.
    """

    def __init__(self, request, policy):
        self.request = request
        self.policy = policy
        self._address = None

    @property
    def address(self):
        if self._address is None:
            self._address = self.policy.resolve(self.request.environ)

        return self._address

    @property
    def host_url(self):
        """The external URL through the host (no path)."""
        return self.address.host_url

    @property
    def application_url(self):
        """
        The external URL including the trusted prefix and SCRIPT_NAME
        (no PATH_INFO or query string).
        """
        request = self.request
        bscript_name = bytes_(request.script_name, request.url_encoding)

        return (
            self.host_url
            + self.address.quoted_prefix
            + url_quote(bscript_name, PATH_SAFE)
        )

    @property
    def path_url(self):
        """
        The external URL including the trusted prefix, SCRIPT_NAME, and
        PATH_INFO, but not QUERY_STRING.
        """
        request = self.request
        bpath_info = bytes_(request.path_info, request.url_encoding)

        return self.application_url + url_quote(bpath_info, PATH_SAFE)

    @property
    def url(self):
        """The full external request URL, including QUERY_STRING."""
        url = self.path_url
        qs = self.request.environ.get("QUERY_STRING")

        if qs:
            url += "?" + qs

        return url
