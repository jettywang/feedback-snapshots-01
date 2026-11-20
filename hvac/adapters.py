"""
HTTP Client Library Adapters

"""
import logging
from abc import ABCMeta, abstractmethod
from urllib.parse import urljoin, urlsplit

import requests
import requests.exceptions

from hvac import exceptions, utils
from hvac.constants.client import DEFAULT_URL

logger = logging.getLogger(__name__)

# Request headers that carry the caller's identity. They may only be sent to
# the configured Vault hosts and must never appear in outbound response objects.
IDENTITY_HEADERS = ("X-Vault-Token", "Authorization")

# HTTP status codes that ask the client to switch the method to GET on the next hop.
_REDIRECT_METHOD_CHANGE_CODES = (301, 302, 303)
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class Adapter(metaclass=ABCMeta):
    """Abstract base class used when constructing adapters for use with the Client class."""

    @classmethod
    def from_adapter(
        cls,
        adapter,
    ):
        """Create a new adapter based on an existing Adapter instance.
        This can be used to create a new type of adapter that inherits the properties of an existing one.

        :param adapter: The existing Adapter instance.
        :type adapter: hvac.Adapters.Adapter
        """

        return cls(
            base_uri=adapter.base_uri,
            token=adapter.token,
            cert=adapter._kwargs.get("cert"),
            verify=adapter._kwargs.get("verify"),
            timeout=adapter._kwargs.get("timeout"),
            proxies=adapter._kwargs.get("proxies"),
            allow_redirects=adapter.allow_redirects,
            session=adapter.session,
            namespace=adapter.namespace,
            ignore_exceptions=adapter.ignore_exceptions,
            strict_http=adapter.strict_http,
            request_header=adapter.request_header,
            allowed_redirect_hosts=adapter.allowed_redirect_hosts,
            max_redirect_hops=adapter.max_redirect_hops,
        )

    def __init__(
        self,
        base_uri=DEFAULT_URL,
        token=None,
        cert=None,
        verify=True,
        timeout=30,
        proxies=None,
        allow_redirects=True,
        session=None,
        namespace=None,
        ignore_exceptions=False,
        strict_http=False,
        request_header=True,
        allowed_redirect_hosts=None,
        max_redirect_hops=2,
    ):
        """Create a new request adapter instance.

        :param base_uri: Base URL for the Vault instance being addressed.
        :type base_uri: str
        :param token: Authentication token to include in requests sent to Vault.
        :type token: str
        :param cert: Certificates for use in requests sent to the Vault instance. This should be a tuple with the
            certificate and then key.
        :type cert: tuple
        :param verify: Either a boolean to indicate whether TLS verification should be performed when sending requests to Vault,
            or a string pointing at the CA bundle to use for verification. See http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification.
        :type verify: Union[bool,str]
        :param timeout: The timeout value for requests sent to Vault.
        :type timeout: int
        :param proxies: Proxies to use when preforming requests.
            See: http://docs.python-requests.org/en/master/user/advanced/#proxies
        :type proxies: dict
        :param allow_redirects: Whether to follow redirects when sending requests to Vault.
        :type allow_redirects: bool
        :param session: Optional session object to use when performing request.
        :type session: request.Session
        :param namespace: Optional Vault Namespace.
        :type namespace: str
        :param ignore_exceptions: If True, _always_ return the response object for a given request. I.e., don't raise an exception
            based on response status code, etc.
        :type ignore_exceptions: bool
        :param strict_http: If True, use only standard HTTP verbs in request with additional params, otherwise process as is
        :type strict_http: bool
        :param request_header: If true, add the X-Vault-Request header to all requests to protect against SSRF vulnerabilities.
        :type request_header: bool
        :param allowed_redirect_hosts: Optional list of Vault failover hosts (URLs or ``host[:port]``
            values) that redirects may target. When set, hvac follows redirects itself instead of letting
            ``requests`` do so, and every hop must match one of these hosts (the configured ``base_uri``
            host is always included). Requests carrying credentials are never sent to other hosts.
        :type allowed_redirect_hosts: list(str)
        :param max_redirect_hops: Maximum number of redirect hops followed when ``allowed_redirect_hosts``
            is configured. Chains longer than this are rejected before the extra request is sent.
        :type max_redirect_hops: int
        """
        if not session:
            session = requests.Session()
            session.cert, session.verify, session.proxies = cert, verify, proxies
        # fix for issue 991 using session verify if set
        else:
            if session.verify:
                # need to set the variable and not assign it to self so it is properly passed in kwargs
                verify = session.verify
            if session.cert:
                cert = session.cert
            if session.proxies:
                proxies = session.proxies

        self.base_uri = base_uri
        self.token = token
        self.namespace = namespace
        self.session = session
        self.allow_redirects = allow_redirects
        self.ignore_exceptions = ignore_exceptions
        self.strict_http = strict_http
        self.request_header = request_header
        self.allowed_redirect_hosts = allowed_redirect_hosts
        self.max_redirect_hops = max_redirect_hops

        self._kwargs = {
            "cert": cert,
            "verify": verify,
            "timeout": timeout,
            "proxies": proxies,
        }

    @staticmethod
    def _normalize_host(host):
        """Return the ``host[:port]`` identity for a URL or host fragment."""
        if "://" not in host:
            host = f"https://{host}"
        return urlsplit(host).netloc

    def _trusted_redirect_hosts(self):
        """Build the set of hosts that authenticated requests may follow redirects to."""
        trusted_hosts = {self._normalize_host(self.base_uri)}
        for host in self.allowed_redirect_hosts or ():
            trusted_hosts.add(self._normalize_host(host))
        return trusted_hosts

    def _strip_identity_headers(self, response):
        """Remove request identity headers from an outbound response before it is returned."""
        for header in IDENTITY_HEADERS:
            response.headers.pop(header, None)
        return response

    @staticmethod
    def urljoin(*args):
        """Joins given arguments into a url. Trailing and leading slashes are stripped for each argument.

        :param args: Multiple parts of a URL to be combined into one string.
        :type args: str | unicode
        :return: Full URL combining all provided arguments
        :rtype: str | unicode
        """

        return "/".join(map(lambda x: str(x).strip("/"), args))

    def close(self):
        """Close the underlying Requests session."""
        self.session.close()

    def get(self, url, **kwargs):
        """Performs a GET request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("get", url, **kwargs)

    def post(self, url, **kwargs):
        """Performs a POST request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("post", url, **kwargs)

    def put(self, url, **kwargs):
        """Performs a PUT request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("put", url, **kwargs)

    def delete(self, url, **kwargs):
        """Performs a DELETE request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("delete", url, **kwargs)

    def list(self, url, **kwargs):
        """Performs a LIST request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("list", url, **kwargs)

    def head(self, url, **kwargs):
        """Performs a HEAD request.

        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        return self.request("head", url, **kwargs)

    def login(self, url, use_token=True, **kwargs):
        """Perform a login request.

        Associated request is typically to a path prefixed with "/v1/auth") and optionally stores the client token sent
            in the resulting Vault response for use by the :py:meth:`hvac.adapters.Adapter` instance under the _adapter
            Client attribute.

        :param url: Path to send the authentication request to.
        :type url: str | unicode
        :param use_token: if True, uses the token in the response received from the auth request to set the "token"
            attribute on the the :py:meth:`hvac.adapters.Adapter` instance under the _adapter Client attribute.
        :type use_token: bool
        :param kwargs: Additional keyword arguments to include in the params sent with the request.
        :type kwargs: dict
        :return: The response of the auth request.
        :rtype: requests.Response
        """
        response = self.post(url, **kwargs)

        if use_token:
            self.token = self.get_login_token(response)

        return response

    @abstractmethod
    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :return: A client token.
        :rtype: str
        """
        return NotImplementedError

    @abstractmethod
    def request(self, method, url, headers=None, raise_exception=True, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri. Intended to be implement by subclasses.

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :param raise_exception: If True, raise an exception via utils.raise_for_error(). Set this parameter to False to
            bypass this functionality.
        :type raise_exception: bool
        :return: The response of the request.
        :rtype: requests.Response
        """
        raise NotImplementedError


class RawAdapter(Adapter):
    """
    The RawAdapter adapter class.
    This adapter adds Vault-specific headers as required and optionally raises exceptions on errors,
    but always returns Response objects for requests.
    """

    def _raise_for_error(self, method: str, url: str, response: requests.Response):
        msg = json = text = errors = None
        try:
            text = response.text
        except Exception:
            pass

        if response.headers.get("Content-Type") == "application/json":
            try:
                json = response.json()
            except Exception:
                pass
            else:
                errors = json.get("errors")

        if errors is None:
            msg = text

        utils.raise_for_error(
            method,
            url,
            response.status_code,
            msg,
            errors=errors,
            text=text,
            json=json,
        )

    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :type response: requests.Response
        :return: A client token.
        :rtype: str
        """
        response_json = response.json()
        return response_json["auth"]["client_token"]

    def _secure_redirect_request(
        self, method, url, headers, request_kwargs, trusted_hosts
    ):
        """Follow redirects manually, allowing only trusted Vault failover hosts.

        Each hop is sent with ``allow_redirects=False`` so the decision about where
        credentials go stays with hvac. Every target host is validated against
        ``trusted_hosts`` before the request (and its identity headers) is sent.
        """
        current_url = url
        current_method = method
        current_headers = headers
        hops = 0

        while True:
            logger.info(
                "vault secure failover hop %s: %s %s",
                hops,
                current_method.upper(),
                current_url,
            )
            response = self.session.request(
                method=current_method,
                url=current_url,
                headers=current_headers,
                allow_redirects=False,
                **request_kwargs,
            )

            if response.status_code not in _REDIRECT_STATUSES:
                return response

            location = response.headers.get("Location")
            if not location:
                logger.warning(
                    "rejecting redirect response without a Location header "
                    "after %s hop(s): %s %s",
                    hops,
                    current_method.upper(),
                    current_url,
                )
                raise exceptions.UnrecognizedProxyResponse(
                    message=(
                        f"redirect response with status {response.status_code} did not "
                        f"provide a Location header"
                    ),
                    method=current_method,
                    url=current_url,
                )

            try:
                target_url = urljoin(current_url, location)
                target_host = urlsplit(target_url).netloc
            except ValueError as value_error:
                logger.warning(
                    "rejecting unparseable redirect target %r after %s hop(s): %s",
                    location,
                    hops,
                    value_error,
                )
                raise exceptions.UnrecognizedProxyResponse(
                    message=f"redirect Location header is not a valid URL: {location!r}",
                    method=current_method,
                    url=current_url,
                ) from value_error

            if target_host not in trusted_hosts:
                logger.warning(
                    "rejecting redirect to untrusted host %r (allowed hosts: %s); "
                    "identity headers were not forwarded",
                    target_host,
                    sorted(trusted_hosts),
                )
                raise exceptions.UntrustedRedirectHost(
                    message=(
                        f"redirect target {target_host!r} is not in the configured "
                        f"allowed_redirect_hosts"
                    ),
                    method=current_method,
                    url=target_url,
                )

            if hops >= self.max_redirect_hops:
                logger.warning(
                    "rejecting redirect chain longer than %s hop(s) at %s",
                    self.max_redirect_hops,
                    target_url,
                )
                raise exceptions.RedirectLimitExceeded(
                    message=(
                        f"redirect chain exceeded the limit of {self.max_redirect_hops} "
                        f"hop(s)"
                    ),
                    method=current_method,
                    url=target_url,
                )

            hops += 1
            if response.status_code in _REDIRECT_METHOD_CHANGE_CODES:
                current_method = "get"
            current_url = target_url

    def request(self, method, url, headers=None, raise_exception=True, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri.

        :param method: HTTP method to use with the request. E.g., GET, POST, etc.
        :type method: str
        :param url: Partial URL path to send the request to. This will be joined to the end of the instance's base_uri
            attribute.
        :type url: str | unicode
        :param headers: Additional headers to include with the request.
        :type headers: dict
        :param raise_exception: If True, raise an exception via utils.raise_for_error(). Set this parameter to False to
            bypass this functionality.
        :type raise_exception: bool
        :param kwargs: Additional keyword arguments to include in the requests call.
        :type kwargs: dict
        :return: The response of the request.
        :rtype: requests.Response
        """
        while "//" in url:
            # Vault CLI treats a double forward slash ('//') as a single forward slash for a given path.
            # To avoid issues with the requests module's redirection logic, we perform the same translation here.
            url = url.replace("//", "/")

        url = self.urljoin(self.base_uri, url)

        if not headers:
            headers = {}

        if self.request_header:
            headers["X-Vault-Request"] = "true"

        if self.token:
            headers["X-Vault-Token"] = self.token

        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace

        wrap_ttl = kwargs.pop("wrap_ttl", None)
        if wrap_ttl:
            headers["X-Vault-Wrap-TTL"] = str(wrap_ttl)

        _kwargs = self._kwargs.copy()
        _kwargs.update(kwargs)

        if self.strict_http and method.lower() in ("list",):
            # Entry point for standard HTTP substitution
            params = _kwargs.get("params", {})
            if method.lower() == "list":
                method = "get"
                params.update({"list": "true"})
            _kwargs["params"] = params

        if self.allowed_redirect_hosts is not None:
            response = self._secure_redirect_request(
                method=method,
                url=url,
                headers=headers,
                request_kwargs=_kwargs,
                trusted_hosts=self._trusted_redirect_hosts(),
            )
        else:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                allow_redirects=self.allow_redirects,
                **_kwargs
            )

        # Never echo request identity headers back to the caller, even on failover responses.
        self._strip_identity_headers(response)

        if not response.ok and (raise_exception and not self.ignore_exceptions):
            self._raise_for_error(method, url, response)

        return response


class JSONAdapter(RawAdapter):
    """
    The JSONAdapter adapter class.
    This adapter works just like the RawAdapter adapter except that HTTP 200 responses are returned as JSON dicts.
    All non-200 responses are returned as Response objects.
    """

    def get_login_token(self, response):
        """Extracts the client token from a login response.

        :param response: The response object returned by the login method.
        :type response: dict | requests.Response
        :return: A client token.
        :rtype: str
        """
        return response["auth"]["client_token"]

    def request(self, *args, **kwargs):
        """Main method for routing HTTP requests to the configured Vault base_uri.

        :param args: Positional arguments to pass to RawAdapter.request.
        :type args: list
        :param kwargs: Keyword arguments to pass to RawAdapter.request.
        :type kwargs: dict
        :return: Dict on HTTP 200 with JSON body, otherwise the response object.
        :rtype: dict | requests.Response
        """
        response = super().request(*args, **kwargs)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                pass

        return response


# Retaining the legacy name
Request = RawAdapter
