# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Connection boundaries for external account credentials.

A connection boundary is an opt-in admission layer.  It checks the endpoint and
the credentials attached to credential-read, token-exchange, impersonation,
and authorization requests before the underlying transport is called.

The implementation never opens a network connection itself.  Tests can pass a
recording callable as the transport and inspect the records collected by the
boundary.
"""

from contextlib import contextmanager
from contextvars import ContextVar
import dataclasses
import ipaddress
import socket
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from google.auth.exceptions import ConnectionBoundaryError


CREDENTIAL_READ = "credential_read"
EXCHANGE = "exchange"
IMPERSONATION = "impersonation"
TRUST_BOUNDARY = "trust_boundary"
AUTHORIZATION = "authorization"

BoundaryDenied = ConnectionBoundaryError
BoundaryRejected = ConnectionBoundaryError

# Verbose aliases keep call sites readable in tests.
STAGE_CREDENTIAL_READ = CREDENTIAL_READ
STAGE_EXCHANGE = EXCHANGE
STAGE_IMPERSONATION = IMPERSONATION
STAGE_TRUST_BOUNDARY = TRUST_BOUNDARY
STAGE_AUTHORIZATION = AUTHORIZATION

_ALL_STAGES = frozenset(
    (CREDENTIAL_READ, EXCHANGE, IMPERSONATION, TRUST_BOUNDARY, AUTHORIZATION)
)

_current_operation = ContextVar(
    "google_auth_connection_boundary_operation", default=None
)
_current_stage = ContextVar(
    "google_auth_connection_boundary_stage", default=None
)


@dataclasses.dataclass(frozen=True)
class Endpoint:
    """A normalized network endpoint."""

    url: str
    scheme: str
    host: str
    port: Optional[int]
    path: str

    @property
    def origin(self) -> str:
        port = "" if self.port is None else ":{}".format(self.port)
        return "{}://{}{}".format(self.scheme, self.host, port)

    @property
    def ip_address(self):
        try:
            return ipaddress.ip_address(self.host)
        except ValueError:
            return None

    @property
    def is_loopback(self) -> bool:
        ip = self.ip_address
        if ip is not None:
            return ip.is_loopback
        return self.host == "localhost" or self.host.endswith(".localhost")

    @property
    def is_link_local(self) -> bool:
        ip = self.ip_address
        return bool(ip is not None and ip.is_link_local)

    @property
    def is_private_network(self) -> bool:
        if self.is_loopback or self.is_link_local:
            return True
        ip = self.ip_address
        return bool(
            ip is not None
            and (ip.is_private or getattr(ip, "is_unique_local", False))
        )


def parse_endpoint(url: str) -> Endpoint:
    """Parses an HTTP URL into an :class:`Endpoint`."""
    if not isinstance(url, str):
        raise ConnectionBoundaryError(
            "Connection boundary requires a URL string, got {!r}.".format(type(url))
        )
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        raise ConnectionBoundaryError("Invalid connection boundary URL: {}".format(url))
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConnectionBoundaryError("Invalid port in URL: {}".format(url)) from exc
    return Endpoint(
        url=url,
        scheme=parsed.scheme.lower(),
        host=parsed.hostname.lower(),
        port=port,
        path=parsed.path or "/",
    )


def _host_matches(host: str, pattern: str) -> bool:
    pattern = pattern.lower().strip()
    if not pattern:
        return False
    if "://" in pattern:
        try:
            allowed = parse_endpoint(pattern)
        except ConnectionBoundaryError:
            return False
        if allowed.host != host and not _host_matches(host, allowed.host):
            return False
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != pattern[2:]
    if pattern.startswith("."):
        return host.endswith(pattern)
    return host == pattern

def _endpoint_matches(endpoint: Endpoint, allowed: str) -> bool:
    allowed = allowed.strip()
    if "://" not in allowed:
        return _host_matches(endpoint.host, allowed)

    allowed_endpoint = parse_endpoint(allowed)
    if allowed_endpoint.scheme != endpoint.scheme:
        return False
    if allowed_endpoint.port not in (None, endpoint.port):
        return False
    if not _host_matches(endpoint.host, allowed_endpoint.host):
        return False
    if allowed_endpoint.path in ("", "/"):
        return True
    return endpoint.path.startswith(allowed_endpoint.path)


def describe_credentials(
    headers: Optional[Mapping[str, str]] = None, body: Any = None
) -> Tuple[str, ...]:
    """Returns non-secret labels for credentials present in a request."""
    headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    kinds: List[str] = []

    authorization = headers.get("authorization")
    if authorization:
        scheme = str(authorization).split(" ", 1)[0].lower()
        if scheme == "bearer":
            kinds.append("bearer_access_token")
        elif scheme == "basic":
            kinds.append("basic_client_credentials")
        else:
            kinds.append("authorization_{}".format(scheme))

    if headers.get("x-goog-api-key"):
        kinds.append("api_key")
    if headers.get("x-aws-ec2-metadata-token"):
        kinds.append("aws_imdsv2_token")

    body_text = ""
    if body is not None:
        if isinstance(body, bytes):
            body_text = body.decode("utf-8", errors="ignore")
        elif isinstance(body, str):
            body_text = body
        else:
            body_text = str(body)

    for marker, label in (
        ("subject_token=", "external_subject_token"),
        ("refresh_token=", "oauth_refresh_token"),
        ("assertion=", "jwt_assertion"),
    ):
        if marker in body_text and label not in kinds:
            kinds.append(label)

    return tuple(kinds)


@dataclasses.dataclass
class AdmissionDecision:
    """The result of admitting one endpoint/stage combination."""

    allowed: bool
    stage: str
    url: str
    reason: str = ""
    endpoint: Optional[Endpoint] = None
    credentials: Tuple[str, ...] = ()
    cached: bool = False

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise ConnectionBoundaryError(
                "Connection boundary denied {} request to {}: {}".format(
                    self.stage, self.url, self.reason or "endpoint is not admitted"
                )
            )


@dataclasses.dataclass
class CallRecord:
    """A recorded transport call."""

    stage: str
    url: str
    method: str
    headers: Dict[str, str]
    body: Any
    credentials: Tuple[str, ...]
    connection_key: str
    attempt: int
    status: Optional[int] = None
    error: Optional[BaseException] = None
    response_headers: Optional[Mapping[str, str]] = None


@dataclasses.dataclass
class ConnectionRecord:
    """A logical origin connection and all attempts made through it."""

    key: str
    origin: str
    built_at: str
    endpoint: Endpoint
    decision: AdmissionDecision
    attempts: int = 0


class BoundaryOperation:
    """One credential operation whose retries share admission decisions."""

    def __init__(
        self,
        boundary: "ConnectionBoundary",
        credential: Any = None,
    ) -> None:
        self.boundary = boundary
        self.credential = credential
        self.decisions: Dict[Tuple[str, str, str], AdmissionDecision] = {}
        self.connections: Dict[str, ConnectionRecord] = {}
        self.calls: List[CallRecord] = []
        self.local_identities: List[Dict[str, Any]] = []
        self._token: Any = None

    def __enter__(self) -> "BoundaryOperation":
        if self._token is None:
            self._token = _current_operation.set(self)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._token is not None:
            _current_operation.reset(self._token)
            self._token = None

    @contextmanager
    def stage(self, stage: str):
        token = _current_stage.set(stage)
        try:
            yield self
        finally:
            _current_stage.reset(token)

    def record_local_identity(self, source: str, **details: Any) -> None:
        self.local_identities.append({"source": source, "details": details})
        self.boundary.local_identities.append(
            {"source": source, "details": details, "operation": self}
        )

    def check(
        self,
        stage: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        body: Any = None,
        method: str = "GET",
    ) -> AdmissionDecision:
        key = (stage, method.upper(), url)
        existing = self.decisions.get(key)
        if existing is not None:
            decision = dataclasses.replace(existing, cached=True)
        else:
            decision = self.boundary.admit(
                stage=stage, url=url, headers=headers, body=body, method=method
            )
            self.decisions[key] = decision
            if decision.allowed:
                connection_key = decision.endpoint.origin if decision.endpoint else url
                if connection_key not in self.connections:
                    self.connections[connection_key] = ConnectionRecord(
                        key=connection_key,
                        origin=connection_key,
                        built_at=stage,
                        endpoint=decision.endpoint,
                        decision=decision,
                    )
                    self.boundary.connections.append(
                        self.connections[connection_key]
                    )
        decision.credentials = describe_credentials(headers, body)
        return decision

    def guard(self, transport: Callable[..., Any]) -> "GuardedTransport":
        if isinstance(transport, GuardedTransport):
            return GuardedTransport(transport.transport, self)
        return GuardedTransport(transport, self)


class GuardedTransport:
    """Transport wrapper that enforces a :class:`ConnectionBoundary`."""

    def __init__(
        self, transport: Callable[..., Any], operation: BoundaryOperation
    ) -> None:
        self.transport = transport
        self.operation = operation

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        url = kwargs.get("url")
        if url is None and args:
            url = args[0]
        method = kwargs.get("method", "GET")
        headers = kwargs.get("headers")
        body = kwargs.get("body")
        stage = _current_stage.get() or self.boundary.stage_for(url)

        decision = self.operation.check(
            stage, url, headers=headers, body=body, method=method
        )
        record = CallRecord(
            stage=stage,
            url=url,
            method=method.upper(),
            headers=dict(headers or {}),
            body=body,
            credentials=decision.credentials,
            connection_key=decision.endpoint.origin if decision.endpoint else url,
            attempt=0,
        )
        if not decision.allowed:
            error = ConnectionBoundaryError(decision.reason or "connection denied")
            record.error = error
            self.operation.calls.append(record)
            self.operation.boundary.calls.append(record)
            decision.raise_if_denied()

        connection = self.operation.connections[decision.endpoint.origin]
        connection.attempts += 1
        record.connection_key = connection.key
        record.attempt = connection.attempts

        try:
            response = self.transport(*args, **kwargs)
        except BaseException as exc:  # noqa: B902 - record and re-raise.
            record.error = exc
            self.operation.calls.append(record)
            self.operation.boundary.calls.append(record)
            raise

        record.status = getattr(response, "status", None)
        record.response_headers = getattr(response, "headers", None)
        self.operation.calls.append(record)
        self.operation.boundary.calls.append(record)
        return response

    @property
    def boundary(self) -> "ConnectionBoundary":
        return self.operation.boundary


class ConnectionBoundary:
    """Policy and records for external-account connection boundaries."""

    def __init__(
        self,
        exchange_url: Optional[str] = None,
        *,
        credential_read_urls: Optional[Iterable[str]] = None,
        exchange_urls: Optional[Iterable[str]] = None,
        impersonation_urls: Optional[Iterable[str]] = None,
        trust_boundary_urls: Optional[Iterable[str]] = None,
        authorization_urls: Optional[Iterable[str]] = None,
        allowed_hosts: Optional[Iterable[str]] = None,
        allowed_networks: Optional[Iterable[str]] = None,
        approved_regions: Optional[Iterable[str]] = None,
        private_exchange_only: bool = True,
        private_credential_read_only: bool = True,
        allow_public_impersonation: bool = True,
        require_https_authorization: bool = True,
        allow_private_http: bool = True,
        resolver: Optional[Callable[[str], Iterable[str]]] = None,
        policy: Optional[Callable[..., bool]] = None,
        **aliases: Any,
    ) -> None:
        exchange_values = list(exchange_urls or [])
        if exchange_url:
            exchange_values.append(exchange_url)
        for key in ("token_url", "token_urls", "exchange_endpoint", "exchange_endpoints"):
            value = aliases.pop(key, None)
            if value is None:
                continue
            exchange_values.extend([value] if isinstance(value, str) else list(value))

        credential_values = list(credential_read_urls or [])
        for key in ("credential_source_urls", "credential_urls", "local_urls"):
            value = aliases.pop(key, None)
            if value is None:
                continue
            credential_values.extend([value] if isinstance(value, str) else list(value))

        authorization_values = list(authorization_urls or [])
        for key in ("allowed_authorization_urls", "authorization_origins"):
            value = aliases.pop(key, None)
            if value is None:
                continue
            authorization_values.extend([value] if isinstance(value, str) else list(value))

        cidr_values = list(allowed_networks or [])
        allowed_cidrs = aliases.pop("allowed_cidrs", None)
        if allowed_cidrs is not None:
            cidr_values.extend(
                [allowed_cidrs] if isinstance(allowed_cidrs, str) else list(allowed_cidrs)
            )

        if aliases:
            raise TypeError(
                "Unknown connection boundary options: {}".format(", ".join(aliases))
            )

        self.stage_urls: Dict[str, Tuple[str, ...]] = {
            CREDENTIAL_READ: tuple(credential_values),
            EXCHANGE: tuple(exchange_values),
            IMPERSONATION: tuple(impersonation_urls or ()),
            TRUST_BOUNDARY: tuple(trust_boundary_urls or ()),
            AUTHORIZATION: tuple(authorization_values),
        }
        self.allowed_hosts = tuple(allowed_hosts or ())
        self.allowed_networks = tuple(
            ipaddress.ip_network(value, strict=False) for value in cidr_values
        )
        self.approved_regions = frozenset(approved_regions or ())
        self.private_exchange_only = private_exchange_only
        self.private_credential_read_only = private_credential_read_only
        self.allow_public_impersonation = allow_public_impersonation
        self.require_https_authorization = require_https_authorization
        self.allow_private_http = allow_private_http
        self.resolver = resolver
        self.policy = policy

        self.connections: List[ConnectionRecord] = []
        self.calls: List[CallRecord] = []
        self.local_identities: List[Dict[str, Any]] = []

    @classmethod
    def private_network(
        cls, exchange_url: Optional[str] = None, **kwargs: Any
    ) -> "ConnectionBoundary":
        """Creates a boundary whose exchange path is private-only by default."""
        kwargs.setdefault("private_exchange_only", True)
        kwargs.setdefault("private_credential_read_only", True)
        return cls(exchange_url=exchange_url, **kwargs)

    def operation(self, credential: Any = None) -> Any:
        current = _current_operation.get()
        if current is not None and current.boundary is self:
            return _ReusableOperationContext(current)
        return BoundaryOperation(self, credential)

    def guard(
        self, transport: Callable[..., Any], credential: Any = None
    ) -> GuardedTransport:
        return BoundaryOperation(self, credential).guard(transport)

    def stage_for(self, url: str) -> str:
        try:
            endpoint = parse_endpoint(url)
        except ConnectionBoundaryError:
            return EXCHANGE
        for stage, allowed_urls in self.stage_urls.items():
            if any(_endpoint_matches(endpoint, value) for value in allowed_urls):
                return stage
        host = endpoint.host
        if "iamcredentials.googleapis.com" in host or ":generateAccessToken" in url:
            return IMPERSONATION
        if "allowedLocations" in url or "trust-boundary" in url:
            return TRUST_BOUNDARY
        if "sts." in host or "/token" in endpoint.path:
            return EXCHANGE
        return AUTHORIZATION

    def region_approved(self, region: Optional[str]) -> bool:
        if not self.approved_regions:
            return True
        return region in self.approved_regions

    def approve_region_switch(self, template_or_url: str, region: str) -> AdmissionDecision:
        if not self.region_approved(region):
            decision = AdmissionDecision(
                False,
                CREDENTIAL_READ,
                template_or_url,
                "region {!r} is not approved".format(region),
            )
            decision.raise_if_denied()
        url = template_or_url.replace("{region}", region)
        return self.check(CREDENTIAL_READ, url)

    def check(
        self,
        stage: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        body: Any = None,
        method: str = "GET",
    ) -> AdmissionDecision:
        return self.admit(stage, url, headers, body, method)

    def admit(
        self,
        stage: str,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        body: Any = None,
        method: str = "GET",
    ) -> AdmissionDecision:
        if stage not in _ALL_STAGES:
            stage = EXCHANGE
        endpoint = parse_endpoint(url)
        credentials = describe_credentials(headers, body)
        allowed, reason = self._default_admission(stage, endpoint)

        if allowed and self.policy is not None:
            result = self.policy(
                stage=stage,
                url=url,
                endpoint=endpoint,
                headers=headers or {},
                body=body,
                method=method,
                credentials=credentials,
            )
            if isinstance(result, AdmissionDecision):
                return result
            if result is False:
                allowed, reason = False, "rejected by custom policy"

        decision = AdmissionDecision(
            allowed=allowed,
            stage=stage,
            url=url,
            reason=reason,
            endpoint=endpoint,
            credentials=credentials,
        )
        return decision

    def _default_admission(
        self, stage: str, endpoint: Endpoint
    ) -> Tuple[bool, str]:
        if any(_endpoint_matches(endpoint, host) for host in self.allowed_hosts):
            return self._scheme_admission(stage, endpoint)

        allowed_urls = self.stage_urls.get(stage, ())
        if allowed_urls and any(
            _endpoint_matches(endpoint, value) for value in allowed_urls
        ):
            region = _region_from_host(endpoint.host)
            if region is not None and not self.region_approved(region):
                return False, "region {!r} is not approved".format(region)
            return self._scheme_admission(stage, endpoint)

        is_private = self._is_private_endpoint(endpoint)
        region = _region_from_host(endpoint.host)
        if (
            region is not None
            and self.approved_regions
            and region in self.approved_regions
        ):
            return self._scheme_admission(stage, endpoint)

        if stage == EXCHANGE:
            if self.private_exchange_only and not is_private:
                return False, "exchange endpoint is not on an admitted private network"
            return self._scheme_admission(stage, endpoint)

        if stage == CREDENTIAL_READ:
            if self.private_credential_read_only and not is_private:
                return False, "credential source is not local or private"
            return self._scheme_admission(stage, endpoint)

        if stage == IMPERSONATION:
            if not self.allow_public_impersonation and not is_private:
                return False, "impersonation endpoint is not private"
            return self._scheme_admission(stage, endpoint)

        if stage == TRUST_BOUNDARY:
            return self._scheme_admission(stage, endpoint)

        if stage == AUTHORIZATION:
            if self.stage_urls[AUTHORIZATION] and not any(
                _endpoint_matches(endpoint, value)
                for value in self.stage_urls[AUTHORIZATION]
            ):
                return False, "authorization endpoint is not in the allowed list"
            return self._scheme_admission(stage, endpoint)

        return False, "unknown stage"

    def _scheme_admission(
        self, stage: str, endpoint: Endpoint
    ) -> Tuple[bool, str]:
        if endpoint.scheme == "https":
            return True, ""
        if endpoint.scheme == "http" and self.allow_private_http:
            if endpoint.is_loopback or endpoint.is_link_local:
                return True, ""
            if self._is_private_endpoint(endpoint):
                return True, ""
        if stage == AUTHORIZATION and self.require_https_authorization:
            return False, "authorization requests must use HTTPS"
        if endpoint.scheme != "https":
            return False, "requests must use HTTPS"
        return True, ""

    def _is_private_endpoint(self, endpoint: Endpoint) -> bool:
        if endpoint.ip_address is not None:
            if any(endpoint.ip_address in network for network in self.allowed_networks):
                return True
            if endpoint.is_private_network:
                return True
        elif self.resolver is None:
            return endpoint.is_private_network

        if self.resolver is None or endpoint.ip_address is not None:
            return endpoint.is_private_network

        resolver = self.resolver
        if resolver is True:
            def resolve(host):
                return [info[4][0] for info in socket.getaddrinfo(host, None)]

            resolver = resolve

        addresses = resolver(endpoint.host)
        if not addresses:
            return False
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if any(ip in network for network in self.allowed_networks):
                continue
            if not (
                ip.is_loopback
                or ip.is_link_local
                or ip.is_private
                or getattr(ip, "is_unique_local", False)
            ):
                return False
        return True


class _ReusableOperationContext:
    def __init__(self, operation: BoundaryOperation) -> None:
        self.operation = operation

    def __enter__(self) -> BoundaryOperation:
        return self.operation

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


@contextmanager
def authorization_scope(credential: Any, method: str, url: str, headers: Mapping[str, str]):
    """Admit an authorization URL before and after credential headers are added."""
    boundary = getattr(credential, "_connection_boundary", None)
    if boundary is None:
        yield None
        return

    with boundary.operation(credential) as operation:
        decision = operation.check(
            AUTHORIZATION, url, headers=headers, method=method
        )
        decision.raise_if_denied()
        with operation.stage(AUTHORIZATION):
            yield operation
        operation.check(AUTHORIZATION, url, headers=headers, method=method)


class PrivateNetworkBoundary(ConnectionBoundary):
    """A :class:`ConnectionBoundary` with local/private defaults enabled."""

    def __init__(self, exchange_url: Optional[str] = None, **kwargs: Any) -> None:
        kwargs.setdefault("private_exchange_only", True)
        kwargs.setdefault("private_credential_read_only", True)
        super(PrivateNetworkBoundary, self).__init__(
            exchange_url=exchange_url, **kwargs
        )


NetworkBoundary = ConnectionBoundary
AdmissionBoundary = ConnectionBoundary
ConnectionPolicy = ConnectionBoundary
BoundaryPolicy = ConnectionBoundary
BoundaryTransport = GuardedTransport


class RecordingTransport:
    """Small in-memory transport useful for boundary tests and demos."""

    def __init__(self, responses: Optional[Iterable[Any]] = None) -> None:
        self.requests: List[Dict[str, Any]] = []
        self._responses = list(responses or [])

    def add_response(self, response: Any) -> None:
        self._responses.append(response)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        url = kwargs.get("url") or (args[0] if args else None)
        self.requests.append(
            {
                "url": url,
                "method": kwargs.get("method", "GET"),
                "headers": dict(kwargs.get("headers") or {}),
                "body": kwargs.get("body"),
                "kwargs": kwargs,
            }
        )
        if self._responses:
            return self._responses.pop(0)
        return _RecordingResponse(200, b"{}")


@dataclasses.dataclass
class _RecordingResponse:
    status: int
    data: bytes
    headers: Mapping[str, str] = dataclasses.field(default_factory=dict)


def _region_from_host(host: str) -> Optional[str]:
    parts = host.split(".")
    if len(parts) >= 3 and parts[0] == "sts" and parts[1] not in ("googleapis",):
        return parts[1]
    if len(parts) >= 4 and parts[0] == "sts" and parts[2] == "amazonaws":
        return parts[1]
    return None


RecordingRequest = RecordingTransport
