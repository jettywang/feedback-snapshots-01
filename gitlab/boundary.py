"""Network boundary policy for response-driven GitLab requests.

Pagination links and redirects can point outside the reverse-proxy prefix used
to construct :class:`gitlab.Gitlab`.  This module keeps that decision explicit:
the instance prefix is always allowed, other destinations are followed only
when registered as migrations, and each migration independently declares
whether GitLab identity headers may be sent.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urljoin, urlparse, ParseResult

import requests
from requests.structures import CaseInsensitiveDict

from gitlab.exceptions import BoundaryViolation


GITLAB_IDENTITY_HEADERS = frozenset({"authorization", "private-token", "job-token"})
IDENTITY_HEADERS = GITLAB_IDENTITY_HEADERS | {"cookie"}


def _parse_location(value: str) -> ParseResult:
    value = str(value).strip()
    if "://" not in value:
        if value.startswith("//"):
            value = f"https:{value}"
        else:
            value = f"https://{value}"
    return urlparse(value)


def _origin_key(parsed: ParseResult) -> tuple[str, str, int]:
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    if parsed.port is not None:
        port = parsed.port
    else:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def _path_within_prefix(path: str, prefix: str) -> bool:
    prefix = (prefix or "").rstrip("/")
    if not prefix:
        return True
    return path == prefix or path.startswith(f"{prefix}/")


def strip_identity_headers(
    headers: Mapping[str, Any] | None, *, include_cookie: bool = True
) -> Mapping[str, Any] | None:
    """Remove GitLab identity headers in-place from ``headers``."""
    if headers is None:
        return None

    forbidden = IDENTITY_HEADERS if include_cookie else GITLAB_IDENTITY_HEADERS
    for name in list(headers.keys()):
        if str(name).lower() in forbidden:
            del headers[name]  # type: ignore[attr-defined]
    return headers


class AnonymousIdentityAuth(requests.auth.AuthBase):
    """Auth policy that suppresses GitLab and ambient identity headers."""

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        strip_identity_headers(request.headers)
        return request


@dataclasses.dataclass(frozen=True)
class AllowedMigration:
    """An explicitly admitted response-driven destination.

    ``url`` may be an origin (``https://mirror.example``) or a path prefix
    (``https://mirror.example/gitlab``).  Identity is not carried unless
    ``carry_gitlab_identity`` is explicitly enabled.
    """

    url: str
    carry_gitlab_identity: bool = False

    def __post_init__(self) -> None:
        parsed = _parse_location(self.url)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"Invalid allowed migration URL: {self.url!r}")
        normalized = parsed._replace(path=parsed.path.rstrip("/")).geturl()
        object.__setattr__(self, "url", normalized)

    @property
    def origin(self) -> str:
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @property
    def carry_credentials(self) -> bool:
        return self.carry_gitlab_identity

    @property
    def send_gitlab_identity(self) -> bool:
        return self.carry_gitlab_identity

    def matches(self, parsed: ParseResult) -> bool:
        allowed = urlparse(self.url)
        if _origin_key(parsed) != _origin_key(allowed):
            return False
        return _path_within_prefix(parsed.path, allowed.path)


@dataclasses.dataclass(frozen=True)
class BoundaryDecision:
    """The result of admitting a URL."""

    allowed: bool
    url: str
    reason: str
    same_instance: bool = False
    migration: bool = False
    carry_gitlab_identity: bool = False
    matched: AllowedMigration | None = None

    @property
    def carry_credentials(self) -> bool:
        return self.carry_gitlab_identity

    @property
    def code(self) -> str:
        return self.reason


MigrationInput = (
    str | AllowedMigration | Mapping[str, Any] | tuple[str, bool] | Sequence[Any]
)


def coerce_migration(
    value: MigrationInput, *, carry_gitlab_identity: bool | None = None
) -> AllowedMigration:
    if isinstance(value, AllowedMigration):
        if carry_gitlab_identity is None:
            return value
        return AllowedMigration(value.url, carry_gitlab_identity)

    if isinstance(value, Mapping):
        raw_url = (
            value.get("url")
            or value.get("origin")
            or value.get("location")
            or value.get("base_url")
            or value.get("host")
            or value.get("domain")
        )
        if not raw_url:
            raise ValueError(f"Invalid allowed migration mapping: {value!r}")
        identity = value.get(
            "carry_gitlab_identity",
            value.get(
                "carry_credentials",
                value.get("send_gitlab_identity", value.get("with_credentials", False)),
            ),
        )
        return AllowedMigration(str(raw_url), bool(identity))

    if isinstance(value, tuple) and len(value) == 2:
        raw_url, identity = value
        return AllowedMigration(str(raw_url), bool(identity))

    if carry_gitlab_identity is not None:
        return AllowedMigration(str(value), carry_gitlab_identity)
    return AllowedMigration(str(value), False)


class NetworkBoundary:
    """Admit URLs against an instance prefix and explicit migrations."""

    def __init__(
        self,
        base_url: str | None = None,
        allowed_migrations: (
            Sequence[MigrationInput] | Mapping[str, bool] | None
        ) = None,
        *,
        credentialed_migrations: Sequence[MigrationInput] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.allowed_migrations = self._coerce_migrations(
            allowed_migrations, credentialed_migrations or ()
        )

    @staticmethod
    def _coerce_migrations(
        allowed: Sequence[MigrationInput] | Mapping[str, bool] | None,
        credentialed: Sequence[MigrationInput],
    ) -> tuple[AllowedMigration, ...]:
        merged: dict[str, AllowedMigration] = {}

        def add(item: MigrationInput, *, identity: bool | None = None) -> None:
            migration = coerce_migration(item, carry_gitlab_identity=identity)
            key = migration.url
            existing = merged.get(key)
            if existing is None:
                merged[key] = migration
            elif migration.carry_gitlab_identity:
                merged[key] = AllowedMigration(existing.url, carry_gitlab_identity=True)

        if isinstance(allowed, Mapping):
            for url, identity in allowed.items():
                add((url, bool(identity)))
        elif allowed:
            for item in allowed:
                add(item)

        for item in credentialed:
            add(item, identity=True)

        return tuple(merged.values())

    def bind(self, base_url: str) -> NetworkBoundary:
        """Return a policy bound to *base_url* if this policy has no base."""
        if self.base_url == base_url:
            return self
        return NetworkBoundary(
            base_url=base_url,
            allowed_migrations=self.allowed_migrations,
        )

    def with_migrations(
        self,
        allowed_migrations: Sequence[MigrationInput] | Mapping[str, bool] | None = None,
        *,
        credentialed_migrations: Sequence[MigrationInput] | None = None,
    ) -> NetworkBoundary:
        migrations: list[MigrationInput] = list(self.allowed_migrations)
        if allowed_migrations:
            if isinstance(allowed_migrations, Mapping):
                for url, identity in allowed_migrations.items():
                    migrations.append((url, bool(identity)))
            else:
                migrations.extend(allowed_migrations)
        credentialed = list(credentialed_migrations or ())
        return NetworkBoundary(
            self.base_url,
            migrations,
            credentialed_migrations=credentialed,
        )

    def classify(self, url: str) -> BoundaryDecision:
        if not self.base_url:
            raise RuntimeError("NetworkBoundary must be bound to a GitLab URL")

        absolute_url = url
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            absolute_url = urljoin(f"{self.base_url}/", url)
            parsed = urlparse(absolute_url)

        base = _parse_location(self.base_url)
        if _origin_key(parsed) == _origin_key(base) and _path_within_prefix(
            parsed.path, base.path
        ):
            return BoundaryDecision(
                allowed=True,
                url=absolute_url,
                reason="same-instance-prefix",
                same_instance=True,
                carry_gitlab_identity=True,
            )

        for migration in self.allowed_migrations:
            if migration.matches(parsed):
                return BoundaryDecision(
                    allowed=True,
                    url=absolute_url,
                    reason="allowed-migration",
                    migration=True,
                    carry_gitlab_identity=migration.carry_gitlab_identity,
                    matched=migration,
                )

        return BoundaryDecision(
            allowed=False,
            url=absolute_url,
            reason="outside-instance-network-boundary",
        )

    def check(self, url: str) -> BoundaryDecision:
        decision = self.classify(url)
        if not decision.allowed:
            raise BoundaryViolation(
                "Blocked response-driven transition outside the GitLab instance "
                f"network boundary: {decision.url!r} ({decision.reason}). Add an "
                "explicit AllowedMigration if this destination is intentional.",
                decision=decision,
            )
        return decision

    def apply_auth(
        self, opts: dict[str, Any], decision: BoundaryDecision
    ) -> dict[str, Any]:
        """Apply the credential policy to backend request options."""
        headers = opts.setdefault("headers", {})

        if not decision.carry_gitlab_identity:
            strip_identity_headers(headers)
            opts["auth"] = AnonymousIdentityAuth()
            auth = opts["auth"]
        else:
            auth = opts.get("auth")

        if auth is not None:
            prepared = requests.PreparedRequest()
            prepared.headers = CaseInsensitiveDict(headers)
            auth(prepared)
            opts["headers"] = dict(prepared.headers)

        return opts
