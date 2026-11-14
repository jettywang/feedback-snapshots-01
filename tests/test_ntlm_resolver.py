# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import dataclasses
import logging
import socket
import typing

import pytest

import spnego
import spnego._negotiate as negotiate
from spnego._ntlm import NTLMProxy
from spnego._ntlm_resolver import (
    FileNTLMCredentialResolver,
    NTLMCredentialResolver,
    NTLMCredentialRotationPolicy,
    NTLMCredentialVersion,
    ResolvedNTLMCredential,
)
from spnego.exceptions import (
    InvalidTokenError,
    NoCredentialError,
    OperationNotAvailableError,
)


class InMemoryNTLMCredentialResolver(NTLMCredentialResolver):
    """Test tenant backed by an explicit in-memory credential map.

    The key is the exact (domain, username) pair where an empty domain means
    the account advertised no domain. Every credential set bumps the revision
    so a mid-handshake rotation is observable through current_version().
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self._entries: typing.Dict[typing.Tuple[str, str], ResolvedNTLMCredential] = {}
        self._revision = 0
        self.resolve_calls = 0
        self.raise_on_resolve: typing.Optional[Exception] = None

    def _key(self, domain: str, username: str) -> typing.Tuple[str, str]:
        return domain.upper(), username.upper()

    def set_credential(self, domain: str, username: str, password: str) -> None:
        self._revision += 1
        self._entries[self._key(domain, username)] = self._build(domain, username, password)

    def rotate_credential(self, domain: str, username: str, password: str) -> None:
        # A rotation replaces the entry while retaining its identity.
        self.set_credential(domain, username, password)

    def _build(self, domain: str, username: str, password: str) -> ResolvedNTLMCredential:
        from spnego._ntlm_raw.crypto import lmowfv1, ntowfv1

        return ResolvedNTLMCredential(
            domain=domain,
            username=username,
            lm_hash=lmowfv1(password),
            nt_hash=ntowfv1(password),
            version=self.current_version(),
        )

    def current_version(self) -> NTLMCredentialVersion:
        return NTLMCredentialVersion(source=self.name, revision=str(self._revision))

    def resolve(self, domain: str, username: str) -> ResolvedNTLMCredential:
        self.resolve_calls += 1
        if self.raise_on_resolve is not None:
            raise self.raise_on_resolve

        key = self._key(domain, username)
        if key not in self._entries:
            raise NoCredentialError(
                context_msg=(f"Resolver {self.name} has no credential for {self.diagnostic_id(domain, username)}")
            )

        entry = self._entries[key]
        return dataclasses.replace(entry, version=self.current_version())


def _full_handshake(client: spnego.ContextProxy, server: spnego.ContextProxy) -> None:
    # Generic loop so the same helper covers raw NTLM (3 tokens) and SPNEGO
    # wrapped NTLM (extra mechListMIC round trip).
    token: typing.Optional[bytes] = client.step()
    peer = server
    while not (client.complete and server.complete):
        token = peer.step(token)
        peer = client if peer is server else server

    assert client.complete
    assert server.complete


def _make_tenant(
    resolver: NTLMCredentialResolver,
    policy: NTLMCredentialRotationPolicy = NTLMCredentialRotationPolicy.pin,
) -> NTLMProxy:
    return typing.cast(
        NTLMProxy,
        spnego.server(
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
            ntlm_credential_resolver=resolver,
            ntlm_credential_rotation_policy=policy,
        ),
    )


def _make_client(domain: str, username: str, password: str) -> spnego.ContextProxy:
    principal = f"{domain}\\{username}" if domain else username
    return spnego.client(
        principal,
        password,
        hostname=socket.gethostname(),
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )


def test_resolved_credential_repr_excludes_secret_material():
    resolver = InMemoryNTLMCredentialResolver("tenant-a")
    resolver.set_credential("DOMAIN", "user", "Password01")
    resolved = resolver.resolve("DOMAIN", "user")

    rendered = repr(resolved)
    assert "Password01" not in rendered
    assert "lm_hash" not in rendered
    assert "nt_hash" not in rendered
    assert "version" not in rendered
    assert resolved.username == "user"
    assert len(resolved.lm_hash) == 16
    assert len(resolved.nt_hash) == 16


def test_version_diagnostic_contains_only_identity_and_revision():
    resolver = InMemoryNTLMCredentialResolver("tenant-a")
    resolver.set_credential("DOMAIN", "user", "Password01")
    version = resolver.current_version()

    assert str(version) == "tenant-a@1"
    assert "Password01" not in str(version)
    assert resolver.diagnostic_id("DOMAIN", "user") == "DOMAIN\\user"
    assert resolver.diagnostic_id("", "user") == "user"


def test_two_tenants_interleaved_same_username_different_passwords():
    shared_user = "shared_admin"
    password_a = "Tenant-A-Password"
    password_b = "Tenant-B-Password"

    resolver_a = InMemoryNTLMCredentialResolver("tenant-a")
    resolver_a.set_credential("DOMA", shared_user, password_a)
    resolver_b = InMemoryNTLMCredentialResolver("tenant-b")
    resolver_b.set_credential("DOMB", shared_user, password_b)

    server_a = _make_tenant(resolver_a)
    server_b = _make_tenant(resolver_b)
    client_a = _make_client("DOMA", shared_user, password_a)
    client_b = _make_client("DOMB", shared_user, password_b)

    # Interleave the two handshakes step by step so state cannot bleed across
    # acceptor instances.
    nego_a = client_a.step()
    nego_b = client_b.step()
    challenge_a = server_a.step(nego_a)
    challenge_b = server_b.step(nego_b)
    auth_a = client_a.step(challenge_a)
    auth_b = client_b.step(challenge_b)
    server_a.step(auth_a)
    server_b.step(auth_b)

    assert server_a.complete
    assert server_b.complete
    assert server_a.client_principal == f"DOMA\\{shared_user}"
    assert server_b.client_principal == f"DOMB\\{shared_user}"

    # Each success is attributed to its own instance; the other tenant's
    # password must not authenticate against this resolver.
    foreign_client = _make_client("DOMA", shared_user, password_b)
    foreign_server = _make_tenant(resolver_a)
    foreign_challenge = foreign_server.step(foreign_client.step())
    with pytest.raises(InvalidTokenError, match="Invalid NTLM response from initiator"):
        foreign_server.step(foreign_client.step(foreign_challenge))


def test_resolver_no_match_does_not_fall_back_to_other_tenant():
    resolver_a = InMemoryNTLMCredentialResolver("tenant-a")
    resolver_a.set_credential("DOMA", "user", "Password01")
    resolver_b = InMemoryNTLMCredentialResolver("tenant-b")
    resolver_b.set_credential("DOMB", "user", "Password02")

    server_a = _make_tenant(resolver_a)
    client_b = _make_client("DOMB", "user", "Password02")

    challenge = server_a.step(client_b.step())
    with pytest.raises(NoCredentialError, match="Resolver tenant-a has no credential for DOMB\\\\user"):
        server_a.step(client_b.step(challenge))


def test_domain_presence_is_significant():
    # An account without a domain and an identically named domain account are
    # distinct; an empty/no domain lookup must not match the domain entry.
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("", "local", "NoDomainPass")
    resolver.set_credential("DOMAIN", "local", "DomainPass")

    no_domain = resolver.resolve("", "local")
    with_domain = resolver.resolve("DOMAIN", "local")

    assert no_domain.nt_hash != with_domain.nt_hash
    assert no_domain.domain == ""
    assert with_domain.domain == "DOMAIN"

    with pytest.raises(NoCredentialError):
        resolver.resolve("OTHER", "local")


def test_username_and_domain_matching_is_case_insensitive():
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "User", "Password01")

    resolved = resolver.resolve("domain", "USER")
    assert resolved.username == "User"
    assert resolved.domain == "DOMAIN"


def test_rotation_pin_policy_rejects_mid_handshake_change():
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "OriginalPass")
    server = _make_tenant(resolver, NTLMCredentialRotationPolicy.pin)
    client = _make_client("DOMAIN", "user", "OriginalPass")

    challenge = server.step(client.step())

    # Rotate while the handshake is waiting for the AUTHENTICATE message.
    resolver.rotate_credential("DOMAIN", "user", "RotatedPass")

    authenticate = client.step(challenge)
    with pytest.raises(NoCredentialError, match="NTLM credential rotation detected mid-handshake"):
        server.step(authenticate)
    assert not server.complete


def test_rotation_reload_policy_accepts_fresh_credential():
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "OriginalPass")
    server = _make_tenant(resolver, NTLMCredentialRotationPolicy.reload)
    client = _make_client("DOMAIN", "user", "OriginalPass")

    challenge = server.step(client.step())
    resolver.rotate_credential("DOMAIN", "user", "RotatedPass")

    # The client still proves the original credential; the reload policy
    # validates against the current store revision and therefore rejects it.
    with pytest.raises(InvalidTokenError, match="Invalid NTLM response from initiator"):
        server.step(client.step(challenge))

    # A fresh handshake against the rotated credential succeeds.
    rotated_client = _make_client("DOMAIN", "user", "RotatedPass")
    rotated_server = _make_tenant(resolver, NTLMCredentialRotationPolicy.reload)
    _full_handshake(rotated_client, rotated_server)
    assert rotated_server.client_principal == "DOMAIN\\user"


def test_pin_policy_allows_handshake_without_rotation():
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "Password01")
    server = _make_tenant(resolver)
    client = _make_client("DOMAIN", "user", "Password01")

    _full_handshake(client, server)
    assert resolver.resolve_calls == 1
    assert server.client_principal == "DOMAIN\\user"


def test_resolver_exception_propagates_without_fallback(monkeypatch):
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "Password01")
    boom = RuntimeError("resolver backend unavailable")
    resolver.raise_on_resolve = boom

    server = _make_tenant(resolver)
    client = _make_client("DOMAIN", "user", "Password01")
    challenge = server.step(client.step())

    with pytest.raises(RuntimeError, match="resolver backend unavailable"):
        server.step(client.step(challenge))
    assert not server.complete

    # The process default (NTLM_USER_FILE) must not be consulted as a fallback.
    monkeypatch.delenv("NTLM_USER_FILE", raising=False)
    resolver.raise_on_resolve = boom
    server_two = _make_tenant(resolver)
    client_two = _make_client("DOMAIN", "user", "Password01")
    challenge_two = server_two.step(client_two.step())
    with pytest.raises(RuntimeError, match="resolver backend unavailable"):
        server_two.step(client_two.step(challenge_two))


def test_resolver_diagnostics_omit_secrets(caplog):
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "SecretPassword")

    server = _make_tenant(resolver)
    client = _make_client("DOMAIN", "user", "SecretPassword")

    with caplog.at_level(logging.DEBUG, logger="spnego._ntlm"):
        _full_handshake(client, server)

    assert "DOMAIN\\user" in caplog.text
    assert "SecretPassword" not in caplog.text
    assert "tenant@1" in caplog.text


def test_explicit_resolver_ignores_ntlm_user_file(monkeypatch, tmp_path):
    # Even when the legacy env var points at another store, an explicit
    # instance resolver must be the sole source of credentials.
    decoy = tmp_path / "decoy.creds"
    decoy.write_text("DECOY\\user:WrongPassword", encoding="utf-8")
    monkeypatch.setenv("NTLM_USER_FILE", str(decoy))

    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "Password01")
    server = _make_tenant(resolver)
    client = _make_client("DOMAIN", "user", "Password01")

    _full_handshake(client, server)
    assert server.client_principal == "DOMAIN\\user"


def test_ntlm_user_file_remains_compatibility_entry(tmp_path, monkeypatch):
    cred_file = tmp_path / "legacy.creds"
    cred_file.write_text("DOMAIN:user:Password01", encoding="utf-8")
    monkeypatch.setenv("NTLM_USER_FILE", str(cred_file))

    server = typing.cast(
        NTLMProxy,
        spnego.server(
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
        ),
    )
    client = _make_client("DOMAIN", "user", "Password01")
    _full_handshake(client, server)
    assert server.client_principal == "DOMAIN\\user"
    assert isinstance(server._credential_resolver, FileNTLMCredentialResolver)


def test_missing_store_and_resolver_raises(monkeypatch):
    monkeypatch.delenv("NTLM_USER_FILE", raising=False)
    with pytest.raises(
        OperationNotAvailableError,
        match="NTLM acceptor requires NTLM credential cache to be provided through the env var NTLM_USER_FILE",
    ):
        spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)


def test_file_resolver_strict_domain_matching(tmp_path):
    cred_file = tmp_path / "ntlm.creds"
    cred_file.write_text("DOMAIN:user:Password01\n:local:LocalPass\n", encoding="utf-8")
    resolver = FileNTLMCredentialResolver(str(cred_file))

    domain_match = resolver.resolve("domain", "USER")
    assert domain_match.domain == "DOMAIN"
    assert domain_match.username == "user"

    no_domain = resolver.resolve("", "local")
    assert no_domain.domain == ""

    with pytest.raises(NoCredentialError):
        resolver.resolve("DOMAIN", "local")
    with pytest.raises(NoCredentialError):
        resolver.resolve("", "user")


def test_file_resolver_reports_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist.creds"
    with pytest.raises(NoCredentialError, match="NTLM credential store does not exist or is not a file"):
        FileNTLMCredentialResolver(str(missing))


def test_file_resolver_rotation_changes_version(tmp_path):
    cred_file = tmp_path / "ntlm.creds"
    cred_file.write_text("DOMAIN:user:Password01", encoding="utf-8")
    resolver = FileNTLMCredentialResolver(str(cred_file))
    initial = resolver.current_version()

    cred_file.write_text("DOMAIN:user:Password02", encoding="utf-8")
    rotated = resolver.current_version()
    assert rotated != initial
    assert str(initial).startswith(f"{cred_file}@")


def test_resolver_threads_through_spnego_negotiate():
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "Password01")

    server = spnego.server(
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
        ntlm_credential_resolver=resolver,
    )
    assert isinstance(server, negotiate.NegotiateProxy)
    assert server._ntlm_credential_resolver is resolver

    client = spnego.client(
        "DOMAIN\\user",
        "Password01",
        hostname=socket.gethostname(),
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate,
    )
    _full_handshake(client, server)
    assert server.client_principal == "DOMAIN\\user"
    assert resolver.resolve_calls == 1


def test_invalid_rotation_policy_value_rejected():
    resolver = InMemoryNTLMCredentialResolver("tenant")
    resolver.set_credential("DOMAIN", "user", "Password01")
    with pytest.raises(ValueError, match="'bogus' is not a valid NTLMCredentialRotationPolicy"):
        spnego.server(
            protocol="ntlm",
            options=spnego.NegotiateOptions.use_ntlm,
            ntlm_credential_resolver=resolver,
            ntlm_credential_rotation_policy="bogus",  # type: ignore[arg-type]  # runtime enum validation
        )
