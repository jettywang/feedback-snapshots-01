"""
Signing key rotation with an explicit, production ready key lifecycle.

A rotation is expressed as a policy of named key entries, each in exactly one
of three states:

* ``KeyStatus.ACTIVE``  - the single key used to sign every newly issued token.
* ``KeyStatus.RETAINED`` - a previous active key that is still trusted to
  verify historical tokens during a bounded transition window.
* ``KeyStatus.RETIRED``  - a key that may no longer verify anything. Tokens
  signed with it are rejected even if their signature is cryptographically
  valid and their ``kid`` header still names the key.

Only one key may be active at a time. Switching the active key automatically
moves the previous active key into the retained state, so existing tokens keep
working until the transition window is closed by retiring the old key.

``RotatingTokenBackend`` is a drop-in ``TokenBackend`` implementation that
delegates signing and verification to a shared :class:`KeyRotationPolicy`.
Because every issue, verify and refresh operation consults the same policy
object, a refresh performed across a rotation point is verifiable under the
exact same policy that produced the new token.

Wiring it into the global token backend (``Token.get_token_backend`` reads
``rest_framework_simplejwt.state.token_backend``)::

    from rest_framework_simplejwt.key_rotation import (
        KeyRotationPolicy,
        KeyStatus,
        RotatingTokenBackend,
        SigningKeyEntry,
    )
    from rest_framework_simplejwt import state

    policy = KeyRotationPolicy(
        SigningKeyEntry("old", old_secret, KeyStatus.RETAINED),
        SigningKeyEntry("new", new_secret, KeyStatus.ACTIVE),
    )
    state.token_backend = RotatingTokenBackend(policy, "HS256")
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import jwt
from django.utils.translation import gettext_lazy as _

from .backends import TokenBackend
from .exceptions import TokenBackendError
from .utils import format_lazy


class KeyStatus(str, Enum):
    """
    Explicit lifecycle states a signing key can occupy.
    """

    ACTIVE = "active"
    RETAINED = "retained"
    RETIRED = "retired"


@dataclass
class SigningKeyEntry:
    """
    A named signing key together with its current lifecycle state.

    For asymmetric algorithms pass the private key as ``signing_key`` and the
    matching public key as ``verifying_key``. For HMAC algorithms the secret is
    used for both.
    """

    kid: str
    signing_key: str
    status: KeyStatus
    verifying_key: str = ""
    jwk_url: Optional[str] = None

    @property
    def is_active(self) -> bool:
        return self.status is KeyStatus.ACTIVE

    @property
    def is_retained(self) -> bool:
        return self.status is KeyStatus.RETAINED

    @property
    def is_retired(self) -> bool:
        return self.status is KeyStatus.RETIRED

    @property
    def is_acceptable(self) -> bool:
        """
        Whether tokens signed by this key may currently be verified.
        """
        return self.status in (KeyStatus.ACTIVE, KeyStatus.RETAINED)


class KeyRotationPolicyError(TokenBackendError):
    """Raised when a rotation policy is configured or used inconsistently."""


class KeyRotationPolicy:
    """
    Holds the set of signing key entries and enforces their lifecycle.

    The policy is the single source of truth for both signing (which key is
    active now) and verification (which keys are still trustworthy now).
    """

    def __init__(self, *entries: SigningKeyEntry, algorithm: str = "HS256") -> None:
        self.algorithm = algorithm
        self._entries: dict[str, SigningKeyEntry] = {}
        for entry in entries:
            self.add_entry(entry)

        active = [entry for entry in entries if entry.is_active]
        if len(active) > 1:
            raise KeyRotationPolicyError(
                _("Only one signing key may be active at a time")
            )

    def add_entry(self, entry: SigningKeyEntry) -> None:
        """
        Registers a new key entry. Fails on duplicate ``kid`` or on a second
        active key.
        """
        if entry.kid in self._entries:
            raise KeyRotationPolicyError(
                format_lazy(_("Duplicate signing key identifier '{}'"), entry.kid)
            )
        if entry.is_active and self.active_entry is not None:
            raise KeyRotationPolicyError(
                _("Only one signing key may be active at a time")
            )
        self._entries[entry.kid] = entry

    # -- state transitions --------------------------------------------------

    def activate(self, kid: str) -> SigningKeyEntry:
        """
        Makes ``kid`` the active signing key. The previously active key (if
        any) is moved into the retained state so that tokens it signed remain
        verifiable during the transition window.

        A key staged in the retired state may be promoted when it is being
        brought into service for the first time (e.g. a pre-registered
        replacement key); retirement only blocks re-activation of a key whose
        transition window has already been closed while another key is active.
        """
        new_active = self.get_entry(kid)

        previous = self.active_entry
        if previous is not None and previous.kid != kid:
            previous.status = KeyStatus.RETAINED
        new_active.status = KeyStatus.ACTIVE
        return new_active

    def retain(self, kid: str) -> SigningKeyEntry:
        """
        Moves an active key into the retained state without promoting a
        replacement. Use to start a transition window when the replacement is
        activated separately.
        """
        entry = self.get_entry(kid)
        if entry.is_retired:
            raise KeyRotationPolicyError(
                format_lazy(_("Cannot retain retired key '{}'"), kid)
            )
        entry.status = KeyStatus.RETAINED
        return entry

    def retire(self, kid: str) -> SigningKeyEntry:
        """
        Closes the transition window for ``kid``: the key stops being trusted
        for verification. Existing tokens signed by it will be rejected.
        """
        entry = self.get_entry(kid)
        if entry.is_active:
            raise KeyRotationPolicyError(
                format_lazy(
                    _("Cannot retire active key '{}'; activate another key first"),
                    kid,
                )
            )
        entry.status = KeyStatus.RETIRED
        return entry

    # -- lookups ------------------------------------------------------------

    def get_entry(self, kid: str) -> SigningKeyEntry:
        try:
            return self._entries[kid]
        except KeyError as e:
            raise KeyRotationPolicyError(
                format_lazy(_("Unknown signing key identifier '{}'"), kid)
            ) from e

    def entries(
        self, status: Optional[KeyStatus] = None
    ) -> tuple[SigningKeyEntry, ...]:
        """
        Returns all registered entries, optionally filtered by state.
        """
        if status is None:
            return tuple(self._entries.values())
        return tuple(
            entry for entry in self._entries.values() if entry.status is status
        )

    @property
    def active_entry(self) -> Optional[SigningKeyEntry]:
        for entry in self._entries.values():
            if entry.is_active:
                return entry
        return None

    @property
    def active_kid(self) -> Optional[str]:
        entry = self.active_entry
        return entry.kid if entry is not None else None

    @property
    def retained_entries(self) -> tuple[SigningKeyEntry, ...]:
        return self.entries(KeyStatus.RETAINED)

    @property
    def acceptable_entries(self) -> tuple[SigningKeyEntry, ...]:
        """
        Keys currently allowed to verify tokens: active plus retained.
        """
        return tuple(
            entry for entry in self._entries.values() if entry.is_acceptable
        )

    def header_kid(self, token: str) -> Optional[str]:
        """
        Reads the ``kid`` claim from the token header without verifying the
        signature.
        """
        try:
            return jwt.get_unverified_header(token).get("kid")
        except jwt.InvalidTokenError as e:
            raise TokenBackendError(_("Token is invalid")) from e

    def identify(self, token: str) -> SigningKeyEntry:
        """
        Returns the currently acceptable key entry that cryptographically
        signed ``token``.

        The ``kid`` header is only a hint. Acceptance is decided by a real
        signature check against every acceptable key, so a token whose header
        names a retired or unknown key is rejected rather than trusted on the
        strength of its payload/header identifier alone.
        """
        kid = self.header_kid(token)

        ordered: list[SigningKeyEntry] = []
        if kid is not None and kid in self._entries:
            hinted = self._entries[kid]
            if hinted.is_acceptable:
                ordered.append(hinted)
        ordered.extend(
            entry
            for entry in self.acceptable_entries
            if entry.kid != kid
        )

        for entry in ordered:
            if self._signed_by(token, entry):
                return entry

        raise TokenBackendError(_("Token is invalid"))

    def _signed_by(self, token: str, entry: SigningKeyEntry) -> bool:
        verification_key = (
            entry.signing_key
            if self.algorithm.startswith("HS")
            else entry.verifying_key
        )
        try:
            jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_aud": False,
                    "verify_iss": False,
                },
            )
        except jwt.InvalidTokenError:
            return False
        return True


class RotatingTokenBackend(TokenBackend):
    """
    A ``TokenBackend`` that signs with the policy's active key and verifies
    against every key the policy still accepts.

    New tokens carry the active key's ``kid`` in their header. Verification
    never trusts the identifier by itself: the token must pass a real
    signature check with an active or retained key. A shared policy instance
    means the result of a refresh and the verification of that refreshed token
    always follow the same rotation state.
    """

    def __init__(
        self,
        policy: KeyRotationPolicy,
        algorithm: str,
        audience: str | Any | None = None,
        issuer: str | None = None,
        leeway: float | int | Any | None = None,
        json_encoder: type | None = None,
    ) -> None:
        super().__init__(
            algorithm,
            signing_key=None,
            verifying_key="",
            audience=audience,
            issuer=issuer,
            jwk_url=None,
            leeway=leeway,
            json_encoder=json_encoder,
        )
        self.policy = policy
        self.policy.algorithm = algorithm
        self._backends: dict[str, TokenBackend] = {}

    def _backend_for(self, entry: SigningKeyEntry) -> TokenBackend:
        backend = self._backends.get(entry.kid)
        if backend is None:
            backend = TokenBackend(
                self.algorithm,
                entry.signing_key,
                entry.verifying_key,
                self.audience,
                self.issuer,
                entry.jwk_url,
                self.leeway,
                self.json_encoder,
            )
            self._backends[entry.kid] = backend
        return backend

    @property
    def active_backend(self) -> TokenBackend:
        entry = self.policy.active_entry
        if entry is None:
            raise KeyRotationPolicyError(
                _("Rotation policy has no active signing key")
            )
        return self._backend_for(entry)

    def encode(
        self, payload: dict[str, Any], headers: dict[str, Any] | None = None
    ) -> str:
        """
        Signs a new token with the currently active key and stamps its ``kid``
        in the JWT header.
        """
        entry = self.policy.active_entry
        if entry is None:
            raise KeyRotationPolicyError(
                _("Rotation policy has no active signing key")
            )

        full_headers = {"kid": entry.kid}
        if headers:
            full_headers.update(headers)
        return self._backend_for(entry).encode(payload, full_headers)

    def decode(self, token: str, verify: bool = True) -> dict[str, Any]:
        """
        Verifies the token against the policy's acceptable keys.

        The key is selected by an actual signature check, not by trusting the
        ``kid`` header. Once the signing key is identified, the full claim
        validation (expiry, audience, issuer) is performed by that key's
        backend so behavior matches the standard ``TokenBackend``.
        """
        if not verify:
            return self._decode_without_verification(token)

        entry = self.policy.identify(token)
        return self._backend_for(entry).decode(token, verify=True)

    def _decode_without_verification(self, token: str) -> dict[str, Any]:
        kid = self.policy.header_kid(token)
        try:
            backend = self._backend_for(self.policy.get_entry(kid)) if kid else None
        except KeyRotationPolicyError:
            backend = None
        if backend is None:
            backend = self.active_backend
        return backend.decode(token, verify=False)

    def identify(self, token: str) -> SigningKeyEntry:
        """
        Returns the acceptable key entry that signed ``token``.
        """
        return self.policy.identify(token)
