"""Opt-in two-phase workflow for resolving duplicate third-party registrations.

Customer support cannot merge two local accounts on its own: only the person
controlling both identities can prove ownership. This module implements an
optional suggestion/confirmation split that keeps that boundary explicit:

- :func:`suggest_account_link` is read-only. It inspects current storage state
  and tells an embedding application whether linking a provider identity to a
  local account looks possible, and why. It never writes an association.
- :func:`confirm_account_link` performs the change. The integration layer
  (which owns sessions and login) must call it only after the same browser
  session has authenticated both local accounts, passing the two resolved user
  objects. Every identifier is revalidated against storage at confirmation
  time, so request-supplied ids cannot bind an identity to another account.

The module is framework-agnostic: it depends only on the strategy and storage
interfaces and raises structured social-auth exceptions. It is not part of the
default pipeline and stays inert unless an application opts into it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .exceptions import AuthAssociationError, AuthInputError, AuthSessionError
from .utils import user_is_active, user_is_authenticated

if TYPE_CHECKING:
    from .backends.base import BaseAuth
    from .storage import UserMixin, UserProtocol

LinkDecision = Literal["accept", "reject"]


@dataclass(frozen=True)
class LinkConflict:
    """A provider identity that already points at a different local account."""

    provider: str
    uid: str
    social_auth: UserMixin
    reason: str


@dataclass(frozen=True)
class LinkSuggestion:
    """Read-only recommendation produced before any user has confirmed.

    ``linkable`` is the only decision field callers need; the remaining
    attributes explain the evidence so an integration can render a prompt.
    """

    primary_user: UserProtocol
    provider: str
    uid: str
    email: str | None
    matching_users: tuple[UserProtocol, ...]
    conflict: LinkConflict | None

    @property
    def linkable(self) -> bool:
        return self.conflict is None


@dataclass(frozen=True)
class LinkConfirmation:
    """Result of a confirmation attempt, bound to the two logged-in users."""

    accepted: bool
    primary_user: UserProtocol
    secondary_user: UserProtocol
    provider: str
    uid: str
    social_auth: UserMixin | None
    reason: str


def _user_storage(backend: BaseAuth[object]):
    return backend.strategy.storage.user


def _require_authenticated(
    backend: BaseAuth[object], user: UserProtocol | None, *, role: str
) -> UserProtocol:
    if not user_is_authenticated(user):
        raise AuthSessionError(
            backend,
            f"An authenticated {role} account is required to confirm linking",
            code="session_context_missing",
            stage="pipeline",
        )
    if not user_is_active(user):
        raise AuthAssociationError(
            backend,
            f"The {role} account is inactive",
            code="link_not_authorized",
            stage="pipeline",
        )
    return user


def suggest_account_link(
    backend: BaseAuth[object],
    primary_user: UserProtocol,
    provider: str,
    uid: str,
    *,
    email: str | None = None,
) -> LinkSuggestion:
    """Return a read-only suggestion for linking ``uid`` to ``primary_user``.

    The call performs no writes. A conflict is reported when the provider
    identity already belongs to another local account. When ``email`` is given,
    the primary account must share it, otherwise the suggestion fails closed:
    an email address alone is not proof of ownership.
    """
    storage = _user_storage(backend)
    uid = str(uid)

    if email is not None and getattr(primary_user, "email", None) != email:
        raise AuthAssociationError(
            backend,
            "The authenticated account does not match the reported email address",
            code="link_not_authorized",
            stage="pipeline",
        )

    matching_users: tuple[UserProtocol, ...] = ()
    if email:
        matching_users = tuple(storage.get_users_by_email(email))

    conflict: LinkConflict | None = None
    social_auth = storage.get_social_auth(provider, uid)
    if social_auth is not None and social_auth.user != primary_user:
        conflict = LinkConflict(
            provider=provider,
            uid=uid,
            social_auth=social_auth,
            reason="identity_in_use",
        )

    return LinkSuggestion(
        primary_user=primary_user,
        provider=provider,
        uid=uid,
        email=email,
        matching_users=matching_users,
        conflict=conflict,
    )


def confirm_account_link(
    backend: BaseAuth[object],
    primary_user: UserProtocol | None,
    secondary_user: UserProtocol | None,
    provider: str,
    uid: str,
    decision: LinkDecision,
    *,
    email: str | None = None,
) -> LinkConfirmation:
    """Confirm or reject a suggested link after both accounts have logged in.

    The integration layer resolves ``primary_user`` and ``secondary_user``
    from its authenticated sessions; request-supplied identifiers are never
    trusted on their own. A rejection never writes anything. An acceptance
    re-runs the read-only checks against live storage and creates the
    association on the primary account, failing closed on any conflict.
    """
    if decision not in ("accept", "reject"):
        raise AuthInputError(
            backend,
            f"Unsupported link decision: {decision!r}",
            code="invalid_parameter",
            parameter="decision",
            stage="pipeline",
        )

    primary = _require_authenticated(backend, primary_user, role="primary")
    secondary = _require_authenticated(backend, secondary_user, role="secondary")
    uid = str(uid)

    if decision == "reject":
        return LinkConfirmation(
            accepted=False,
            primary_user=primary,
            secondary_user=secondary,
            provider=provider,
            uid=uid,
            social_auth=None,
            reason="rejected",
        )

    if primary == secondary:
        raise AuthAssociationError(
            backend,
            "Both sides of a link must be distinct accounts",
            code="link_not_authorized",
            stage="pipeline",
        )

    # Re-derive the suggestion from live storage so a change between the
    # suggestion and the dual-login confirmation cannot be smuggled through.
    suggestion = suggest_account_link(backend, primary, provider, uid, email=email)
    if suggestion.conflict is not None:
        raise AuthAssociationError(
            backend,
            "This identity is already associated with another account",
            code="identity_in_use",
            stage="pipeline",
            context={
                "user_id": primary.id,
                "existing_user_id": suggestion.conflict.social_auth.user.id,
                "provider": provider,
            },
        )

    if email is not None and getattr(secondary, "email", None) != email:
        raise AuthAssociationError(
            backend,
            "The second authenticated account does not match the reported email",
            code="link_not_authorized",
            stage="pipeline",
        )

    storage = _user_storage(backend)
    existing = storage.get_social_auth(provider, uid)
    if existing is not None:
        # Idempotent duplicate submission: the identity is already bound to
        # the same primary account, so report success without a second write.
        if existing.user == primary:
            return LinkConfirmation(
                accepted=True,
                primary_user=primary,
                secondary_user=secondary,
                provider=provider,
                uid=uid,
                social_auth=existing,
                reason="already_linked",
            )
        raise AuthAssociationError(
            backend,
            "This identity is already associated with another account",
            code="identity_in_use",
            stage="pipeline",
            context={
                "user_id": primary.id,
                "existing_user_id": existing.user.id,
                "provider": provider,
            },
        )

    try:
        social_auth = storage.create_social_auth(primary, uid, provider)
    # pylint: disable-next=broad-exception-caught
    except Exception as err:
        if not backend.strategy.storage.is_integrity_error(err):
            raise
        # Concurrent confirmation between the check above and the insert:
        # re-read and stay idempotent for the same owner, fail otherwise.
        raced = storage.get_social_auth(provider, uid)
        if raced is not None and raced.user == primary:
            return LinkConfirmation(
                accepted=True,
                primary_user=primary,
                secondary_user=secondary,
                provider=provider,
                uid=uid,
                social_auth=raced,
                reason="already_linked",
            )
        raise AuthAssociationError(
            backend,
            "This identity is already associated with another account",
            code="identity_in_use",
            stage="pipeline",
        ) from err

    return LinkConfirmation(
        accepted=True,
        primary_user=primary,
        secondary_user=secondary,
        provider=provider,
        uid=uid,
        social_auth=social_auth,
        reason="linked",
    )
