import datetime
import hashlib
import secrets

from django.contrib.auth import authenticate
from django.db import transaction
from django.utils import timezone

from sesame.utils import get_token

from .exceptions import (
    MagicLinkAlreadyConsumed,
    MagicLinkExpired,
    MagicLinkInvalid,
    MagicLinkNotFound,
    MagicLinkRevoked,
    MagicLinkUnavailable,
)
from .models import MagicLink

__all__ = [
    "hash_token",
    "issue_magic_link",
    "claim_magic_link",
    "release_magic_link",
    "consume_magic_link",
    "revoke_magic_link",
    "resend_magic_link",
]

# Separates the business scope chosen by the application from the random nonce
# that makes every issued link unique. The nonce is part of the cryptographic
# sesame scope, so a token minted for one link cannot be replayed on another.
SCOPE_SEPARATOR = "#"


def hash_token(token):
    """
    Hash a raw sesame token before storing it in the database.

    """
    return hashlib.sha256(token.encode()).hexdigest()


def build_token_scope(scope, nonce):
    return f"{scope}{SCOPE_SEPARATOR}{nonce}"


def issue_magic_link(user, scope, *, max_age=None, revoke_previous=True):
    """
    Create a single-use magic link for ``user`` in the business ``scope``.

    Return the ``(link, token)`` pair. The token is the raw, scoped sesame
    token that must be sent to the user; only its hash is persisted.

    A random nonce is appended to the scope when the sesame token is signed, so
    two links issued for the same user and scope never share a token, even
    without token expiration. The business ``scope`` is stored unchanged.

    If ``max_age`` is set, the link expires after that duration, expressed as a
    :class:`~datetime.timedelta` or a number of seconds.

    By default, other active links of the same user and scope are revoked when
    a new one is issued, so re-sending an email supersedes the previous link.

    """
    nonce = secrets.token_urlsafe(16)
    token = get_token(user, build_token_scope(scope, nonce))
    expires_at = None
    if max_age is not None:
        if isinstance(max_age, datetime.timedelta):
            max_age = max_age.total_seconds()
        expires_at = timezone.now() + datetime.timedelta(seconds=max_age)

    if revoke_previous:
        revoke_active_magic_links(user, scope)

    link = MagicLink.objects.create(
        user_id=str(user.pk),
        scope=scope,
        nonce=nonce,
        token_hash=hash_token(token),
        expires_at=expires_at,
    )
    return link, token


def claim_magic_link(token, scope, *, max_age=None):
    """
    Atomically reserve a magic link for the current request.

    The reservation relies on a conditional database update, so two concurrent
    requests presenting the same token cannot both win: at most one call
    returns a ``(link, user)`` pair. If anything fails before login, the
    reservation is rolled back and a subclass of
    :class:`~sesame.magiclink.exceptions.MagicLinkError` is raised.

    """
    now = timezone.now()
    token_hash = hash_token(token)

    try:
        link = MagicLink.objects.get(token_hash=token_hash)
    except MagicLink.DoesNotExist:
        raise MagicLinkNotFound("Unknown magic link token")

    if link.scope != scope:
        # A token from another business scope must not be accepted here.
        raise MagicLinkNotFound("Unknown magic link token", link)

    if link.status == MagicLink.CONSUMED:
        raise MagicLinkAlreadyConsumed("Magic link was already consumed", link)
    if link.status == MagicLink.REVOKED:
        raise MagicLinkRevoked("Magic link was revoked", link)
    if link.is_expired:
        raise MagicLinkExpired("Magic link has expired", link)

    # Conditional UPDATE: the database guarantees that only one transaction can
    # flip an ISSUED row to CLAIMED, even under concurrent requests.
    claimed = MagicLink.objects.filter(pk=link.pk, status=MagicLink.ISSUED).update(
        status=MagicLink.CLAIMED, claimed_at=now
    )
    if claimed == 0:
        link.refresh_from_db(fields=["status"])
        if link.status == MagicLink.CONSUMED:
            raise MagicLinkAlreadyConsumed("Magic link was already consumed", link)
        if link.status == MagicLink.REVOKED:
            raise MagicLinkRevoked("Magic link was revoked", link)
        raise MagicLinkUnavailable("Magic link is already in use", link)

    # The row is now reserved for this request. Reload the values written above.
    link.refresh_from_db(fields=["status", "claimed_at"])

    user = authenticate(
        sesame=token,
        scope=build_token_scope(link.scope, link.nonce),
        max_age=max_age,
    )
    if user is None or str(user.pk) != str(link.user_id):
        release_magic_link(link)
        raise MagicLinkInvalid("Magic link token is invalid", link)

    return link, user


def release_magic_link(link):
    """
    Roll back a reservation after a failure before the session is created.

    The link becomes usable again instead of being consumed or revoked.

    """
    MagicLink.objects.filter(pk=link.pk, status=MagicLink.CLAIMED).update(
        status=MagicLink.ISSUED, claimed_at=None
    )


def consume_magic_link(link):
    """
    Mark a claimed link as consumed after the session was created.

    """
    now = timezone.now()
    updated = MagicLink.objects.filter(pk=link.pk, status=MagicLink.CLAIMED).update(
        status=MagicLink.CONSUMED, consumed_at=now
    )
    if updated:
        link.status = MagicLink.CONSUMED
        link.consumed_at = now


def revoke_magic_link(link):
    """
    Revoke a link that hasn't been consumed yet.

    Consumed links stay consumed: consumption and revocation remain distinct
    states. Return :obj:`True` when the link was revoked.

    """
    if link.status == MagicLink.CONSUMED:
        return False
    now = timezone.now()
    updated = (
        MagicLink.objects.exclude(status=MagicLink.CONSUMED)
        .filter(pk=link.pk)
        .update(status=MagicLink.REVOKED, revoked_at=now)
    )
    if updated:
        link.status = MagicLink.REVOKED
        link.revoked_at = now
    return bool(updated)


def revoke_active_magic_links(user, scope):
    """
    Revoke every link of ``user`` in ``scope`` that wasn't consumed yet.

    """
    now = timezone.now()
    return (
        MagicLink.objects.filter(user_id=str(user.pk), scope=scope)
        .exclude(status=MagicLink.CONSUMED)
        .update(status=MagicLink.REVOKED, revoked_at=now)
    )


def resend_magic_link(user, scope, *, max_age=None):
    """
    Issue a replacement link and revoke the previous one.

    The old link ends up in the :attr:`~MagicLink.REVOKED` state while the new
    one starts as :attr:`~MagicLink.ISSUED`, which keeps revocation clearly
    distinct from a link that was consumed.

    """
    with transaction.atomic():
        return issue_magic_link(
            user,
            scope,
            max_age=max_age,
            revoke_previous=True,
        )
