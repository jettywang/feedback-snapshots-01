"""Explicit authorization principals.

Guardian historically distinguishes only two kinds of identities: a database
``User`` (or ``Group``) and Django's :class:`~django.contrib.auth.models.AnonymousUser`,
which Guardian maps to the configured anonymous user.  Some deployments have a
third kind: a guest account that the ingress layer explicitly marks as a
*visitor*.  A visitor is a real, persisted identity; it is not the site-wide
anonymous user and must not silently inherit the anonymous user's permissions.

This module makes that distinction explicit at the request boundary.  The
ingress layer marks a request as a visitor (by setting ``request.guardian_visitor``
or by sending the configured header), and
:class:`~guardian.middleware.GuardianPrincipalMiddleware` or
:func:`resolve_request_principal` turns that marker into a :class:`Principal`
whose ``type`` is :attr:`PrincipalType.VISITOR` and whose ``identity`` is the
configured visitor account.

Switching an authenticated user to the visitor identity is treated as a
privilege transition.  For an inactive user the switch is refused unless the
caller explicitly confirms it; every confirmed switch produces a
:class:`PrincipalSwitch` record that is logged, sent through the
``principal_switched`` signal and, when configured, passed to an audit handler.
If the audit path fails, the switch is refused: a transition that cannot be
traced is not allowed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.utils.module_loading import import_string

from guardian.conf import settings as guardian_settings
from guardian.exceptions import PrincipalSwitchDenied, VisitorNotConfigured
from guardian.signals import principal_switched

logger = logging.getLogger(__name__)

VISITOR_REQUEST_ATTRIBUTE = "guardian_visitor"
_TRUE_VALUES = {"1", "true", "t", "yes", "y", "on"}

#: Request attribute that carries the principal resolved by the middleware.
PRINCIPAL_REQUEST_ATTRIBUTE = "guardian_principal"


class PrincipalType(str, Enum):
    """The kind of subject that actually participates in a permission decision."""

    USER = "user"
    GROUP = "group"
    ANONYMOUS = "anonymous"
    VISITOR = "visitor"


@dataclass(frozen=True)
class PrincipalSwitch:
    """Traceable record of an authenticated user being replaced by a visitor.

    A record is created for every authenticated-to-visitor transition.  For an
    inactive source user the transition only happens when ``confirmed`` is
    ``True``.  ``confirmation`` can carry the caller's reference (for example a
    ticket id or operator name) so the audit trail identifies who approved it.
    """

    from_user: Any
    to_user: Any
    from_user_id: Any
    to_user_id: Any
    confirmed: bool
    confirmation: str | None
    path: str | None
    timestamp: datetime

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation suitable for audit sinks."""

        return {
            "from_user_id": self.from_user_id,
            "to_user_id": self.to_user_id,
            "confirmed": self.confirmed,
            "confirmation": self.confirmation,
            "path": self.path,
            "timestamp": self.timestamp.isoformat(),
        }


class Principal:
    """An explicit authorization subject.

    ``identity`` is the value Guardian passes to its existing permission
    machinery: a user model instance, a group, or Django's ``AnonymousUser``.
    ``type`` records what that identity means in the current scenario.  A
    visitor is therefore never confused with the site-wide anonymous user even
    though both may be represented by a database row somewhere.

    Instances are produced by the class methods rather than by constructing
    them directly, so the type and identity stay consistent.
    """

    __slots__ = ("type", "identity", "request_user", "source", "switch")

    def __init__(
        self,
        type: PrincipalType,
        identity: Any,
        *,
        request_user: Any | None = None,
        source: str = "",
        switch: PrincipalSwitch | None = None,
    ) -> None:
        self.type = PrincipalType(type)
        self.identity = identity
        self.request_user = request_user
        self.source = source
        self.switch = switch

    def __repr__(self) -> str:
        return f"Principal(type={self.type.value!r}, identity={self.identity!r}, source={self.source!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Principal):
            return NotImplemented
        return self.type is other.type and self.identity == other.identity

    def __hash__(self) -> int:
        try:
            return hash((self.type, self.identity))
        except TypeError:
            return hash((self.type, id(self.identity)))

    @classmethod
    def for_user(cls, user: Any, *, request_user: Any | None = None, source: str = "request.user") -> Principal:
        """Create a principal for an authenticated (or explicitly supplied) user."""

        return cls(PrincipalType.USER, user, request_user=request_user, source=source)

    @classmethod
    def for_group(cls, group: Any, *, source: str = "explicit") -> Principal:
        """Create a principal for a group identity."""

        return cls(PrincipalType.GROUP, group, source=source)

    @classmethod
    def for_anonymous(cls, user: Any | None = None, *, source: str = "request.user") -> Principal:
        """Create a principal for Django's anonymous identity.

        The identity intentionally remains Django's ``AnonymousUser`` so the
        regular Guardian paths keep applying the site's ``ANONYMOUS_USER_NAME``
        configuration instead of the visitor configuration.
        """

        identity = user if user is not None else AnonymousUser()
        return cls(PrincipalType.ANONYMOUS, identity, request_user=user, source=source)

    @classmethod
    def for_visitor(
        cls,
        visitor: Any,
        *,
        request_user: Any | None = None,
        source: str = "ingress",
        switch: PrincipalSwitch | None = None,
    ) -> Principal:
        """Create a principal for an explicitly marked visitor account."""

        return cls(PrincipalType.VISITOR, visitor, request_user=request_user, source=source, switch=switch)

    @classmethod
    def for_request_user(cls, user: Any | None) -> Principal:
        """Build a non-visitor principal from ``request.user``."""

        if user is not None and getattr(user, "is_authenticated", False):
            return cls.for_user(user)
        return cls.for_anonymous(user)

    @property
    def user(self) -> Any | None:
        """Return the user identity, or ``None`` for a group principal."""

        return None if self.is_group else self.identity

    @property
    def group(self) -> Any | None:
        """Return the group identity, or ``None`` for a user/anonymous principal."""

        return self.identity if self.is_group else None

    @property
    def is_user(self) -> bool:
        return self.type is PrincipalType.USER

    @property
    def is_group(self) -> bool:
        return self.type is PrincipalType.GROUP

    @property
    def is_anonymous(self) -> bool:
        return self.type is PrincipalType.ANONYMOUS

    @property
    def is_visitor(self) -> bool:
        return self.type is PrincipalType.VISITOR

    @property
    def is_authenticated(self) -> bool:
        """Whether the subject represents an authenticated participation.

        Visitors are real guest identities and count as authenticated even
        though they are not the original logged-in user.  Anonymous principals
        are not authenticated.
        """

        return self.type in (PrincipalType.USER, PrincipalType.VISITOR)

    def has_perm(self, perm: str, obj: Any | None = None) -> bool:
        """Check a permission using the existing Guardian machinery.

        For a group principal an object is required because group identities
        only participate through object permissions.  Anonymous principals
        keep Django's ``AnonymousUser`` as their identity, so Guardian's backend
        applies the site's ``ANONYMOUS_USER_NAME`` configuration.
        """

        if self.is_group:
            if obj is None:
                return False
            from guardian.core import ObjectPermissionChecker

            return ObjectPermissionChecker(self.identity).has_perm(perm, obj)

        # Both a real user and Django's AnonymousUser go through Django's
        # backend chain. Guardian's backend maps the latter to the configured
        # anonymous user, preserving the site-wide anonymous configuration.
        return bool(self.identity.has_perm(perm, obj))

    def get_objects_for_user(self, perms: str | list[str], klass: Any = None, **kwargs: Any) -> Any:
        """Return objects visible to this principal.

        Group principals are routed through ``get_objects_for_group``; all
        other principals use ``get_objects_for_user``.  Anonymous principals
        keep using Django's ``AnonymousUser`` so the site's anonymous-user
        configuration remains authoritative.
        """

        from guardian.shortcuts import get_objects_for_group, get_objects_for_user

        if self.is_group:
            return get_objects_for_group(self.identity, perms, klass, **kwargs)
        return get_objects_for_user(self.identity, perms, klass, **kwargs)

    def __str__(self) -> str:
        return f"{self.type.value}:{self.identity}"


def _get_setting(name: str, default: Any = None) -> Any:
    """Read a ``GUARDIAN_*`` setting, honouring ``override_settings``.

    ``guardian.conf.settings`` snapshots Django settings on import.  Reading
    Django's settings first keeps request-time overrides (and tests) working,
    while falling back to the snapshot keeps existing Guardian behaviour.
    """

    return getattr(settings, f"GUARDIAN_{name}", getattr(guardian_settings, name, default))


def _is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in _TRUE_VALUES


def is_visitor_request(request: Any) -> bool:
    """Return whether the ingress layer explicitly marked ``request`` as a visitor.

    The marker is either the ``guardian_visitor`` request attribute (set by
    trusted ingress middleware) or the header configured through
    ``GUARDIAN_VISITOR_HEADER``.  Header support is opt-in and should only be
    enabled when the header is injected by a trusted proxy.
    """

    if _is_true(getattr(request, VISITOR_REQUEST_ATTRIBUTE, False)):
        return True

    header = _get_setting("VISITOR_HEADER")
    if not header:
        return False

    headers = getattr(request, "headers", None)
    if headers is not None:
        return _is_true(headers.get(header))
    meta_key = "HTTP_" + str(header).upper().replace("-", "_")
    return _is_true(getattr(request, "META", {}).get(meta_key))


def _anonymous_user_name() -> Any:
    # ANONYMOUS_USER_NAME predates the GUARDIAN_ prefix and is read from the
    # top-level setting, mirroring guardian.conf.settings.
    if hasattr(settings, "ANONYMOUS_USER_NAME"):
        return settings.ANONYMOUS_USER_NAME
    return guardian_settings.ANONYMOUS_USER_NAME


def _validate_visitor(visitor: Any) -> Any:
    User = get_user_model()
    if not isinstance(visitor, User):
        raise VisitorNotConfigured(
            "Guardian visitor configuration must resolve to an instance of %s (got %r)." % (User._meta.label, visitor)
        )

    anonymous_name = _anonymous_user_name()
    username_field = getattr(User, "USERNAME_FIELD", "username")
    visitor_name = getattr(visitor, username_field, None)
    if anonymous_name is not None and visitor_name == anonymous_name:
        raise VisitorNotConfigured(
            "The Guardian visitor account must be distinct from the anonymous user "
            f"(both resolve to {anonymous_name!r})."
        )
    if not getattr(visitor, "is_active", True):
        raise VisitorNotConfigured(
            "The Guardian visitor account %r is inactive; an inactive visitor cannot "
            "participate in permission decisions." % visitor_name
        )
    if getattr(visitor, "is_superuser", False):
        raise VisitorNotConfigured(
            "The Guardian visitor account %r must not be a superuser; a visitor is "
            "expected to see only its explicitly granted objects." % visitor_name
        )
    return visitor


def _lookup_user_by_name(name: str) -> Any:
    User = get_user_model()
    username_field = getattr(User, "USERNAME_FIELD", "username")
    try:
        return User.objects.get(**{username_field: name})
    except User.DoesNotExist:
        raise VisitorNotConfigured(
            "Guardian visitor account %r does not exist. Create the guest account or "
            "set GUARDIAN_GET_VISITOR_USER to a resolver that returns it." % name
        )


def get_visitor_user(request: Any | None = None) -> Any:
    """Return the account that represents a marked visitor request.

    Resolution order:

    1. ``GUARDIAN_GET_VISITOR_USER``, a callable (or dotted path) receiving the
       request.  It may return a user instance or a username.  Returning
       ``None`` raises :class:`~guardian.exceptions.VisitorNotConfigured`.
    2. ``GUARDIAN_VISITOR_USER_NAME``, looked up through the user model's
       ``USERNAME_FIELD``.

    The visitor must be a real user account and must never be the configured
    anonymous user.  This keeps the visitor's explicitly granted object
    permissions separate from the site-wide anonymous identity.
    """

    resolver = _get_setting("GET_VISITOR_USER")
    if resolver:
        resolve = import_string(resolver) if isinstance(resolver, str) else resolver
        result = resolve(request)
        if result is None:
            raise VisitorNotConfigured("GUARDIAN_GET_VISITOR_USER returned None for a request marked as a visitor.")
        if isinstance(result, str):
            return _validate_visitor(_lookup_user_by_name(result))
        return _validate_visitor(result)

    name = _get_setting("VISITOR_USER_NAME")
    if not name:
        raise VisitorNotConfigured(
            "A request was marked as a visitor but Guardian has no visitor account. "
            "Set GUARDIAN_VISITOR_USER_NAME or GUARDIAN_GET_VISITOR_USER."
        )
    return _validate_visitor(_lookup_user_by_name(name))


def _emit_switch_audit(record: PrincipalSwitch, request: Any, audit: Any = None) -> None:
    """Persist a switch record through every configured audit channel.

    A failure here propagates: the caller asked for a traceable transition, so
    continuing without a trace would violate that contract.
    """

    handler_path = _get_setting("PRINCIPAL_AUDIT_HANDLER")
    if handler_path:
        handler = import_string(handler_path) if isinstance(handler_path, str) else handler_path
        handler(record)

    if audit is not None:
        audit(record)

    logger.info(
        "Guardian principal switch: user %s -> visitor %s (confirmed=%s, confirmation=%s, path=%s)",
        record.from_user_id,
        record.to_user_id,
        record.confirmed,
        record.confirmation,
        record.path,
        extra={"guardian_principal_switch": record},
    )
    principal_switched.send(sender=PrincipalSwitch, record=record, request=request)


def resolve_request_principal(
    request: Any,
    *,
    allow_inactive_switch: bool | None = None,
    confirmation: str | None = None,
    audit: Any = None,
) -> Principal:
    """Resolve the principal that should participate in this request.

    A request marked as a visitor uses the configured visitor account even when
    ``request.user`` is anonymous.  An ordinary request keeps Django's user or
    anonymous identity, so the site's normal anonymous configuration is
    untouched.

    Switching an authenticated *inactive* user to the visitor identity is a
    deliberate transition.  It is refused with
    :class:`~guardian.exceptions.PrincipalSwitchDenied` unless
    ``allow_inactive_switch`` is ``True`` (or the corresponding setting is
    enabled).  Every authenticated-to-visitor switch is recorded as a
    :class:`PrincipalSwitch`; ``confirmation`` can hold the caller's ticket or
    operator reference.

    Args:
        request: The current request.  ``request.user`` is inspected but never
            modified here.
        allow_inactive_switch: The caller's explicit confirmation.  ``None``
            means "use ``GUARDIAN_ALLOW_INACTIVE_VISITOR_SWITCH``".
        confirmation: Optional caller reference stored in the audit record.
        audit: Optional callable receiving the :class:`PrincipalSwitch` record.

    Raises:
        PrincipalSwitchDenied: An inactive authenticated user would be replaced
            without confirmation.
        VisitorNotConfigured: The request is marked as a visitor but no valid
            visitor account is configured.
    """

    request_user = getattr(request, "user", None)

    if not is_visitor_request(request):
        return Principal.for_request_user(request_user)

    visitor = get_visitor_user(request)
    switch: PrincipalSwitch | None = None

    if (
        request_user is not None
        and getattr(request_user, "is_authenticated", False)
        and getattr(request_user, "pk", None) != getattr(visitor, "pk", None)
    ):
        confirmed = (
            _is_true(_get_setting("ALLOW_INACTIVE_VISITOR_SWITCH", False))
            if allow_inactive_switch is None
            else bool(allow_inactive_switch)
        )
        is_active = bool(getattr(request_user, "is_active", True))
        if not is_active and not confirmed:
            raise PrincipalSwitchDenied(
                "Refusing to switch inactive user %s to the visitor account %s. "
                "Pass allow_inactive_switch=True after confirming the transition."
                % (getattr(request_user, "pk", request_user), getattr(visitor, "pk", visitor))
            )

        switch = PrincipalSwitch(
            from_user=request_user,
            to_user=visitor,
            from_user_id=getattr(request_user, "pk", None),
            to_user_id=getattr(visitor, "pk", None),
            confirmed=confirmed,
            confirmation=confirmation,
            path=getattr(request, "path", None) or getattr(request, "META", {}).get("PATH_INFO"),
            timestamp=datetime.now(timezone.utc),
        )
        _emit_switch_audit(switch, request, audit=audit)
        source = "ingress-after-auth"
    else:
        source = "ingress"

    return Principal.for_visitor(
        visitor,
        request_user=request_user,
        source=source,
        switch=switch,
    )


def get_request_principal(request: Any) -> Principal:
    """Return the request's already-resolved principal or build a plain one.

    Use this in views that need the principal type.  When
    :class:`~guardian.middleware.GuardianPrincipalMiddleware` is installed the
    resolved visitor principal is reused; otherwise a user/anonymous principal
    is derived from ``request.user`` without any visitor lookup.
    """

    principal = getattr(request, PRINCIPAL_REQUEST_ATTRIBUTE, None)
    if isinstance(principal, Principal):
        return principal
    return Principal.for_request_user(getattr(request, "user", None))
