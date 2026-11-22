import functools

from django.core.exceptions import PermissionDenied

from . import utils

__all__ = [
    "CAPABILITY_ATTRIBUTE",
    "Capability",
    "get_capability",
    "get_capability_parameters",
    "get_capability_query_string",
    "get_capability_token",
    "require_capability",
]

# Name of the attribute set on the request while a capability contract is
# enforced. It records the action that the token authorized for this request.
CAPABILITY_ATTRIBUTE = "sesame_capability"


def get_capability(request):
    """
    Return the action that the request is authorized to perform, if any.

    When the request was authenticated with a :class:`Capability` contract,
    return the name of the authorized action. Otherwise, return :obj:`None`.

    This lets a view introspect the *valid capability* established for the
    current request without granting the user a session.

    """
    return getattr(request, CAPABILITY_ATTRIBUTE, None)


class Capability:
    """
    Verification contract that authorizes a single, named action.

    A :class:`Capability` binds a django-sesame token to one ``action``: a
    token minted by the contract is only accepted when the same contract
    authenticates the request. This provides frictionless, one-click access to
    a specific resource — such as viewing a quote sent by email — without
    establishing a session and therefore without exposing the rest of the site.

    The contract is explicit on both sides:

    * :meth:`mint_token` (and the related helpers) generate a token tied to
      the action;
    * :meth:`require` returns a view decorator that only accepts such a token.

    A successfully authenticated request gains:

    * ``request.user`` set to the corresponding user, for the duration of the
      request only;
    * ``request.sesame_capability`` (see :data:`CAPABILITY_ATTRIBUTE`) set to
      the action, allowing the view to state the capability that was granted.

    No session is created and Django's ``user_logged_in`` signal is never sent,
    so ordinary login hooks do not run.

    """

    def __init__(self, action, *, max_age=None):
        if not action:
            raise ValueError("a capability requires a non-empty action")
        self.action = action
        self.max_age = max_age

    def __repr__(self):
        return f"Capability({self.action!r})"

    def __eq__(self, other):
        if not isinstance(other, Capability):
            return NotImplemented
        return self.action == other.action and self.max_age == other.max_age

    def mint_token(self, user):
        """Generate a token that authorizes this capability for ``user``."""
        return utils.get_token(user, scope=self.action)

    def mint_parameters(self, user):
        """Generate query string parameters carrying an authorizing token."""
        return utils.get_parameters(user, scope=self.action)

    def mint_query_string(self, user):
        """Generate a complete query string carrying an authorizing token."""
        return utils.get_query_string(user, scope=self.action)

    def authenticate(self, request):
        """
        Authenticate ``request`` against this contract.

        Return the user if the request carries a valid token for this action,
        else return :obj:`None`. This never logs the user in and never creates
        a session.

        """
        return utils.get_user(request, scope=self.action, max_age=self.max_age)

    def require(self, view=None):
        """
        Decorate ``view`` so that it is reachable only through this contract.

        A valid token for the action sets ``request.user`` and records the
        capability on the request. Any other token, or no token at all, raises
        :exc:`~django.core.exceptions.PermissionDenied` without creating a
        session or running login hooks.

        The action may contain ``str.format`` placeholders, which are
        interpolated with the view's positional and keyword arguments, just
        like the ``scope`` argument of
        :func:`~sesame.decorators.authenticate`.

        """
        if view is None:
            return functools.partial(self.require)

        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            action = self.action.format(*args, **kwargs)
            user = utils.get_user(
                request,
                scope=action,
                max_age=self.max_age,
            )

            # Record the outcome of the contract on the request so that views
            # can introspect what (if anything) was authorized.
            setattr(request, CAPABILITY_ATTRIBUTE, action if user else None)

            if user is None:
                raise PermissionDenied

            request.user = user
            return view(request, *args, **kwargs)

        return wrapper


def get_capability_token(user, action):
    """Generate a token authorizing ``action`` for ``user``."""
    return Capability(action).mint_token(user)


def get_capability_parameters(user, action):
    """Generate query string parameters authorizing ``action``."""
    return Capability(action).mint_parameters(user)


def get_capability_query_string(user, action):
    """Generate a complete query string authorizing ``action``."""
    return Capability(action).mint_query_string(user)


def require_capability(action, *, max_age=None):
    """
    Return a view decorator enforcing a :class:`Capability` for ``action``.

    This is a convenience wrapper around ``Capability(action).require``.

    """
    return Capability(action, max_age=max_age).require
