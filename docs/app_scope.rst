.. _app_scope:

Application-scoped tokens
=========================

By default a token identifies a user only by the configured
``USER_ID_CLAIM``.  If one API serves several applications whose user tables
are independent, two different people can share the same numeric ID.  Checking
only that ID would let a token issued for one application read another
application's data.

Simple JWT can attach an application scope to tokens and enforce it in both
``JWTAuthentication`` and ``JWTStatelessUserAuthentication``.  The feature is
opt-in and only active when ``APP_SCOPE_RESOLVER`` is configured.

Configuration
-------------

.. code-block:: python

  # project/settings.py

  SIMPLE_JWT = {
      "APP_SCOPE_CLAIM": "app_scope",
      "APP_SCOPE_RESOLVER": "project.auth.scope_registry",
      "APP_SCOPE_LEGACY_POLICY": "reject",
      "APP_SCOPE_REQUIRED": False,
  }

``APP_SCOPE_RESOLVER``
~~~~~~~~~~~~~~~~~~~~~~

A callable (or dotted path, or mapping) from a scope name to an
``AppScopeBinding``.  The binding names the user source that is authoritative
for that scope:

.. code-block:: python

  from rest_framework_simplejwt.app_scope import AppScopeBinding, AppScopeRegistry

  from app_a.models import User as AppAUser
  from app_b.models import User as AppBUser

  scope_registry = AppScopeRegistry(
      {
          "app-a": AppScopeBinding("app-a", users=AppAUser.objects),
          "app-b": AppScopeBinding("app-b", users=AppBUser.objects),
      }
  )

The resolver must only return bindings it approves.  A binding may be reused
for several user rows, a specific database alias
(``User.objects.using("app_b")``), or a separate ``user_model``.  The binding's
``user_id_field`` defaults to ``USER_ID_FIELD``.

``JWTAuthentication`` looks users up through the binding, so the same integer
ID resolves to the user row of the token's application.  If the resolver
returns ``None``, the binding's scope differs from the requested scope, or the
binding is not an ``AppScopeBinding``, authentication fails closed.

``JWTStatelessUserAuthentication`` performs exactly the same resolution before
constructing a ``TokenUser``.  Its ``TokenUser.token`` still contains the
original claims; ``TokenUser.app_scope`` exposes the approved scope.  A binding
may set ``token_user_class`` to use a different ``TokenUser`` subclass for that
application.

Route requirements
~~~~~~~~~~~~~~~~~~

A DRF view can require a scope:

.. code-block:: python

  class AppAView(APIView):
      authentication_classes = (JWTAuthentication,)
      required_app_scope = "app-a"          # or an iterable of allowed scopes

Setting ``required_app_scope = True`` requires any approved scope.  To require
a scope on every authenticated route, set ``APP_SCOPE_REQUIRED = True``.
Because the requirement is read from the view, the same check applies to both
authentication backends.

Issuing scoped tokens
~~~~~~~~~~~~~~~~~~~~~

Pass ``app_scope`` when creating a token:

.. code-block:: python

  refresh = RefreshToken.for_user(user, app_scope="app-a")
  access = refresh.access_token

The claim is copied to the access token created from a refresh token.  Existing
call sites that do not pass ``app_scope`` keep producing legacy tokens.

Legacy token policy
~~~~~~~~~~~~~~~~~~~

Tokens without the scope claim do not participate unless the policy says so.
``APP_SCOPE_LEGACY_POLICY`` accepts:

- ``"reject"`` (default): legacy tokens are rejected whenever the resolver is
  configured.
- ``"allow_unscoped"``: legacy tokens may authenticate on routes that do not
  require a scope; they are still rejected on scoped routes.
- a callable ``policy(validated_token, request)`` returning ``True`` for
  "allow unscoped", or the name of an approved scope to migrate that token into
  that scope.  Any other value rejects the token.  A named scope must still
  resolve through ``APP_SCOPE_RESOLVER``, so the token cannot invent an
  ownership.

The policy is evaluated before any user lookup, and a route requirement is
checked afterwards.  An unscoped legacy token can therefore never satisfy a
route that requires an application scope.

Behavior summary
~~~~~~~~~~~~~~~~

- ``APP_SCOPE_RESOLVER`` unset, token has no scope: all behavior is unchanged.
- ``APP_SCOPE_RESOLVER`` unset, token carries a scope: authentication and
  refresh fail with ``app_scope_not_configured`` rather than silently falling
  back to a default user lookup.
- Resolver configured, token has a scope: the scope must resolve to a binding
  and satisfy the route requirement.  The bound user source is the only user
  table consulted.
- Resolver configured, token has no scope: ``APP_SCOPE_LEGACY_POLICY`` decides.

A scoped route with no resolver configured also fails with
``app_scope_not_configured``.

The ``token_blacklist`` ``OutstandingToken`` model can only reference the
Django ``AUTH_USER_MODEL``.  Scoped tokens therefore store no outstanding user
association by default; a project that needs per-application attribution should
extend the blacklist models or record the scope in its own audit table.
