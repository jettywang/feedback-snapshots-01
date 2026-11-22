API reference
=============

Settings
--------

.. admonition:: Changing settings invalidates all existing tokens.
    :class: warning

    The format of tokens depends on settings. As a consequence, changing any
    setting invalidates all existing tokens. There is a limited exception for
    :data:`SESAME_MAX_AGE`.

    For this reason, you should configure settings carefully before you start
    generating tokens.

.. data:: SESAME_TOKEN_NAME
    :value: "sesame"

    Name of the query string parameter containing the authentication token.

.. data:: SESAME_MAX_AGE
    :value: None

    Lifetime of authentications tokens, as a :class:`datetime.timedelta` or a
    number of seconds.

    When :data:`SESAME_MAX_AGE` is :obj:`None`, tokens always have an unlimited
    lifetime.

    When :data:`SESAME_MAX_AGE` is not :obj:`None`, you can adjust the desired
    lifetime in any API that accepts a ``max_age`` argument.

    .. admonition:: Changing :data:`SESAME_MAX_AGE` doesn't always invalidate
            tokens.
        :class: tip

        Changing the value of :data:`SESAME_MAX_AGE` doesn't invalidate tokens
        as long as it isn't :obj:`None`.

        The new value applies to all tokens, even those that were generated
        before the change.

        Only switching it between :obj:`None` and another value invalidates all
        tokens.

.. data:: SESAME_ONE_TIME
    :value: False

    Set :data:`SESAME_ONE_TIME` to :obj:`True` to invalidate tokens when they're
    used.

    Specifically, updating the user's last login date invalidates tokens.

.. data:: SESAME_INVALIDATE_ON_PASSWORD_CHANGE
    :value: True

    By default, tokens are invalidated when a user changes their password.

    Set :data:`SESAME_INVALIDATE_ON_PASSWORD_CHANGE` to :obj:`False` to prevent
    this.

.. data:: SESAME_INVALIDATE_ON_EMAIL_CHANGE
    :value: False

    Set :data:`SESAME_INVALIDATE_ON_EMAIL_CHANGE` to :obj:`True` to
    invalidate tokens when a user changes their email.

.. data:: SESAME_PRIMARY_KEY_FIELD
    :value: "pk"

    Name of the field used as a primary key. See :ref:`Custom primary keys`.

.. data:: SESAME_PACKER
    :value: None

    Dotted path to a built-in or custom packer. See :ref:`Custom primary keys`.

.. data:: SESAME_TOKENS
    :value: ["sesame.tokens_v2", "sesame.tokens_v1"]

    Supported token formats. New tokens are generated with the first format.
    Existing tokens are accepted in any format listed here.

    The default value means "generate tokens v2, accept tokens v2 and v1". No
    other versions exist at this time.

.. data:: SESAME_KEY
    :value: ""

    Change the value of this setting if you need to invalidate all tokens.

    This setting only applies to tokens v2. See :ref:`Tokens design`.

.. data:: SESAME_SIGNATURE_SIZE
    :value: 10

    Size of the signature in bytes.

    This setting only applies to tokens v2. See :ref:`Tokens design`.

.. data:: SESAME_SALT
    :value: "sesame"

    Change the value of this setting if you need to invalidate all tokens.

    This setting only applies to tokens v1. See :ref:`Tokens design`.

.. SESAME_DIGEST was never documented and tokens v1 are superseded by tokens v2.

.. SESAME_ITERATIONS was never documented and tokens v1 are superseded by tokens v2.

Token generation
----------------

django-sesame provides three utility functions for generating tokens,
according to the context.

.. autofunction:: sesame.utils.get_query_string

.. autofunction:: sesame.utils.get_parameters

.. autofunction:: sesame.utils.get_token

Token validation
----------------

django-sesame provides high-level APIs to authenticate a user or to log
them in permanently.

.. autoclass:: sesame.middleware.AuthenticationMiddleware

.. autoclass:: sesame.views.LoginView

.. autodecorator:: sesame.decorators.authenticate

django-sesame also provides a low-level utility function for validating tokens.

.. autofunction:: sesame.utils.get_user

Token customization
-------------------

.. autoclass:: sesame.packers.BasePacker
    :members:

    See :ref:`Custom primary keys`.

Authentication backend
----------------------

django-sesame requires configuring a compatible authentication backend in
:setting:`AUTHENTICATION_BACKENDS`.

.. autoclass:: sesame.backends.ModelBackend

    .. automethod:: get_user
    .. automethod:: get_user_for_database

.. autoclass:: sesame.backends.SesameBackendMixin

    .. automethod:: authenticate
    .. automethod:: resolve_site
    .. automethod:: get_user_for_database

Multiple sites
--------------

.. data:: SESAME_SITE_MODE
    :value: "disabled"

    How tokens and requests are bound to sites. Possible values:

    - ``"disabled"``: tokens aren't bound to sites; users are read from the
      default database. This preserves the historical behavior.
    - ``"compatible"``: new tokens are bound to their site; unbound tokens are
      accepted only when they match exactly one user across databases.
    - ``"enforced"``: every request must identify a known site and every token
      must be bound to it.

.. data:: SESAME_SITES
    :value: {}

    A :class:`dict` mapping site identifiers to database aliases, for example
    ``{"site_a": "default", "site_b": "site_b"}``.

.. data:: SESAME_SITE
    :value: None

    Default site when :data:`SESAME_SITE_RESOLVER` doesn't identify one. Useful
    for single-site deployments that still want token binding.

.. data:: SESAME_SITE_RESOLVER
    :value: None

    A callable or the dotted path to a callable receiving the request and
    returning a site identifier or :obj:`None`.

.. data:: SESAME_LEGACY_SITES
    :value: []

    Restricts the databases audited when accepting unbound tokens to the
    selected sites. Use it when only some sites issued tokens before the
    migration. Defaults to every database in :data:`SESAME_SITES` plus
    ``"default"``.

.. autofunction:: sesame.legacy.audit_token

.. autoclass:: sesame.legacy.LegacyAudit
    :members:

.. autoclass:: sesame.legacy.LegacyMatch
    :members:

.. autoclass:: sesame.middleware.SiteMiddleware
