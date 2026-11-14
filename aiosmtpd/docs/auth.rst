.. _auth:

=======================
 Authentication System
=======================

``aiosmtpd`` provides a framework for SMTP Authentication that fully complies with :rfc:`4954`.


Activating Authentication
=========================

``aiosmtpd`` authentication is always activated,
but attempts to authenticate will always be rejected
unless the :attr:`~aiosmtpd.smtp.SMTP.authenticator` parameter of :class:`~aiosmtpd.smtp.SMTP`
is set to a valid & working :ref:`authcallback`.


AUTH API
========

The ``aiosmtpd`` Authentication Framework comprises several components,
who are collectivelly called the "AUTH API".

.. _authhandler:

AUTH Handler Hook
-----------------

.. py:method:: handle_AUTH(server: SMTP, session: Session, envelope: Envelope, args)
   :async:

   Called to handle ``AUTH`` command, if you need custom AUTH behavior.

   Most of the time, you will NOT *need* to implement this hook;
   :ref:`authmech` are provided to override/implement selective
   SMTP AUTH mechanisms (see below).

   If you do implement this hook:

   You *MUST* comply with :rfc:`4954`.

   ``args`` will contain the list of words following the ``AUTH`` command.

   You will have to leverage the :meth:`~aiosmtpd.smtp.SMTP.push` and :meth:`~aiosmtpd.smtp.SMTP.challenge_auth` methods
   to interact with the clients.

   You will need to modify the :attr:`session.auth_data <Session.auth_data>`
   and :attr:`session.authenticated <Session.authenticated>` attributes.

   You may ignore the ``envelope``.

.. _authmech:

AUTH Mechanism Hooks
--------------------

Separately from :ref:`authhandler`,
``aiosmtpd`` also implement support for "AUTH Mechanism Hooks".
These **async** hooks will implement the logic for SMTP Authentication Mechanisms.

Every AUTH Mechanism Hook is named ``auth_MECHANISM``
where ``MECHANISM`` is the all-uppercase name of the mechanism
that the hook will implement.

(Mechanism is the word following the ``AUTH`` command sent by client.)

.. important::

   If ``MECHANISM`` has a dash within its name,
   use **double-underscore** to represent the dash.
   For example, to implement a ``MECH-WITH-DASHES`` mechanism,
   name the AUTH hook as ``auth_MECH__WITH__DASHES``.

   Single underscores will not be modified.
   So a hook named ``auth_MECH_WITH_UNDERSCORE``
   will implement the ``MECH_WITH_UNDERSCORE`` mechanism.

   (If in the future a SASL mechanism with double underscores in its name gets defined,
   this name-mangling mechanism will be revisited.
   That is very unlikely to happen, though.)

   Alternatively, you can also use the :func:`~aiosmtpd.smtp.auth_mechanism` decorator,
   which you can import from the :mod:`aiosmtpd.smtp` module.

The SMTP class provides built-in AUTH hooks for the ``LOGIN``, ``PLAIN`` and
``OAUTHBEARER`` mechanisms, named ``auth_LOGIN``, ``auth_PLAIN`` and
``auth_OAUTHBEARER``, respectively.
If the handler class implements ``auth_LOGIN`` and/or ``auth_PLAIN``, then
the methods of the handler instance will override the built-in methods.

.. py:method:: auth_MECHANISM(server: SMTP, args: List[str]) -> aiosmtpd.smtp.AuthResult
   :async:

   :param server: The instance of the :class:`~aiosmtpd.smtp.SMTP` class invoking the AUTH Mechanism hook
   :param args: A list of string split from the characters following the ``AUTH`` command.
      ``args[0]`` is usually equal to ``MECHANISM``
      (unless the :func:`~aiosmtpd.smtp.auth_mechanism` decorator has been used).

   The AUTH hook MUST perform the actual validation of AUTH credentials.

   In the built-in AUTH hooks,
   this is done by invoking the function specified
   by the :attr:`~aiosmtpd.smtp.SMTP.authenticator` initialization argument.

   AUTH Mechanism Hooks in handlers are NOT required to do the same,
   and MAY implement their own authenticator system.

   The AUTH Mechanism Hook MUST return an instance of :class:`AuthResult`
   containing the result of the Authentication process.

.. important::

   Defining *additional* AUTH hooks in your handler
   will NOT disable the built-in LOGIN and PLAIN hooks;
   if you do not want to offer the LOGIN and PLAIN mechanisms,
   specify them in the :attr:`~aiosmtpd.smtp.SMTP.auth_exclude_mechanism` parameter
   of the :class:`~aiosmtpd.smtp.SMTP` class.


.. _authcallback:

Authenticator Callback
----------------------

.. py:function:: Authenticator(server, session, envelope, mechanism, auth_data) -> AuthResult

   :param server: The :class:`~aiosmtpd.smtp.SMTP` instance that invoked the authenticator
   :param session: A :class:`Session` instance containing session data *so far*
   :param envelope: An :class:`Envelope` instance containing transaction data *so far*
   :param mechanism: name of the AUTH Mechanism chosen by the client
   :type mechanism: str
   :param auth_data: A data structure containing authentication data gathered by the AUTH Mechanism
   :return: Result of authentication
   :rtype: AuthResult

   This function would be invoked during or at the end of an Authentication Process by
   AUTH Mechanisms.
   Based on ``mechanism`` and ``auth_data``,
   this function should return a decision on whether Authentication has been successful or not.

   This function SHOULD NOT modify the attributes of ``session`` and ``envelope``.

   The type and contents of the ``auth_data`` parameter is wholly at the discretion of the
   calling AUTH Mechanism. For the built-in ``LOGIN`` and ``PLAIN`` Mechanisms, the type
   of data will be :class:`aiosmtpd.smtp.LoginPassword`

   .. versionadded:: 1.3

AuthResult API
--------------

.. class:: AuthResult(*, success, handled, message, auth_data)

   .. py:attribute:: success
      :type: bool

      This attribute indicates whether Authentication is successful or not.

   .. py:attribute:: handled
      :type: bool
      :value: True

      This attribute indicates whether Authenticator Decision process
      (e.g., sending of status codes)
      have been carried out by Authenticator or not.

      If set to ``True``, :meth:`~aiosmtpd.smtp.SMTP.smtp_AUTH` will not perform additional processing
      and will simply exits.

      Applicable only if ``success=False``

   .. py:attribute:: message
      :type: Optional[str]
      :value: None

      The message to send back to client, regardless of success status.

      This message will be sent as-is;
      as such, it MUST be prefixed with the correct SMTP Status Code
      and optionally, SMTP Extended Status Code.

      If not given (set/kept to ``None``),
      :meth:`~aiosmtpd.smtp.SMTP.smtp_AUTH` will use standard SMTP Status Code & Message.

   .. py:attribute:: auth_data
      :type: Any
      :value: None

      Optional free-form authentication data.
      This will be saved by :meth:`~aiosmtpd.smtp.SMTP.smtp_AUTH` into the ``session.auth_data`` attribute.

      If ``auth_data`` has the attribute ``login``,
      then :meth:`~aiosmtpd.smtp.SMTP.smtp_AUTH` will save ``auth_data.login`` into ``session.login_data`` as well.
      This is to cater for possible backward-compatibility requirements,
      where legacy handlers might be looking for ``session.login_data`` for some reasons.


.. _oauthbearer:

OAUTHBEARER (RFC 7628)
======================

The built-in ``OAUTHBEARER`` mechanism implements :rfc:`7628` for OAuth 2.0
bearer tokens.  It is intended for mail submission where the client presents a
short-lived OAuth access token instead of a password.

The library performs the strict, token-agnostic parts of the mechanism and
enforces the local security policy, but it **never** contacts an identity
service itself.  Token validation is delegated to a caller-supplied, locally
invoked callback.

Configuring the mechanism
-------------------------

The mechanism is enabled by passing these :class:`~aiosmtpd.smtp.SMTP`
arguments:

.. py:attribute:: oauth_token_validator
   :noindex:

   A :data:`~aiosmtpd.oauthbearer.OAuthTokenValidatorType` callable that
   receives the parsed :class:`~aiosmtpd.oauthbearer.OAuthBearerRequest` and
   returns the :class:`~aiosmtpd.oauthbearer.OAuthIdentity` established by the
   credential, or raises :class:`~aiosmtpd.oauthbearer.OAuthBearerError`.  It
   runs locally; use it to verify a JWT, consult a local cache, or perform any
   other validation that does not require this library to make network calls.

.. py:attribute:: oauth_service_audience
   :noindex:

   The audience that identifies *this* mail service.  A token whose
   ``audiences`` do not include it is rejected, so a token minted for another
   service (for example a calendar service) cannot be used to authenticate.

.. py:attribute:: oauth_required_scopes
   :noindex:

   The scopes a token must carry to use this service (for example an
   ``SMTP.send`` scope).  A token missing any of them is rejected.

Strict wire validation
----------------------

The initial client response is parsed strictly according to the RFC 7628
grammar:

* The GS2 header (:rfc:`5801`) must use the non-channel-binding form ``n,`` or
  ``n,a=<authzid>,``; channel-binding flags (``y`` or ``p=``) are rejected.
* Fields are separated by the ``%x01`` separator and must follow the
  ``key=value`` layout; malformed or empty elements are rejected.
* The required ``auth`` field must be ``Bearer <token>`` (the scheme name is
  matched case-insensitively) with a non-empty token.
* ``port`` must be a decimal positive integer without leading zeros.
* Repeated or otherwise conflicting fields are rejected.  Unknown fields are
  ignored as the RFC permits, but duplicates of any field are an error.
* ``host`` and ``port``, when present, are checked against the service
  endpoint the client is connected to.

Identity and authzid
--------------------

The authenticated identity is the ``subject`` returned by your validator,
never an identity chosen by the client.  If the client asserts an
``authzid`` (the ``a=`` part of the GS2 header), it must be identical to the
validated subject; an attempt to assume another user is rejected.  On success
the :class:`~aiosmtpd.oauthbearer.OAuthIdentity` is stored in
:attr:`session.auth_data <Session.auth_data>` and its ``subject`` is exposed
as the legacy ``login_data``; later mail authorization (such as ``MAIL FROM``)
is therefore based on the validated identity.

TLS and the error interaction
-----------------------------

Bearer tokens require TLS.  A bearer token presented over a cleartext
channel is rejected with ``538`` regardless of the ``auth_require_tls``
setting, and the session is never marked authenticated.

On any failure the server follows the RFC 7628 error interaction: it sends the
JSON error result (for example ``{"status":"invalid_token", ...}``) in a
``334`` message, then waits for the client's dummy response (a single
``%x01``) or an abort (``*``).  Only after that exchange does it return the
final ``535``.  A failure inside the validator (including an unexpected
exception) is treated as a validation failure, never as a successful
authentication.

.. py:class:: OAuthBearerRequest
   :noindex:

   The strictly parsed initial client response.  Its representation hides the
   bearer token, so logging this object cannot leak the credential.

.. py:class:: OAuthIdentity
   :noindex:

   The identity established by the validated token: ``subject``,
   ``audiences`` and ``scopes``.

.. py:class:: OAuthBearerError
   :noindex:

   Raised on validation or policy failure; its ``error_status`` carries the
   OAuth 2.0 error code placed in the JSON error result.


Security Considerations
=======================

We have taken steps to prevent leakage of sensitive information (i.e., password) through logging
by overriding the ``__repr__`` and ``__str__`` methods of the :class:`~aiosmtpd.smtp.AuthResult` and
:class:`~aiosmtpd.smtp.LoginPassword` classes.

The same care is applied to OAUTHBEARER:
:class:`~aiosmtpd.oauthbearer.OAuthBearerRequest` hides the bearer token in
its ``__repr__``/``__str__``, the raw ``AUTH OAUTHBEARER`` command line is
sanitized before it is written to the log, and the built-in mechanism never
logs the token itself or the parsed request's credential.

However, we have no control on the (logging) output of your custom hooks.
Please be very careful emitting/recording AUTH information (including bearer
tokens) to prevent leakage.


Example
=======

An example is provided in ``examples/authenticated_relayer``.
