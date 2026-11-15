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

The SMTP class provides built-in AUTH hooks for the ``LOGIN`` and ``PLAIN``
mechanisms, named ``auth_LOGIN`` and ``auth_PLAIN``, respectively.
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


.. _sender-authorization:

Envelope-sender authorization
=============================

Authentication answers *who* the client is.  It does not, by itself, decide
*which envelope sender* that client may use.  A submission server must make
that second decision in ``handle_MAIL``, before writing
``envelope.mail_from``.

The ``examples/authenticated_relayer/sender_policy.py`` module demonstrates a
reusable shape for this:

``parse_envelope_address(address, *, smtp_utf8, smtp_utf8_enabled)``
   Converts the addr-spec delivered to ``handle_MAIL`` into one canonical
   identity.  It does not re-run a lenient RFC 5322 parser over the wire
   command.  The local-part keeps its exact case and Unicode code points; only
   the RFC 5321 equivalence between quoted and unquoted forms is applied.
   ``<>`` is returned as the distinct null reverse-path, while
   ``""@example.com`` is rejected as an empty local-part.

   The domain is canonicalized with one explicit IDNA policy.  The example
   uses strict IDNA2008 with STD3 rules and lowercases ASCII letters.  UTS #46
   compatibility folding is intentionally *not* used, so a full-width or other
   homoglyph is rejected instead of being mapped onto the legitimate alias.

   If either the local-part or the domain contains non-ASCII text, the
   ``smtp_utf8`` argument must be the MAIL command's SMTPUTF8 assertion.
   Merely enabling ``enable_SMTPUTF8`` on the server is not enough: a client
   that did not negotiate SMTPUTF8 must not reach the Unicode identity path,
   even though ``aiosmtpd`` has already decoded the command bytes.

``SenderPolicy``
   Maps an authenticated username to an exact set of envelope-sender
   identities.  Aliases may be written as U-labels or A-labels; matching is
   on the canonical key.  There are no domain-wide, prefix, plus-address, or
   case-folded local-part matches.

``SenderAuthorizedHandler``
   A ``handle_MAIL`` hook that applies the policy.  It writes
   ``envelope.mail_from`` only after authorization succeeds and explicitly
   clears it on every rejection.  Consequently a later ``RCPT`` or ``DATA``
   cannot inherit a sender from a rejected ``MAIL``.  The message body's
   ``From`` header is never consulted.

The hook logs the original input in a bounded, control-character-escaped form
and records the canonical identity and the exact match basis separately, so
operators can investigate a rejection without allowing a crafted address to
forge log lines.


Security Considerations
=======================

We have taken steps to prevent leakage of sensitive information (i.e., password) through logging
by overriding the ``__repr__`` and ``__str__`` methods of the :class:`~aiosmtpd.smtp.AuthResult` and
:class:`~aiosmtpd.smtp.LoginPassword` classes.

However, we have no control on the (logging) output of your custom hooks.
Please be very careful emitting/recording AUTH information to prevent leakage.


Example
=======

An example is provided in ``examples/authenticated_relayer``.
Its ``sender_policy.py`` also demonstrates
:ref:`authenticated envelope-sender authorization <sender-authorization>`.
