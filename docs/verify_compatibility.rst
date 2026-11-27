.. _verify_compatibility:

Using TokenVerifyView as an admission check
===========================================

``TokenVerifyView`` is often proposed as a backend admission gate: another
service verifies a token before letting a request through.  This page records
what the standalone endpoint actually checks, compared with the protected API
that uses ``JWTAuthentication`` and the refresh endpoint a deployment really
serves.  All numbers below were produced by
``tests/test_verify_compatibility.py`` against this repository, not inferred
from the documentation.

What verify actually does
-------------------------

``TokenVerifySerializer`` wraps the token in ``UntypedToken``.  That means:

* **Signature** is checked against ``ALGORITHM`` / ``SIGNING_KEY`` (or
  ``VERIFYING_KEY`` / ``JWK_URL``) and the usual ``exp``/``aud``/``iss``
  validation runs in ``TokenBackend.decode``.
* **``exp`` and ``jti`` presence** are required (unless ``JTI_CLAIM`` is
  ``None``).  Expired tokens and missing claims return 401.
* **``TOKEN_TYPE_CLAIM`` is ignored.**  ``UntypedToken`` overrides
  ``verify_token_type`` to do nothing, so access, refresh, sliding and custom
  tokens are equally acceptable.  ``AUTH_TOKEN_CLASSES`` is not consulted by
  the verify path at all.
* **No subject is resolved.**  ``user_id`` is never read, no database lookup
  happens, and the response body is always ``{}``.  ``is_active``, deletion,
  ``CHECK_USER_IS_ACTIVE`` and ``CHECK_REVOKE_TOKEN`` are not evaluated.
* **The blacklist is checked only when ``BLACKLIST_AFTER_ROTATION`` was true
  when the serializer module was imported.**  If it was false at process
  start, enabling it later raises ``NameError: BlacklistedToken`` instead of
  checking anything (see below).

By contrast, ``JWTAuthentication.get_validated_token`` iterates
``AUTH_TOKEN_CLASSES``, so a token must match one enabled class's
``token_type``.  ``get_user`` then resolves the subject from
``USER_ID_CLAIM`` and enforces ``CHECK_USER_IS_ACTIVE`` and
``CHECK_REVOKE_TOKEN``.  The refresh serializers are hard-wired to
``RefreshToken`` or ``SlidingToken`` and use ``refresh_exp`` for sliding
tokens.

Reproducing the matrix
----------------------

The executable matrix lives in ``tests/test_verify_compatibility.py``.  It
issues tokens through the normal obtain views, keeps the values issued before
each configuration switch, and sends the same credential to verify, the
protected view and the deployment's refresh entry::

    .venv/bin/python -m pytest -q -o addopts= \
        tests/test_verify_compatibility.py -s

Each test prints a Markdown table; the assertions pin the status codes and
error text.  ``tests/verify_urls.py`` and ``tests/verify_support.py`` add the
custom token classes (``ServiceAccessToken`` / ``ServiceRefreshToken``) and
the protected echo views used by the matrix.

The custom class is a minimal but realistic third deployment: a refresh class
with ``token_type = "service-refresh"`` and an access sibling with
``token_type = "service-access"``.  Its obtain and refresh views are wired to
the corresponding serializers, exactly as a real service would do.

Cross enabled class
-------------------

Token issuance did not change between rows: the same five credentials were
issued once, then ``AUTH_TOKEN_CLASSES`` was switched.  Verify returned 200
for every row, while the protected API only accepted the class that matched
the deployment's enabled profile.

.. list-table::
   :header-rows: 1

   * - Credential
     - Enabled class
     - Verify
     - API subject
     - Protected API
     - Refresh entry
   * - access token
     - access
     - 200 ``{}``
     - resolved (id=1)
     - 200 ``subject=1``
     - 401 Token has wrong type
   * - access token
     - sliding
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 401 Token has wrong type
   * - access token
     - custom
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 401 Token has wrong type
   * - refresh token
     - access
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - refresh token
     - sliding
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - refresh token
     - custom
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - sliding token
     - access
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - sliding token
     - sliding
     - 200 ``{}``
     - resolved (id=1)
     - 200 ``subject=1``
     - 200 new-token subject=1
   * - sliding token
     - custom
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - custom access
     - access
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 401 Token has wrong type
   * - custom access
     - sliding
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 401 Token has wrong type
   * - custom access
     - custom
     - 200 ``{}``
     - resolved (id=1)
     - 200 ``subject=1``
     - 401 Token has wrong type
   * - custom refresh
     - access
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - custom refresh
     - sliding
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1
   * - custom refresh
     - custom
     - 200 ``{}``
     - not resolved
     - 401 token_not_valid
     - 200 new-token subject=1

Key observations:

* Verify is type-blind.  A refresh token or another deployment's access token
  gets 200 even though it cannot authenticate at all.
* The refresh entry is independent of ``AUTH_TOKEN_CLASSES``.  Switching the
  enabled class does not move the refresh route: each deployment's refresh
  view always expects its own serializer's token class.
* ``/token/verify/`` does not resolve a subject, so a 200 cannot distinguish a
  live user from a deleted or deactivated one.

Blacklist
---------

The blacklist is enforced by three different paths, with different
dependencies:

.. list-table::
   :header-rows: 1

   * - Scenario
     - Verify
     - Protected API
     - Refresh entry
   * - access pair, refresh half blacklisted
     - 400
     - 401 Token has wrong type
     - 401 Token is blacklisted
   * - same, ``BLACKLIST_AFTER_ROTATION=False``
     - 200
     - 401 Token has wrong type
     - 401 Token is blacklisted
   * - access token's own jti given a manual blacklist row
     - 400
     - 200 ``subject=1``
     - 401 Token has wrong type
   * - sliding token blacklisted
     - 400
     - 401 Token is blacklisted
     - 401 Token is blacklisted
   * - sliding token blacklisted, ``BLACKLIST_AFTER_ROTATION=False``
     - 200
     - 401 Token is blacklisted
     - 401 Token is blacklisted
   * - custom refresh half blacklisted
     - 400
     - 401 token_not_valid
     - 401 Token is blacklisted
   * - custom access token, refresh half blacklisted
     - 200
     - 200 ``subject=1``
     - 401 Token has wrong type

Reverse asymmetry to watch for: an access token is never blacklisted by the
normal flow (``AccessToken`` is not a ``BlacklistMixin``).  If an operator
adds an access ``jti`` to ``BlacklistedToken`` manually, verify rejects it
(400) but the protected API still returns 200.  In this repository verify is
stricter than the API for access tokens, and looser than the API for sliding
tokens.  Neither direction is a safe admission rule on its own.

``BLACKLIST_AFTER_ROTATION`` is read at import time in ``serializers.py``.
Enabling it in a running process after starting with it disabled raises
``NameError: BlacklistedToken`` on the next verify call, because the name was
never imported.  A restart is required after changing that setting.

Sliding refresh window
----------------------

``TokenVerifySerializer`` checks ``exp``.  ``TokenRefreshSlidingSerializer``
also checks ``exp`` first and then ``refresh_exp``.  A sliding token whose
auth ``exp`` has passed but whose ``refresh_exp`` is still open returns 401
from verify and from the protected API, and 401 from the refresh entry as
well (``Token is expired``); it cannot be refreshed either.  A token whose
auth ``exp`` is open but whose ``refresh_exp`` has passed returns 200 from
verify, 200 from the API, and 401 from the refresh entry
(``Token 'refresh_exp' claim has expired``).

Subject resolution and revocation
---------------------------------

Verify never resolves a subject.  The API and refresh paths do, and reject in
ways verify cannot see.  The tokens below were issued normally and kept
across the state changes.

.. list-table::
   :header-rows: 1

   * - State
     - Verify
     - Protected API
     - Refresh entry
   * - fresh access token
     - 200
     - 200 ``subject=1``
     - 401 Token has wrong type
   * - fresh refresh token
     - 200
     - 401 token_not_valid
     - 200 new-token subject=1
   * - user deactivated
     - 200
     - 401 User is inactive
     - 401 No active account found
   * - user deleted
     - 200
     - 401 User not found
     - 401 No active account found
   * - no ``user_id`` claim (access half)
     - 200
     - 401 no recognizable user identification
     - 401 Token has wrong type
   * - no ``user_id`` claim (refresh half)
     - 200
     - 401 token_not_valid
     - 200 new-token, no subject
   * - ``CHECK_REVOKE_TOKEN=True``, token issued before the switch
     - 200
     - 401 password has been changed
     - 401 password has been changed
   * - ``CHECK_REVOKE_TOKEN=True``, hash claim present, password changed
     - 200
     - 401 password has been changed
     - 401 password has been changed
   * - ``CHECK_REVOKE_TOKEN=False``, password changed
     - 200
     - 200 ``subject=2``
     - 200 new-token subject=2
   * - signed with a different HS256 key
     - 401
     - 401 token_not_valid
     - 401 Token is invalid

A refresh token without ``user_id`` still mints an access token with no
subject.  That new token also passes verify (200) and fails the protected API
(401).  Verify accepts a missing subject as long as signature, ``exp`` and
``jti`` are intact.

Configuration switches and previously issued values
---------------------------------------------------

Tokens issued before a claim-name change keep the old claim and are handled
differently by each gate:

.. list-table::
   :header-rows: 1

   * - Change
     - Verify
     - Protected API
     - Refresh entry
     - Issued after switch
   * - ``TOKEN_TYPE_CLAIM="typ"``
     - 200 ``{}``
     - 401 Token has no type
     - 401 Token has no type
     - all three accept
   * - ``JTI_CLAIM="jti2"`` (access)
     - 401 Token has no id
     - 401 Token has no id
     - 401 Token has wrong type
     - verify/API accept, refresh crashes
   * - ``JTI_CLAIM="jti2"`` (refresh)
     - 401 Token has no id
     - 401 token_not_valid
     - 500 ``KeyError('jti2')``
     - verify/API accept, refresh crashes
   * - ``JTI_CLAIM=None`` (blacklist app installed)
     - 200 ``{}``
     - 200 ``subject=1``
     - 500 ``KeyError(None)``
     - verify/API accept, refresh crashes

Two failures are worth calling out for anyone deploying a claim rename:

* Renaming ``TOKEN_TYPE_CLAIM`` keeps verify green while silently breaking
  every token issued before the rename at the API and refresh gates.
* Renaming or disabling ``JTI_CLAIM`` leaves verify behaving normally but
  makes the refresh entry raise ``KeyError`` (a 500), because
  ``BlacklistMixin.check_blacklist`` indexes the configured claim directly.
  A missing ``jti`` on a refresh token has the same effect.

Permission decisions still required
-----------------------------------

A 200 from verify is not an authorization decision.  A non-staff user gets
200 from verify and 403 (``permission_denied``) from an ``IsAdminUser`` view.
With ``JWTStatelessUserAuthentication`` the opposite risk appears: the view
trusts the token's claims, so a token carrying ``is_staff=True`` for a
database user who is not staff gets 200.  ``TokenUser.has_perm`` always
returns ``False`` and ``TokenUser.groups`` is empty, so permission codes that
rely on database groups or Django model permissions cannot be evaluated by
the stateless backend at all.

Deployments that need an additional check before admitting a request:

* **Sliding-token deployments.** Verify accepts the sliding token even after
  it has been revoked in the blacklist if ``BLACKLIST_AFTER_ROTATION`` is
  false, while the API still rejects it.  Verify is weaker here.
* **Custom token deployments.** Verify accepts the access token of a
  different deployment.  Only the API's ``AUTH_TOKEN_CLASSES`` separates
  them, and verify cannot see that setting.
* **Any deployment using ``CHECK_REVOKE_TOKEN``.** Verify never reads the
  password hash claim.  Tokens issued before the switch are rejected by the
  API but admitted by verify, so verify cannot replace the API for revocation.
* **Any deployment relying on ``is_active``, account deletion or Django
  permissions.** Verify performs no database lookup and no permission check;
  the API's 401/403 is the only place those states are enforced.
* **Stateless deployments.** The API grants whatever the token claims say.
  Verify adds nothing, and a permission layer must validate claims against an
  authoritative source if claims are not trustworthy.
* **Processes that toggle ``BLACKLIST_AFTER_ROTATION``.** The change requires
  a restart; toggling in-process turns verify into a 500.
