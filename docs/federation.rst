.. _federation:

Federated (OIDC) credentials
============================

Simple JWT's default authentication and signing paths are for credentials this
service issues itself.  When an API also accepts credentials from external OIDC
providers, that is a separate boundary: the provider must be registered
explicitly, its issuer must match exactly, and the token's audience must map to
an approved purpose.  Only then are claims projected into a local identity.

Local issuance is unchanged.  ``JWTAuthentication``, ``TokenBackend`` and the
token obtain/refresh/verify views behave exactly as before.  The federation
layer lives in ``rest_framework_simplejwt.federation``,
``rest_framework_simplejwt.federation_authentication``,
``rest_framework_simplejwt.federation_views`` and
``rest_framework_simplejwt.permissions``.

Provider registration
---------------------

.. code-block:: python

  SIMPLE_JWT = {
      ...
      "FEDERATION_PROVIDERS": {
          "company": {
              # Discovery metadata or an equivalent local stand-in.
              "metadata": {
                  "issuer": "https://company-idp.example",
                  "jwks_uri": "https://company-idp.example/.well-known/jwks.json",
                  "id_token_signing_alg_values_supported": ["RS256"],
              },
              # Audiences are mapped to purposes.  A token may only be used for
              # the purpose(s) its audience maps to.
              "audiences": {"company-api": "company-portal"},
              "verifying_key": COMPANY_PUBLIC_KEY,
              "applications": {"company-crm": "billing"},
              "identity": {
                  "claim": "email",
                  "template": "company:{value}",
                  "lookup_field": "username",
              },
              "projected_claims": ("email", "roles"),
          },
          "partner": {
              "metadata": { ... },
              "audiences": {"partner-api": "partner-portal"},
              "verifying_key": PARTNER_PUBLIC_KEY,
              "applications": {"partner-crm": "support"},
              "identity": {
                  "claim": "email",
                  "template": "partner:{value}",
                  "lookup_field": "username",
              },
              "projected_claims": ("email",),
          },
      },
  }

Each provider owns its issuer, keys, algorithm, audiences/purposes and claim
mapping.  Registration fails closed when:

* the issuer is empty or already registered by another provider;
* the issuer matches the local ``ISSUER`` setting;
* an HMAC provider reuses the local ``SIGNING_KEY``;
* the configured algorithm is not in the metadata's supported list;
* an audience has no purpose, or two audiences in one token map to two
  different purposes.

Verification, authentication and authorization are different facts
------------------------------------------------------------------

``FederatedToken`` performs provider-pinned verification: the ``iss`` selects the
provider first, and the signature, algorithms, issuer and audience are checked
with that provider's backend only.  A valid signature alone is not enough; the
token must also carry an approved audience, an approved purpose and a mappable
identity.

``FederatedJWTAuthentication`` turns that into a ``FederatedPrincipal``.  If the
provider declares ``lookup_field``, the mapped identity is looked up as a local
user; otherwise the principal is authenticated but has no permissions.  In
either case, token claims cannot set ``is_staff``, ``is_superuser`` or grant
application access.

Application authorization is a downstream check:

.. code-block:: python

  from rest_framework_simplejwt.federation_authentication import (
      LocalOrFederatedJWTAuthentication,
  )
  from rest_framework_simplejwt.permissions import HasApplication

  class BillingView(APIView):
      authentication_classes = (LocalOrFederatedJWTAuthentication,)
      permission_classes = (IsAuthenticated, HasApplication)
      application = "billing"

A locally issued token authenticates through the local path but never matches
``HasApplication``: local tokens have no federated application mapping, so
validity does not silently grant federated application scope.

``LocalOrFederatedJWTAuthentication`` tries the local path first and only then
the registered providers.  This is required because DRF stops the authenticator
chain on the first authentication failure; listing two separate classes would
prevent foreign tokens from reaching the federation layer.

An endpoint can additionally restrict the approved purpose by subclassing the
authentication class and setting ``purposes``::

  class CompanyPortalAuthentication(LocalOrFederatedJWTAuthentication):
      purposes = ("company-portal",)

Local tokens are unaffected by ``purposes`` because they have no provider
purpose; they simply authenticate on the local path.

Verify endpoint
---------------

``FederatedTokenVerifyView`` (``federated_token_verify``) is separate from
``TokenVerifyView``.  A 200 response reports the provider, subject, purpose and
mapped applications and states ``"scope": "identity_only"`` and
``"authorization": "not_evaluated"``.  It is identity evidence, not an
authorization decision.

Observed outcomes with two stand-ins and one subject
----------------------------------------------------

The test module ``tests/test_federation.py`` uses two local providers whose
tokens share the same ``sub`` and the same email.  The observed behaviour is:

* ``/federation/verify/``: 200 for either provider, with distinct provider names
  and purposes, and no authorization conclusion.
* ``/federation/identity/``: 200 for either provider; the identities differ
  (``company:...`` vs ``partner:...``) despite the shared subject.
* ``/federation/company-portal/`` (purpose-bound auth): 200 only for the
  company provider's purpose; the partner token is 401 even though it is valid.
* ``/federation/billing/``: 200 only when the token carries the provider-mapped
  application (``company-crm`` → ``billing``); 403 for identity-only tokens, for
  partner tokens, and for locally issued tokens.
* A token with a valid signature but the wrong provider's key, or the other
  provider's issuer, is rejected (401).
