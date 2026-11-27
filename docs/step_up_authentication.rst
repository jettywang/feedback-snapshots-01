.. _step_up_authentication:

Step-up (second factor) authentication
=======================================

Some endpoints, such as financial or other sensitive operations, require a
recent additional identity confirmation while the rest of the API keeps using
the ordinary login. Simple JWT supports this with an **optional** step-up
verification state carried inside the token.

The feature is off by default, so existing login, token issuance and refresh
behavior are unchanged until you opt in.

Configuration
-------------

Enable it and register a server-side verifier in the ``SIMPLE_JWT`` settings:

.. code-block:: python

  from datetime import timedelta

  SIMPLE_JWT = {
      # ...your existing settings...
      "STEP_UP_ENABLED": True,
      "STEP_UP_CLAIM": "step_up_exp",
      "STEP_UP_LIFETIME": timedelta(minutes=5),
      # A dotted path to a callable you control. This is the ONLY source the
      # backend trusts when minting a step-up claim.
      "STEP_UP_VERIFIER": "my_project.verifiers.verify_totp",
  }

The verifier is a callable with the signature
``verifier(user, evidence, request) -> bool``. It should check the second
factor (TOTP code, push approval, hardware key, ...) and return ``True`` only
when the evidence is valid. If no verifier is configured while the feature is
enabled, the step-up endpoint fails closed with ``403`` and never issues a
proof.

Requesting a step-up proof
--------------------------

The user first logs in normally to obtain an access/refresh pair. To elevate,
they call the step-up endpoint while authenticated, optionally passing the
second-factor evidence:

.. code-block:: python

  from rest_framework_simplejwt.views import TokenStepUpView

  # urls.py
  urlpatterns = [
      # ...
      path("token/step-up/", TokenStepUpView.as_view(), name="token_step_up"),
  ]

On success the response contains a new refresh/access pair. Both tokens carry
a ``step_up_exp`` claim whose value is the timestamp until which the proof is
valid. The ordinary access token lifetime (``exp``) is not changed.

Protecting sensitive endpoints
------------------------------

Add the ``StepUpRequired`` permission alongside ``IsAuthenticated``:

.. code-block:: python

  from rest_framework import permissions
  from rest_framework.views import APIView
  from rest_framework_simplejwt.permissions import StepUpRequired

  class FinanceView(APIView):
      permission_classes = (permissions.IsAuthenticated, StepUpRequired)

      def get(self, request):
          ...

A request without a live step-up claim is rejected with ``403`` and the
``step_up_required`` code. Ordinary views that only use ``IsAuthenticated``
continue to work with any valid access token.

How refresh interacts with the proof
------------------------------------

Refreshing stays online and works exactly as before, but it never extends or
re-issues the step-up proof. When a refresh token carries ``step_up_exp``, the
new access token inherits that same claim verbatim (this also holds when
``ROTATE_REFRESH_TOKENS`` is enabled). Therefore:

* The access token ``exp`` lifetime is unaffected by step-up verification.
* A refreshed token keeps serving ordinary pages for its whole lifetime.
* Once ``step_up_exp`` passes, sensitive endpoints are locked again even
  though the access token itself is still valid; the user must re-verify.

The same rule backs issuance, refresh and the permission check through
``Token.has_valid_step_up``, so all three make an identical decision from a
single source of truth.
