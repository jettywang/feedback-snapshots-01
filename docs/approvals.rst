.. _approvals:

Temporary approvals
===================

A service that already authenticates with Simple JWT often needs something
narrower than a session: a one-shot authorization for a single sensitive
business operation (for example, paying one invoice) that a manager can
withdraw before it is actually committed.  Simple JWT provides this as a
*temporary approval*.

An approval is intentionally separate from access and refresh tokens:

* refreshing an ordinary access credential never mints, extends or revives an
  approval;
* an approval is bound to the exact operation identifier and amount it was
  issued for and is valid for nothing else;
* withdrawing and consuming race with a clear winner, and a caller can always
  look up the outcome of an approval it already used.

The approval is stored in the ``rest_framework_simplejwt.token_blacklist`` app,
which must be installed and migrated.

Issuing an approval
-------------------

Issue an approval only after whatever extra confirmation your business
requires (a step-up check, a second factor, a manager's sign-off)::

  from rest_framework_simplejwt.approvals import issue_approval

  approval = issue_approval(user, "invoice-4711", "199.95")
  # approval.token is the signed string to hand to the business layer

``issue_approval`` accepts a lifetime override via ``lifetime=..``; otherwise
``APPROVAL_TOKEN_LIFETIME`` applies.

Committing exactly once
-----------------------

Two executors may legitimately hold the same approval string.  Commit through
``commit_approval`` so only one of them ever runs the business action::

  from rest_framework_simplejwt.approvals import commit_approval

  outcome = commit_approval(
      approval_token,
      operation="invoice-4711",
      amount="199.95",
      operation_runner=pay_invoice,   # called only for the winner
  )

  outcome.executed     # True only for the call that ran the operation
  outcome.is_settled   # True once a business result was stored
  outcome.result       # the stored result, e.g. a payment reference

``operation_runner`` is invoked after the claim is committed and never for a
losing or replaying caller.  If the operation itself raises, the grant stays
consumed but unsettled, and a retry raises ``ApprovalIncomplete`` instead of
charging again.

Note that a successful authentication or a 200 response does **not** mean the
payment happened: check ``is_settled``/``executed`` for that.

Withdrawing
-----------

A manager can withdraw a pending approval until it is committed::

  from rest_framework_simplejwt.approvals import withdraw_approval

  withdraw_approval(approval.token)

If the approval was already consumed, ``ApprovalConflict`` is raised and the
recorded outcome is preserved.

Inspecting a finished approval
------------------------------

``inspect_approval`` returns the recorded state, including consumed and
withdrawn history::

  from rest_framework_simplejwt.approvals import inspect_approval

  approval = inspect_approval(approval_token)
  approval.status     # "pending", "consumed" or "withdrawn"
  approval.result     # stored business result, if any
  approval.is_settled # whether the operation actually completed

Reconciling a partial failure
-----------------------------

If the operation succeeded but writing its result failed (for example, the
finance record write raised), the grant is consumed but unsettled.  After
verifying the side effect yourself, record the known result without paying
again::

  from rest_framework_simplejwt.approvals import record_approval_result

  record_approval_result(approval_token, "payment-0001")

HTTP endpoints
--------------

``ApprovalObtainView``, ``ApprovalWithdrawView`` and ``ApprovalCommitView``
provide ready-made endpoints.  The commit view needs a business hook: either
set ``APPROVAL_OPERATION_RUNNER`` or subclass ``ApprovalCommitView`` and
override ``run_operation``.  For example::

  from rest_framework_simplejwt.views import ApprovalCommitView

  class PayInvoiceView(ApprovalCommitView):
      def run_operation(self, approval):
          return payments.charge(approval.operation, approval.amount)

The obtain view requires an authenticated request; a refresh token cannot be
used to obtain or restore an approval.
