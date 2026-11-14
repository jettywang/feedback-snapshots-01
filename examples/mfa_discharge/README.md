# Local MFA discharge service example

This is a self-contained, in-memory demonstration of using a third-party
macaroon caveat as a second-factor gate.  It does not call SMS, push, OAuth,
or any identity provider.  It requires Python 3.7+ (for `dataclasses`) and
runs against the repository's existing `pymacaroons` package.  The point is
the protocol:

1. The business service creates a root macaroon that restricts the user, the
   exact operation digest, and the expiry, then adds a third-party caveat
   addressed to the authentication service.
2. The authentication service records a challenge that binds the subject,
   operation digest, expiry, and a one-time caveat key.
3. The simulated MFA verifier answers only one question: did this subject
   complete the challenge it sent them?
4. Only after that answer does the authentication service exchange a one-time
   verification receipt for a signed discharge macaroon.
5. The business service binds the discharge to the root signature and verifies
   the root key, the binding, and every caveat itself.

A caveat identifier is a public lookup key.  It is never itself evidence that
MFA was completed.  The discharge is useless without the issuer's caveat key
and a matching verification receipt.

## Files

- `clock.py` - a manually advanced logical clock for deterministic expiry.
- `model.py` - `Operation` and its canonical SHA-256 digest, plus `Denied`.
- `mfa.py` - the simulated MFA verifier with out-of-band proof codes.
- `auth_service.py` - the authentication service and discharge issuer; it
  records every discharge it actually signs.
- `business_service.py` - creates root macaroons and performs final
  verification.
- `demo.py` - the success path and the rejection cases.

## Run the demo

From the repository root:

```sh
python -m examples.mfa_discharge.demo
```

Expected outcome:

```text
challenge_created                   pending  # expires_at=...
alice_approved                      allowed  # transfer:account:alice (...) by alice
cross_user_confirmation             denied:wrong_subject
cross_user_redemption               denied:wrong_subject
issuer_signed_after_cross_user      none
operation_swapped_after_mfa         denied:operation_changed
expired_before_issue                denied:challenge_expired
repeat_confirmation_after_issue     denied:challenge_already_consumed
repeat_issue_after_issue            denied:challenge_already_consumed
cross_operation_replay              denied:discharge_challenge_mismatch
issuer_signed_for_replayed_request  none
tampered_discharge                  denied:invalid_signature

Discharges actually signed by the issuers: 4
```

Each of the four signed-discharge audit records lists the scenario, challenge,
subject, operation digest, issuance time, expiry, and actual signature.  All
four come from scenarios where a valid flow completed; none of the rejected
attempts caused a signature.

The demo uses one issuer and one business service per scenario so the audit
log shows exactly what each scenario caused.

## Run the tests

```sh
python -m pytest -q -o addopts= tests/functional_tests/mfa_discharge_tests.py
```

## What each guard is for

- `verify_mfa` checks the challenge is still pending, unexpired, and owned by
  the subject presenting the proof, and that the submitted operation digest
  matches the recorded one.  It returns a receipt only on success.
- `issue_discharge` consumes the receipt once.  It rechecks expiry and the
  receipt binding, then confirms the root carries exactly one caveat for this
  challenge, addressed to this issuer, with matching `user`, `operation`, and
  `expires` first-party restrictions.
- `BusinessService.complete` looks up the pending request by its own handle;
  the user, operation, and root macaroon come from that record, not the caller.  It
  then verifies the root signature, the discharge-to-root binding, and every
  caveat using `pymacaroons`.
- Every signed discharge is appended to `MfaDischargeService.issued_discharges`.

## Production caveats

This example deliberately keeps secrets in memory and uses the pymacaroons
API directly.  In a real deployment:

- serve the issuer over an authenticated transport and authenticate the MFA
  confirmation itself; do not expose a method that a browser can call with a
  bare challenge identifier;
- derive the `user_id` in `verify_mfa` from the authenticated session, never
  from a request field the user controls;
- persist challenges and receipts atomically, with single-use consumption,
  rather than in dictionaries;
- use a real MFA verifier whose assertions are scoped to the challenge;
- treat the operation digest as canonical data and reject unknown detail
  types before hashing.
