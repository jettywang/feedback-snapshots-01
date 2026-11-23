# Support-Initiated Credential Replacement

This guide covers replacing a user's passkey when support cannot use the old
device any more. The old credential stays usable until the verified replacement
has been reliably written. The library verifies the WebAuthn ceremonies; your
application owns the storage and makes the swap transactional.

## The Contract

Implement `WebAuthn::CredentialReplacement::Store` in your persistence layer:

```ruby
class CredentialStore
  include WebAuthn::CredentialReplacement::Store

  def save_replacement_approval(approval)
    # Persist approval.id, account_id, replaced_credential_id, operators.
    # Saving an already applied/superseded approval must not reset it.
  end

  def commit_credential_replacement(approval:, credential:, operator:)
    # In ONE transaction:
    # 1. lock the account/replaced credential;
    # 2. make sure approval is still pending and operator is allowed;
    # 3. if this approval was already applied -> :already_applied;
    # 4. if another approval already replaced this credential -> :conflict
    #    (return winning_approval_id / winning_approval_state);
    # 5. otherwise delete approval.replaced_credential_id, insert credential,
    #    mark this approval :applied and its competing pending approvals
    #    :superseded -> :applied with revoked_credential_id.
  end
end
```

Return a `WebAuthn::CredentialReplacement::Outcome` (a Hash with the same keys
also works). The rules that matter:

- Commit at most once per `approval.id`.
- Only the commit that actually applies may return `status: :applied`, and it
  must revoke exactly `approval.replaced_credential_id`.
- A late conflicting approval returns `status: :conflict` and changes nothing.
  Fill `winning_approval_id` and `winning_approval_state` so the caller can
  tell whether the earlier approval is still valid.
- On a failed write raise `WebAuthn::CredentialReplacement::Store::WriteError`
  (or return `status: :failed`). Leave both the credential set and the approval
  pending so the operation can be retried.

Serialization of commits for the same account is the store's job. That is what
makes two legitimate support approvals resolve deterministically.

## Flow

```ruby
approval = relying_party.begin_credential_replacement(
  account_id: user.id,
  replaced_credential_id: old_credential.webauthn_id,
  operators: ["support-agent-7"],
  store: credential_store
)

# Same registration ceremony as always, but with the old credential excluded.
options = relying_party.options_for_replacement_registration(
  approval: approval,
  user: { id: user.webauthn_id, name: user.name }
)
session[:replacement_challenge] = options.challenge

# Later, on the verification request:
credential = relying_party.verify_replacement_registration(
  params[:publicKeyCredential],
  session[:replacement_challenge],
  approval: approval,
  operator: current_support_operator
)

result = relying_party.complete_credential_replacement(
  approval: approval,
  credential: credential,
  operator: current_support_operator,
  store: credential_store
)

if result.applied?
  # result.revoked_credential_id is the old device; the new one can log in.
elsif result.duplicate? || result.failed?
  # Same approval retried: no additional change, safe to retry after failure.
elsif result.conflict?
  # result.winning_approval_id applied; result.winning_approval_still_valid?
  # says whether that earlier approval is still the effective one.
end
```

`verify_replacement_registration` and `complete_credential_replacement` are
separate so a caller can retry the write without asking the user to register
again. `commit_credential_replacement` is the convenience wrapper that does both
in one call.

Ordinary registration keeps its own entry point
(`options_for_registration` / `verify_registration`). The replacement flow only
adds the operator check, the exclusion of the replaced credential and the
transactional commit; it does not change normal registration.

## Guarantees Exposed on the Result

- `result.applied?` - this call performed the swap.
- `result.credential_set_changed?` - true only for that same call.
- `result.revoked_credential_id` - set only for that same call; `nil` on
  duplicate, conflict, invalid and failed results.
- `result.approval_still_valid?` - stays true after a retryable write failure.
- `result.winning_approval_still_valid?` - for a conflict, whether the earlier
  approval is still the effective one.
- `result.retryable?` - true on a failed write.

`WebAuthn::CredentialReplacement::InMemoryStore` is a working reference
implementation, useful for tests. `#fail_next_write!` simulates a failed write,
and `#credential_set(account_id)` reports the credentials that can log in.
