# Account Binding Contract

This document is the integrator-facing contract between a verified WebAuthn
assertion and a session principal. It applies to applications that expose both
of these authentication entries:

- **usernameless** — the user presents no account identifier; the credential is
  discoverable and the account is resolved from the credential.
- **known-account** — the user is already identified before the ceremony (for
  example by an existing `account_id` in the session), and some of those
  accounts only have legacy user handles stored.

The contract is implemented by `WebAuthn::AccountBinding::Contract` and is
backed by the existing `RelyingParty#verify_authentication` lookup callback.
It is intentionally separate from the WebAuthn assertion API: verifying an
assertion is necessary, but it is not sufficient to sign a user in.

## The three authorities

A session may only be created when all three of the following hold for the
*same moment in time*:

1. **Signature-verified assertion.** The library verified the challenge,
   origin, RP ID, type, user presence/verification flags, signature and
   sign count against the public key read from the credential record.
2. **Handle policy for the entry.** The user handle presented by the
   authenticator, and the handle stored on the account, satisfy the policy
   configured for that entry.
3. **Currently valid account binding.** The credential still belongs to the
   account, the account is active, it has not been merged into another account,
   and it still carries the handle the policy requires.

The verification material read during lookup is only an input to (1). It never
decides (2) or (3) after a concurrent change.

## Two phases: verify, then commit

`Contract#verify` performs lookup and signature verification and returns an
`Attempt`. An `Attempt` is **not** a session and `Attempt#session?` is always
`false`. `Contract#commit` re-reads the account and credential and only then
returns a `Result` carrying a `Principal`.

```ruby
contract = WebAuthn::AccountBinding::Contract.new(
  store: account_store,
  relying_party: relying_party,
  handle_policies: {
    usernameless: :modern_only,          # default, and the only allowed value
    known_account: :legacy_fallback      # explicit opt-in for legacy handles
  }
)

attempt = contract.verify(
  entry: :usernameless,
  raw_credential: params[:publicKeyCredential],
  challenge: session[:authentication_challenge],
  user_verification: true
)

# Do not create a session here. The account may change between the two calls.

result = contract.commit(attempt)

if result.session_created?
  sign_in(result.principal.account_id)
else
  # result.reason tells the integrator why the binding is no longer valid.
  render json: { error: result.reason }, status: :unauthorized
end
```

`Contract#authenticate` is the convenience form that calls `verify` followed
immediately by `commit`. It is correct for the stable path, but it cannot
observe an account change that happens *between* the callback returning and
the session being created; use the two-phase form at any point where another
writer can touch the account (background merges, admin disable, unbind jobs).

## Entry policies

### usernameless

- The credential must be discoverable.
- The account is resolved **only** from the credential's `account_id`.
- `modern_only` is the only supported policy: the assertion must carry a user
  handle and it must match the account's current handle.
- Legacy handles are never used to resolve a usernameless login. A credential
  stored in the legacy format is rejected with `legacy_handle_not_allowed`.

### known-account

- The caller must pass the `account_id` established before the ceremony.
- The credential must still be bound to that same account at verification
  time and again at commit time; otherwise the attempt is rejected
  (`credential_rebound`).
- With the default `modern_only` policy the account must have a modern handle
  and the assertion may carry either no handle or a matching one.
- With the explicitly enabled `legacy_fallback` policy the assertion may carry
  no handle, the account's modern handle or the account's/credential's legacy
  handle. This is the compatibility rule for accounts whose handle has not
  been migrated to the new format. Legacy material is only accepted while the
  account or the credential is still stored in the legacy format; once both
  carry a modern handle, that modern handle remains authoritative. The policy
  is never enabled implicitly and never applies to the usernameless entry.

## What commit checks again

`commit` takes a fresh read of the credential and then the account. It rejects
the attempt with the following reasons:

| reason | meaning |
| --- | --- |
| `unknown_credential` | the credential record disappeared |
| `unknown_account` | the account record disappeared |
| `account_merged` | the account was merged into another account |
| `account_disabled` | the account is no longer active |
| `credential_disabled` | the credential itself was disabled |
| `credential_unbound` | the credential no longer belongs to any account |
| `credential_rebound` | the credential now belongs to a different account |
| `credential_changed` | the public key changed since verification |
| `handle_missing` / `handle_mismatch` | the current handle no longer satisfies the entry policy |
| `legacy_handle_not_allowed` | a legacy handle was used without the compatibility policy |
| `sign_count_replayed` | the assertion's sign count is not greater than the fresh stored count |
| `attempt_consumed` | the same attempt was already committed |

An `Attempt` can be committed at most once, so one assertion cannot mint two
sessions. A failed `commit` returns `Result#session_created? == false` and
never returns a `Principal`.

## Account read counts

`Attempt#account_reads` and `Result#account_reads` expose how many account
reads each phase performed. The contract always reads the account once during
verification and once during commit for a successful path, so integrators can
assert that the session decision was made from a read newer than the one used
for verification. The same applies to `credential_reads`.

## Executable example

`bin/account-binding-demo` uses an in-memory account store and locally
generated valid assertions. For each scenario it stops a successful passkey
verification right after the lookup callback returns, optionally changes the
account state, then commits and reports the result. The final table is:

```
scenario                               | entry         | verify                    | commit                    | principal | account reads (verify+commit=total)
---------------------------------------+---------------+---------------------------+---------------------------+-----------+------------------------------------
usernameless / stable                  | usernameless  | verified                  | session                   | alpha     | 1+1=2
usernameless / merged after callback   | usernameless  | verified                  | account_merged            | -         | 1+1=2
usernameless / unbound after callback  | usernameless  | verified                  | credential_unbound        | -         | 1+1=2
usernameless / disabled after callback | usernameless  | verified                  | account_disabled          | -         | 1+1=2
known / legacy policy enabled          | known_account | verified                  | session                   | beta      | 1+1=2
known / disabled after callback        | known_account | verified                  | account_disabled          | -         | 1+1=2
known / legacy policy disabled         | known_account | legacy_handle_not_allowed | legacy_handle_not_allowed | -         | 1+0=1
```

The `usernameless / stable` and `known / legacy policy enabled` rows are the
control flows: the correct account stays active and unmerged and the session
principal is the account behind the credential. In the other rows verification
still succeeds against the material read before the mutation, but commit
rejects the attempt because the fresh account read wins.

`spec/webauthn/account_binding/scenarios_spec.rb` asserts the same table as
part of the test suite.
