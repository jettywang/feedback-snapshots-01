# Backup Attributes and Action Policy

WebAuthn authenticators report two backup flags in the authenticator data:

- `BE` (backup eligibility): the credential can be synchronized to another device. This is a stable property of the credential.
- `BS` (backup state): the credential is currently backed up. This can change between ceremonies.

They describe different things. Registration should persist the `BE` value observed at registration time. Authentication should use the `BE` value stored with the credential, and only update the stored `BS` value from the new observation. Do not infer that a mutable `BS` value makes a synced credential equivalent to a device-bound one.

## Policy

`WebAuthn::BackupPolicy` classifies actions and applies the following rules.

| Credential evidence | Daily actions (`:login`) | Sensitive actions (`:financial`) |
| --- | --- | --- |
| Device-bound (`BE=false`) | Approved | Approved |
| Synced (`BE=true`) | Approved | Rejected |
| Legacy record with no stored flags | Approved | Rejected |
| `BS=true` observed while stored `BE=false` | Rejected | Rejected |
| Stored `BE` and observed `BE` disagree | Rejected | Rejected |

Legacy rows are treated with the daily policy only. A single authentication does not promote their entire history to a trusted state, and a late or parallel response cannot rewrite the conclusion.

The defaults can be adjusted for action names, at policy construction:

```ruby
policy = WebAuthn::BackupPolicy.new(
  daily_actions: [:login, :profile_update],
  sensitive_actions: [:financial, :credential_delete],
  legacy_actions: [:login]
)
```

## Registration and authentication

`WebAuthn::BackupCredentialManager` wraps relying-party verification with a versioned credential store:

```ruby
manager = WebAuthn::BackupCredentialManager.new(
  relying_party: relying_party,
  store: WebAuthn::InMemoryCredentialStore.new,
  policy: WebAuthn::BackupPolicy.new
)

registration = manager.register(
  params[:publicKeyCredential],
  session[:creation_challenge],
  requested_actions: [:login, :financial]
)

# registration.approved_actions => [:login]
# registration.version => 1
# registration.basis => :synced_registration
```

At authentication, pass what should be authorized:

```ruby
authentication = manager.authenticate(
  params[:publicKeyCredential],
  session[:authentication_challenge],
  requested_actions: [:login, :financial]
)
```

The receipt contains only the approved actions, the committed store version, and the basis for the decision. A credential that is eligible but not yet backed up cannot be used for financial actions; it can still be used for daily actions.

## Migrating legacy credentials

Credentials stored before backup flags were available can be loaded explicitly:

```ruby
manager.migrate(
  id: credential.webauthn_id,
  public_key: credential.public_key,
  sign_count: credential.sign_count,
  # Omit both values only when the source genuinely has no backup evidence.
  # backup_eligible: nil,
  # backup_state: nil,
  requested_actions: [:login, :financial]
)
```

Passing `backup_eligible` and `backup_state` records trusted evidence and allows the normal policy to apply. Leaving both unset records an explicitly unknown legacy row that remains on the daily policy until stronger evidence is stored.

## Concurrent authentications

`authenticate` accepts an optional `snapshot:` captured before verification. The store commits with an optimistic version check. If a newer authentication already advanced the version, the late response returns:

```ruby
# { approved_actions: [], version: 2, basis: :stale_observation }
```

The stale response cannot overwrite a newer confirmed backup state or sign count. The store also refuses to lower a stored sign count.

## FakeClient coverage

The specs use `WebAuthn::FakeClient` and `WebAuthn::InMemoryCredentialStore` to cover the three paths:

- a legacy row without stored flags, which stays on the daily policy;
- a synced credential whose `BS` changes from backed up to not backed up;
- two parallel authentications whose responses arrive in reverse order, where the older response is rejected.

`FakeClient#create` and `FakeClient#get` expose `backup_eligibility:` and `backup_state:`, so both flags can be driven independently in tests.
