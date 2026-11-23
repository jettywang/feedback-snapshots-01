# Advanced Configuration

## Global vs Instance Based Configuration

Which approach suits best your needs will depend on the architecture of your application and how do your users need to register and authenticate to it.

If you have a multi-tenant application, or any application segmentation, where your users register and authenticate to each of these tenants or segments individually using different hostnames, or with different security needs, you need to go through [Instance Based Configuration](#instance-based-configuration).

However, if your application is served for just one hostname, or else if your users authenticate to only one subdomain (e.g. your application serves www.example.com and admin.example.com but all your users authenticate through auth.example.com) you can still rely on one [Global Configuration](../README.md#configuration).

If you are still not sure, or want to keep your options open, be aware that [Instance Based Configuration](#instance-based-configuration) is also a valid way of defining a single instance configuration and how you share such configuration across your application, it's up to you.


## Instance Based Configuration

Instead of the [Global Configuration](../README.md#configuration) you place in `config/initializers/webauthn.rb`,
 you can now have an on-demand instance of `WebAuthn::RelyingParty` with the same configuration options, that
 you can build anywhere in your application, in the following way:

```ruby
  relying_party = WebAuthn::RelyingParty.new(
    # This value needs to match `window.location.origin` evaluated by
    # the User Agent during registration and authentication ceremonies.
    # Multiple origins can be used when needed. Using more than one will imply you MUST configure rp_id explicitely. If you need your credentials to be bound to a single origin but you have more than one tenant, please see [our Advanced Configuration section](https://github.com/cedarcode/webauthn-ruby/blob/master/docs/advanced_configuration.md) instead of adding multiple origins.
    allowed_origins: ["https://admin.example.com"],

    # Relying Party name for display purposes
    name: "Admin Site for Example Inc."

    # Optionally configure a client timeout hint, in milliseconds.
    # This hint specifies how long the browser should wait for any
    # interaction with the user.
    # This hint may be overridden by the browser.
    # https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-timeout
    # credential_options_timeout: 300_000

    # You can optionally specify a different Relying Party ID
    # (https://www.w3.org/TR/webauthn/#relying-party-identifier)
    # if it differs from the default one.
    #
    # In this case the default would be "admin.example.com", but you can set it to
    # the suffix "example.com"
    #
    # id: "example.com"

    # Configure preferred binary-to-text encoding scheme. This should match the encoding scheme
    # used in your client-side (user agent) code before sending the credential to the server.
    # Supported values: `:base64url` (default), `:base64` or `false` to disable all encoding.
    #
    # encoding: :base64url

    # Possible values: "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "RS1"
    # Default: ["ES256", "PS256", "RS256"]
    #
    # algorithms: ["ES384"]
  )
```

## Instance Based API

The explanation for each ceremony can be found in depth in [Credential Registration](../README.md#credential-registration) and [Credential Authentication](../README.md#credential-authentication) but if you choose this instance based approach to define your WebAuthn configurations and assuming `relying_party` is the result of an instance you get through `WebAuthn::RelyingParty.new(...)` the code in those explanations needs to be updated to:

### Credential Registration

#### Initiation phase

```ruby
# Generate and store the WebAuthn User ID the first time the user registers a credential
if !user.webauthn_id
  user.update!(webauthn_id: WebAuthn.generate_user_id)
end

options = relying_party.options_for_registration(
  user: { id: user.webauthn_id, name: user.name },
  exclude: user.credentials.map { |c| c.external_id }
)

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:creation_challenge] = options.challenge

# Send `options` back to the browser, so that they can be used
# to call `navigator.credentials.create({ "publicKey": options })`
#
# You can call `options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: options` will just work.
# I.e. it will encode and convert the options to JSON automatically.

# For your frontend code, you might find @github/webauthn-json npm package useful.
# Especially for handling the necessary decoding of the options, and sending the
# `PublicKeyCredential` object back to the server.
```

#### Verification phase

```ruby
# Assuming you're using @github/webauthn-json package to send the `PublicKeyCredential` object back
# in params[:publicKeyCredential]:
begin
  webauthn_credential = relying_party.verify_registration(
    params[:publicKeyCredential],
    session[:creation_challenge]
  )

  # Store Credential ID, Credential Public Key and Sign Count for future authentications
  user.credentials.create!(
    external_id: webauthn_credential.id,
    public_key: webauthn_credential.public_key,
    sign_count: webauthn_credential.sign_count
  )
rescue WebAuthn::Error => e
  # Handle error
end
```

### Credential Authentication

#### Initiation phase

```ruby
options = relying_party.options_for_authentication(allow: user.credentials.map { |c| c.webauthn_id })

# Store the newly generated challenge somewhere so you can have it
# for the verification phase.
session[:authentication_challenge] = options.challenge

# Send `options` back to the browser, so that they can be used
# to call `navigator.credentials.get({ "publicKey": options })`

# You can call `options.as_json` to get a ruby hash with a JSON representation if needed.

# If inside a Rails controller, `render json: options` will just work.
# I.e. it will encode and convert the options to JSON automatically.

# For your frontend code, you might find @github/webauthn-json npm package useful.
# Especially for handling the necessary decoding of the options, and sending the
# `PublicKeyCredential` object back to the server.
```

#### Verification phase

```ruby
begin
  # Assuming you're using @github/webauthn-json package to send the `PublicKeyCredential` object back
  # in params[:publicKeyCredential]:
  webauthn_credential, stored_credential = relying_party.verify_authentication(
    params[:publicKeyCredential],
    session[:authentication_challenge]
  ) do |webauthn_credential|
    # the returned object needs to respond to #public_key and #sign_count
    user.credentials.find_by(external_id: webauthn_credential.id)
  end

  # Update the stored credential sign count with the value from `webauthn_credential.sign_count`
  stored_credential.update!(sign_count: webauthn_credential.sign_count)

  # Continue with successful sign in or 2FA verification...

rescue WebAuthn::SignCountVerificationError => e
  # Cryptographic verification of the authenticator data succeeded, but the signature counter was less than or equal
  # to the stored value. This can have several reasons and depending on your risk tolerance you can choose to fail or
  # pass authentication. For more information see https://www.w3.org/TR/webauthn/#sign-counter
rescue WebAuthn::Error => e
  # Handle error
end
```

## Site-scoped Credential Operations

When several sites (tenants, brands, subdomains) share a process, issuing
options from a live `WebAuthn::RelyingParty` and verifying later is fragile: the
instance (or the global configuration) may have been hot-reloaded in between.

`WebAuthn::RelyingParty#registration_operation` and
`WebAuthn::RelyingParty#authentication_operation` return a
`WebAuthn::CredentialOperation`: a self-contained record of one ceremony.

```ruby
# Issued by the site-specific relying party.
relying_party = WebAuthn::RelyingParty.new(
  allowed_origins: ["https://admin.example.com"],
  id: "example.com",
  name: "Admin"
)

operation = relying_party.registration_operation(
  user: { id: user.webauthn_user_handle, name: user.name },
  # Requirements requested now are enforced on verification, even if the
  # configuration is reloaded in the meantime.
  user_verification: true
)

session[:credential_operation] = operation.to_json
```

The operation captures, at issuance time:

- `allowed_origins`, the RP ID and the RP name
- the encoder implied by `encoding`
- the verification policy: algorithms, attestation policy, cross-origin policy
  and silent authentication
- the verification requirements (`user_presence`, `user_verification`)

Public key options issued by `registration_operation` and
`authentication_operation` carry the same challenge that the operation will
verify against, so storing the operation is enough to verify the callback.

None of those are read from the live instance during verification, so a hot
reload cannot silently change how an already-issued ceremony is decoded or
accepted. `operation.options` returns the same public-key options (with the
same challenge) that were sent to the browser.

### Verification, including asynchronous callbacks

The serialized operation can be rehydrated anywhere — another process, a job,
or a callback handler that has no access to the original instance:

```ruby
operation = WebAuthn::CredentialOperation.from_json(session[:credential_operation])

# Verification uses the issuance-time configuration.
webauthn_credential = operation.verify_registration(params[:publicKeyCredential])
```

`operation.diagnose(raw_credential)` explains what will actually happen:
decoded credential ID, client-data origin, whether the origin was allowed, the
RP ID hash comparison, the user handle, and the sign count. This is useful when
two sites produce similar-looking payloads.

### Continue or stop after a configuration change

`operation.compatibility_with(relying_party)` compares the issuance-time flow
with the current one:

```ruby
compatibility = operation.compatibility_with(relying_party)
compatibility.decision        # => :continue or :stop
compatibility.changed_fields  # => [] or [:allowed_origins, :encoding, ...]
compatibility.explain         # human-readable summary
```

Flow-defining changes (`allowed_origins`, RP ID, encoding, verification policy)
produce `:stop`; descriptive changes (RP name, timeout) produce `:continue`.
Pass the live configuration explicitly if you want a stop to be enforced:

```ruby
operation.verify_registration(raw_credential, against: relying_party)
# => raises WebAuthn::CredentialOperation::CompatibilityError
#    (error.compatibility has the details)
```

If the integration deliberately wants to finish an in-flight ceremony anyway,
use `on_change: :continue`. Each attempt is recorded in
`operation.verifications` / `operation.last_verification`, including the
decision, changed fields and the credential/user attribution:

```ruby
operation.verify_registration(raw_credential, against: relying_party, on_change: :continue)

operation.last_verification.to_h
# => {
#   kind: :registration, outcome: :verified, decision: :stop,
#   credential_id: "...", user_handle: nil, origin: "https://admin.example.com",
#   details: { changed_fields: [:allowed_origins], ... }
# }
```

Settings that are not part of the ceremony flow (the root-certificate finders,
for example) are not serialized. When rehydrating, pass them explicitly with
`WebAuthn::CredentialOperation.from_json(json, attestation_root_certificates_finders: [finder])`.

The snapshot also carries a SHA-256 `fingerprint` of the flow-defining fields
and an operation-level fingerprint (`operation.fingerprint`). Log either next to
each registration/authentication attempt to prove which site configuration was
applied. `operation.to_h`/`to_json` and `operation.explain` include both.

The compatibility-first API is additive: `options_for_registration`,
`options_for_authentication`, `verify_registration`, `verify_authentication` and
the global configuration keep working. Options built through
`options_for_*` also expose `.operation`, so the legacy-style code can record
which issuance configuration it is using.

## Moving from Global to Instance Based Configuration

Adding a configuration for a new instance does not mean you need to get rid of your Global configuration. They can co-exist in your application and be both available for the different usages you might have. `WebAuthn.configuration.relying_party` will always return the global one while `WebAuthn::RelyingParty.new`, executed anywhere in your codebase, will allow you to create a different instance as you see the need. They will not collide and instead operate in isolation without any shared state.

The gem API described in the current [Usage](../README.md#usage) section for the [Global Configuration](../README.md#configuration) approach will still be valid but the [Instance Based API](#instance-based-api) also works with the global `relying_party` that is maintained globally at `WebAuthn.configuration.relying_party`.
