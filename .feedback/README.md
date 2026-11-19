# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib spec/webauthn/relying_party_spec.rb spec/webauthn/authenticator_data_spec.rb spec/webauthn/public_key_credential_with_assertion_spec.rb
```

Measured on macOS in 1.459 seconds. Tests use local fixtures and require no external service.
