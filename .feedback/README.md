# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r ./spec/spec_helper spec/integration/contract/call_spec.rb
```

Measured on macOS in 0.953 seconds. Tests use local fixtures and require no external service.
