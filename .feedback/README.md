# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r ./spec/spec_helper spec/formatters/json_spec.rb spec/formatters/raw_spec.rb
```

Measured on macOS in 1.959 seconds. Tests use local fixtures and require no external service.
