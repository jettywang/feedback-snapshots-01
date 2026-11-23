# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null spec/advisory_spec.rb spec/configuration_spec.rb spec/report_spec.rb
```

Measured on macOS in 3.665 seconds. Tests use local fixtures and require no external service.
