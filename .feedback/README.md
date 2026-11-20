# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null spec/rollbar/request_data_extractor_spec.rb
```

Measured on macOS in 2.351 seconds. Tests use local fixtures and require no external service.
