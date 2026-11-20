# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null --pattern 'spec/**/*_spec.rb'
```

Measured on macOS in 0.885 seconds. Tests use local fixtures and require no external service.
