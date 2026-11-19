# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest test/adapters/memory_test.rb
```

Measured on macOS in 0.247 seconds. Tests use local fixtures and require no external service.
