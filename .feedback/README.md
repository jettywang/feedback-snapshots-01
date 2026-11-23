# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib .feedback/offline-test.rb
```

Measured on macOS in 0.950 seconds. Tests use local fixtures and require no external service.
