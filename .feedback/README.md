# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null spec/controllers/sorcery_controller_session_timeout_spec.rb
```

Measured on macOS in 8.341 seconds. Tests use local fixtures and require no external service.
