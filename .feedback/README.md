# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib spec/warden/manager_spec.rb spec/warden/proxy_spec.rb spec/warden/session_serializer_spec.rb spec/warden/hooks_spec.rb
```

Measured on macOS in 0.339 seconds. Tests use local fixtures and require no external service.
