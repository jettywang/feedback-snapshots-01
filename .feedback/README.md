# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -Iminitest -e 'Dir["minitest/*test.rb"].grep_v(/helper/).each { |path| require_relative(path) }'
```

Measured on macOS in 0.296 seconds. Tests use local fixtures and require no external service.
