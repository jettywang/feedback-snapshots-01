# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -e 'ARGV.each { |path| require_relative path }' test/defaults_options_test.rb test/decorator_scope_test.rb
```

Measured on macOS in 0.407 seconds. Tests use local fixtures and require no external service.
