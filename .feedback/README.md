# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -Iminitest -e 'ARGV.each { |path| require_relative path }' minitest/test_webmock.rb minitest/webmock_spec.rb
```

Measured on macOS in 0.740 seconds. Tests use local fixtures and require no external service.
