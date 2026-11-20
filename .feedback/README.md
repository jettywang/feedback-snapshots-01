# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -e 'ARGV.each { |path| require_relative path }' test/unit/serializer_test.rb test/unit/response_test.rb test/unit/transport_base_test.rb
```

Measured on macOS in 2.167 seconds. Tests use local fixtures and require no external service.
