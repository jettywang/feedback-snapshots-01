# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -r ./test/test_helper -e 'ARGV.each { |path| require_relative path }' test/request_store_test.rb test/middleware_test.rb
```

Measured on macOS in 0.268 seconds. Tests use local fixtures and require no external service.
