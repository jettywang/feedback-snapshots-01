# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -Itest/lib -e 'ARGV.each { |path| require_relative path }' test/net/http/test_http_request.rb test/net/http/test_httpresponse.rb
```

Measured on macOS in 0.348 seconds. Tests use local fixtures and require no external service.
