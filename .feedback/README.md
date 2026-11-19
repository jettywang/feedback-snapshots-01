# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -e 'ARGV.each { |path| require_relative path }' test/spec_session_cookie.rb test/spec_session_encryptor.rb test/spec_session_pool.rb
```

Measured on macOS in 0.345 seconds. Tests use local fixtures and require no external service.
