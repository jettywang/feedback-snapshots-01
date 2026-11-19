# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -e 'ARGV.each { |path| require_relative path }' test/action_policy/policy/base_test.rb test/action_policy/policy/cache_test.rb test/action_policy/policy/pre_check_test.rb
```

Measured on macOS in 0.415 seconds. Tests use local fixtures and require no external service.
