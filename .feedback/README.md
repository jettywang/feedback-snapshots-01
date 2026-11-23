# Local test setup

From the repository root, install the pinned dependencies and run the focused local baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec env -u CI ruby -Ilib -Itest -e 'ARGV.each { |path| require_relative path }' test/test_macho.rb test/test_fat.rb test/test_create_load_commands.rb
```

Measured on macOS in 0.463 seconds. Tests use local fixtures and require no external service.
