# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Itest -Itest/lib -e 'ARGV.each { |path| require_relative path }' test/net/ftp/test_mlsx_entry.rb test/net/ftp/test_buffered_socket.rb
```

Measured on macOS in 0.290 seconds. Tests use local fixtures and require no external service.
