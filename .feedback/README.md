# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Ispec -e 'ARGV.each { |path| require_relative path }' spec/plugin/route_csrf_spec.rb spec/plugin/sessions_spec.rb spec/plugin/header_matchers_spec.rb spec/plugin/host_routing_spec.rb spec/plugin/public_spec.rb
```

Measured on macOS in 0.398 seconds. Tests use local fixtures and require no external service.
