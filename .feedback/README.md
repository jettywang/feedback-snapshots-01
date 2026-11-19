# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec ruby -Ilib -Ispec -e 'ARGV.each { |path| require_relative path }' spec/graphql/analysis/query_complexity_spec.rb spec/graphql/authorization_spec.rb spec/graphql/schema/visibility_spec.rb
```

Measured on macOS in 1.187 seconds. Tests use local fixtures and require no external service.
