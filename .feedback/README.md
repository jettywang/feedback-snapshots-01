# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r grape -r ./spec/spec_helper spec/grape/router/route_spec.rb spec/grape/request_spec.rb spec/grape/endpoint/options_spec.rb
```

Measured on macOS in 4.362 seconds. Tests use local fixtures and require no external service.
