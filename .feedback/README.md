# Local test setup

From the repository root, install the pinned dependencies and run the focused upstream baseline.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r grape-entity -r ./spec/spec_helper spec/grape_entity/options_spec.rb
```

Measured on macOS in 4.614 seconds. Tests use local fixtures and require no external service.
