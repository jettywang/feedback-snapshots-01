# Local test setup

From the repository root, install the pinned gems and run the advisory, configuration and report baseline. The shared test helper uses an empty local database fixture for this focused set.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r ./.feedback/offline-spec-helper.rb spec/advisory_spec.rb spec/configuration_spec.rb spec/report_spec.rb spec/approval_spec.rb spec/exemption_identity_spec.rb
```

Focused baseline reports 93 examples on macOS in 0.845 seconds.
