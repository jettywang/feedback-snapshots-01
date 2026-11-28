# Local test setup

From the repository root, install the pinned gems and run the advisory, configuration and report baseline. The shared test helper uses an empty local database fixture for this focused set.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r ./.feedback/offline-spec-helper.rb spec/advisory_spec.rb spec/configuration_spec.rb spec/report_spec.rb
```

Focused baseline reports 60 examples on macOS in 0.845 seconds.

## Source policy regression

The source-policy regression uses a local synthetic advisory database, fixture
lockfiles, and a deterministic resolver. It does not need network access.

```sh
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r ./.feedback/offline-spec-helper.rb spec/source_policy_regression_spec.rb
```

The fixtures live under `spec/fixtures/source_policy/` and
`spec/bundle/source_policy_*`. Approved items and their reasons are recorded in
`spec/fixtures/source_policy/approvals/`.
