# Local test setup

From the repository root, install the pinned gems and run the advisory, configuration and report baseline. The shared test helper uses an empty local database fixture for this focused set.

```sh
BUNDLE_FROZEN=true .feedback/bundle-env install --quiet
.feedback/bundle-env exec rspec -Ilib -Ispec --options /dev/null -r ./.feedback/offline-spec-helper.rb spec/advisory_spec.rb spec/configuration_spec.rb spec/report_spec.rb
```

Focused baseline reports 60 examples on macOS in 0.845 seconds.

## Release-task migration demo

The four release-pipeline scenarios (finding, trusted offline clean scan,
database identity changing during update, failed report delivery) run fully
offline against local lockfiles, git advisory databases and output doubles:

```sh
sh .feedback/demo/run_all.sh
```

The script rebuilds the fixtures via `demo/setup_demo.rb`, runs each scenario
through `Bundler::Audit::ReleaseTask` via `demo/run_scenarios.rb`, then runs
`spec/release_task_spec.rb`. Because the sandbox forbids nested `.git/`
directories inside the workspace, each advisory database keeps its git
metadata under `$TMPDIR` and exposes it through a `.git` symlink in the
worktree. See `release-task-migration.md` for the migration path and the
exit-code decision table.
