# Local preparation

Upstream: https://github.com/rubysec/bundler-audit
Pinned upstream: `14ffd143663fb0f154dbd749b831689c4056722f`

This commit contains environment preparation only. Application source is unchanged.

Use Ruby 3.3.12 and Bundler 4.0.16. Dependencies are locked in Gemfile.lock.

Fresh machine: `BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=.feedback/vendor bundle install`. Run commands through `.feedback/run.rb` so Bundler paths remain local.

Offline advisory fixture: https://github.com/rubysec/ruby-advisory-db at `89cdde9a725bb6f8a483bca97c5da344e060ac61`; tests expect it at spec/fixtures/database. The prepared local workspace has an independent copy.

Existing fast baseline (not a task solution):

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec rspec -Ilib spec/advisory_spec.rb --format progress
```

Recorded exit code: 0. Local elapsed seconds: 0.554.
