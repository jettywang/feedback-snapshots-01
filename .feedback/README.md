# Local preparation

Upstream: https://github.com/presidentbeef/brakeman
Pinned upstream: `4bfdad0c35f3bcedb7c5d97baba98c537e689bf2`

This commit contains environment preparation only. Application source is unchanged.

Use Ruby 3.3.12 and Bundler 4.0.16. Dependencies are locked in Gemfile.lock.

Fresh machine: `BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=.feedback/vendor bundle install`. Run commands through `.feedback/run.rb` so Bundler paths remain local.

Existing fast baseline (not a task solution):

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec /opt/homebrew/opt/ruby@3.3/bin/ruby -Ilib:test test/tests/checks.rb
```

Recorded exit code: 0. Local elapsed seconds: 2.007.
