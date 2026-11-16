# Local preparation

Upstream: https://github.com/sinatra/sinatra
Pinned upstream: `cb22afd7902b566b6eaba6c4ea89739494a65d12`

This commit contains environment preparation only. Application source is unchanged.

Use Ruby 3.3.12 and Bundler 4.0.16. Dependencies are locked in Gemfile.lock.

Fresh machine: `BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=.feedback/vendor bundle install`. Run commands through `.feedback/run.rb` so Bundler paths remain local.

Existing fast baseline (not a task solution):

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec rspec -Irack-protection/lib:rack-protection/spec --require ./rack-protection/spec/spec_helper.rb rack-protection/spec/lib/rack/protection/host_authorization_spec.rb --format progress
```

Recorded exit code: 0. Local elapsed seconds: 0.286.
