# Local preparation

Upstream: https://github.com/rapid7/ruby_smb
Pinned upstream: `b303067d412eb18994260573030b0ba3c69e263e`

This commit contains environment preparation only. Application source is unchanged.

Use Ruby 3.3.12 and Bundler 4.0.16. Dependencies are locked in Gemfile.lock.

Fresh machine: `BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=.feedback/vendor bundle install`. Run commands through `.feedback/run.rb` so Bundler paths remain local.

Existing fast baseline (not a task solution):

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec rspec -Ilib spec/lib/ruby_smb/smb2/negotiate_context_spec.rb spec/lib/ruby_smb/smb2/packet/transform_header_spec.rb --format progress
```

Recorded exit code: 0. Local elapsed seconds: 1.527.
