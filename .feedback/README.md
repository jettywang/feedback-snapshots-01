# Local preparation

Upstream: https://github.com/WinRb/WinRM
Pinned upstream: `83d57d2062007e75a66b9120cfd4b50ac0946076`

This commit contains environment preparation only. Application source is unchanged.

Use Ruby 3.3.12 and Bundler 4.0.16. Dependencies are locked in Gemfile.lock.

Fresh machine: `BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=.feedback/vendor bundle install`. Run commands through `.feedback/run.rb` so Bundler paths remain local.

Existing fast baseline (not a task solution):

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec rspec -Ilib:tests/spec --require ./tests/spec/spec_helper.rb tests/spec/wsmv/receive_response_reader_spec.rb tests/spec/wsmv/command_output_decoder_spec.rb --format progress
```

Recorded exit code: 0. Local elapsed seconds: 2.109.
