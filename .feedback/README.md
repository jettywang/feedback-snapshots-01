# Local preparation

Upstream: https://github.com/net-ssh/net-ssh
Pinned upstream: `348b78049bfe815d4c4e46d3d0185f3b9fd88978`

This commit contains environment preparation only. Application source is unchanged.

Use Ruby 3.3.12 and Bundler 4.0.16. Dependencies are locked in Gemfile.lock.

Fresh machine: `BUNDLE_GEMFILE=.feedback/Gemfile BUNDLE_PATH=.feedback/vendor bundle install`. Run commands through `.feedback/run.rb` so Bundler paths remain local.

Existing fast baseline (not a task solution):

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec /opt/homebrew/opt/ruby@3.3/bin/ruby -Ilib:test test/transport/test_packet_stream.rb
```

Recorded exit code: 0. Local elapsed seconds: 0.825.
