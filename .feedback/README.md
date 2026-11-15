# Local preparation

Upstream: https://github.com/SAML-Toolkits/ruby-saml
Commit: 7c7dccd3c18768e54b6fc56522d6d5d8dfb79bd8
Runtime: Ruby 3.3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb install
```

Run the existing fast baseline:

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec /opt/homebrew/opt/ruby@3.3/bin/ruby -I.feedback/support:lib:test test/response_test.rb
```

The selected upstream tests passed in 1.634 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.

The preparation host copies the already installed locked gems into each independent workspace before `bundle check`. No dependency directory is shared by the question workspaces. A fresh host can use the install command above. `.feedback/run.rb` only selects this checkout’s Gemfile, gem directory and the current Ruby executable.

The upstream test helper still requires `mocha/setup`; `.feedback/support/mocha/setup.rb` maps that compatibility name to the installed `mocha/minitest` adapter. No test assertion is removed or skipped. The baseline runs the full Response suite.
