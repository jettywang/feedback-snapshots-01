# Local preparation

Upstream: https://github.com/cedarcode/webauthn-ruby
Commit: 3e44a002b80cc89427ed98d9fb72c69b78b6571d
Runtime: Ruby 3.3.12. Application source and existing tests are unchanged.

Install the locked runtime and test dependencies:

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb install
```

Run the existing fast baseline:

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec rspec -Ilib spec/webauthn/authenticator_assertion_response_spec.rb
```

The selected upstream tests passed in 1.79 seconds on the preparation host. This is a baseline, not an acceptance test or a solution to a future task. The complete output and its hash are kept in batch preparation evidence. No external service is required by the baseline.

The preparation host copies the already installed locked gems into each independent workspace before `bundle check`. No dependency directory is shared by the question workspaces. A fresh host can use the install command above. `.feedback/run.rb` only selects this checkout’s Gemfile, gem directory and the current Ruby executable.
