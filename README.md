# Warden

[![Build Status](https://github.com/wardencommunity/warden/workflows/Tests/badge.svg?branch=master)](https://github.com/wardencommunity/warden/actions)

## Getting Started

Please see the [Warden Wiki](https://github.com/wardencommunity/warden/wiki) for overview documentation.

## Maintainers

* Daniel Neighman (hassox)
* José Valim (josevalim)
* Justin Smestad (jsmestad)
* Whitney Smestad (whithub)

[A list of all contributors is available on Github.](https://github.com/hassox/warden/contributors)

## LICENSE

See `LICENSE` file.

## Restricted failure applications

A failure application that is maintained outside the trusted application (for
example a public login-failure page) can be configured per manager with
`restricted_failure_app`. It receives a separate Rack environment containing
only the metadata needed to build a response and a frozen
`Warden::FailureContext` under `env['warden.failure']`:

```ruby
Warden::Manager.new(app) do |config|
  config.restricted_failure_app = public_failure_page
  config.approved_return_paths = ["/staff", %r{\A/orders/}] # optional
end
```

When both are configured, the restricted failure app takes precedence for
failures and the full failure app is not invoked. The context exposes only `action`,
`category` and `return_to`.
`before_failure` callbacks still run first with the complete Rack environment
and options hash; a callback can select a safe `:failure_category` (for example
`:account_locked`) but other keys it adds are not copied to the page. The
existing `failure_app` contract is unchanged and still receives the full
environment. The same is true for a strategy's `:custom` and `:redirect`
responses, which never reach the restricted failure app.
