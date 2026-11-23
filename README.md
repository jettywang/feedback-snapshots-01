# Warden

[![Build Status](https://github.com/wardencommunity/warden/workflows/Tests/badge.svg?branch=master)](https://github.com/wardencommunity/warden/actions)

## Getting Started

Please see the [Warden Wiki](https://github.com/wardencommunity/warden/wiki) for overview documentation.

## Callbacks across mounted applications

A process can mount several Rack applications, each with its own
`Warden::Manager` (for example an employee entry point and an external one).

* Callbacks registered directly on `Warden::Manager` are **global** and are the
  only callbacks shared between applications. Register a callback here only when
  it is explicitly approved for cross-application use.
* Callbacks declared inside a manager's configuration block are **local** to
  that application and never run for another application:

  ```ruby
  use Warden::Manager do |config|
    config.on_request { |proxy| # runs only for this application }
  end
  ```

For every callback kind the effective chain for a request runs, in order:

1. the global (shared) callbacks in their order of declaration, then
2. the application's own callbacks in their order of declaration.

`prepend_*` only reorders within the application layer, so a local callback can
never run ahead of a global one. Scope/event conditions are applied on top of
this ordering.

Each request captures (and freezes) its callback chains and configuration when
the proxy is created. Removing a callback or changing a default strategy while a
request is already in flight therefore does not change the flow that request
selected; the change applies to later requests. With nested Rack mounts, the
outermost warden manager owns the request and its callbacks, and an inner warden
manager defers to it.


## Maintainers

* Daniel Neighman (hassox)
* José Valim (josevalim)
* Justin Smestad (jsmestad)
* Whitney Smestad (whithub)

[A list of all contributors is available on Github.](https://github.com/hassox/warden/contributors)

## LICENSE

See `LICENSE` file.
