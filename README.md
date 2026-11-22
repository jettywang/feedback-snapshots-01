# Warden

[![Build Status](https://github.com/wardencommunity/warden/workflows/Tests/badge.svg?branch=master)](https://github.com/wardencommunity/warden/actions)

## Getting Started

Please see the [Warden Wiki](https://github.com/wardencommunity/warden/wiki) for overview documentation.

## Authentication levels

Strategies may declare the level of verification they perform. Ordinary logins
are level 1; a strategy can raise it when it performs a stronger check:

```ruby
Warden::Strategies.add(:password) do
  authentication_level 1 # the default when not declared

  def authenticate!
    success!(user)
  end
end

Warden::Strategies.add(:reauthenticate) do
  authentication_level 2

  def authenticate!
    success!(user) # or success!(user, nil, :level => 2) for a one-off level
  end
end
```

The level that produced a session is stored alongside it
(`warden.user.<scope>.level`) and restored on later requests. Protect a
sensitive action by requiring a minimum level:

```ruby
env['warden'].authenticate!(:reauthenticate, :min_level => 2)
env['warden'].authenticated?(:default, :min_level => 2) # no strategies run
env['warden'].authentication_level                      # current level, or nil
```

Behaviour worth knowing:

- A session that already meets `:min_level` is reused without running strategies.
- A session below `:min_level` is offered to the strategies for elevation. If
  elevation does not reach the level, the call returns failure, `#message`
  explains the shortfall, and the existing session is left unchanged.
- Sessions written before levels existed report
  `Warden::UNKNOWN_AUTHENTICATION_LEVEL` (0): they still work for ordinary
  authentication but never satisfy a positive `:min_level`.
- `logout` removes the stored level with the user.

## Maintainers

* Daniel Neighman (hassox)
* José Valim (josevalim)
* Justin Smestad (jsmestad)
* Whitney Smestad (whithub)

[A list of all contributors is available on Github.](https://github.com/hassox/warden/contributors)

## LICENSE

See `LICENSE` file.
