# Warden

[![Build Status](https://github.com/wardencommunity/warden/workflows/Tests/badge.svg?branch=master)](https://github.com/wardencommunity/warden/actions)

## Getting Started

Please see the [Warden Wiki](https://github.com/wardencommunity/warden/wiki) for overview documentation.

## Scope inheritance

Each scope normally keeps its own session and runs its own strategies. Some
applications need a lower-privilege scope to reuse an identity established by
another scope (for example a customer-service scope confirming an employee's
ordinary identity) while leaving a privileged scope, such as a back-office
scope, independently verified.

Scope inheritance is opt-in and directional. Declare it while configuring
`Warden::Manager`:

```ruby
use Warden::Manager do |config|
  # :support may reuse the :default identity; :admin is never inherited
  config.inherit_scope :support, :default

  # several rules at once, or with the :from option
  config.inherit_scope :auditor => :admin
  config.inherit_scope :support, :from => :default
end
```

For any request, a scope always consults its own session first. Only when that
is empty does Warden walk the declared inheritance chain, resolving each source
scope through its own session and deserialization. If nothing resolves, the
scope runs its own strategies as usual. Inheritance is read-only: reusing an
identity never writes, renews, or clears any source scope's session, and scopes
without a rule behave exactly as before.

Malformed rules (unknown/blank scopes, self-inheritance) and inheritance cycles
raise `Warden::InvalidScopeInheritance` while Warden is configured, with a
message describing the offending scope.

## Maintainers

* Daniel Neighman (hassox)
* José Valim (josevalim)
* Justin Smestad (jsmestad)
* Whitney Smestad (whithub)

[A list of all contributors is available on Github.](https://github.com/hassox/warden/contributors)

## LICENSE

See `LICENSE` file.
