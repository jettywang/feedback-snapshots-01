# Rack::Session

Session management implementation for Rack.

[![Development Status](https://github.com/rack/rack-session/workflows/Test/badge.svg)](https://github.com/rack/rack-session/actions?workflow=Test)

## Usage

In your `config.ru`:

``` ruby
# config.ru

require 'rack/session'
use Rack::Session::Cookie,
  :domain => 'mywebsite.com',
  :path => '/',
  :expire_after => 3600*24,
  :secret => '**unique secret key**'
```

Usage follows the standard outlined by `rack.session`, i.e.:

``` ruby
class MyApp
  def call(env)
    session = env['rack.session']

    # Set some state:
    session[:key] = "value"
  end
end
```

### Rotating a session

When a session's privilege level changes, for example when an ordinary user is
elevated to an administrative session after an extra confirmation, rotate the
session instead of reusing it. `SessionHash#rotate!` issues a new session
identifier, retires the previous one, and migrates only the keys the caller
explicitly declares:

``` ruby
class MyApp
  def call(env)
    session = env['rack.session']

    if env['PATH_INFO'] == '/elevate' && confirmed?(env)
      # Keep only non-sensitive preferences across the privilege change:
      session.rotate!(keys: ['locale'])
      session['user_id'] = current_user.id
      session['role'] = 'admin'
    end
  end
end
```

Every other key, including any previous authorization data, is discarded. The
same keys may be declared with the `keys:`, `keep:`, `migrate:`, `allow:` or
`only:` keyword; passing no keys discards all session data. `session_id` is
never migrated.

The previous identifier is retired before the replacement is written:

- `Rack::Session::Pool` removes the old record atomically, so a request still
  holding the old cookie reads an empty session.
- `Rack::Session::Cookie` records the retired identifier and rejects cookies
  carrying it, and refuses to write a request that still holds the retired
  identifier (for example a request that loaded the session before the
  rotation but commits afterwards). Revoked identifiers are remembered in
  memory; the `:max_revoked_sessions` option controls the bound (default
  `10_000`).

If the rotation cannot be completed (for example because the identifier was
already retired), `Rack::Session::Abstract::RotationError` is raised and the
session is left untouched.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
