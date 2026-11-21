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

### Rotating the secret and cookie format

`Rack::Session::Cookie` supports an explicit read/write rotation policy for
releases that change both the session secret and the cookie format. New
cookies are always written in the current format (encrypted with the first of
`:secrets`); legacy HMAC cookies are only read, and only until the
`:legacy_hmac_until` deadline. After the deadline, legacy cookies are
rejected and only the current format is accepted:

``` ruby
use Rack::Session::Cookie,
  :secrets => [new_secret],
  :legacy_hmac_secret => old_secret,
  :legacy_hmac_until => Time.utc(2027, 1, 1)
```

For each request, the handling of the presented cookie is recorded in
`env['rack.session.rotation']` (`:current`, `:legacy`, `:legacy_expired`,
`:invalid` or `:none`), so applications can observe and log how old cookies
were treated during the rotation window.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
