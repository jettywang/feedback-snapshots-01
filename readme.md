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

### Server-side retention

`Rack::Session::Pool` can discard sessions stored on the server after two
kinds of time limits:

``` ruby
use Rack::Session::Pool,
  :idle_timeout => 3600,        # sliding window, renewed on every access
  :absolute_timeout => 86400,   # fixed maximum lifetime from creation
  :legacy_sessions => :backfill # or :reject
```

Sessions stored before retention was enabled carry no timing information.
They can either be cautiously rejected (`:reject`) or gradually stamped with
the current time as they are accessed (`:backfill`, the default). A `:clock`
option accepting a callable is available for testing.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
