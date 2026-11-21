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

### Partitioned sessions

Some applications are embedded into a partner page, and the session used while
embedded has a different owner than the session used when the site is opened
directly. An optional partition strategy lets the same middleware keep those
sessions apart and lets the application say exactly which session to issue or
expire:

``` ruby
use Rack::Session::Cookie,
  :secrets => '**unique secret key**',
  # Select the partition for each request. Return nil for the ordinary site.
  :partition => lambda {|request| request.path_info.start_with?('/embed') ? :embedded : nil},
  # Cookie attributes for each named partition. A named partition defaults to
  # Partitioned, Secure and SameSite=None.
  :partitions => {
    :embedded => {:partitioned => true, :secure => true, :same_site => :none}
  }
```

Each named partition gets its own cookie (`rack.session.embedded` by default,
or a `:key` you declare), so the direct and embedded sessions never overwrite
each other. Only a named partition receives the `Partitioned` attribute; the
ordinary session is never partitioned.

Inside the application, `env['rack.session'].partition` reports the current
partition, and `expire!` clears exactly one of them:

``` ruby
env['rack.session'].expire!             # clear the current partition
env['rack.session'].expire!(:embedded)  # clear only the embedded session
```

The session data records its partition, so a cookie from one partition is not
accepted by another. `:partition` may be a Symbol for a fixed partition,
`:auto` to detect cross-site embeds from `Sec-Fetch-Site`, or a callable
receiving the request. A request can override the strategy with
`env['rack.session.partition']`.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
