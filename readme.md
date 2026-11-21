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

### Commit Policies

By default, Rack sessions are committed whenever they are loaded or forced to
update, regardless of the application's response. Applications which stage
sensitive state (for example, a login or privilege change) can configure a
commit policy so the staged data is only persisted for the responses the
caller considers successful.

``` ruby
use Rack::Session::Pool,
  # Only persist staged data for 2xx and 3xx responses.
  commit_policy: Rack::Session::CommitPolicy.new(:success, :redirect)
```

The policy can combine the response family with a business marker:

``` ruby
use Rack::Session::Pool,
  commit_policy: {on: :success, require_business: true}
```

In the application, set the marker before returning:

``` ruby
def call(env)
  env['rack.session'][:pending_privilege] = :admin
  env['rack.session.business_success'] = operation_succeeded?
  [200, {}, ["done"]]
end
```

Supported inputs for `commit_policy` include:

- `:success`, `:redirect`, `:client_error`, `:server_error`, `:all`, `:none`,
  `:error`, a status code, a `Range` of status codes, or an array of these.
- A `Hash` of options, e.g. `{on: :success, require_business: true}`.
- A callable which receives a `Rack::Session::CommitContext`, or the pieces it
  needs (`env, status, headers, body, session, options`).
- `true` or `false` to always allow or always deny.

Per-request overrides are available:

``` ruby
env['rack.session.options'][:commit_policy] = :server_error
env['rack.session.commit_policy'] = :server_error
env['rack.session.commit'] = false # explicit deny (use true to force)
```

A business marker may also be expressed as an explicit failure:

``` ruby
env['rack.session.business_failure'] = true
```

When a policy is configured and the response body is streaming, the commit is
deferred until the body has been fully enumerated and closed. If enumeration or
close raises, the staged data is not committed.

The outcome is available without conflating business success and persistence:

``` ruby
result = env['rack.session.commit_result']
result.business_success? # what the application reported
result.committed?        # whether a write was attempted
result.persisted?        # whether the store accepted the data
```

The same information is mirrored in `env['rack.session.persisted']` and the
session options. When no policy is configured, the middleware keeps its
historical behaviour and does not add these keys.

### Compatibility

`rack-session` code used to be part of Rack, but it was extracted in Rack v3 to this gem. The v1 release of this gem is compatible with Rack v2, and the v2 release of this gem is compatible with Rack v3+. That means you can add `gem "rack-session"` to your application and it will be compatible with all versions of Rack.

## Contributing

We welcome contributions to this project.

1.  Fork it.
2.  Create your feature branch (`git checkout -b my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin my-new-feature`).
5.  Create new Pull Request.
