# Rack::Protection

This gem protects against typical web attacks.
Should work for all Rack apps, including Rails.

# Usage

Use all protections you probably want to use:

``` ruby
# config.ru
require 'rack/protection'
use Rack::Protection
run MyApp
```

Skip a single protection middleware:

``` ruby
# config.ru
require 'rack/protection'
use Rack::Protection, :except => :path_traversal
run MyApp
```

Use a single protection middleware:

``` ruby
# config.ru
require 'rack/protection'
use Rack::Protection::AuthenticityToken
run MyApp
```


## More examples

Enable host authorization with an explicit allowlist:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection::HostAuthorization,
  permitted_hosts: ['example.com', '.example.org']

run MyApp
```

Enable HTTPS-related headers in production only:

``` ruby
# config.ru
require 'rack/protection'

if ENV['RACK_ENV'] == 'production'
  use Rack::Protection::StrictTransport,
    max_age: 31_536_000, # 1 year
    include_subdomains: true
end

run MyApp
```

Customize CSP directives:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection::ContentSecurityPolicy,
  default_src: "'self'",
  script_src: ["'self'", 'https://cdn.example.com']

run MyApp
```

Disable more than one protection middleware:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection,
  except: [:path_traversal, :json_csrf]

run MyApp
```

Apply different protection profiles to different routes, e.g. keep the
full browser protections for pages while relaxing browser-specific
checks for non-browser webhook endpoints:

``` ruby
# config.ru
require 'rack/protection'

use Rack::Protection,
  # default profile: applied to every request that matches no rule
  except: [:path_traversal],
  profiles: {
    webhooks: {
      paths:   %w[/webhooks/stripe /webhooks/github], # exact paths
      methods: %w[POST],                              # optional method list
      options: { except: %i[http_origin remote_token json_csrf] }
    }
  }

run MyApp
```

Profile rules are matched against the literal `PATH_INFO` and
`REQUEST_METHOD` of the request, exactly as the downstream router sees
them at this point of the middleware stack:

* When the app is mounted under a prefix with `map`, declare paths
  relative to the mount point (the prefix is already stripped).
* No decoding or normalization is applied, so percent-encoded variants
  never match a declared path and fall through to the default profile.
* When `Rack::MethodOverride` sits upstream, the effective (overridden)
  method is matched, just like the router does.
* The first matching profile wins; its `options` are merged over the
  top-level options. Requests matching no rule use the default profile
  built from the top-level options alone.

All profile stacks are built once when the middleware is created and
cannot be changed afterwards. Note that profiles only choose which
protections apply -- they are not authentication. Webhook endpoints must
still verify their callers themselves (e.g. by checking a signature).


# Prevented Attacks

## DNS rebinding and other Host header attacks

* [`Rack::Protection::HostAuthorization`][host-authorization] (not included by `use Rack::Protection`)

## Cross Site Request Forgery

Prevented by:

* [`Rack::Protection::AuthenticityToken`][authenticity-token] (not included by `use Rack::Protection`)
* [`Rack::Protection::FormToken`][form-token] (not included by `use Rack::Protection`)
* [`Rack::Protection::JsonCsrf`][json-csrf]
* [`Rack::Protection::RemoteReferrer`][remote-referrer] (not included by `use Rack::Protection`)
* [`Rack::Protection::RemoteToken`][remote-token]
* [`Rack::Protection::HttpOrigin`][http-origin]

## Cross Site Scripting

Prevented by:

* [`Rack::Protection::EscapedParams`][escaped-params] (not included by `use Rack::Protection`)
* [`Rack::Protection::XSSHeader`][xss-header] (Internet Explorer and Chrome only)
* [`Rack::Protection::ContentSecurityPolicy`][content-security-policy]

## Clickjacking

Prevented by:

* [`Rack::Protection::FrameOptions`][frame-options]

## Directory Traversal

Prevented by:

* [`Rack::Protection::PathTraversal`][path-traversal]

## Session Hijacking

Prevented by:

* [`Rack::Protection::SessionHijacking`][session-hijacking] (not included by `use Rack::Protection`)

## Cookie Tossing

Prevented by:

* [`Rack::Protection::CookieTossing`][cookie-tossing] (not included by `use Rack::Protection`)

## IP Spoofing

Prevented by:

* [`Rack::Protection::IPSpoofing`][ip-spoofing]

## Helps to protect against protocol downgrade attacks and cookie hijacking

Prevented by:

* [`Rack::Protection::StrictTransport`][strict-transport] (not included by `use Rack::Protection`)

# Installation

    gem install rack-protection

# Instrumentation

Instrumentation is enabled by passing in an instrumenter as an option.

```
use Rack::Protection, instrumenter: ActiveSupport::Notifications
```

The instrumenter is passed a namespace (String) and environment (Hash). The namespace is 'rack.protection' and the attack type can be obtained from the environment key 'rack.protection.attack'.

[authenticity-token]: http://www.sinatrarb.com/protection/authenticity_token
[content-security-policy]: http://www.sinatrarb.com/protection/content_security_policy
[cookie-tossing]: http://www.sinatrarb.com/protection/cookie_tossing
[escaped-params]: http://www.sinatrarb.com/protection/escaped_params
[form-token]: http://www.sinatrarb.com/protection/form_token
[frame-options]: http://www.sinatrarb.com/protection/frame_options
[host-authorization]: https://github.com/sinatra/sinatra/blob/main/rack-protection/lib/rack/protection/host_authorization.rb
[http-origin]: http://www.sinatrarb.com/protection/http_origin
[ip-spoofing]: http://www.sinatrarb.com/protection/ip_spoofing
[json-csrf]: http://www.sinatrarb.com/protection/json_csrf
[path-traversal]: http://www.sinatrarb.com/protection/path_traversal
[remote-referrer]: http://www.sinatrarb.com/protection/remote_referrer
[remote-token]: http://www.sinatrarb.com/protection/remote_token
[session-hijacking]: http://www.sinatrarb.com/protection/session_hijacking
[strict-transport]: http://www.sinatrarb.com/protection/strict_transport
[xss-header]: http://www.sinatrarb.com/protection/xss_header
