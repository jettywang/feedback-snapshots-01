# Response Header Splitting

Response (header) splitting is possible when attacker-controlled data
containing carriage return (`\r`) or line feed (`\n`) characters is written
to an HTTP response header. The newlines are interpreted as the end of the
header, allowing an attacker to inject additional headers or an entirely
forged response.

This check uses data flow analysis to track request data — parameters,
cookies, and `request.env` header values — into the final response headers
through:

```ruby
response.headers["X-Header"] = value
headers["X-Header"] = value
response.set_header("X-Header", value)
response.headers.merge!("X-Header" => value)
```

Local and instance variable aliases of the response header hash are
followed, so assigning through an alias is detected as well.

Header names and header values are analyzed separately. A header name built
from request data is treated the same as a tainted header value.

## What is not a warning

The check stays quiet when CR/LF characters are provably removed or the
request is rejected before the assignment.

Filtering that removes both carriage returns and line feeds, including
filters spread across a chain or followed by safe string methods, is
recognized:

```ruby
response.headers["X"] = params[:value].to_s.gsub(/[\r\n]/, "")
response.headers["X"] = params[:value].delete("\r\n")
response.headers["X"] = params[:value].gsub(/\R/, "").upcase
response.headers["X"] = params[:value].to_s.split(/[\r\n]/).join(" ")
```

Rejecting the request when the value contains a newline is also recognized:

```ruby
raw = params[:value]
raise "invalid" if raw =~ /[\r\n]/
response.headers["X"] = raw
```

Filtering that does not remove CR/LF (for example `strip`, or a `gsub` with
an unrelated pattern) does not make the assignment safe. Sanitizing or
validating a different variable does not protect the value actually assigned,
and the last assignment to a variable determines whether it is tainted.

Constants and values with no request-derived data never produce a warning.

Note that this check analyzes self-constructed raw header assignments. Rails
version-level protections (where the framework itself rejects newlines) are
covered by the separate response splitting CVE checks rather than by
generalizing over same-named methods.
