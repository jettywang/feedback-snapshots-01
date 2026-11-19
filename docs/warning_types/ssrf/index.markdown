# Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) occurs when an application makes an
outbound HTTP request to a URL that an attacker can influence. The attacker
may be able to direct the request at internal services, cloud metadata
endpoints (such as `http://169.254.169.254`), loopback addresses, or arbitrary
hosts, and then read or exfiltrate the response.

Brakeman reports SSRF when user-controlled input (parameters, cookies, or
request headers) reaches an identifiable HTTP or `open-uri` call, for example
`Net::HTTP`, `URI.open`/`URI.read`, `open`, `HTTParty`, `Faraday`, or
`RestClient`.

## Which Part of the URL Is Controlled?

The warning message states which part of the URL the input can reach:

* Input that can supply or replace the **scheme and/or host** is reported with
  high confidence, because the request can be redirected to an arbitrary
  destination:

      Net::HTTP.get(URI.parse(params[:target]))
      open(params[:url])
      Faraday.new(url: params[:target])

* Input that only reaches the **path, query string, or fragment** of a URL
  whose scheme and host are fixed in source is reported with weak confidence.
  The authority cannot be replaced, but the value may still reach unexpected
  routes on the fixed host:

      Net::HTTP.get(URI("https://api.internal.example.com/v1/#{params[:id]}"))

A literal prefix that merely looks like a domain is not treated as a fixed
authority. For example, `"//#{params[:host]}/callback"` is scheme-relative and
leaves the host under user control, and interpolation inside the userinfo or
host portion of an otherwise absolute URL is still considered controllable.

`URI.join` is handled conservatively: a user-controlled later argument can be
an absolute URL that replaces the base authority, which cannot be ruled out
statically.

## Scope and Limitations

This is a source-to-sink data flow check with intentional limits:

* Only HTTP/`open-uri` calls Brakeman can recognize syntactically are examined.
* Values returned by helper methods are followed when the method is in scope,
  but resolution is bounded; deeply dynamic or metaprogrammed URLs may not be
  traced.
* The check does not prove how a string is parsed at runtime, whether a client
  follows redirects, or what a host name resolves to via DNS. It therefore does
  not claim that a hostname is "safe", nor does it model DNS rebinding,
  redirect-based bypasses, or numeric/decimal IP encodings.
* Calls with entirely fixed, literal destinations and no user input are not
  reported.

## Mitigation

* Avoid passing user input directly into a request URL. Where possible, allow
  only a fixed allowlist of destinations or identifiers mapped server-side to
  concrete URLs.
* When only a path segment is variable, build the request against a fixed base
  URL and ensure the input cannot introduce a new authority (for example by
  rejecting values containing `://`, `//`, or `@`).
* Disable or restrict redirects, and validate the final resolved URL before
  sending the request.
* Block access to link-local, loopback, and private address ranges where those
  destinations are not required.
