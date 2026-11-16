HTTPX supports setting up [HTTP proxies](https://en.wikipedia.org/wiki/Proxy_server#Web_proxy_servers) via the `proxy` parameter to be passed on client initialization or top-level API functions like `httpx.get(..., proxy=...)`.

<div align="center">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/27/Open_proxy_h2g2bob.svg/480px-Open_proxy_h2g2bob.svg.png"/>
    <figcaption><em>Diagram of how a proxy works (source: Wikipedia). The left hand side "Internet" blob may be your HTTPX client requesting <code>example.com</code> through a proxy.</em></figcaption>
</div>

## HTTP Proxies

To route all traffic (HTTP and HTTPS) to a proxy located at `http://localhost:8030`, pass the proxy URL to the client...

```python
with httpx.Client(proxy="http://localhost:8030") as client:
    ...
```

For more advanced use cases, pass a mounts `dict`. For example, to route HTTP and HTTPS requests to 2 different proxies, respectively located at `http://localhost:8030`, and `http://localhost:8031`, pass a `dict` of proxy URLs:

```python
proxy_mounts = {
    "http://": httpx.HTTPTransport(proxy="http://localhost:8030"),
    "https://": httpx.HTTPTransport(proxy="http://localhost:8031"),
}

with httpx.Client(mounts=proxy_mounts) as client:
    ...
```

For detailed information about proxy routing, see the [Routing](#routing) section.

!!! tip "Gotcha"
    In most cases, the proxy URL for the `https://` key _should_ use the `http://` scheme (that's not a typo!).

    This is because HTTP proxying requires initiating a connection with the proxy server. While it's possible that your proxy supports doing it via HTTPS, most proxies only support doing it via HTTP.

    For more information, see [FORWARD vs TUNNEL](#forward-vs-tunnel).

## Authentication

Proxy credentials can be passed as the `userinfo` section of the proxy URL. For example:

```python
with httpx.Client(proxy="http://username:password@localhost:8030") as client:
    ...
```

## Proxy mechanisms

!!! note
    This section describes **advanced** proxy concepts and functionality.

### FORWARD vs TUNNEL

In general, the flow for making an HTTP request through a proxy is as follows:

1. The client connects to the proxy (initial connection request).
2. The proxy transfers data to the server on your behalf.

How exactly step 2/ is performed depends on which of two proxying mechanisms is used:

* **Forwarding**: the proxy makes the request for you, and sends back the response it obtained from the server.
* **Tunnelling**: the proxy establishes a TCP connection to the server on your behalf, and the client reuses this connection to send the request and receive the response. This is known as an [HTTP Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel). This mechanism is how you can access websites that use HTTPS from an HTTP proxy (the client "upgrades" the connection to HTTPS by performing the TLS handshake with the server over the TCP connection provided by the proxy).

### Troubleshooting proxies

If you encounter issues when setting up proxies, please refer to our [Troubleshooting guide](../troubleshooting.md#proxies).

## Explaining proxy selection

Managed backends sometimes need an auditable answer to "for this outbound request, did we connect directly, and if not which proxy rule applied?". `Client.explain_proxy()` (also available on `AsyncClient`) evaluates the same ordered routing rules used by the send chain — `trust_env` proxies, `NO_PROXY` bypasses and explicit `mounts`, matched against the target scheme, host and port — and returns a `ProxyDecision` describing the outcome.

```python
decision = client.explain_proxy("https://internal.example.com/v1")

print(decision.outcome)        # "direct" or "proxied"
print(decision.direct)         # True for a direct connection
print(decision.matched_key)    # e.g. "all://*example.com"
print(decision.source)         # e.g. "NO_PROXY", "HTTP_PROXY" or "mounts argument"
print(decision.transport)      # the exact transport used to send the request
print(decision.masked_summary())
# Proxy decision for https://internal.example.com/v1: direct connection (...)
```

Because the explanation is produced from the client's own rule list rather than a parallel interpreter, `decision.transport` is guaranteed to be the same transport instance that `client.send(...)` would call. The ordered `decision.rules` list keeps every candidate with its `kind`, `source` and match pattern, so rule precedence and conflicts between environment and explicit mounts are visible. Any rule that could not be parsed is reported with `kind="unparseable_rule"` and an `error` message instead of silently disappearing.

Matching reuses httpx's `URLPattern` logic. Exact hosts, subdomain rules (`*.example.com` vs `*example.com`) and IPv6 literals are therefore distinct — a domain is never treated as matching by a naive string suffix. A debug-level log line using `masked_summary()` is emitted for each request when the `"httpx"` logger is set to `DEBUG`.

The explanation only describes routing:

* Proxy passwords are never included; credentialed proxy URLs have their userinfo stripped, and `masked_summary()` masks any remaining password.
* No DNS resolution is performed. The target host is treated purely as a string.
* Recording that a request goes direct or through a proxy is **not** itself an SSRF defence — it explains the routing decision, it does not validate or block the destination.

## SOCKS

In addition to HTTP proxies, `httpcore` also supports proxies using the SOCKS protocol.
This is an optional feature that requires an additional third-party library be installed before use.

You can install SOCKS support using `pip`:

```shell
$ pip install httpx[socks]
```

You can now configure a client to make requests via a proxy using the SOCKS protocol:

```python
httpx.Client(proxy='socks5://user:pass@host:port')
```
