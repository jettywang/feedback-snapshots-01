HTTPX is careful to enforce timeouts everywhere by default.

The default behavior is to raise a `TimeoutException` after 5 seconds of
network inactivity.

## Setting and disabling timeouts

You can set timeouts for an individual request:

```python
# Using the top-level API:
httpx.get('http://example.com/api/v1/example', timeout=10.0)

# Using a client instance:
with httpx.Client() as client:
    client.get("http://example.com/api/v1/example", timeout=10.0)
```

Or disable timeouts for an individual request:

```python
# Using the top-level API:
httpx.get('http://example.com/api/v1/example', timeout=None)

# Using a client instance:
with httpx.Client() as client:
    client.get("http://example.com/api/v1/example", timeout=None)
```

## Setting a default timeout on a client

You can set a timeout on a client instance, which results in the given
`timeout` being used as the default for requests made with this client:

```python
client = httpx.Client()              # Use a default 5s timeout everywhere.
client = httpx.Client(timeout=10.0)  # Use a default 10s timeout everywhere.
client = httpx.Client(timeout=None)  # Disable all timeouts by default.
```

## Fine tuning the configuration

HTTPX also allows you to specify the timeout behavior in more fine grained detail.

There are four different types of timeouts that may occur. These are **connect**,
**read**, **write**, and **pool** timeouts.

* The **connect** timeout specifies the maximum amount of time to wait until
a socket connection to the requested host is established. If HTTPX is unable to connect
within this time frame, a `ConnectTimeout` exception is raised.
* The **read** timeout specifies the maximum duration to wait for a chunk of
data to be received (for example, a chunk of the response body). If HTTPX is
unable to receive data within this time frame, a `ReadTimeout` exception is raised.
* The **write** timeout specifies the maximum duration to wait for a chunk of
data to be sent (for example, a chunk of the request body). If HTTPX is unable
to send data within this time frame, a `WriteTimeout` exception is raised.
* The **pool** timeout specifies the maximum duration to wait for acquiring
a connection from the connection pool. If HTTPX is unable to acquire a connection
within this time frame, a `PoolTimeout` exception is raised. A related
configuration here is the maximum number of allowable connections in the
connection pool, which is configured by the `limits` argument.

You can configure the timeout behavior for any of these values...

```python
# A client with a 60s timeout for connecting, and a 10s timeout elsewhere.
timeout = httpx.Timeout(10.0, connect=60.0)
client = httpx.Client(timeout=timeout)

response = client.get('http://example.com/')
```

## Setting a total deadline

The connect, read, write and pool timeouts each govern a *single* operation.
They do not bound the overall time an exchange can take when it is made up of
several operations — for example a request followed by an authentication
retry, or a chain of redirects.

For high-sensitivity outbound calls you can additionally set a **deadline**,
which is an overall budget for the whole exchange. It is measured against a
monotonic clock and is created once per request, so it is *not* reset on each
redirect or authentication hop:

```python
# Allow at most 30s for the entire exchange, with 5s per individual operation.
timeout = httpx.Timeout(5.0, deadline=30.0)
client = httpx.Client(timeout=timeout)
```

The remaining deadline budget is intersected with the per-operation
connect/read/write/pool timeouts before every network operation. Whichever is
shorter wins, so the deadline can cut an exchange short even when no single
hop would have timed out.

The deadline spans:

* The initial request send.
* Any authentication interactions (additional requests issued by an auth flow).
* Every redirect hop.
* Consumption of the response body, when the response is read to completion by
  `Client.send()` / `AsyncClient.send()` (the default for `get()`, `post()`,
  and friends) or while a streamed response is iterated.

When the budget is exhausted a `httpx.TotalDeadlineExceeded` exception is
raised. It is a subclass of `httpx.TimeoutException`. The response in flight is
closed before the exception propagates, and no further request — the next
redirect hop or authentication retry — is sent.

The deadline is **disabled by default** (`deadline=None`), in which case the
behavior is identical to omitting it entirely. Set it explicitly to opt in:

```python
# Disable all per-operation timeouts, but still cap the whole exchange.
timeout = httpx.Timeout(None, deadline=30.0)
```