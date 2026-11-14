# h2connect — extended CONNECT ingress adapter

`h2connect` wraps a server-side [`h2.H2Connection`](https://h2.readthedocs.io)
with the gate an ingress needs before turning an HTTP/2 stream into a tunnel.
It supports ordinary CONNECT (RFC 9113) and extended CONNECT (RFC 8441) for an
explicitly allowed set of protocols.

## Gate order

For every CONNECT stream the adapter performs, in order:

1. **Pseudo-header / shape check.** Ordinary CONNECT may only carry
   `:method` + `:authority`; extended CONNECT must additionally carry
   `:protocol`, `:scheme` and `:path`. The two shapes can never be downgraded
   into one another, and duplicate or mis-ordered pseudo-headers are rejected.
2. **Setting check.** An extended request is refused unless the peer
   advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
3. **Allow list + negotiation.** `:protocol` must be in the configured allow
   list and satisfy the per-protocol `ProtocolPolicy` (required scheme/headers).
4. **Application authorization.** Only after every local check passes is the
   authorizer invoked.
5. **One target connection.** The connector is called exactly once, only for an
   authorized request. Refusals, unknown protocols and failed negotiation never
   reach the connector.

## Early DATA and cleanup

- DATA arriving while authorization is pending is buffered per stream and is
  never written to a target; it is flushed in arrival order on acceptance.
- Rejection, RST_STREAM, GOAWAY or a connection error aborts any downstream
  connection the stream held, so no target connection is leaked.
- Each stream keeps an independent state object; resetting one tunnel never
  affects another.
- After the `200` acceptance the stream carries opaque bytes: payloads are
  forwarded byte-for-byte and are never re-interpreted as HTTP headers.

## Minimal use

```python
from h2connect import H2ConnectAdapter, ProtocolPolicy
from h2connect.target import FakeTargetConnector

def authorizer(request, resolve):
    # resolve(False) may also be called later, asynchronously.
    resolve(request.authority.endswith(":443"))

adapter = H2ConnectAdapter(
    allowed_protocols=[
        ProtocolPolicy(name="websocket", required_schemes=frozenset({"https", "wss"})),
    ],
    authorizer=authorizer,
    connector=FakeTargetConnector(),
)
adapter.initiate()

events = adapter.feed(socket.recv(65535))
socket.sendall(adapter.data_to_send())
```

## Events

`feed()` returns `TunnelEvent` objects: `TunnelAccepted`, `TunnelRejected`,
`TunnelData`, `TunnelClosed`, `TunnelAborted`, `TunnelFailed` and
`TunnelRequestReceived` (non-CONNECT traffic, left to the host application).
