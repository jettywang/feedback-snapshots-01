# Expect: 100-continue gate adapter for h11

Large request bodies must not cross into business logic until the request
**headers** have been authenticated. This example adds that gate to an
`h11` server while honoring `Expect: 100-continue`
([RFC 7231 §5.1.1](https://www.rfc-editor.org/rfc/rfc7231#section-5.1.1),
[RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110#section-10.1.1)).

## Files

- `adapter.py` — transport-agnostic `Expect100Gate`. You supply an h11
  server connection's I/O, a clock, an authenticator, and a business
  consumer.
- `demo.py` — deterministic demo over an in-memory `FakeTransport` with a
  `FakeClock`. No sockets, no real time; every ordering is scripted and
  asserted.

Run it:

```sh
python demo.py            # from this directory, or:
python examples/expect100_gate/demo.py
```

## Ordering rules enforced

```
request headers  ->  authenticate  ->  (maybe) 100 Continue  ->  body -> consumer
```

1. The authenticator sees only the parsed `h11.Request` headers. It returns
   `None` to allow the request or an `h11.Response` (401/403/...) to reject.
2. A `100 Continue` is sent **only** after authentication succeeds and
   **only** when the client is genuinely paused waiting for it.
3. On rejection the final error response is sent directly — a `100` is never
   emitted first, and the consumer is never called, even if the client
   ignored the expectation and streamed its body early.

### Detecting "waiting" vs "raced ahead"

`Connection.they_are_waiting_for_100_continue` only reflects that the
`Expect` header was present; h11 clears it as soon as body bytes are
consumed. The adapter performs a one-event lookahead right after the
`Request`:

- `NEED_DATA` → no body buffered → the client is really waiting.
- a `Data` / `EndOfMessage` event → the body is already in flight.

## What happens to the connection after an early rejection

The rejected body still has to be accounted for, or its leftover bytes
would be misparsed as the next pipelined request (request smuggling).

| Situation | Policy | Behavior |
|---|---|---|
| Client paused waiting for the 100 | always `CLOSE` | Send the error response without a 100, then close. Draining is impossible without deadlock: the peer is blocked on us. |
| Client sent the body early | `CLOSE` | Send the error response, then close. |
| Client sent the body early | `DRAIN` | Send the error response, then read the body **through h11's framing** and discard it; reuse the connection only after h11 emits `EndOfMessage`. |

The `DRAIN` path has two hard bounds:

- `max_drain_bytes` — close once the rejected body exceeds the cap.
- `max_drain_seconds` — a deadline checked against the injected clock;
  close when it expires, so a stalled peer cannot pin the connection.

Drained bytes are never passed to the consumer and never re-parsed as a new
request. A peer that disconnects mid-body is a framing error (`truncated
body`) and also forces a close. Only a fully framed, fully drained rejected
request calls `start_next_cycle()` and makes the connection reusable.

## Demo scenarios

1. Legal streaming upload: wait → `100` → chunked body → `200`, kept alive.
2. Bad auth while the client waits: `401`, no `100`, connection closed.
3. Early body, bad auth, `DRAIN`: `401`, bounded drain, connection reused by
   a legitimate `100` → `200` request on the same connection.
4. Early body larger than `max_drain_bytes`: `401`, then close.
5. Early body stalls past `max_drain_seconds` (driven by the fake clock):
   `401`, then close.
6. Early body with the `CLOSE` policy: `401`, then close.
7. Request-looking bytes inside a rejected body are drained, never parsed.
8. Peer EOF in the middle of a drain: protocol error, then close.

The run ends with an evidence table and a per-request truth table
`(rejected, consumer_calls)`, plus counters snapshotted at the exact moment
of each rejection proving `100s at rejection == 0` and
`consumer calls at rejection == 0`.

## Adapting to a real socket

`FakeTransport` mirrors a non-blocking socket: `read()` raises
`BlockingIOError` when no data is available, plus `write()` and `close()`.
To use the gate with `asyncio`/Trio/selectors, feed bytes from your
readability callback into `pump()`, register for writability when
`write()` would block, and pass `time.monotonic` as the clock. The drain
deadline then integrates with your normal timer registration.
