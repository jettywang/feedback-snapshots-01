# Guarded STARTTLS upgrade

A Twisted TCP client that sends a plaintext greeting, upgrades to TLS
mid-stream, and keeps its write queue, producer state and the encrypted
transport consistent during the upgrade window.

## Layout

- `starttls_upgrade/client.py` — `StartTLSClient` (the protected-phase
  protocol) and `ReconnectingStartTLSFactory` (retains unsent business data for
  replay).
- `starttls_upgrade/memorytransport.py` — in-memory, connection-oriented
  transports with a **real** `startTLS` (a genuine `TLSMemoryBIOProtocol`
  layer) and a `Pump` that moves wire bytes between the two ends.
- `starttls_upgrade/testingpeers.py` — test server and a recording push
  producer.
- `starttls_upgrade/test/test_upgrade.py` — comparative tests.
- `compare_scenarios.py` — prints the three scenarios side by side.

## Write-side security conventions during the upgrade

1. Explicit phase. `_upgrading` is set when `startTLS` is called and cleared
   only by `handshakeCompleted` or `connectionLost`; `_secured` becomes true
   only once the transport actually provides `ISSLTransport`.
2. Queued, never-leaked writes. `sendBusinessData` while `_upgrading` appends
   to `_protectedQueue` instead of touching the half-built layer. The queue is
   flushed in order only after the handshake completes, so no business byte is
   ever written to the plaintext transport.
3. Producer coherence. Producers may register before or during the window.
   Registration is routed to the active layer, so after `startTLS` the TLS
   wrapper owns the producer (via its membrane) and pause/resume back-pressure
   reaches it even while the handshake is open. A pre-upgrade producer is
   migrated by the transport's `startTLS`.
4. Explicit failure result. The upgrade `Deferred` resolves exactly once:
   success on handshake, otherwise an errback with the concrete transport
   error (application cancellation surfaces `ConnectionLost`, never a bare
   `CancelledError`). On failure the protected queue is preserved and handed to
   the factory; the next connection replays it over a fresh TLS session.

## Scenarios compared

- successful upgrade,
- cancellation order 1: the application cancels the upgrade Deferred,
- cancellation order 2: the underlying transport dies mid-handshake.

Each is compared on: the raw bytes the underlying transport receives
(plaintext greeting vs TLS records, with the business payload asserted absent
in cleartext), upper-layer producer pause count, the close notice on each side,
and usability after reconnect (including replay of the retained data).

## Run

```sh
.venv/bin/python -m pytest -q -o addopts= starttls_upgrade
.venv/bin/python starttls_upgrade/compare_scenarios.py
```
