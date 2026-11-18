# TLS 1.3 early data: what `supports_early_data` proves

`ScanCommand.TLS_1_3_EARLY_DATA` answers one narrow question: **did this TLS stack
acknowledge one byte of 0-RTT data on a resumed TLS 1.3 session?** It does not test
whether an application accepts, processes, or replays a transaction.

## Probe sequence

1. Open a TLS 1.3 connection and complete the handshake.
2. Send a complete HTTP/1.1 `GET /` request **inside the normal (post-handshake) TLS
   stream**, then read up to 2048 bytes. This bootstraps a resumable
   session/ticket; it is not 0-RTT traffic.
3. Save the session returned by OpenSSL.
4. Open a second TCP connection. Skip the TLS handshake, install the saved session,
   and call `write_early_data(b"E")`.
5. Complete the handshake and call `get_early_data_status()`.
6. Set `supports_early_data = True` only when the status is `ACCEPTED`.

The probe never sends an HTTP request as early data and never reads an application
response after the early-data write. A `True` result therefore says nothing about
application-level replay.

## Outcome boundary

| Observed by SSLyze | `supports_early_data` | Scan attempt | What it means |
|---|---|---|---|
| Server rejects TLS 1.3 handshake | `false` | `COMPLETED` | TLS 1.3 unavailable; early data not tested |
| TLS 1.3 handshake times out | `false` | `COMPLETED` | Inconclusive; not a negative security finding |
| HTTP read times out before session is saved | `false` | `COMPLETED` | Inconclusive; no 0-RTT attempt |
| Full exchange succeeds but no session/ticket | `false` | `COMPLETED` | No resumable session; no 0-RTT attempt |
| OpenSSL raises "function you should not call" from `write_early_data()` | `false` | `COMPLETED` | 0-RTT write refused before handshake |
| Handshake completes, status `REJECTED` | `false` | `COMPLETED` | 0-RTT sent but rejected by the server |
| Handshake completes, status `NOT_SENT` | `false` | `COMPLETED` | No acceptance observed; inconclusive |
| Handshake completes, status `ACCEPTED` | `true` | `COMPLETED` | TLS stack accepted `b"E"`; no app behavior observed |
| First or second TCP connection times out, or second handshake times out | unset | `ERROR` (`CONNECTIVITY_ISSUE`) | Scan failure, not a negative result |
| Client certificate requested | unset | `ERROR` (`CLIENT_CERTIFICATE_NEEDED`) | Scan failure, not a negative result |
| Unexpected OpenSSL error | unset | `ERROR` (`BUG_IN_SSLYZE`) | Scan failure, not a negative result |

Only the plugin's own `read()` timeout is folded into `false` by its
`except socket.timeout` branch; connection-level timeouts are retried and surface as
`ConnectionToServerTimedOut`, which the scanner records as `ERROR`.

The CLI and JSON schemas expose only `supports_early_data: bool`. The attempt wrapper
adds `status`, `error_reason`, and `error_trace`, but a `COMPLETED` attempt with
`false` does not distinguish "TLS 1.3 unavailable", "timeout", "no ticket",
"write refused", "0-RTT rejected", or "status not sent". Consumers must not treat
every `false` as a clean negative, and must not treat `true` as a replay finding.

## What a replay finding still needs

Without sending a transaction or exercising application state, a report cannot claim
application replay. To confirm replay risk, a separate authorized test would need:

- an application endpoint whose request is safe to submit twice and whose effect is
  observable server-side (for example an idempotency key, nonce, or audit record);
- a way to distinguish the 0-RTT request from a normal retry, and to observe whether
  the application processed it before or after the handshake;
- confirmation that the application's anti-replay control (if any) actually rejects
  the second 0-RTT copy;
- a negative control showing the same request is not replayed when 0-RTT is disabled.

Until those are available, report the observed boundary only: early-data acceptance
at the TLS layer was or was not observed, and whether the probe was conclusive.
