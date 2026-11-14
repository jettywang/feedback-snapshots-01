# Offline CMP transaction validator

Stateful, I/O-free validator for the RFC 4210 Certificate Management
Protocol messages used by an offline initialization registration.

## Scope

Only four messages (plus the polling sub-protocol) are accepted:

| PKIBody choice | Direction | Meaning |
| --- | --- | --- |
| `ir` (tag 0) | client -> CA | Initialization Request |
| `ip` (tag 1) | CA -> client | Initialization Response (`accepted` / `waiting` / `rejection`) |
| `pollReq` (25) / `pollRep` (26) | both | Polling while a `certReqId` is waiting |
| `certConf` (24) | client -> CA | Certificate confirmation (`certHash`) |
| `pkiconf` (19) | CA -> client | Final PKI confirmation |

Everything else (for example `error`, `genm`, revocation messages) returns
`RejectReason.UNSUPPORTED_BODY`. The outer PKIMessage protection (MAC or
signature, RFC 4210 section 5.1.3) is assumed to have been verified by the
caller; the validator works on the raw DER of an already-protected message.

## Correlation model

Transactions are keyed by the `(client GeneralName, transactionID)` tuple
recommended by RFC 4210 section 5.1.1, so multiple clients and multiple
transactions can be interleaved on one validator instance without sharing
state.

The following fields are correlated across the whole transaction:

- `transactionID` must be identical on every message;
- `sender`/`recipient` must match the parties established at the `ir` and
  flip direction on every hop;
- `recipNonce` must equal the previous message's `senderNonce`, and a
  `senderNonce` may never be reused inside a transaction;
- every `certReqId` is tracked independently, so a multi-certificate
  transaction is validated entry by entry rather than by its first item.

Each `certReqId` moves through
`requested -> waiting -> issued -> confirmed` (with terminal
`rejected-by-ca` / `rejected-by-client` branches). Issued certificates are
bound to the `ir` CertTemplate: the subject Name and SubjectPublicKeyInfo
of the certificate must equal what was requested, and the `certConf`
`certHash` must match the SHA-256 of the bare Certificate DER.

## Deterministic rejection and atomicity

Replay, stale polling, responses after a terminal state and unknown
`certReqId` values all produce a stable `RejectReason`. A rejected message
never mutates state: the transaction is restored from a pre-validation
snapshot, so a correct follow-up message is always accepted. Time-based
decisions (message-time skew and the polling `checkAfter` deadline) use a
clock callable supplied by the caller; the validator never sleeps.

## Layout

- `validator.py` -- `CMPTransactionValidator`, states and rejection codes.
- `builders.py` -- RFC 4210 message/certificate constructors used by tests
  and demos; they emit DER but do not compute real protection bits.
- `../tests/test_cmp_transaction.py` -- hermetic unit tests (no network,
  no external processes).
- `../tools/cmp_interleaved_demo.py` -- two interleaved transactions with
  real OpenSSL-minted certificates and a cross-transaction response
  injection, persisting every message as raw DER.
