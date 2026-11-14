# NTLM SPN Target Name Admission Policy

An NTLMv2 response only proves that the client knows the account password. The
`MSV_AV_TARGET_NAME` AV pair inside the `NTLMv2_CLIENT_CHALLENGE` records which
service principal name (SPN) the client minted the token for, but by default an
acceptor ignores it. When several backends share the same NTLM credential
component, a token produced for service A can therefore be replayed against
service B and accepted purely because the password proof is valid.

`SPNTargetPolicy` lets an acceptor define, through **local configuration**, the
names it is willing to admit. A name presented by the client is only ever
compared against that configuration; presenting a new name never adds it to the
trusted set.

## Configuring a policy

```python
import spnego
from spnego import SPNTargetPolicy, SPNTargetPolicyMode

policy = SPNTargetPolicy(
    allowed_names=["http/server.example.com"],
    trusted_aliases=["http/server.example.org"],
    mode=SPNTargetPolicyMode.strict,
)

server = spnego.server(
    protocol="ntlm",
    options=spnego.NegotiateOptions.use_ntlm,
    spn_target_policy=policy,
)
```

* `allowed_names` - one or more SPNs this service answers to. A single string
  or a sequence is accepted. The SPN built from the acceptor's `service` and
  `hostname` should normally be listed here.
* `trusted_aliases` - additional locally configured SPNs known to refer to the
  same service. Aliases cannot be registered by a client.
* `mode` - `strict` (reject anything not admitted) or `permissive` (the
  default; emit a `UserWarning` and keep the historical behaviour).

## How a presentation is classified

The acceptor exposes the outcome on `server.spn_target_result`:

| `SPNTargetNameStatus` | Meaning |
| --- | --- |
| `missing` | No `MSV_AV_TARGET_NAME` AV pair was present (or it was empty) |
| `mismatch` | The service/host does not match any allowed name or alias |
| `mismatch_malformed` | The value is not an `service/host` SPN |
| `allowed_name` | Exact match against a configured allowed name |
| `trusted_alias` | Match against a configured trusted alias |
| `representation` | Match after canonicalization, e.g. case or trailing DNS dot |

Canonicalization lower cases the `service/host` form and strips a trailing dot
from the host, so `HTTP/Server.Example.COM.` and
`http/server.example.com` are treated as the same service with a different
representation rather than two distinct services.

## Enforcement point and failure mode

The policy runs while the `AUTHENTICATE_MESSAGE` is processed, before the NT/LM
password proof is verified. Under strict mode a presentation that is missing or
not admitted raises `spnego.exceptions.SPNTargetPolicyError`
(`ErrorCode.spn_target_policy`) and the context never completes. NTLMv1/LM
responses cannot carry a target name, so a strict policy fails closed on them as
well. In permissive mode the same condition logs a warning and authentication
proceeds as before.

## Provider support

Only the pure Python NTLM provider can inspect and enforce the target name AV
pair. Passing `spn_target_policy` to the GSSAPI, SSPI, or CredSSP providers
raises `OperationNotAvailableError` at construction time rather than silently
ignoring the policy. The pure Python Negotiate provider
(`options=NegotiateOptions.use_negotiate`) accepts the policy and forwards it to
its NTLM sub context.

## Client traceability

The NTLM client sets `MSV_AV_TARGET_NAME` from its `service` and `hostname`
arguments (the context's `spn`). At debug level it logs both inputs and the
resulting target name, so the value embedded in a client response can be traced
back to the local client configuration.
