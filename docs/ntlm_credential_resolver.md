# NTLM Acceptor Credential Resolvers

The Python NTLM acceptor needs the LM/NT hashes of every account it
authenticates. The original lookup read a single flat file through the
`NTLM_USER_FILE` environment variable. That is a process wide setting so it
cannot host two tenants with different credential sets in the same process
without mutating global state between handshakes.

An instance level `NTLMCredentialResolver` solves this. Each acceptor receives
its own resolver and credentials are resolved per handshake.

## Resolver contract

A resolver implements two methods:

* `current_version()` returns an opaque `NTLMCredentialVersion` that identifies
  the current revision of the backing store.
* `resolve(domain, username)` returns the `ResolvedNTLMCredential` for the
  exact identity advertised in the NTLM `AUTHENTICATE` message.

Lookup rules are deliberate:

* The domain and username are matched case insensitively, matching the NTLM
  wire protocol, but domain presence is significant. An identity that
  advertises no domain (`""`) only matches entries without a domain; empty
  domains are never wildcards and the two are not collapsed into one rule.
* A missing match raises `spnego.NoCredentialError`. The resolver never falls
  back to another tenant, another resolver, or the process default
  `NTLM_USER_FILE` store.
* Any exception raised by a custom resolver propagates unchanged; the acceptor
  does not swallow it or try another source.
* Diagnostics only contain the identity (`DOMAIN\user`) and the opaque
  version. Passwords and LM/NT hashes never appear in logs, exception text, or
  `repr()` output.

## Built-in file resolver

`FileNTLMCredentialResolver` reads the same Heimdal and smbpasswd flat file
formats documented for `NTLM_USER_FILE`. The file is re-read on every
`resolve()` call and its revision is derived from the file metadata so an
in-place rotation produces a new version.

```python
import spnego

resolver = spnego.FileNTLMCredentialResolver("/etc/pyspnego/tenant-a.creds")
server = spnego.server(
    protocol="ntlm",
    options=spnego.NegotiateOptions.use_ntlm,
    ntlm_credential_resolver=resolver,
)
```

## Hosting multiple tenants in one process

Bind one resolver per tenant and keep the acceptor instances independent. Two
handshakes for the same username but different domains and passwords can then
be interleaved safely; each success is attributed to the instance that
validated it.

```python
import spnego

tenant_a = spnego.server(
    protocol="ntlm",
    options=spnego.NegotiateOptions.use_ntlm,
    ntlm_credential_resolver=resolver_a,
)
tenant_b = spnego.server(
    protocol="ntlm",
    options=spnego.NegotiateOptions.use_ntlm,
    ntlm_credential_resolver=resolver_b,
)
```

A custom resolver only needs to subclass `NTLMCredentialResolver`, for example
one backed by a database or a secret manager.

## Rotation policy

The store revision is captured when the `NEGOTIATE` message arrives and
compared with the version attached to the credential resolved for the
`AUTHENTICATE` message. `NTLMCredentialRotationPolicy` defines what happens
when they differ:

* `pin` (default): the handshake is rejected with `spnego.NoCredentialError`.
  Every completed handshake therefore uses one consistent credential version.
* `reload`: the current credential is used to validate the response. A client
  that still proves the old credential fails the normal response check; a new
  handshake against the rotated credential succeeds.

## Backwards compatibility

When no resolver is supplied the acceptor keeps using the file referenced by
`NTLM_USER_FILE` exactly as before. That remains the explicit compatibility
entry for single-tenant deployments and existing tests, and new code that
needs more than one tenant should pass a resolver instead.
