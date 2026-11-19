# Verified combinations

Source: `lib/winrm/http/transport.rb` (HTTP transports),
`HTTPClient 2.10.0` (`lib/httpclient/ssl_config.rb`,
`lib/httpclient/ssl_socket.rb`), OpenSSL 3.6.3 via Ruby 3.3.12.
Every row below was reproduced by `verify.rb`; `verify.rb` exits non-zero if a
row stops holding.

## What each option reads and changes

| Option | Applied where | Effect |
| --- | --- | --- |
| `no_ssl_peer_verification` | `no_ssl_peer_verification!`, every transport | `verify_mode = VERIFY_NONE`. Also disables the hostname check; the store's chain/CRL policy is not exercised. |
| `ssl_peer_fingerprint` | BasicAuthSSL, ClientCertAuthSSL, HttpNegotiate | Adds a preflight TLS connection and a post-response check; on first success sets `VERIFY_NONE` for the rest of the session. |
| `ca_trust_path` | same three | `set_trust_ca` → `cert_store.add_file`; **replaces** HTTPClient's bundled CA bundle. |
| `cert_store` | same three | Replaces the whole `X509::Store`; overrides `ca_trust_path`. |

Plaintext transport ignores `ssl_peer_fingerprint`, `ca_trust_path`, and
`cert_store`; it still calls `no_ssl_peer_verification!` if given, though it
never uses TLS. Kerberos transport reads `no_ssl_peer_verification` but not
`ssl_peer_fingerprint`, `ca_trust_path`, or `cert_store` (read from source; the
GSSAPI extension crashed in this sandbox).

## Protection retained, by profile

Legend: ✓ enforced, ✗ not enforced, — inapplicable.

| Profile | Chain to a trusted CA | Expiry | Hostname | Pins one leaf | Certificate accepted |
| --- | --- | --- | --- | --- | --- |
| Default (`:ssl`, bundled store) | ✓ | ✓ | ✓ | ✗ | Public CA or OS-trusted only |
| `cert_store` / `ca_trust_path` | ✓ | ✓ | ✓ | ✗ | Leaves under that root |
| `ssl_peer_fingerprint` | ✗ | ✗ | ✗ | ✓ SHA-1 | Only the exact leaf |
| `ssl_peer_fingerprint` + CA options | ✗ | ✗ | ✗ | ✓ | Only the exact leaf |
| `no_ssl_peer_verification` | ✗ | ✗ | ✗ | ✗ | Any certificate |
| `V_FLAG_PARTIAL_CHAIN` leaf anchors | ✗ | ✓ | ✓ | ✓ (several leaves) | Only listed leaves |

The important negative result: `ssl_peer_fingerprint` does not refine CA
verification, it replaces it. With a matching pin, an expired certificate, a
self-signed certificate, and a certificate for the wrong hostname are all
accepted (three scenarios in `verify.rb`). `no_ssl_peer_verification` combined
with a pin still pins, because the pin is checked before `VERIFY_NONE` is
installed and again on the response.

## Fingerprint mechanics

- Binds to the leaf presented on the wire, i.e. the server's end-entity
  certificate, not a CA or intermediate. Matching a CA fingerprint can only
  work if that CA is itself served as the leaf.
- Computed as SHA-1 over DER and compared with `String#casecmp`:
  lowercase and uppercase hex both match; SHA-256, colon-separated, and
  space-separated forms never match and fail closed (`RuntimeError: ssl
  fingerprint mismatch!!!!`). A non-string value raises `NoMethodError`.
- `nil` means no pin.
- It is validated twice per request: preflight (before the SOAP body is sent)
  and on the response's `peer_cert`. A server that changes identity between
  those two connections is rejected after the POST, i.e. after the request
  body has already gone out.
- The same pin value is re-checked on every request, so mid-session rotation
  away from the pinned leaf fails on the next request.
- SHA-1 is a legacy choice. Treat it as an identity pin against accidental
  substitution, not as a modern cryptographic signature.

## Rotation: how many certificates can be allowed, and how

- `ssl_peer_fingerprint`: exactly one leaf. There is no documented or
  implemented form for several pins. Passing an array raises `NoMethodError`
  on `casecmp`.
- `ca_trust_path` with a PEM bundle of several CA roots: works; all roots in
  the file are loaded and any leaf under any of them is accepted.
- `ca_trust_path` with several **same-subject** self-signed leaves: only one
  wins. The same subject/serial-keyed lookup collapses entries, so the second
  leaf is rejected even though it is in the file. Rotating a self-signed leaf
  while keeping its subject therefore cannot be expressed with a PEM bundle.
- `ca_trust_path` with distinct-subject leaves: both are accepted.
- `cert_store` with `V_FLAG_PARTIAL_CHAIN`: accepts several leaves, including
  same-subject ones, and keeps expiry and hostname checks. This is the only
  option set found that gives "several leaves + hostname + expiry" without
  manual inspection of the chain.
- CA-issued leaves: a single internal root covers unlimited old/new leaves;
  expiry and hostname remain enforced. This is the normal rotation story.

## Other observed behaviour

- `ca_trust_path`/`cert_store` replace HTTPClient's bundled CA file
  (`httpclient/cacert.pem`, 118 roots in this version). Codepaths that relied
  on public CAs stop working once either option is set. In practice this
  matters for fixed managed endpoints, not for the public web.
- `cert_store` wins over `ca_trust_path` regardless of option order.
- HTTPClient's context-level `verify_callback` (not a WinRM option):
  - an accept-all callback accepts an untrusted chain;
  - it does **not** disable the hostname check;
  - a callback that raises is swallowed and treated as reject (fails closed).
  - a callback set on `X509::Store` is inert under HTTPClient, which installs
    its own delegating callback on the context.
- HTTPClient follows up to 10 redirects by default. With verification on, a
  redirect to another host fails the hostname check; with a pin, a redirect to
  another leaf fails the pin. Redirects are not part of `verify.rb`.
- `no_ssl_peer_verification` is checked per request only through the pin;
  otherwise once set it stays off for the life of the transport.
