# Recommendation for fixed managed WinRM terminals

Assumptions: a fleet of fixed-address Windows endpoints, each managed by the
same operations team, addressed by a stable DNS name or a stable IP, and
reached only from controlled clients. No public CA is involved.

The goal is to remove `no_ssl_peer_verification` without replacing it with
`ssl_peer_fingerprint`, because the fingerprint option drops expiry, hostname,
and chain verification (see `MATRIX.md`).

## Preferred profile: internal CA with certificate_store

1. Issue the WinRM listener certificate from an internal CA whose root is
   distributed to the clients. Subject/SAN must match the name the client
   dials (DNS SAN for a name, IP SAN for an address).
2. On the client:

```ruby
store = OpenSSL::X509::Store.new
store.add_cert(OpenSSL::X509::Certificate.new(File.read('/etc/winrm/root.pem')))

WinRM::Connection.new(
  endpoint: 'https://winrm-01.corp.example:5986/wsman',
  transport: :ssl,
  user: ENV.fetch('WINRM_USER'),
  password: ENV.fetch('WINRM_PASSWORD'),
  cert_store: store
)
```

Why this profile:

- Chain, expiry, and hostname stay enforced on every connection. `verify.rb`
  confirms wrong hostname, expired leaf, self-signed leaf, and foreign-CA leaf
  are all rejected; a CA-issued leaf is accepted.
- Rotation needs no client change: reissue the leaf from the same root. A
  second request in `verify.rb` proves a renewed leaf from the same CA is
  accepted while a leaf from another root is rejected.
- If the root itself must rotate, ship a bundle containing both roots; that
  is supported and covered by `verify.rb` (multi-root bundle).
- `ca_trust_path` pointing at the same root PEM is equivalent for this
  endpoint, but it replaces that transport's HTTPClient bundle rather than
  using a dedicated store. `cert_store` is preferable when the same process
  also talks to public HTTPS endpoints.

## If an internal CA is not available

Use leaf pinning that keeps name and expiry checks: a `cert_store` holding the
allowed leaves with `V_FLAG_PARTIAL_CHAIN`.

```ruby
store = OpenSSL::X509::Store.new
allowed.each { |pem| store.add_cert(OpenSSL::X509::Certificate.new(File.read(pem))) }
store.flags = OpenSSL::X509::V_FLAG_PARTIAL_CHAIN
```

This is the only form found that allows several leaves, including same-subject
rollover leaves, while still rejecting an expired leaf and a certificate for
the wrong hostname. Constraints:

- It accepts exactly the listed leaves; any new leaf requires a client update.
- A bundle of same-subject self-signed leaves via `ca_trust_path` does **not**
  work (only the first entry is honoured), so do not express rotation that way.
- This is a stronger pin than `ssl_peer_fingerprint` only because it retains
  expiry and hostname. It still has no chain to a CA.

## If only ssl_peer_fingerprint is acceptable

Use it only as a last resort, and know what is gone:

- pin the leaf's SHA-1 (lowercase hex, no separators); SHA-256 is not
  supported by this version;
- expiry, hostname, and chain are not checked, so an expired or
  wrong-host certificate with the right key material is accepted;
- one pin covers one leaf; a rollover requires a client-side pin change at the
  moment of cutover.

## Do not

- Do not set `no_ssl_peer_verification: true` to make a self-signed endpoint
  work. `verify.rb` shows it accepts a certificate from an unrelated CA.
- Do not treat `no_ssl_peer_verification` plus a fingerprint as "verification
  is on". It is a pin with no PKI behind it.
- Do not rely on `ca_trust_path` replacement to *add* a private root while
  keeping public trust; it replaces the bundle.

## What this task verified, and what it did not

Verified locally, against the pinned Ruby 3.3.12 / OpenSSL 3.6.3 / HTTPClient
2.10.0, with generated certificates and real TLS handshakes over socketpairs:

- fingerprint format and binding to the presented leaf;
- fingerprint behaviour for mismatch, wrong hostname, expiry, self-signed, and
  rotation between the preflight and the POST;
- CA trust behaviour for good, wrong-host, expired, self-signed, and
  foreign-CA leaves, and `no_ssl_peer_verification` accepting all of them;
- `ca_trust_path` vs `cert_store` precedence and bundle semantics;
- multi-root bundles, same-subject bundle collapse, and
  `V_FLAG_PARTIAL_CHAIN` leaf anchoring;
- callback accept-all, hostname-still-checked, and fail-closed behaviour.

Not verified here:

- Any real WinRM/HTTP.sys listener, WinRM service configuration, channel
  binding (`CbtHardeningLevel`), or Windows certificate store behaviour.
- Client-certificate mutual TLS end to end beyond the option plumbing.
- Kerberos/GSSAPI option handling; the native extension crashed in this
  sandbox and that path is read from source only.
- Redirect and proxy paths; the harness deliberately removes proxy variables
  and does not exercise redirects.
- Anything about the target fleet's DNS, certificate issuance, clock sync, or
  root distribution. Those are deployment facts that must be checked on the
  actual managed terminals.
