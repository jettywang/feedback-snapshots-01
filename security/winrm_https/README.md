# WinRM HTTPS: what the options actually enforce

This directory contains a runnable, local-only comparison of WinRM's HTTPS
verification options. Everything runs against generated certificates and a
real OpenSSL handshake; no Windows host or network access is required.

## Quick start

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec ruby \
  -Ilib security/winrm_https/verify.rb
```

That runs 45 scenarios and exits non-zero if any observed result differs from
the claim being tested. To regenerate the configuration comparison:

```sh
/opt/homebrew/opt/ruby@3.3/bin/ruby .feedback/run.rb exec ruby \
  -Ilib security/winrm_https/config_matrix.rb
```

## How the harness works

`verify.rb` drives `WinRM::HTTP::BasicAuthSSL` end to end. The sandbox cannot
bind a listening port, so each connection handed to HTTPClient is one end of
a `Socket.pair`; the other end runs a genuine `OpenSSL::SSL::SSLSocket` server
with a generated certificate. `TCPSocket.new` is redirected to hand out those
socketpairs. The WinRM transport, HTTPClient's TLS handshake, OpenSSL chain
verification, and Ruby's hostname check are all the real implementations.
Only the socket source is substituted.

Which certificate a scenario uses, and what each option does with it, is
listed in `MATRIX.md`. The generated `config/cases.yml` shows the option sets
and the transport class each one resolves to.

## Certificate fixtures

All generated in a temporary directory at runtime:

| Fixture | Identity |
| --- | --- |
| root | `CN=Contoso WinRM Root CA`, CA:TRUE |
| good | `CN=winrm.corp.example`, SAN `DNS:winrm.corp.example`, signed by root |
| wrong_host | `CN=other.corp.example`, SAN `DNS:other.corp.example`, signed by root |
| expired | `CN=winrm.corp.example`, same SAN, signed by root, expired one hour ago |
| rogue | `CN=winrm.corp.example`, same SAN, signed by an unrelated root |
| self_signed | `CN=winrm.corp.example`, same SAN, self-signed |
| rotated | self-signed, same subject and SAN as self_signed, different serial |

## Boundaries this local harness does not prove

- No real WinRM listener, WinRM service configuration, HTTP.sys binding, or
  `CbtHardeningLevel` behaviour is exercised. Those depend on the target.
- No Windows certificate store lookup: `cert_store` here is an explicit
  `OpenSSL::X509::Store`, not the Windows store.
- Kerberos/GSSAPI (`HttpGSSAPI`) crashed the pinned interpreter's native
  extension in this sandbox, so its option handling is read from source only.
- Redirect behaviour: HTTPClient follows up to 10 redirects by default. A
  redirect to a different host would be rejected by the hostname check when
  verification is on, but this harness does not exercise redirects.
- Proxy behaviour: the harness removes proxy environment variables so that
  HTTPClient connects to the socketpair directly.
- SHA-1 fingerprint collision/preimage resistance is not evaluated. The pin
  is a legacy check, not a chain.
