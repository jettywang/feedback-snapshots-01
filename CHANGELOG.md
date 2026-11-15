# Changelog

## [Unreleased]

**Features:**

- Add General and Flattened JWE JSON Serialization entry points
  (`JWE.encrypt_general` / `JWE.decrypt_general` and
  `JWE.encrypt_flattened` / `JWE.decrypt_flattened`), sharing one content
  ciphertext and Content Encryption Key across recipients
- Decryption results expose the recipient that actually opened the token
  (`JWE::DecryptionResult`)
- Support external Additional Authenticated Data for JSON Serialization

**Security:**

- Reject duplicate header parameter names across the protected, shared
  unprotected and per-recipient header locations (RFC 7516 section 7.2.2)
- Reject `dir` and direct `ECDH-ES` algorithms for JSON Serialization, as they
  cannot share a single Content Encryption Key across recipients
- Authenticate the original serialized AAD; a recipient that fails to unwrap its
  key cannot borrow another recipient's headers, and no plaintext is returned
  when every recipient fails

## [v1.1.1](https://github.com/jwt/ruby-jwe/tree/v1.1.1) (2025-08-07)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v1.1.0...v1.1.1)

**Fixes and enhancements:**

- Fix tag length checking for AES-GCM (CVE-2025-54887)

## [v1.1.0](https://github.com/jwt/ruby-jwe/tree/v1.1.0) (2025-07-22)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v1.0.0...v1.1.0)

**Features:**

- Add RsaOaep256 algorithm (https://github.com/jwt/ruby-jwe/pull/31)

## [v1.0.0](https://github.com/jwt/ruby-jwe/tree/v1.0.0) (2025-02-16)

[Full Changelog](https://github.com/jwt/ruby-jwe/compare/v0.4.0...v1.0.0)

**Features:**

- Support Ruby 3.4 (https://github.com/jwt/ruby-jwe/pull/26)
- Drop support for Ruby versions prior to 2.5 (https://github.com/jwt/ruby-jwe/pull/27)

**Fixes and enhancements:**

- Refreshed codebase (CI and linter fixes) (https://github.com/jwt/ruby-jwe/pull/27, https://github.com/jwt/ruby-jwe/pull/28)
