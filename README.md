# JWE

[![Build Status](https://github.com/jwt/ruby-jwe/actions/workflows/test.yml/badge.svg)](https://github.com/jwt/ruby-jwe/actions/workflows/test.yml)
[![Gem Version](https://badge.fury.io/rb/jwe.svg)](https://badge.fury.io/rb/jwe)

A ruby implementation of the [RFC 7516 JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516) standard.

## Installing

```bash
gem install jwe
```
## Usage

This example uses the default alg and enc methods (RSA-OAEP and A128GCM). It requires an RSA key.

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key)
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example uses a custom enc method:

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key, enc: 'A192GCM')
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example uses the 'dir' alg method. It requires an encryption key of the correct size for the enc method

```ruby
require 'jwe'

key = SecureRandom.random_bytes(32)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key, alg: 'dir')
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example uses the DEFLATE algorithm on the plaintext to reduce the result size.

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key, zip: 'DEF')
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example sets an extra **plaintext** custom header.

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

# In this case we add a copyright line to the headers (it can be anything you like
# just remember it is plaintext).
encrypted = JWE.encrypt(payload, key, copyright: 'This is my stuff! All rights reserved')
puts encrypted
```

## JSON Serialization (multiple recipients)

Besides the compact serialization, the gem supports the [General and Flattened
JWE JSON Serialization](https://tools.ietf.org/html/rfc7516#section-7.2). The
payload is encrypted once with a single Content Encryption Key; that key is then
wrapped independently for every recipient, so all recipients share the same
content ciphertext, IV and authentication tag.

### General JWE JSON Serialization

Each entry in the recipients array carries its own key, key management algorithm
and optional per-recipient headers. The same token can be opened by any of the
legitimate recipients.

```ruby
require 'jwe'

first_key  = OpenSSL::PKey::RSA.generate(2048)
second_key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt_general(
  payload,
  [
    { key: first_key,  alg: 'RSA-OAEP', kid: 'first' },
    { key: second_key, alg: 'RSA-OAEP', kid: 'second' }
  ]
)

result = JWE.decrypt_general(encrypted, second_key)
puts result.plaintext       # "The quick brown fox jumps over the lazy dog."
puts result.recipient_index # 1 (the recipient that actually opened the token)
puts result.header['kid']   # "second"
```

Recipients may use different key management algorithms (for example `RSA-OAEP`
for one recipient and `A128KW` for another) as long as every wrapped key
protects the same shared Content Encryption Key.

### Flattened JWE JSON Serialization

The flattened representation holds a single recipient with its members at the
top level of the JSON object.

```ruby
encrypted = JWE.encrypt_flattened(payload, first_key, kid: 'solo')
result = JWE.decrypt_flattened(encrypted, first_key)
puts result.plaintext
```

### External Additional Authenticated Data (AAD)

The authenticated data normally is the base64url encoded protected header. When
the protected header is omitted, the shared header parameters move to the
`unprotected` member and the external AAD is authenticated instead. The AAD is
always taken from its original serialization, so any modification makes
decryption fail with a `JWE::DecodeError`.

```ruby
encrypted = JWE.encrypt_general(
  payload,
  [{ key: first_key, alg: 'RSA-OAEP', kid: 'first' }],
  protected: false,
  aad: 'external additional authenticated data',
  cty: 'text/plain'
)

JWE.decrypt_general(encrypted, first_key).plaintext
```

### JSON Serialization rules

* A header parameter name must appear in only one of the protected, shared
  unprotected and per-recipient header locations; duplicates raise
  `JWE::DecodeError`.
* `dir` and the direct key agreement variant `ECDH-ES` derive a per-recipient
  Content Encryption Key and therefore cannot be combined with a JSON
  Serialization that shares one CEK; they raise `JWE::DecodeError`.
* When no recipient can unwrap a key, or content authentication fails, a
  `JWE::DecodeError` is raised and no plaintext is returned. A failing recipient
  is never able to reuse another recipient's headers.

## Available Algorithms

The RFC 7518 JSON Web Algorithms (JWA) spec defines the algorithms for [encryption](https://tools.ietf.org/html/rfc7518#section-5.1)
 and [key management](https://tools.ietf.org/html/rfc7518#section-4.1) to be supported by a JWE implementation.

Only a subset of these algorithms is implemented in this gem. Striked elements are not available:

Key management:
* RSA1_5
* RSA-OAEP (default)
* RSA-OAEP-256 (if OpenSSL::VERSION >= '3.0')
* A128KW
* A192KW
* A256KW
* dir
* ~~ECDH-ES~~
* ~~ECDH-ES+A128KW~~
* ~~ECDH-ES+A192KW~~
* ~~ECDH-ES+A256KW~~
* ~~A128GCMKW~~
* ~~A192GCMKW~~
* ~~A256GCMKW~~
* ~~PBES2-HS256+A128KW~~
* ~~PBES2-HS384+A192KW~~
* ~~PBES2-HS512+A256KW~~

Encryption:
* A128CBC-HS256
* A192CBC-HS384
* A256CBC-HS512
* A128GCM (default)
* A192GCM
* A256GCM

## License

The MIT License

* Copyright © 2016 Francesco Boffa

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
