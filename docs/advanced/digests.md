# Response Digests

HTTPX can optionally verify a response body against a digest that the caller
supplies. Verification is opt-in, and the trusted digest is always a caller
input. HTTPX does **not** treat `Content-Digest`, `Content-MD5`, or any other
response header as an authenticated digest, and a matching `Content-Length`
does not prove that the body is authentic.

## Verifying a response

Use `response.verify_digest(...)` with an explicit scope:

* `scope="raw"` covers the encoded body as received on the wire, before any
  `Content-Encoding` decoding.
* `scope="decoded"` covers the body after `Content-Encoding` decoding, which is
  the same body that `response.content` exposes.

```python
import hashlib

import httpx

expected = "16354af4c309138a0d84405ca83e0c5c47ec65c89e66b7cf752546437b3162b5"

with httpx.Client() as client:
    with client.stream("GET", "https://example.org/data") as response:
        verifier = response.verify_digest(expected, scope="raw")
        with verifier:
            for chunk in verifier.iter_bytes():
                handle(chunk)
        verifier.require_verified()
```

Both hexadecimal and base64 digests are accepted. Supply `algorithm=` when the
digest value does not include an algorithm prefix:

```python
verifier = response.verify_digest(digest_bytes, scope="decoded", algorithm="sha256")
```

A prefixed value such as `"sha256=<hex>"` is also accepted. The algorithm must
correspond to a hash supported by Python's `hashlib`.

## Verification status

The returned `DigestVerifier` starts in `DigestStatus.PENDING`. Status changes
only after the complete promised range has been consumed and compared:

* `PENDING`: not yet fully consumed.
* `VERIFIED`: the complete byte range was consumed and matched.
* `MISMATCH`: the complete range was consumed but did not match.
* `INCOMPLETE`: the stream ended early, was cancelled, or the raw bytes were no
  longer available.
* `ERROR`: decoding failed while verifying a decoded digest.

A verifier can be consumed with `read()`, `aread()`, `iter_bytes()` or
`aiter_bytes()`. The decoded body is cached on the response only after a
successful verification. Partial or unverified content is never written to
`response.content`.

Use `require_verified()` to turn any non-verified state into an exception.
`DigestMismatchError` indicates that the digest did not match, while
`DigestIncompleteError` indicates that the promised range was not fully
covered. Decoding failures surface as `DecodingError`, with the verifier's
status set to `ERROR`.

## Streaming and cancellation

A streaming response can only be consumed once. When verification is used, the
verifier must be the only consumer. If iteration is abandoned, use a
`with verifier:` or `async with verifier:` block, or call `abort()`/`aclose()`.
Leaving the block marks a still-pending verifier as `INCOMPLETE` and closes the
response.

```python
with client.stream("GET", url) as response:
    verifier = response.verify_digest(expected, scope="decoded")
    with verifier:
        for chunk in verifier.iter_bytes():
            if should_stop(chunk):
                break
```

In this example the verifier ends as `INCOMPLETE`, and the partial body is not
available from `response.content`.

## Raw digests

Raw digests cover encoded bytes, so they differ from decoded digests for
compressed responses. Raw bytes are retained for responses created from an
in-memory body. For streaming responses the encoded bytes are available while
the body is being consumed.

If a response has already been streamed and decoded, the raw body is no longer
available. In that case a raw verifier reports `INCOMPLETE` rather than
pretending that any remaining bytes cover the original encoded body.

```python
verifier = response.verify_digest(raw_digest, scope="raw")
print(verifier.status)   # DigestStatus.INCOMPLETE
verifier.require_verified()  # raises DigestIncompleteError
```

## Decoding failures

For decoded digests, `scope="decoded"` also waits for the content decoder to
report a complete encoded stream. A truncated gzip body that happens to decode
to a matching prefix is therefore reported as `INCOMPLETE`, not `VERIFIED`.
