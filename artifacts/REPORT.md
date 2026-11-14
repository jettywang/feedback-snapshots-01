# OpenPGP literal metadata: what the sender actually signed

Reproduced offline against this repository's PGPy `0.6.0` and Python `3.12.11`.

## Why a renamed literal still verifies

PGPy's message verification pairs each signature with `PGPMessage.message`:

```python
for sig in _filter_sigs(subject.signatures):
    sspairs.append((sig, subject.message))   # pgpy/pgp.py
```

For a literal message `message` returns `LiteralData.contents` (`pgpy/pgp.py`), and `PGPSignature.hashdata` hashes exactly that subject for a binary-document signature (`pgpy/pgp.py`). The filename, timestamp, and format octet live in the same Literal Data packet but are read into separate attributes during parsing (`pgpy/packet/packets.py`). They are never appended to the hash context, so changing them cannot change the signature verdict.

The signature packet itself then adds a trailer containing only the version, signature type, key algorithm, hash algorithm, hashed subpacket area, and its length (`pgpy/pgp.py`). Unhashed subpackets such as `Issuer` sit outside that trailer. The MDC is computed over the decrypted plaintext and prefix inside the tag-18 container (`pgpy/packet/packets.py`), so it speaks about the container, not about who chose the filename.

## Method

Every case is audited as raw bytes. `tools/pgp_literal_audit.py` walks packet headers itself, records offsets and SHA-256 values, and reports two signature verdicts:

- `signature_math` - the signature packet checked over the literal octets as they appear on the wire.
- `signature_pgpy` - PGPy's high-level `PGPKey.verify`, which decodes text literals for display before hashing.

Splitting these apart is what prevents a display artefact from being misreported as a broken signer signature.

## signed-zip

Original bytes: 243 bytes, sha256 `fd352acc7525d6afd34356a73901a278056d5a8c873501f1e10bedf40725c224`.

| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |
| --- | --- | --- | --- | --- | --- | --- |
| `filename-same-length` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `filename-shortened` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `mtime-zeroed` | `literal.mtime` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.mtime; the change is invisible to both |
| `format-to-t` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `format-to-u` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `body-bitflip` | `literal.contents` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | sender document signature covers literal.contents; changing it breaks the signature over the literal octets |
| `compression-uncompressed` | `framing.compression` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `compression-zlib` | `framing.compression` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `signature-hashed-subpacket` | `signature.hashed-subpacket` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | signature.hashed-subpacket lives in the hashed region of the Signature packet, so the signature trailer no longer matches |
| `signature-unhashed-subpacket` | `signature.unhashed-subpacket` | PASS | FAIL | NOT-PRESENT | only-routing-affected | advisory routing hint outside the signed hash; the signature math over the literal octets still verifies |
| `signature-hash2` | `signature.hash2` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | quick check only; the signature math is unaffected |
| `armor-header` | `armor.headers` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | envelope metadata; armor headers are not hashed by the signature |
| `armor-crc` | `armor.crc24` | PASS | PASS | NOT-PRESENT | checksum-warning-only | unkeyed checksum: detects accidental corruption, trivially recomputed |


## signed-uncompressed

Original bytes: 241 bytes, sha256 `450218fcbf21c1251a58519a6c8bfaf278159423305bf042ce427930027b9108`.

| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |
| --- | --- | --- | --- | --- | --- | --- |
| `filename-same-length` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `filename-shortened` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `mtime-zeroed` | `literal.mtime` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.mtime; the change is invisible to both |
| `format-to-t` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `format-to-u` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `body-bitflip` | `literal.contents` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | sender document signature covers literal.contents; changing it breaks the signature over the literal octets |
| `signature-hashed-subpacket` | `signature.hashed-subpacket` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | signature.hashed-subpacket lives in the hashed region of the Signature packet, so the signature trailer no longer matches |
| `signature-unhashed-subpacket` | `signature.unhashed-subpacket` | PASS | FAIL | NOT-PRESENT | only-routing-affected | advisory routing hint outside the signed hash; the signature math over the literal octets still verifies |
| `signature-hash2` | `signature.hash2` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | quick check only; the signature math is unaffected |
| `armor-header` | `armor.headers` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | envelope metadata; armor headers are not hashed by the signature |
| `armor-crc` | `armor.crc24` | PASS | PASS | NOT-PRESENT | checksum-warning-only | unkeyed checksum: detects accidental corruption, trivially recomputed |


Signature packet: v4, type 0x00, hash 10, hashed subpackets `05025e0be100162104d396fe3105c7676c74de84760e79e47169aec37a`, unhashed subpackets `09100e79e47169aec37a`.

## signed-text

Original bytes: 232 bytes, sha256 `3015b9cb6b9b0b806ec8d8c40491235bc9c9229649eb27ca3b5c566c2b7dd4ad`.

| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |
| --- | --- | --- | --- | --- | --- | --- |
| `filename-same-length` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `filename-shortened` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `mtime-zeroed` | `literal.mtime` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.mtime; the change is invisible to both |
| `format-to-b` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `format-to-u` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `body-bitflip` | `literal.contents` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | sender document signature covers literal.contents; changing it breaks the signature over the literal octets |
| `compression-uncompressed` | `framing.compression` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `compression-zlib` | `framing.compression` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `signature-hashed-subpacket` | `signature.hashed-subpacket` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | signature.hashed-subpacket lives in the hashed region of the Signature packet, so the signature trailer no longer matches |
| `signature-unhashed-subpacket` | `signature.unhashed-subpacket` | PASS | FAIL | NOT-PRESENT | only-routing-affected | advisory routing hint outside the signed hash; the signature math over the literal octets still verifies |
| `signature-hash2` | `signature.hash2` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | quick check only; the signature math is unaffected |
| `armor-header` | `armor.headers` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | envelope metadata; armor headers are not hashed by the signature |
| `armor-crc` | `armor.crc24` | PASS | PASS | NOT-PRESENT | checksum-warning-only | unkeyed checksum: detects accidental corruption, trivially recomputed |


## signed-nonascii-binary

Original bytes: 232 bytes, sha256 `964359b0cdbcc51659a26778bae9d2e935ea2f34ccf0ef50ebb251248e628e5a`.

| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |
| --- | --- | --- | --- | --- | --- | --- |
| `filename-same-length` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `filename-shortened` | `literal.filename` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `mtime-zeroed` | `literal.mtime` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | neither the document signature nor the MDC binds literal.mtime; the change is invisible to both |
| `format-to-t` | `literal.format` | PASS | FAIL | NOT-PRESENT | display-artifact-only | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `format-to-u` | `literal.format` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `body-bitflip` | `literal.contents` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | sender document signature covers literal.contents; changing it breaks the signature over the literal octets |
| `compression-uncompressed` | `framing.compression` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `compression-zlib` | `framing.compression` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `signature-hashed-subpacket` | `signature.hashed-subpacket` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | signature.hashed-subpacket lives in the hashed region of the Signature packet, so the signature trailer no longer matches |
| `signature-unhashed-subpacket` | `signature.unhashed-subpacket` | PASS | FAIL | NOT-PRESENT | only-routing-affected | advisory routing hint outside the signed hash; the signature math over the literal octets still verifies |
| `signature-hash2` | `signature.hash2` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | quick check only; the signature math is unaffected |
| `armor-header` | `armor.headers` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | envelope metadata; armor headers are not hashed by the signature |
| `armor-crc` | `armor.crc24` | PASS | PASS | NOT-PRESENT | checksum-warning-only | unkeyed checksum: detects accidental corruption, trivially recomputed |


## encrypted

Original bytes: 558 bytes, sha256 `2451cd894e1d75e0e49ad50e5320e5970d1c2874c4c5f5e17ea5a2499feab55f`.

| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |
| --- | --- | --- | --- | --- | --- | --- |
| `filename-same-length` | `literal.filename` | PASS | PASS | PASS | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `filename-shortened` | `literal.filename` | PASS | PASS | PASS | undetected-by-any-layer | neither the document signature nor the MDC binds literal.filename; the change is invisible to both |
| `mtime-zeroed` | `literal.mtime` | PASS | PASS | PASS | undetected-by-any-layer | neither the document signature nor the MDC binds literal.mtime; the change is invisible to both |
| `format-to-t` | `literal.format` | PASS | PASS | PASS | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `format-to-u` | `literal.format` | PASS | PASS | PASS | undetected-by-any-layer | format is outside the signed octets; the raw signed bytes still verify, but a decoder may re-encode what it displays |
| `body-bitflip` | `literal.contents` | FAIL | FAIL | PASS | detected-by-document-signature | sender document signature covers literal.contents; changing it breaks the signature over the literal octets |
| `compression-uncompressed` | `framing.compression` | PASS | PASS | PASS | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `compression-zlib` | `framing.compression` | PASS | PASS | PASS | undetected-by-any-layer | outer framing only; the document signature covers literal data, not the wrapper |
| `armor-header` | `armor.headers` | PASS | PASS | PASS | undetected-by-any-layer | envelope metadata; armor headers are not hashed by the signature |
| `armor-crc` | `armor.crc24` | PASS | PASS | PASS | checksum-warning-only | unkeyed checksum: detects accidental corruption, trivially recomputed |
| `ciphertext-bitflip` | `container.ciphertext` | NOT-REACHABLE | NOT-REACHABLE | FAIL | detected-by-mdc-integrity | MDC integrity covers the container ciphertext |
| `filename-stale-mdc` | `literal.filename` | NOT-REACHABLE | NOT-REACHABLE | FAIL | detected-by-mdc-integrity | MDC rejects a stale container: integrity of the envelope, not sender authentication |


## detached

Original bytes: 181 bytes, sha256 `3ecb4b01aa14e9551372b704839773896f8c0c649910065b4ba4fd241ad665af`.

| mutation | field | signature math | PGPy verify | MDC | verdict | attribution |
| --- | --- | --- | --- | --- | --- | --- |
| `detached-subject` | `detached.subject` | FAIL | FAIL | NOT-PRESENT | detected-by-document-signature | detached signature verifies over supplied bytes; the literal packet never existed in this composition |
| `armor-header` | `armor.headers` | PASS | PASS | NOT-PRESENT | undetected-by-any-layer | envelope metadata; armor headers are not hashed by the signature |
| `armor-crc` | `armor.crc24` | PASS | PASS | NOT-PRESENT | checksum-warning-only | unkeyed checksum: detects accidental corruption, trivially recomputed |


Signature packet: v4, type 0x00, hash 10, hashed subpackets `05025e0be100162104d396fe3105c7676c74de84760e79e47169aec37a`, unhashed subpackets `09100e79e47169aec37a`.

## Which layer each change hits

| change | document signature | MDC container | armor |
| --- | --- | --- | --- |
| literal body | detected | resealed: passes | unchanged |
| literal filename | passes | resealed: passes | unchanged |
| literal timestamp | passes | resealed: passes | unchanged |
| literal format flag | passes over signed octets | passes | unchanged |
| compression wrapper | passes | passes | unchanged |
| armor header line | passes | passes | unprotected |
| armor CRC-24 | passes | passes | unkeyed checksum only |
| ciphertext bit | not reachable | detected | unchanged |
| hashed subpacket | detected | n/a | unchanged |
| unhashed Issuer hint | routing only | n/a | unchanged |

The first column is a claim about coverage, not about implementation quality. OpenPGP never promised to bind literal metadata, so an unchanged verdict there is conformant behaviour.

## Separate PGPy text-literal defect (not field tampering)

Artifact `artifacts/signed-text-nonascii.asc` stores a non-ASCII body with format flag `t`.

- PGPy high-level verify: `PASS`
- Signature over the raw signed octets: `FAIL`
- GnuPG: `BAD`

PGPSignature.hashdata encodes a str subject as UTF-8; PGPMessage.message decodes a t literal as latin-1.  PGPy therefore signs and verifies over double-encoded bytes, so its own check passes. Verifiers hashing the literal octets on the wire - including this audit signature_math path and GnuPG - reject the artifact. This is a PGPy text-literal defect, not evidence that literal metadata is signed.

Read the direction carefully: PGPy signs and verifies through the same lossy decode/re-encode path, so its PASS is a tool artefact. A conformant verifier hashing the octets on the wire rejects the artifact (raw-octet math FAIL, GnuPG BAD). This is reported apart from the mutation matrix so it is never mistaken for literal-metadata tampering.

## GnuPG cross-check

| case | mutation | PGPy signature math | GnuPG |
| --- | --- | --- | --- |
| signed-zip | baseline | PASS | GOOD |
| signed-zip | filename | PASS | GOOD |
| signed-zip | body | FAIL | BAD |
| signed-zip | armor-crc | PASS (warning: Incorrect crc24) | NODATA (refuses bad CRC) |
| signed-text | format-to-binary | PASS | GOOD |
| encrypted | baseline | PASS | blocked-by-environment |

## Field policy for archive display and safe landing

| field | authenticated by | display | landing |
| --- | --- | --- | --- |
| `literal.contents` | sender document signature | may be shown as authenticated; bind it to the original packet hash | write the literal body (or its hash) as the canonical artefact |
| `literal.filename` | none | untrusted hint; never use as a path, a filename, or a trust input; show the packet hash instead | discard, or store next to the signed packet hash with an explicit unauthenticated label |
| `literal.filename` | none (the MDC covers only the container) | untrusted hint; a resealed container passes the MDC, so an MDC failure means tamper, not signer intent | store beside the signed body with an explicit unauthenticated label; never derived from the literal packet |
| `literal.format` | none | untrusted hint; never use as a path, a filename, or a trust input; show the packet hash instead | discard, or store next to the signed packet hash with an explicit unauthenticated label |
| `literal.mtime` | none | untrusted hint; never use as a path, a filename, or a trust input; show the packet hash instead | discard, or store next to the signed packet hash with an explicit unauthenticated label |

Concretely:

- Store the original packet bytes and their SHA-256. Display values are derived views, never the record of truth.
- When a filename is needed for the archive, derive it from a trusted index or from the signed body hash, not from the literal packet. Sanitize it as hostile input: basename only, no path separators, no leading dot, length-capped.
- Show the format flag and timestamp as metadata with an unauthenticated badge. Do not use the format flag to pick a parser that then feeds a trust decision.
- Never surface "MDC OK" as "signature OK". Two different checks with two different keys: the MDC uses the session key, the signature uses the signer's key.
- Record both verdicts separately in the archive manifest so a later reviewer can tell envelope integrity from signer intent.

## What this report does not claim

- MDC integrity is not sender authentication of literal.filename.
- Do not describe a literal filename, timestamp, or format flag as signed.
- Do not call the signature algorithm broken when a field it never covered is changed; check signature_math before making that claim.
- Do not describe the MDC as authenticating a filename.
- A literal field that changes without breaking the signature is not evidence that the signature algorithm failed. The field was never inside the signed data.
