# Forensic parsing samples

These fixtures are deliberately hand-assembled from raw RFC 4880 packet
bytes so that offsets and partial-length segments are fully deterministic.
Nothing in them is executable; there are no encrypted or signed payloads.

## Files

- `generate_samples.py` — regenerates the two `.pgp` fixtures deterministically.
- `sample.marker-unknown-compressed-literals.pgp` — outer packet order:
  1. Marker packet (tag 10, body `PGP`) — ignored by the high-level API.
  2. Unknown packet (tag 16, not defined by RFC 4880) — surfaced as opaque.
  3. Compressed Data packet (tag 8, ZLIB) containing two Literal Data packets
     in a separate, zero-based offset space.
  4. An outer Literal Data packet.
  5. A Literal Data packet encoded with new-format partial lengths
     (two 512-octet partial segments plus a final short segment).
- `sample.trailing-garbage.pgp` — the same bytes followed by four
  non-packet bytes (`de ad be ef`) that must remain visible in the report.

## How to verify

```python
from pgpy import forensic_scan

report = forensic_scan(open('sample.marker-unknown-compressed-literals.pgp', 'rb').read())
print(report.explain())
assert report.reassemble() == open('sample.marker-unknown-compressed-literals.pgp', 'rb').read()
```

The high-level `PGPMessage.from_blob(...)` raises on the unknown tag, while
`forensic_scan(...).high_level_message()` shows only the first literal that
the high-level loader actually accepts. Every other packet stays fully
accounted for in the forensic report.
