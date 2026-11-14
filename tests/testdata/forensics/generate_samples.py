"""Generate deterministic read-only forensic OpenPGP samples.

Run from the repository root:

    python tests/testdata/forensics/generate_samples.py

The samples are hand-assembled from raw OpenPGP packet bytes (RFC 4880) so
that byte offsets and partial-length segments stay fully under control.
Nothing here is executed or decrypted; the files only contain marker,
unknown, compressed and literal packets.
"""
import os
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def new_length(length):
    if length < 192:
        return bytes([length])
    if length < 8384:
        value = length - 192
        return bytes([(value >> 8) + 192, value & 0xFF])
    return b'\xff' + length.to_bytes(4, 'big')


def new_packet(tag, body):
    return bytes([0xC0 | tag]) + new_length(len(body)) + body


def literal_packet(filename, text):
    name = filename.encode('utf-8')
    body = (b'b' + bytes([len(name)]) + name
            + b'\x00\x00\x00\x00' + text.encode('utf-8'))
    return new_packet(11, body)


def partial_literal_packet(text):
    """A new-format literal packet split across partial-length segments."""
    body = b'b' + b'\x00' + b'\x00\x00\x00\x00' + text.encode('utf-8')
    # force at least three segments: 512, 512, then a short final one
    assert len(body) > 1024
    first = body[:512]
    second = body[512:1024]
    rest = body[1024:]
    # 0xE9 -> partial length 2^(0xE9 & 0x1F) = 2^9 = 512
    return (bytes([0xCB]) + b'\xe9' + first
            + b'\xe9' + second
            + new_length(len(rest)) + rest)


def build_message():
    # two literal packets compressed together with ZLIB (algorithm 2)
    inner = (literal_packet('first.txt', 'first compressed literal')
             + literal_packet('second.txt', 'second compressed literal'))
    compressed = new_packet(8, bytes([2]) + zlib.compress(inner))

    marker = new_packet(10, b'PGP')          # Marker packet (tag 10)
    unknown = new_packet(16, b'\x01\x02')    # tag 16 is not defined by RFC 4880
    outer_literal = literal_packet('outer.txt', 'outer literal body')
    partial_literal = partial_literal_packet('P' * 1100)

    return {
        'marker': marker,
        'unknown': unknown,
        'compressed': compressed,
        'outer_literal': outer_literal,
        'partial_literal': partial_literal,
        'inner_first': literal_packet('first.txt', 'first compressed literal'),
        'inner_second': literal_packet('second.txt', 'second compressed literal'),
    }


def main():
    parts = build_message()
    clean = (parts['marker'] + parts['unknown'] + parts['compressed']
             + parts['outer_literal'] + parts['partial_literal'])

    clean_path = os.path.join(HERE, 'sample.marker-unknown-compressed-literals.pgp')
    with open(clean_path, 'wb') as handle:
        handle.write(clean)

    garbage_path = os.path.join(HERE, 'sample.trailing-garbage.pgp')
    with open(garbage_path, 'wb') as handle:
        handle.write(clean + b'\xde\xad\xbe\xef')

    print('wrote', clean_path, len(clean), 'bytes')
    print('wrote', garbage_path, len(clean) + 4, 'bytes')


if __name__ == '__main__':
    main()
