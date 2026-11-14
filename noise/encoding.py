import struct


def encode_bytes(value):
    """Encode a byte string with an explicit big-endian length prefix."""
    return struct.pack('>I', len(value)) + value


def encode_bytes_list(values):
    """Encode a list of byte strings without relying on delimiters."""
    return struct.pack('>I', len(values)) + b''.join(encode_bytes(value) for value in values)


class Decoder(object):
    """Small cursor for the length-prefixed encodings used by this package."""

    def __init__(self, data):
        self.data = bytes(data)
        self.offset = 0

    @property
    def remaining(self):
        return len(self.data) - self.offset

    def read_exact(self, length):
        if length < 0 or length > self.remaining:
            raise ValueError('Truncated or malformed byte sequence')
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def read_u8(self):
        return self.read_exact(1)[0]

    def read_u32(self):
        return struct.unpack('>I', self.read_exact(4))[0]

    def read_bytes(self):
        return self.read_exact(self.read_u32())

    def read_bytes_list(self):
        count = self.read_u32()
        # Every element has at least a four byte length prefix. This bound
        # avoids allocation or long loops for malformed inputs.
        if count > self.remaining // 4:
            raise ValueError('Malformed list length')
        return [self.read_bytes() for _ in range(count)]

    def ensure_exhausted(self):
        if self.remaining:
            raise ValueError('Trailing bytes after encoded value')
