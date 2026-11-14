class Empty:
    pass


# Handshake pattern tokens
TOKEN_E = 'e'
TOKEN_S = 's'
TOKEN_EE = 'ee'
TOKEN_ES = 'es'
TOKEN_SE = 'se'
TOKEN_SS = 'ss'
TOKEN_PSK = 'psk'


# In bytes, as in Section 8 of specification (rev 32)
MAX_PROTOCOL_NAME_LEN = 255

MAX_MESSAGE_LEN = 65535

MAX_NONCE = 2 ** 64 - 1

# Length-prefixed framing used by the byte-stream adapter (see noise/stream.py).
# Every frame on the wire is a fixed-width big-endian length prefix followed by
# exactly that many bytes of payload. The declared length is validated against
# the size that the current phase can actually produce before any payload bytes
# are read off the stream.
LENGTH_PREFIX_BYTES = 4

# AEAD authentication tag appended to every encrypted Noise payload (Section 5.1).
TAG_LEN = 16

# Largest supported Diffie-Hellman public key (448) - used to size the
# handshake frame bound without hard-coding the negotiated DHLEN.
MAX_DH_LEN = 56

# Upper bound on a complete handshake message on the wire: one Noise message of
# MAX_MESSAGE_LEN plus at most two static-key tokens (each DHLEN + TAG).
MAX_HANDSHAKE_FRAME_LEN = MAX_MESSAGE_LEN + 2 * (MAX_DH_LEN + TAG_LEN)

# Transport frame: plaintext of at most MAX_MESSAGE_LEN plus its auth tag.
MAX_TRANSPORT_FRAME_LEN = MAX_MESSAGE_LEN + TAG_LEN
