""" errors.py
"""

__all__ = ('PGPError',
           'PGPEncryptionError',
           'PGPDecryptionError',
           'PGPIncompatibleECPointFormatError',
           'PGPOpenSSLCipherNotSupportedError',
           'PGPInsecureCipherError',
           'BatchEncryptionError',
           'RecipientUnavailableError',
           'NoCommonAlgorithmError',
           'DuplicateRecipientError',
           'MessageAlreadyEncryptedError',
           'WontImplementError',)


class PGPError(Exception):
    """Raised as a general error in PGPy"""
    pass


class PGPEncryptionError(Exception):
    """Raised when encryption fails"""
    pass


class PGPDecryptionError(Exception):
    """Raised when decryption fails"""
    pass


class PGPIncompatibleECPointFormatError(Exception):
    """Raised when the point format is incompatible with the elliptic curve"""
    pass


class PGPOpenSSLCipherNotSupportedError(Exception):
    """Raised when OpenSSL does not support the requested cipher"""
    pass


class PGPInsecureCipherError(Exception):
    """Raised when a cipher known to be insecure is attempted to be used to encrypt data"""
    pass


class WontImplementError(NotImplementedError):
    """Raised when something that is not implemented, will not be implemented"""


class BatchEncryptionError(PGPEncryptionError):
    """Base class for failures that abort batch encryption before any ciphertext exists."""

    def __init__(self, message, details=None):
        super().__init__(message)
        self.details = {} if details is None else details


class RecipientUnavailableError(BatchEncryptionError):
    """Raised when a recipient has no usable, unexpired, unrevoked encryption key."""


class NoCommonAlgorithmError(BatchEncryptionError):
    """Raised when the recipients' authenticated preferences have no usable intersection."""


class DuplicateRecipientError(BatchEncryptionError):
    """Raised when the same recipient key is supplied in conflicting ways."""


class MessageAlreadyEncryptedError(BatchEncryptionError):
    """Raised when batch encryption is asked to alter an already-encrypted message."""
