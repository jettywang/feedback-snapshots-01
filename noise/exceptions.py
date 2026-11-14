class NoiseProtocolNameError(Exception):
    pass


class NoisePSKError(Exception):
    pass


class NoiseValueError(Exception):
    pass


class NoiseHandshakeError(Exception):
    pass


class NoiseInvalidMessage(Exception):
    pass


class NoiseMaxNonceError(Exception):
    pass


class NoiseValidationError(Exception):
    pass


class NoiseStreamError(Exception):
    """Base class for failures raised by the byte-stream adapter."""
    pass


class NoiseFrameTooLargeError(NoiseStreamError):
    """A length prefix advertised more bytes than the current phase allows."""
    pass


class NoiseTruncatedError(NoiseStreamError):
    """The stream ended (EOF) in the middle of an advertised frame."""
    pass


class NoiseStreamClosedError(NoiseStreamError):
    """An operation was attempted on a stream that was torn down after an error."""
    pass
