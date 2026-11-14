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


class NoiseIdentityError(NoiseHandshakeError):
    """Raised when peer identity evidence is rejected or cannot be obtained."""
    pass


# Backwards/forwards friendly alias for callers that prefer the more explicit name.
NoisePeerIdentityError = NoiseIdentityError
