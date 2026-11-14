class MacaroonException(Exception):
    pass


class MacaroonInitException(MacaroonException):
    pass


class MacaroonVerificationFailedException(MacaroonException):
    pass


class MacaroonInvalidSignatureException(MacaroonVerificationFailedException):
    pass


class MacaroonUnmetCaveatException(MacaroonVerificationFailedException):
    pass


class MacaroonSerializationException(MacaroonException):
    pass


class MacaroonDeserializationException(MacaroonException):
    pass


class MacaroonAccessException(MacaroonException):
    pass


class MacaroonAccessCaveatException(MacaroonAccessException):
    pass


class MacaroonAccessContextException(MacaroonAccessException):
    pass
