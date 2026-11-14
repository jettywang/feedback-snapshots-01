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


class DischargeRoutingException(MacaroonException):
    pass


class UnknownDischargeService(DischargeRoutingException):
    pass


class AmbiguousDischargeCaveat(DischargeRoutingException):
    pass


class DischargeRequestException(DischargeRoutingException):
    pass


class UnsafeDischargeTransport(DischargeRequestException):
    pass


class DischargeRedirectRefused(DischargeRequestException):
    pass


class InvalidDischargeResponse(DischargeRequestException):
    pass
