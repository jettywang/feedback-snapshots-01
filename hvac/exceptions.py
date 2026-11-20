class VaultError(Exception):
    def __init__(
        self, message=None, errors=None, method=None, url=None, text=None, json=None
    ):
        if errors:
            message = ", ".join(errors)

        self.errors = errors
        self.method = method
        self.url = url
        self.text = text
        self.json = json

        super().__init__(message)

    def __str__(self):
        return f"{self.args[0]}, on {self.method} {self.url}"

    @classmethod
    def from_status(cls, status_code: int, *args, **kwargs):
        _STATUS_EXCEPTION_MAP = {
            400: InvalidRequest,
            401: Unauthorized,
            403: Forbidden,
            404: InvalidPath,
            429: RateLimitExceeded,
            500: InternalServerError,
            501: VaultNotInitialized,
            502: BadGateway,
            503: VaultDown,
        }

        return _STATUS_EXCEPTION_MAP.get(status_code, UnexpectedError)(*args, **kwargs)


class InvalidRequest(VaultError):
    pass


class Unauthorized(VaultError):
    pass


class Forbidden(VaultError):
    pass


class InvalidPath(VaultError):
    pass


class UnsupportedOperation(VaultError):
    pass


class PreconditionFailed(VaultError):
    pass


class RateLimitExceeded(VaultError):
    pass


class InternalServerError(VaultError):
    pass


class VaultNotInitialized(VaultError):
    pass


class VaultDown(VaultError):
    pass


class UnexpectedError(VaultError):
    pass


class BadGateway(VaultError):
    pass


class ParamValidationError(VaultError):
    pass


class SecureRedirectError(VaultError):
    """Base class for failures of the constrained internal failover logic."""


class UntrustedRedirectHost(SecureRedirectError):
    """Raised when a failover target is not part of the allowed Vault hosts."""


class RedirectLimitExceeded(SecureRedirectError):
    """Raised when a redirect chain is longer than the configured hop limit."""


class UnrecognizedProxyResponse(SecureRedirectError):
    """Raised when a redirect cannot be resolved (missing/invalid Location)."""
