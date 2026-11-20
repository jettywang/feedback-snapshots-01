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


class RevocationPlanError(VaultError):
    """Base class for revocation-plan validation or execution errors."""

    def __init__(self, message=None, *, plan=None, **kwargs):
        self.plan = plan
        super().__init__(message, **kwargs)

    def __str__(self):
        return str(self.args[0]) if self.args else self.__class__.__name__


class RevocationPlanNotApproved(RevocationPlanError):
    """The plan lacks a matching approval; no revocation request was sent."""


class RevocationPlanExpired(RevocationPlanError):
    """The plan is past its validity window; no revocation request was sent."""


class RevocationPlanNamespaceChanged(RevocationPlanError):
    """The client namespace no longer matches the approved namespace."""

    def __init__(self, message=None, *, plan=None, planned_namespace=None, actual_namespace=None, **kwargs):
        self.planned_namespace = planned_namespace
        self.actual_namespace = actual_namespace
        super().__init__(message, plan=plan, **kwargs)


class RevocationPlanScopeChanged(RevocationPlanError):
    """The observed prefix scope changed since the plan was approved."""

    def __init__(self, message=None, *, plan=None, added=(), removed=(), **kwargs):
        self.added = tuple(added)
        self.removed = tuple(removed)
        super().__init__(message, plan=plan, **kwargs)


class RevocationFailed(RevocationPlanError):
    """One or more targets were rejected; the receipt lists each outcome."""

    def __init__(self, message=None, *, plan=None, receipt=None, **kwargs):
        self.receipt = receipt
        super().__init__(message, plan=plan, **kwargs)


class RevocationOutcomeUnknown(RevocationPlanError):
    """A revocation request may have been applied; do not retry blindly."""

    def __init__(self, message=None, *, plan=None, receipt=None, verification_steps=(), **kwargs):
        self.receipt = receipt
        self.verification_steps = tuple(verification_steps)
        super().__init__(message, plan=plan, **kwargs)
