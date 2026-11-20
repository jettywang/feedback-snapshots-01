"""
Exceptions used by django-guardian. All internal and guardian-specific errors
should extend GuardianError class.
"""


class GuardianError(Exception):
    """Base class for all guardian-specific exceptions."""

    pass


class NotUserNorGroup(GuardianError):
    """Raised when an object is neither User nor Group."""

    pass


class ObjectNotPersisted(GuardianError):
    """Raised when the object has not been saved to the database."""

    pass


class WrongAppError(GuardianError):
    """Raised when the app name for a permission is incorrect."""

    pass


class MixedContentTypeError(GuardianError):
    """Raised when content type for the provided permissions and/or class do not match."""

    pass


class MultipleIdentityAndObjectError(GuardianError):
    """Raised when an operation is attempted on both user/group and object."""

    pass


class VisitorNotConfigured(GuardianError):
    """Raised when a request is marked as a visitor but no valid visitor account is available."""

    pass


class PrincipalSwitchDenied(GuardianError):
    """Raised when switching an authenticated identity to a visitor lacks confirmation."""

    pass
