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


class StalePermissionStateError(GuardianError):
    """Raised when an optimistic permission snapshot no longer matches the database.

    The caller submitted the permission set it expected to replace, but another
    write changed the object's permissions in the meantime. The whole submission
    is rejected and no permission row is modified.
    """

    pass
