from __future__ import annotations


class Error(Exception):
    pass


class FileNotFoundError(Error, FileNotFoundError):
    pass


class IsADirectoryError(Error, IsADirectoryError):
    pass


class NotADirectoryError(Error, NotADirectoryError):
    pass


class NotASymlinkError(Error):
    pass


class VolumeGroupError(Error):
    """Base class for volume group and firmlink related errors.

    Args:
        message: Human readable error message.
        scope: Optional description of the volume group scope that was inspected.
        details: Optional structured evidence about the failed operation.
    """

    def __init__(self, message: str = "", *, scope: object | None = None, details: dict | None = None):
        super().__init__(message)
        self.scope = scope
        self.details = details or {}


class FirmlinkError(VolumeGroupError):
    """Base class for firmlink mapping errors."""


class FirmlinkTargetError(FirmlinkError, FileNotFoundError):
    """Raised when a firmlink points to a target that can not be resolved."""


class FirmlinkConflictError(FirmlinkError):
    """Raised when the supplied firmlink mapping material is ambiguous."""


class VolumeGroupIdentityError(VolumeGroupError):
    """Raised when the volume group identity can not be established."""


class VolumeGroupRoleError(VolumeGroupError):
    """Raised when a volume does not have the expected role."""


class VolumeGroupMismatchError(VolumeGroupError):
    """Raised when the provided volumes do not belong to the same volume group."""


class VolumeGroupSelectionError(VolumeGroupError):
    """Raised when volume group candidates do not identify exactly one System/Data pair."""


class UnionSymlinkError(VolumeGroupError):
    """Base class for errors while resolving a symbolic link in a union view."""


class UnionSymlinkLoopError(UnionSymlinkError):
    """Raised when symbolic link resolution does not terminate."""


class UnionSymlinkTargetError(UnionSymlinkError, FileNotFoundError):
    """Raised when a symbolic link target does not exist in the volume group."""


class UnionPathTraversalError(UnionSymlinkError):
    """Raised when a path or link target would escape the volume group root."""


class UnionFileNotFoundError(VolumeGroupError, FileNotFoundError):
    """Raised when a path is not visible in the union view."""


class UnionNotADirectoryError(VolumeGroupError, NotADirectoryError):
    """Raised when a union path component is not a directory."""


class UnionVolumeUnavailableError(VolumeGroupError, FileNotFoundError):
    """Raised when a path requires a volume that was not provided to the union view."""


class UnionConflictError(VolumeGroupError):
    """Raised when a union path has more than one plausible backing entry."""
