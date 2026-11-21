#
# p7zr library
#
# Copyright (c) 2019 Hiroshi Miura <miurahr@linux.com>
# Copyright (c) 2004-2015 by Joachim Bauch, mail@joachim-bauch.de
# 7-Zip Copyright (C) 1999-2010 Igor Pavlov
# LZMA SDK Copyright (C) 1999-2010 Igor Pavlov
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#


from __future__ import annotations

import os
from typing import Any


class ArchiveError(Exception):
    """Base class for exceptions."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class Bad7zFile(ArchiveError):
    """Raised when a file is not a valid 7z archive or its headers are malformed."""


class InvalidPasswordError(Bad7zFile):
    """Raised when an encrypted archive cannot be decoded with the password.

    The password may be wrong, or an encrypted header may have been damaged.
    The archive path is kept on :attr:`path` so callers can report which
    artifact failed without parsing the message.
    """

    def __init__(self, message: str, *, path: str | os.PathLike[str] | None = None) -> None:
        super().__init__(message)
        self.path = path

    def __str__(self) -> str:
        message = super().__str__()
        if self.path is not None:
            return f"{os.fspath(self.path)}: {message}"
        return message


class CrcError(ArchiveError):
    """Exception raised for CRC error when decompression.

    Attributes:
      expected -- expected CRC bytes
      actual -- actual CRC data
      filename -- filename that has CRC error
    """

    def __init__(self, expected: Any, actual: Any, filename: Any) -> None:
        super().__init__(expected, actual, filename)
        self.expected = expected
        self.actual = actual
        self.filename = filename


class UnsupportedCompressionMethodError(ArchiveError):
    """Exception raised for unsupported compression parameter given.

    Attributes:
      data -- unknown property data
      message -- explanation of error
    """

    def __init__(self, data: Any, message: Any) -> None:
        super().__init__(data, message)
        self.data = data
        self.message = message


class DecompressionError(ArchiveError):
    """Raised when extraction fails, for example when a directory cannot be created."""


class InternalError(ArchiveError):
    """Raised on an unexpected internal state; indicates a bug in py7zr."""


class PasswordRequired(Exception):
    """Raised when reading or writing an encrypted archive without a password."""


class ProtectionRequired(ArchiveError):
    """Raised when an archive does not satisfy a required protection policy.

    The exception carries machine-readable context so callers can point at the
    archive and the unmet requirement without parsing the message:

    :ivar path: The archive path as given by the caller, or ``None`` when the
        archive came from a file-like object.
    :ivar missing: A tuple of requirement names that were not met. Current
        names are ``"password"`` (a password is needed), ``"header_encryption"``
        (member names and the directory must be hidden) and
        ``"content_encryption"`` (member data must be encrypted).
    :ivar detail: A human-readable explanation.
    """

    def __init__(
        self,
        message: str,
        *,
        path: str | os.PathLike[str] | None = None,
        missing: tuple[str, ...] = (),
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.missing = missing
        self.detail = detail if detail is not None else message

    def __str__(self) -> str:
        location = os.fspath(self.path) if self.path is not None else "<file-like archive>"
        if self.missing:
            return f"{location}: {self.detail} (missing: {', '.join(self.missing)})"
        return f"{location}: {self.detail}"


class ProtectionWarning(UserWarning):
    """Emitted when an operation cannot be made protected and falls back."""


class DecompressionBombError(ArchiveError):
    """Exception raised when decompressed size exceeds the configured limit."""

    pass


class AbsolutePathError(Exception):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
