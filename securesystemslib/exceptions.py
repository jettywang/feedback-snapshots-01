"""
<Program Name>
  exceptions.py

<Author>
  Geremy Condra
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  VD: April 4, 2012 Revision.

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Define exceptions.  The names chosen for exception classes should end in
  'Error' (except where there is a good reason not to).
"""


class Error(Exception):
    """Indicate a generic error."""


class FormatError(Error):
    """Indicate an error while validating an object's format."""


class UnsupportedAlgorithmError(Error):
    """Indicate an error while trying to identify a user-specified algorithm."""


class UnsupportedLibraryError(Error):
    """Indicate that a supported library could not be located or imported."""


class KeyMismatchError(ValueError):
    """Indicate that a private key does not match the expected public key."""


class StorageError(Error):
    """Indicate an error occured during interaction with an abstracted storage
    backend."""


class UnverifiedSignatureError(Error):
    """Signature could not be verified: either signature was incorrect or
    something failed during process (see VerificationError)"""


class VerificationError(UnverifiedSignatureError):
    """Signature could not be verified because something failed in the process"""


class EnvelopeMergeError(Error):
    """Indicate that DSSE envelopes could not be co-signed.

    The incomplete audit trail describing why the merge was rejected is
    available on the exception as ``report``. No merged envelope is produced
    and no input is modified when this error is raised.
    """

    def __init__(self, message: str, report: object | None = None):
        super().__init__(message)
        self.report = report
