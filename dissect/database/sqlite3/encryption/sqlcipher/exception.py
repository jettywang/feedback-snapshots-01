from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.exception import Error

if TYPE_CHECKING:
    from dissect.database.sqlite3.encryption.sqlcipher.auth import PageAuthentication


class SQLCipherError(Error):
    pass


class PageAuthenticationError(SQLCipherError):
    """Raised when a page fails authentication in strict authentication mode.

    The error carries the secret-free page authentication result and deliberately contains no
    passphrase, key material or digest values.
    """

    def __init__(self, page_number: int, authentication: PageAuthentication | None = None):
        self.page_number = page_number
        self.authentication = authentication
        super().__init__(f"Authentication failed for page {page_number}")
