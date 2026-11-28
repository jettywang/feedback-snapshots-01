# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Concrete credentials for the three marker interfaces used by the example.
"""

from __future__ import annotations

import hmac

from zope.interface import implementer

from .interfaces import (
    IAppPasswordCredentials,
    IAppTokenCredentials,
    IServiceTicketCredentials,
)


class _SecretCredentials:
    def __init__(self, username: bytes, secret: bytes) -> None:
        self.username = username
        self.password = secret

    def checkPassword(self, password: bytes) -> bool:
        return hmac.compare_digest(password, self.password)


@implementer(IAppPasswordCredentials)
class AppPassword(_SecretCredentials):
    """
    Internal username/password credentials.
    """


@implementer(IAppTokenCredentials)
class AppToken(_SecretCredentials):
    """
    Partner-issued username/token credentials.
    """


@implementer(IServiceTicketCredentials)
class ServiceTicket(_SecretCredentials):
    """
    A ticket handed to the never-resolving cancellation checker.
    """
