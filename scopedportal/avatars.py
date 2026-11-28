# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Avatar aspects returned by L{scopedportal.realm.InMemoryScopedRealm}.

A single session (L{SessionAvatar}) backs one or more aspect objects.  Each
aspect implements exactly one resource interface and exposes only the
capabilities the backing identity proved; asking an aspect for a wider
interface is the realm's job to refuse before the aspect is ever created.
"""

from __future__ import annotations

from zope.interface import implementer

from .identity import ScopedIdentity
from .interfaces import IAdmin, ILegacyAvatar, IReader, IWriter


class SessionAvatar:
    """
    Per-login session state shared by every aspect of one identity.
    """

    def __init__(self, identity: ScopedIdentity) -> None:
        self.identity = identity
        self.attached = True
        self.data = b"initial contents"

    def logout(self) -> None:
        self.attached = False


@implementer(IReader)
class ReaderAspect:
    def __init__(self, session: SessionAvatar) -> None:
        self.identity = session.identity
        self._session = session

    def read(self) -> bytes:
        return self._session.data


@implementer(IWriter)
class WriterAspect:
    def __init__(self, session: SessionAvatar) -> None:
        self.identity = session.identity
        self._session = session

    def write(self, payload: bytes) -> None:
        self._session.data = payload


@implementer(IAdmin)
class AdminAspect:
    def __init__(self, session: SessionAvatar, auditLog: list[str]) -> None:
        self.identity = session.identity
        self._session = session
        self._auditLog = auditLog

    def auditLog(self) -> list[str]:
        return list(self._auditLog)


@implementer(ILegacyAvatar)
class LegacyAspect:
    def __init__(self, session: SessionAvatar) -> None:
        self.identity = session.identity
        self._session = session

    def displayName(self) -> bytes:
        return self._session.identity.avatarId
