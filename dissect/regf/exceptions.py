from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.regf.regf import LinkHop, RegistryLink


class Error(Exception):
    pass


class RegistryKeyNotFoundError(Error):
    pass


class RegistryValueNotFoundError(Error):
    pass


class RegistryLinkError(Error):
    """Base class for errors encountered while resolving a registry link.

    The offending :class:`~dissect.regf.regf.RegistryLink` evidence is always
    preserved on ``link`` and every link already traversed is kept in ``hops``,
    so callers never lose the on-disk evidence when a target cannot be
    resolved.
    """

    def __init__(self, message: str, link: RegistryLink | None = None):
        super().__init__(message)
        self.link = link
        self.hops: tuple[LinkHop, ...] = ()

    def with_hops(self, hops: Iterable[LinkHop]) -> RegistryLinkError:
        self.hops = tuple(hops)
        return self


class InvalidLinkError(RegistryLinkError):
    """A key looks like a link but its value type or target encoding is invalid."""


class MountNotFoundError(RegistryLinkError):
    """A link points at a hive that the caller did not provide a mount for."""


class LinkTargetNotFoundError(RegistryLinkError):
    """The mounted target hive does not contain the path the link points at."""


class LinkLoopError(RegistryLinkError):
    """Following the links revisits a cell, forming a resolution loop."""
