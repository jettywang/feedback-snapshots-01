"""
Errors, oh no!
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Any

import attrs

from referencing._attrs import frozen

if TYPE_CHECKING:
    from referencing import Resource
    from referencing.typing import URI


@frozen
class NoSuchResource(KeyError):
    """
    The given URI is not present in a registry.

    Unlike most exceptions, this class *is* intended to be publicly
    instantiable and *is* part of the public API of the package.
    """

    ref: URI

    def __eq__(self, other: object) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        return attrs.astuple(self) == attrs.astuple(other)

    def __hash__(self) -> int:
        return hash(attrs.astuple(self))


@frozen
class NoInternalID(Exception):
    """
    A resource has no internal ID, but one is needed.

    E.g. in modern JSON Schema drafts, this is the :kw:`$id` keyword.

    One might be needed if a resource was to-be added to a registry but no
    other URI is available, and the resource doesn't declare its canonical URI.
    """

    resource: Resource[Any]

    def __eq__(self, other: object) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        return attrs.astuple(self) == attrs.astuple(other)

    def __hash__(self) -> int:
        return hash(attrs.astuple(self))


@frozen
class Unretrievable(KeyError):
    """
    The given URI is not present in a registry, and retrieving it failed.
    """

    ref: URI

    def __eq__(self, other: object) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        return attrs.astuple(self) == attrs.astuple(other)

    def __hash__(self) -> int:
        return hash(attrs.astuple(self))


@frozen
class CannotDetermineSpecification(Exception):
    """
    Attempting to detect the appropriate `Specification` failed.

    This happens if no discernible information is found in the contents of the
    new resource which would help identify it.
    """

    contents: Any

    def __eq__(self, other: object) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        return attrs.astuple(self) == attrs.astuple(other)

    def __hash__(self) -> int:
        return hash(attrs.astuple(self))


@attrs.frozen  # Because here we allow subclassing below.
class Unresolvable(Exception):
    """
    A reference was unresolvable.
    """

    ref: URI

    def __eq__(self, other: object) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        return attrs.astuple(self) == attrs.astuple(other)

    def __hash__(self) -> int:
        return hash(attrs.astuple(self))


@frozen
class PointerToNowhere(Unresolvable):
    """
    A JSON Pointer leads to a part of a document that does not exist.
    """

    resource: Resource[Any]

    def __str__(self) -> str:
        msg = f"{self.ref!r} does not exist within {self.resource.contents!r}"
        if self.ref == "/":
            msg += (
                ". The pointer '/' is a valid JSON Pointer but it points to "
                "an empty string property ''. If you intended to point "
                "to the entire resource, you should use '#'."
            )
        return msg


@frozen
class NoSuchAnchor(Unresolvable):
    """
    An anchor does not exist within a particular resource.
    """

    resource: Resource[Any]
    anchor: str

    def __str__(self) -> str:
        return (
            f"{self.anchor!r} does not exist within {self.resource.contents!r}"
        )


@frozen
class InvalidAnchor(Unresolvable):
    """
    An anchor which could never exist in a resource was dereferenced.

    It is somehow syntactically invalid.
    """

    resource: Resource[Any]
    anchor: str

    def __str__(self) -> str:
        return (
            f"'#{self.anchor}' is not a valid anchor, neither as a "
            "plain name anchor nor as a JSON Pointer. You may have intended "
            f"to use '#/{self.anchor}', as the slash is required *before each "
            "segment* of a JSON pointer."
        )


class FailureCategory(StrEnum):
    """
    An actionable category for a failure to resolve a reference.

    These values are safe to return to a caller outside the service which
    performed resolution: they describe *what* went wrong without including
    reference URIs, schema contents, or messages from the underlying
    exception.
    """

    #: Retrieval of a referenced resource was unavailable or failed.
    RETRIEVAL_UNAVAILABLE = "retrieval_unavailable"

    #: A JSON pointer did not exist within a retrieved resource.
    POINTER_NOT_FOUND = "pointer_not_found"

    #: An anchor was not found, or did not match within a resource.
    ANCHOR_NOT_FOUND = "anchor_not_found"


class ResolutionStage(StrEnum):
    """
    The internal resolution stage at which a reference failed.

    Unlike `FailureCategory`, these are intended for diagnostics *inside* the
    service which performed resolution and may distinguish failures which
    share a public category.
    """

    #: Looking up or retrieving the resource which a reference identified.
    RETRIEVAL = "retrieval"

    #: Resolving a JSON pointer within a resource which was found.
    POINTER = "pointer"

    #: Resolving an anchor within a resource which was found.
    ANCHOR = "anchor"

    #: Determining the specification of a retrieved resource.
    SPECIFICATION = "specification"


@attrs.frozen(init=False)
class ResolutionFailure(Exception):
    """
    A sanitized representation of a failure to resolve a reference.

    The string representation of this exception contains only its
    `category`, which is safe to expose to a caller of a service which
    resolves references (e.g. a schema validation service).

    The original exception is retained as ``__cause__``, so in-process
    diagnostics (e.g. logs or a traceback) can still locate the precise
    failure, including its reference and underlying exception. The `stage`
    additionally identifies the internal resolution phase which failed.

    Use `ResolutionFailure.from_exception` to create one from an exception
    raised while resolving a reference.
    """

    category: FailureCategory
    stage: ResolutionStage = attrs.field(repr=False)
    original: BaseException | None = attrs.field(
        default=None,
        repr=False,
        eq=False,
    )

    def __init__(
        self,
        category: FailureCategory,
        stage: ResolutionStage,
        original: BaseException | None = None,
    ) -> None:
        Exception.__init__(self, category)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "stage", stage)
        object.__setattr__(self, "original", original)
        if original is not None:
            object.__setattr__(self, "__cause__", original)
            object.__setattr__(self, "__suppress_context__", True)

    def __str__(self) -> str:
        return str(self.category)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(category={self.category!r})"

    def __eq__(self, other: object) -> bool:
        if self.__class__ is not other.__class__:
            return NotImplemented
        assert isinstance(other, ResolutionFailure)
        return self.category == other.category and self.stage == other.stage

    def __hash__(self) -> int:
        return hash((self.category, self.stage))

    def as_dict(self) -> dict[str, str]:
        """
        Return a representation safe for returning to an external caller.

        Only the public category is included.
        """
        return {"category": str(self.category)}

    def __reduce__(self) -> tuple[type[ResolutionFailure], tuple[Any, ...]]:
        # Do not include the original exception when serializing, and ensure
        # the required stage survives a round trip.
        return (self.__class__, (self.category, self.stage))

    @classmethod
    def from_exception(
        cls,
        error: BaseException,
        /,
        *,
        stage: ResolutionStage | None = None,
    ) -> ResolutionFailure:
        """
        Create a sanitized failure from an exception raised during resolution.

        The original exception is retained as ``__cause__``.

        Args:
            error: The exception to sanitize.
            stage: The resolution stage, if not inferable from ``error``
                (or its cause chain).

        Raises:
            TypeError: if no resolution stage can be determined.

        """
        if stage is None:
            stage = _stage_of(error)
        if stage is None:
            raise TypeError(
                f"{type(error).__name__} is not a resolution failure",
            )
        return cls(
            category=_CATEGORY_OF[stage],
            stage=stage,
            original=error,
        )


def _stage_of(error: BaseException) -> ResolutionStage | None:
    """
    Determine the resolution stage of an exception.
    """
    for cls, stage in _STAGE_OF.items():
        if isinstance(error, cls):
            return stage

    # A bare Unresolvable is how lookup reports a resource which could not be
    # found or retrieved at all, i.e. a failure during retrieval.
    if isinstance(error, Unresolvable):
        return ResolutionStage.RETRIEVAL
    return None


_CATEGORY_OF = {
    ResolutionStage.RETRIEVAL: FailureCategory.RETRIEVAL_UNAVAILABLE,
    ResolutionStage.POINTER: FailureCategory.POINTER_NOT_FOUND,
    ResolutionStage.ANCHOR: FailureCategory.ANCHOR_NOT_FOUND,
    ResolutionStage.SPECIFICATION: FailureCategory.RETRIEVAL_UNAVAILABLE,
}

_STAGE_OF: dict[type[BaseException], ResolutionStage] = {
    Unretrievable: ResolutionStage.RETRIEVAL,
    NoSuchResource: ResolutionStage.RETRIEVAL,
    PointerToNowhere: ResolutionStage.POINTER,
    NoSuchAnchor: ResolutionStage.ANCHOR,
    InvalidAnchor: ResolutionStage.ANCHOR,
    CannotDetermineSpecification: ResolutionStage.SPECIFICATION,
}
