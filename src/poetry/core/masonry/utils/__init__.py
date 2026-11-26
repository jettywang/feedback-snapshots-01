from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any


if TYPE_CHECKING:
    from poetry.core.masonry.utils.editable_roots import ApprovedRootPolicy
    from poetry.core.masonry.utils.editable_roots import EditableRootEntry
    from poetry.core.masonry.utils.editable_roots import EditableRootPolicy
    from poetry.core.masonry.utils.editable_roots import EditableRootReport
    from poetry.core.masonry.utils.editable_roots import EditableRootValidationError
    from poetry.core.masonry.utils.editable_roots import EditableRootViolation
    from poetry.core.masonry.utils.editable_roots import UnapprovedEditableRootError
    from poetry.core.masonry.utils.editable_roots import check_editable_roots
    from poetry.core.masonry.utils.editable_roots import collect_editable_search_roots
    from poetry.core.masonry.utils.editable_roots import validate_editable_project
    from poetry.core.masonry.utils.editable_roots import validate_editable_roots
    from poetry.core.masonry.utils.editable_roots import verify_editable_roots


_LAZY_EXPORTS = {
    "ApprovedRootPolicy": ("editable_roots", "ApprovedRootPolicy"),
    "EditableRootEntry": ("editable_roots", "EditableRootEntry"),
    "EditableRootPolicy": ("editable_roots", "EditableRootPolicy"),
    "EditableRootReport": ("editable_roots", "EditableRootReport"),
    "EditableRootValidationError": (
        "editable_roots",
        "EditableRootValidationError",
    ),
    "EditableRootViolation": ("editable_roots", "EditableRootViolation"),
    "UnapprovedEditableRootError": (
        "editable_roots",
        "UnapprovedEditableRootError",
    ),
    "check_editable_roots": ("editable_roots", "check_editable_roots"),
    "collect_editable_search_roots": (
        "editable_roots",
        "collect_editable_search_roots",
    ),
    "validate_editable_project": (
        "editable_roots",
        "validate_editable_project",
    ),
    "validate_editable_roots": ("editable_roots", "validate_editable_roots"),
    "verify_editable_roots": ("editable_roots", "verify_editable_roots"),
}

__all__ = [
    "ApprovedRootPolicy",
    "EditableRootEntry",
    "EditableRootPolicy",
    "EditableRootReport",
    "EditableRootValidationError",
    "EditableRootViolation",
    "UnapprovedEditableRootError",
    "check_editable_roots",
    "collect_editable_search_roots",
    "validate_editable_project",
    "validate_editable_roots",
    "verify_editable_roots",
]


def __getattr__(name: str) -> Any:
    if name in _LAZY_EXPORTS:
        from importlib import import_module

        module_name, attr = _LAZY_EXPORTS[name]
        value = getattr(import_module(f"{__name__}.{module_name}"), attr)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return [*globals().keys(), *__all__]
