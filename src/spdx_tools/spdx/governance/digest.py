# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
from dataclasses import fields, is_dataclass
from enum import Enum

from beartype.typing import Any

from spdx_tools.spdx.jsonschema.document_converter import DocumentConverter
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.validation.validation_message import ValidationMessage


def _normalize(value: Any) -> Any:
    """Turn model values into a deterministic, JSON-friendly structure.

    SPDX values such as ``SpdxNone``/``SpdxNoAssertion`` and license expressions are not JSON
    serializable on their own, so they are reduced to stable strings first.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if hasattr(value, "to_serialized_string"):
        return value.to_serialized_string()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if is_dataclass(value):
        return {
            field.name: _normalize(getattr(value, field.name))
            for field in sorted(fields(value), key=lambda item: item.name)
        }
    return str(value)


def content_digest(value: Any) -> str:
    """SHA-256 over the normalized JSON representation of a model value."""
    normalized = _normalize(value)
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def document_digest(document: Document) -> str:
    """Digest of the canonical SPDX-2 representation of the complete document.

    The canonical JSON conversion is used instead of source bytes so that formatting changes
    (indentation, key order, serializer) do not change the identity of the reviewed content.
    """
    return content_digest(DocumentConverter().convert(document))


def subject_digest(message: ValidationMessage) -> str:
    """Digest of the exact element/relationship a validation finding is about."""
    return content_digest(message.context.full_element)
