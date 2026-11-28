# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Unified error contract for the SPDX document import service.

This module wraps the existing parser, validator and writer behind a single
entry point (:func:`import_file`).  Failures are classified with a stable
:class:`ErrorCategory` and :class:`ProcessingStage` and exposed in two
distinct channels:

* :meth:`ImportResult.external_summary` only contains coordinates and
  categories.  It is safe to hand back to API callers because raw parser
  notes (which may mention internal host names, file system paths or other
  deployment details) never reach this channel.
* :meth:`ImportResult.diagnostic_records` keeps the original notes together
  with their data source.  It is meant for internal log pipelines and is not
  part of the external response.

The legacy public entry points (``parse_file``, ``write_file`` and the
per-format parsers/writers) keep their current exception behavior; this layer
only translates exceptions raised by those entry points.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto

from beartype.typing import List, Optional

from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage
from spdx_tools.spdx.writer.write_anything import write_file


class ProcessingStage(Enum):
    """Stages an import goes through, in execution order."""

    PARSE = auto()
    VALIDATION = auto()
    WRITE = auto()


class ErrorCategory(Enum):
    """Stable, format-independent error categories.

    The values are part of the external contract and must not be renamed.
    """

    SYNTAX_ERROR = "syntax_error"
    SCHEMA_VIOLATION = "schema_violation"
    VALIDATION_ERROR = "validation_error"
    WRITE_ERROR = "write_error"
    UNKNOWN_ERROR = "unknown_error"


@dataclass(frozen=True)
class ErrorCoordinates:
    """Location of an error inside the source document.

    Every field is optional; unknown details stay ``None`` instead of being
    guessed.  Coordinates never contain free-form notes.
    """

    document_location: Optional[str] = None
    spdx_id: Optional[str] = None
    element_type: Optional[str] = None
    line_number: Optional[int] = None

    def as_dict(self) -> dict:
        return {
            "document_location": self.document_location,
            "spdx_id": self.spdx_id,
            "element_type": self.element_type,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class ImportErrorRecord:
    """A single classified error.

    ``diagnostic_message`` holds the raw, potentially internal note and is
    only exposed through the diagnostic channel.  Use :meth:`external_view`
    for anything that leaves the service boundary.
    """

    category: ErrorCategory
    stage: ProcessingStage
    coordinates: ErrorCoordinates
    source: str
    diagnostic_message: str

    def external_view(self) -> dict:
        return {
            "category": self.category.value,
            "stage": self.stage.name.lower(),
            "coordinates": self.coordinates.as_dict(),
        }


@dataclass(frozen=True)
class ImportResult:
    """Outcome of an import run.

    A result is either successful (``document`` is set, no records) or failed
    (``document`` is ``None``, at least one record).  When the parse stage
    fails no output file is ever produced.
    """

    source: str
    output_target: Optional[str]
    document: Optional[Document] = None
    records: List[ImportErrorRecord] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.records and self.document is not None

    def external_summary(self) -> dict:
        """Sanitized summary for external API responses.

        Contains only the source coordinate, the output coordinate and the
        category/stage/coordinates of each error.  Raw notes are excluded.
        """
        return {
            "source": self.source,
            "output_target": self.output_target,
            "success": self.success,
            "errors": [record.external_view() for record in self.records],
        }

    def diagnostic_records(self) -> List[dict]:
        """Full records including raw notes, for internal diagnostics only."""
        return [
            {
                "category": record.category.value,
                "stage": record.stage.name.lower(),
                "source": record.source,
                "coordinates": record.coordinates.as_dict(),
                "diagnostic_message": record.diagnostic_message,
            }
            for record in self.records
        ]


class ImportServiceError(Exception):
    """Raised by the new entry point when an import fails.

    The attached :class:`ImportResult` is the single source of truth for both
    the external summary and the internal diagnostics.
    """

    def __init__(self, result: ImportResult):
        self.result = result
        first_category = result.records[0].category.value if result.records else ErrorCategory.UNKNOWN_ERROR.value
        super().__init__(f"import of {result.source} failed with {len(result.records)} error(s): {first_category}")


def _is_syntax_error(error: BaseException) -> bool:
    syntax_error_types = (
        SyntaxError,
        UnicodeDecodeError,
    )
    json_module = _load_optional_module("json")
    if json_module is not None:
        syntax_error_types += (json_module.JSONDecodeError,)
    yaml_module = _load_optional_module("yaml")
    if yaml_module is not None:
        syntax_error_types += (yaml_module.scanner.ScannerError, yaml_module.parser.ParserError)
    xml_expat = _load_optional_module("xml.parsers.expat")
    if xml_expat is not None:
        syntax_error_types += (xml_expat.ExpatError,)
    xml_sax = _load_optional_module("xml.sax")
    if xml_sax is not None:
        syntax_error_types += (xml_sax.SAXParseException,)
    return isinstance(error, syntax_error_types)


def _load_optional_module(dotted_name: str):
    import importlib

    try:
        module = importlib.import_module(dotted_name)
    except ImportError:
        return None
    return module


def _note_from_error(error: BaseException) -> str:
    if isinstance(error, SPDXParsingError):
        return "; ".join(error.get_messages())
    return str(error) or error.__class__.__name__


def _line_number_of(error: BaseException) -> Optional[int]:
    for attribute_name in ("lineno", "position"):
        value = getattr(error, attribute_name, None)
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, tuple) and value and isinstance(value[0], int) and value[0] > 0:
            return value[0]
    # YAML errors point at a Mark object with a zero-based `line` attribute
    for mark_name in ("problem_mark", "context_mark"):
        mark = getattr(error, mark_name, None)
        line = getattr(mark, "line", None)
        if isinstance(line, int) and line >= 0:
            return line + 1
    return None


def _records_from_parse_error(error: BaseException, source: str) -> List[ImportErrorRecord]:
    line_number = _line_number_of(error)
    coordinates = ErrorCoordinates(document_location=source, line_number=line_number)
    if isinstance(error, SPDXParsingError):
        records = []
        for note in error.get_messages():
            records.append(
                ImportErrorRecord(
                    category=ErrorCategory.SCHEMA_VIOLATION,
                    stage=ProcessingStage.PARSE,
                    coordinates=coordinates,
                    source=source,
                    diagnostic_message=note,
                )
            )
        return records
    category = ErrorCategory.SYNTAX_ERROR if _is_syntax_error(error) else ErrorCategory.UNKNOWN_ERROR
    return [
        ImportErrorRecord(
            category=category,
            stage=ProcessingStage.PARSE,
            coordinates=coordinates,
            source=source,
            diagnostic_message=_note_from_error(error),
        )
    ]


def _records_from_validation_messages(
    messages: List[ValidationMessage], source: str
) -> List[ImportErrorRecord]:
    records = []
    for message in messages:
        context = message.context
        coordinates = ErrorCoordinates(
            document_location=source,
            spdx_id=context.spdx_id,
            element_type=context.element_type.name if context.element_type is not None else None,
        )
        records.append(
            ImportErrorRecord(
                category=ErrorCategory.VALIDATION_ERROR,
                stage=ProcessingStage.VALIDATION,
                coordinates=coordinates,
                source=source,
                diagnostic_message=message.validation_message,
            )
        )
    return records


def import_file(
    source: str,
    output_target: Optional[str] = None,
    validate: bool = True,
    raise_on_error: bool = False,
) -> ImportResult:
    """Parse, validate and optionally write an SPDX document under one contract.

    The legacy entry points keep their exception behavior; this wrapper
    translates their exceptions into classified records instead of letting
    raw notes cross the service boundary.

    Args:
        source: path to the SPDX document to import.
        output_target: optional path the converted document is written to.
            Parsing failures guarantee that no file is created here.
        validate: run the full SPDX validation between parse and write.
        raise_on_error: when ``True`` a failed import raises
            :class:`ImportServiceError`; otherwise the failed
            :class:`ImportResult` is returned.
    """
    source = os.fspath(source)
    normalized_target = os.fspath(output_target) if output_target is not None else None

    try:
        document = parse_file(source)
    except Exception as error:
        records = _records_from_parse_error(error, source)
        result = ImportResult(source=source, output_target=normalized_target, records=records)
        if raise_on_error:
            raise ImportServiceError(result) from error
        return result

    if validate:
        validation_messages = validate_full_spdx_document(document)
        if validation_messages:
            records = _records_from_validation_messages(validation_messages, source)
            result = ImportResult(source=source, output_target=normalized_target, records=records)
            if raise_on_error:
                raise ImportServiceError(result)
            return result

    if normalized_target is not None:
        try:
            write_file(document, normalized_target, validate=False)
        except Exception as error:
            record = ImportErrorRecord(
                category=ErrorCategory.WRITE_ERROR,
                stage=ProcessingStage.WRITE,
                coordinates=ErrorCoordinates(document_location=normalized_target),
                source=source,
                diagnostic_message=_note_from_error(error),
            )
            result = ImportResult(source=source, output_target=normalized_target, records=[record])
            if raise_on_error:
                raise ImportServiceError(result) from error
            return result

    return ImportResult(source=source, output_target=normalized_target, document=document)
