#  Copyright 2018-Present The CloudEvents Authors
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Diagnostic receipts for failed CloudEvent reception.

A :class:`DiagnosticReceipt` is attached to the exception raised while receiving a
CloudEvent through a protocol binding.  It only carries identifiers that can be
verified offline against the original carrier (a digest of the raw bytes) plus
binding metadata.  The original payload itself is never copied into the receipt,
so handlers keep processing the original exception type unchanged while gaining
enough context to correlate a failed delivery (for example a RabbitMQ redelivery
that is also observed on the HTTP entry point).
"""

import hashlib
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Iterator

DIAGNOSTIC_RECEIPT_ATTR: Final[str] = "cloudevent_diagnostic_receipt"
FAILURE_STAGE_ATTR: Final[str] = "cloudevent_failure_stage"
_SHA256_PREFIX: Final[str] = "sha256:"


class ReceptionBinding(str, Enum):
    """Protocol binding through which the carrier was received."""

    HTTP = "http"
    RABBITMQ = "rabbitmq"


class ContentMode(str, Enum):
    """CloudEvents content mode used by the received carrier."""

    BINARY = "binary"
    STRUCTURED = "structured"


class FailureStage(str, Enum):
    """Stage of the reception pipeline at which the failure occurred."""

    CONTENT_DECODING = "content_decoding"
    EVENT_CONSTRUCTION = "event_construction"


@dataclass(frozen=True)
class DiagnosticReceipt:
    """
    Offline-verifiable diagnostic information for a failed reception.

    The receipt deliberately contains identifiers only:

    * ``binding`` and ``content_mode`` describe how the carrier was received,
    * ``raw_content_digest`` is the SHA-256 digest of the raw carrier bytes and
      can be recomputed offline to correlate duplicate deliveries,
    * ``failure_stage`` identifies whether content decoding or event
      construction failed,
    * ``exception_type`` is the fully qualified type name of the original
      exception so the failure taxonomy stays visible without retaining the
      exception message (which may embed payload content).

    Two carriers with different encodings of the same event have different
    :attr:`raw_content_digest` values and can therefore be told apart.
    """

    binding: ReceptionBinding
    content_mode: ContentMode
    raw_content_digest: str
    failure_stage: FailureStage
    exception_type: str


def digest_raw_content(raw_content: bytes) -> str:
    """
    Compute the offline-verifiable digest of the raw carrier bytes.

    :param raw_content: The untouched bytes as received from the transport.
    :return: The SHA-256 hex digest prefixed with ``"sha256:"``.
    """
    return _SHA256_PREFIX + hashlib.sha256(raw_content).hexdigest()


def get_qualified_exception_name(exception: BaseException) -> str:
    """
    Return the fully qualified name of the exception's type.

    :param exception: The raised exception.
    :return: A name of the form ``package.module.ClassName``.
    """
    exception_type = type(exception)
    return f"{exception_type.__module__}.{exception_type.__qualname__}"


def mark_failure_stage(exception: BaseException, failure_stage: FailureStage) -> None:
    """
    Record which reception stage produced ``exception``.

    The marker is used by bindings that delegate a pipeline spanning more than
    one stage (structured mode decodes and constructs inside the format layer)
    so that the eventual receipt reports the accurate stage.  Any pre-existing
    marker is preserved.

    :param exception: The exception raised by the failing stage.
    :param failure_stage: The stage at which the exception was raised.
    """
    if not hasattr(exception, FAILURE_STAGE_ATTR):
        setattr(exception, FAILURE_STAGE_ATTR, failure_stage)


def get_failure_stage(
    exception: BaseException, default: FailureStage
) -> FailureStage:
    """
    Return the stage marked on ``exception`` or ``default`` when unmarked.

    :param exception: The exception raised during reception.
    :param default: Stage to assume when the exception carries no marker.
    :return: The recorded failure stage or the provided default.
    """
    stage: Any = getattr(exception, FAILURE_STAGE_ATTR, None)
    if isinstance(stage, FailureStage):
        return stage
    return default


def get_diagnostic_receipt(
    exception: BaseException,
) -> DiagnosticReceipt | None:
    """
    Return the receipt attached to ``exception`` if present.

    :param exception: The exception raised during reception.
    :return: The attached :class:`DiagnosticReceipt` or ``None``.
    """
    receipt: Any = getattr(exception, DIAGNOSTIC_RECEIPT_ATTR, None)
    if isinstance(receipt, DiagnosticReceipt):
        return receipt
    return None


@contextmanager
def diagnostic_receipt(
    binding: ReceptionBinding,
    content_mode: ContentMode,
    raw_content: bytes,
    default_stage: FailureStage,
) -> Iterator[None]:
    """
    Attach a :class:`DiagnosticReceipt` to any exception escaping the block.

    The original exception is re-raised unchanged (same type and message) so
    existing exception handling keeps working; only an additional attribute is
    attached.  Exceptions that already carry a receipt are left untouched.

    :param binding: Binding performing the reception.
    :param content_mode: Content mode of the received carrier.
    :param raw_content: Untouched carrier bytes used for the digest.
    :param default_stage: Stage assumed when the exception is not explicitly
        marked with a more precise stage.
    """
    try:
        yield
    except Exception as exception:
        if get_diagnostic_receipt(exception) is None:
            receipt = DiagnosticReceipt(
                binding=binding,
                content_mode=content_mode,
                raw_content_digest=digest_raw_content(raw_content),
                failure_stage=get_failure_stage(exception, default_stage),
                exception_type=get_qualified_exception_name(exception),
            )
            setattr(exception, DIAGNOSTIC_RECEIPT_ATTR, receipt)
        raise
