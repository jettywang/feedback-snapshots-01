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
Strict structured-to-binary CloudEvent conversion for event relays.

This module converts a structured CloudEvent document (e.g. JSON) into binary
content mode messages for one or more target protocol bindings, verifying
before publication that every attribute and the data payload survive the
round trip through the target binding without loss:

- The input is decoded exactly once; the CloudEvents version of the input
  determines how the core attributes are validated.
- A registry of known extension types gives registered extensions their
  canonical Python type; unknown extensions are accepted as-is per the spec.
- Each target binding declares which value types it can express losslessly;
  every attribute is additionally round-tripped through the binding's own
  value encoder/decoder to check both sides agree on its interpretation.
- The data payload produced by the format's callbacks is held to the same
  standard: it must be bytes and must deserialize back to the original data.
- Attributes that cannot be expressed are reported with their name and the
  failure stage before any target message is created, so a rejected exit
  never yields a partial message to publish.
"""

import base64
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping

from dateutil.parser import isoparse

from cloudevents.core.base import BaseCloudEvent, EventFactory
from cloudevents.core.bindings import amqp, http, kafka
from cloudevents.core.exceptions import (
    CloudEventValidationError,
    ConversionStage,
    StrictConversionError,
)
from cloudevents.core.formats.base import Format
from cloudevents.core.v03.event import OPTIONAL_ATTRIBUTES as V03_OPTIONAL_ATTRIBUTES
from cloudevents.core.v03.event import REQUIRED_ATTRIBUTES as V03_REQUIRED_ATTRIBUTES
from cloudevents.core.v1.event import OPTIONAL_ATTRIBUTES as V1_OPTIONAL_ATTRIBUTES
from cloudevents.core.v1.event import REQUIRED_ATTRIBUTES as V1_REQUIRED_ATTRIBUTES

CORE_ATTRIBUTES: frozenset[str] = frozenset(
    V1_REQUIRED_ATTRIBUTES
    + V1_OPTIONAL_ATTRIBUTES
    + V03_REQUIRED_ATTRIBUTES
    + V03_OPTIONAL_ATTRIBUTES
)
"""Core attribute names across all supported CloudEvents versions."""

MessageFactory = Callable[[BaseCloudEvent, Format], Any]
"""
Type alias for a binding's binary content mode message factory.

Args:
    event: The CloudEvent to convert.
    event_format: Format implementation for data serialization.

Returns:
    A binding-specific message (e.g. HTTPMessage, KafkaMessage, AMQPMessage).
"""


@dataclass(frozen=True)
class BinaryBinding:
    """
    A target protocol binding's binary content mode contract.

    Attributes:
        name: Human-readable binding name used in error messages and results.
        to_binary: The binding's binary content mode message factory.
        supported_types: Python value types the binding expresses losslessly.
        encode_value: The binding's attribute value encoder.
        decode_value: The binding's attribute value decoder, taking the
            attribute name and the encoded value.
    """

    name: str
    to_binary: MessageFactory
    supported_types: tuple[type, ...]
    encode_value: Callable[[Any], Any]
    decode_value: Callable[[str, Any], Any]


@dataclass(frozen=True)
class ExitConversion:
    """
    The outcome of converting one structured CloudEvent to one target exit.

    Exactly one of ``message`` and ``error`` is set: a compatible exit holds
    the ready-to-publish message, an incompatible exit holds the
    StrictConversionError and no message (not even a partial one) is created.

    Attributes:
        binding: Name of the target binding this result belongs to.
        message: The binary content mode message, or None if conversion failed.
        error: The conversion failure, or None if conversion succeeded.
    """

    binding: str
    message: Any | None
    error: StrictConversionError | None


def _kafka_encode_value(value: Any) -> bytes:
    if isinstance(value, datetime):
        str_value = value.isoformat()
        if str_value.endswith("+00:00"):
            str_value = str_value[:-6] + "Z"
        return str_value.encode("utf-8")
    return str(value).encode("utf-8")


def _kafka_decode_value(attr_name: str, value: bytes) -> Any:
    decoded = value.decode("utf-8")
    if attr_name == "time":
        return isoparse(decoded)
    return decoded


HTTP_BINARY_BINDING: BinaryBinding = BinaryBinding(
    name="http",
    to_binary=http.to_binary,
    supported_types=(str, datetime),
    encode_value=http._encode_header_value,
    decode_value=http._decode_header_value,
)
"""HTTP binary content mode: strings and timestamps survive, nothing else."""

KAFKA_BINARY_BINDING: BinaryBinding = BinaryBinding(
    name="kafka",
    to_binary=kafka.to_binary,
    supported_types=(str, datetime),
    encode_value=_kafka_encode_value,
    decode_value=_kafka_decode_value,
)
"""Kafka binary content mode: strings and timestamps survive, nothing else."""

AMQP_BINARY_BINDING: BinaryBinding = BinaryBinding(
    name="amqp",
    to_binary=amqp.to_binary,
    supported_types=(str, bytes, int, bool, datetime),
    encode_value=amqp._encode_amqp_value,
    decode_value=amqp._decode_amqp_value,
)
"""AMQP binary content mode: native AMQP types survive, including binary."""


def _coerce_extension_value(
    extension_name: str, value: Any, registered_type: type
) -> Any:
    """
    Give a registered extension value its canonical Python type.

    :param extension_name: The name of the extension attribute.
    :param value: The value as decoded from the structured document.
    :param registered_type: The registered CloudEvents type of the extension.
    :return: The value coerced to its registered type.
    :raises StrictConversionError: If the value cannot be interpreted as the
        registered type.
    """
    if isinstance(value, registered_type):
        return value
    try:
        if registered_type is bytes and isinstance(value, str):
            return base64.b64decode(value.encode("utf-8"), validate=True)
        if registered_type is datetime and isinstance(value, str):
            return isoparse(value)
        if registered_type is bool and isinstance(value, str):
            lowered = value.lower()
            if lowered in ("true", "false"):
                return lowered == "true"
            raise ValueError(f"Cannot interpret '{value}' as Boolean")
        if registered_type is int and isinstance(value, str):
            return int(value)
    except (ValueError, TypeError) as exc:
        raise StrictConversionError(
            attribute_name=extension_name,
            stage=ConversionStage.DECODE,
            msg=str(exc),
        ) from exc
    raise StrictConversionError(
        attribute_name=extension_name,
        stage=ConversionStage.DECODE,
        msg=f"Extension value {value!r} cannot be interpreted"
        f" as registered type {registered_type}",
    )


def _decode_event(
    data: str | bytes,
    event_format: Format,
    event_factory: EventFactory | None,
) -> BaseCloudEvent:
    """
    Decode the structured document once, validating core attributes according
    to the CloudEvents version of the input.

    :raises StrictConversionError: At stage DECODE if the document cannot be
        parsed or fails version-specific core attribute validation.
    """
    try:
        return event_format.read(event_factory, data)
    except CloudEventValidationError as exc:
        attribute_name = next(iter(exc.errors), None)
        raise StrictConversionError(
            attribute_name=attribute_name,
            stage=ConversionStage.DECODE,
            msg=str(exc),
        ) from exc
    except Exception as exc:
        raise StrictConversionError(
            attribute_name=None,
            stage=ConversionStage.DECODE,
            msg=str(exc),
        ) from exc


def _apply_extension_registry(
    event: BaseCloudEvent,
    extension_types: Mapping[str, type] | None,
) -> BaseCloudEvent:
    """
    Re-interpret registered extension attributes with their canonical types.

    Unknown extensions are left untouched, as the CloudEvents specification
    allows arbitrary extension attributes.
    """
    if not extension_types:
        return event

    attributes = dict(event.get_attributes())
    changed = False
    for attr_name, attr_value in attributes.items():
        if attr_name in CORE_ATTRIBUTES or attr_value is None:
            continue
        registered_type = extension_types.get(attr_name)
        if registered_type is None:
            continue
        coerced = _coerce_extension_value(attr_name, attr_value, registered_type)
        if coerced is not attr_value:
            attributes[attr_name] = coerced
            changed = True

    if not changed:
        return event
    return type(event)(attributes, event.get_data())


def _validate_data(event: BaseCloudEvent, event_format: Format) -> None:
    """
    Hold the data payload produced by the format's callbacks to the same
    standard as attributes: it must serialize to bytes and deserialize back
    to the original data.

    :raises StrictConversionError: At stage DATA if the payload does not
        survive the format round trip.
    """
    event_data = event.get_data()
    datacontenttype = event.get_attributes().get("datacontenttype")
    try:
        body = event_format.write_data(event_data, datacontenttype)
    except Exception as exc:
        raise StrictConversionError(
            attribute_name="data",
            stage=ConversionStage.DATA,
            msg=str(exc),
        ) from exc
    if not isinstance(body, (bytes, bytearray)):
        raise StrictConversionError(
            attribute_name="data",
            stage=ConversionStage.DATA,
            msg=f"Format produced {type(body).__name__} instead of bytes"
            " for the message body",
        )
    try:
        restored = event_format.read_data(bytes(body), datacontenttype)
    except Exception as exc:
        raise StrictConversionError(
            attribute_name="data",
            stage=ConversionStage.DATA,
            msg=str(exc),
        ) from exc
    if restored != event_data:
        raise StrictConversionError(
            attribute_name="data",
            stage=ConversionStage.DATA,
            msg="Data payload does not survive the format round trip",
        )


def _check_binding(
    event: BaseCloudEvent, binding: BinaryBinding
) -> StrictConversionError | None:
    """
    Verify every attribute can be losslessly expressed by the target binding.

    Each attribute value must be of a type the binding supports and must
    survive a round trip through the binding's own value encoder and decoder,
    so both sides agree on its interpretation before anything is published.

    :return: The conversion failure, or None if the event is compatible.
    """
    for attr_name, attr_value in event.get_attributes().items():
        if attr_value is None:
            continue
        if not isinstance(attr_value, binding.supported_types):
            return StrictConversionError(
                attribute_name=attr_name,
                stage=ConversionStage.ATTRIBUTE,
                msg=f"Binding '{binding.name}' cannot losslessly express value"
                f" of type {type(attr_value).__name__}",
            )
        try:
            round_tripped = binding.decode_value(
                attr_name, binding.encode_value(attr_value)
            )
        except Exception as exc:
            return StrictConversionError(
                attribute_name=attr_name,
                stage=ConversionStage.ATTRIBUTE,
                msg=str(exc),
            )
        if round_tripped != attr_value:
            return StrictConversionError(
                attribute_name=attr_name,
                stage=ConversionStage.ATTRIBUTE,
                msg=f"Binding '{binding.name}' round trip changes the value"
                f" from {attr_value!r} to {round_tripped!r}",
            )
    return None


def convert_structured(
    data: str | bytes,
    event_format: Format,
    bindings: Iterable[BinaryBinding],
    event_factory: EventFactory | None = None,
    extension_types: Mapping[str, type] | None = None,
) -> list[ExitConversion]:
    """
    Strictly convert a structured CloudEvent to binary mode for several exits.

    The input is decoded exactly once and the resulting event is checked
    against each target binding. Compatible exits yield a ready-to-publish
    message; incompatible exits yield the failure (attribute name and stage)
    and no message is created for them.

    :param data: The structured CloudEvent document (e.g. JSON).
    :param event_format: Format implementation for decoding and data handling.
    :param bindings: The target binary bindings to convert to.
    :param event_factory: Factory to create CloudEvent instances.
        If None, the version is auto-detected from the input.
    :param extension_types: Registry of known extension attribute types.
    :return: One ExitConversion per target binding, in order.
    :raises StrictConversionError: At stage DECODE or DATA if the input itself
        cannot be converted, regardless of the target binding.
    """
    event = _decode_event(data, event_format, event_factory)
    event = _apply_extension_registry(event, extension_types)
    _validate_data(event, event_format)

    results: list[ExitConversion] = []
    for binding in bindings:
        error = _check_binding(event, binding)
        if error is not None:
            results.append(
                ExitConversion(binding=binding.name, message=None, error=error)
            )
        else:
            message = binding.to_binary(event, event_format)
            results.append(
                ExitConversion(binding=binding.name, message=message, error=None)
            )
    return results


def convert_structured_to_binary(
    data: str | bytes,
    event_format: Format,
    binding: BinaryBinding,
    event_factory: EventFactory | None = None,
    extension_types: Mapping[str, type] | None = None,
) -> Any:
    """
    Strictly convert a structured CloudEvent to one binary mode message.

    Like convert_structured but for a single target binding, raising the
    conversion failure instead of collecting it.

    :param data: The structured CloudEvent document (e.g. JSON).
    :param event_format: Format implementation for decoding and data handling.
    :param binding: The target binary binding to convert to.
    :param event_factory: Factory to create CloudEvent instances.
        If None, the version is auto-detected from the input.
    :param extension_types: Registry of known extension attribute types.
    :return: The binding's binary content mode message.
    :raises StrictConversionError: If the event cannot be losslessly converted;
        no target message is created in that case.
    """
    (result,) = convert_structured(
        data, event_format, [binding], event_factory, extension_types
    )
    if result.error is not None:
        raise result.error
    return result.message
