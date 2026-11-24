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
Common exceptions for CloudEvents (version-agnostic).
"""

from typing import Any


class BaseCloudEventException(Exception):
    """A CloudEvent generic exception."""


class CloudEventValidationError(BaseCloudEventException):
    """
    Holds validation errors aggregated during a CloudEvent creation.
    """

    def __init__(self, errors: dict[str, list[BaseCloudEventException]]) -> None:
        """
        :param errors: The errors gathered during the CloudEvent creation where key
            is the name of the attribute and value is a list of errors related to that attribute.
        """
        super().__init__("Failed to create CloudEvent due to the validation errors:")
        self.errors: dict[str, list[BaseCloudEventException]] = errors

    def __str__(self) -> str:
        error_messages: list[str] = [
            f"{key}: {', '.join(str(e) for e in value)}"
            for key, value in self.errors.items()
        ]
        return f"{super().__str__()}: {', '.join(error_messages)}"


class MissingRequiredAttributeError(BaseCloudEventException, ValueError):
    """
    Raised for attributes that are required to be present by the specification.
    """

    def __init__(self, attribute_name: str) -> None:
        self.attribute_name: str = attribute_name
        super().__init__(f"Missing required attribute: '{attribute_name}'")


class CustomExtensionAttributeError(BaseCloudEventException, ValueError):
    """
    Raised when a custom extension attribute violates naming conventions.
    """

    def __init__(self, attribute_name: str, msg: str) -> None:
        self.attribute_name: str = attribute_name
        super().__init__(msg)


class InvalidAttributeTypeError(BaseCloudEventException, TypeError):
    """
    Raised when an attribute has an unsupported type.
    """

    def __init__(self, attribute_name: str, expected_type: type) -> None:
        self.attribute_name: str = attribute_name
        super().__init__(f"Attribute '{attribute_name}' must be a {expected_type}")


class InvalidAttributeValueError(BaseCloudEventException, ValueError):
    """
    Raised when an attribute has an invalid value.
    """

    def __init__(self, attribute_name: str, msg: str) -> None:
        self.attribute_name: str = attribute_name
        super().__init__(msg)


class AdmissionDeniedError(BaseCloudEventException, PermissionError):
    """
    Raised when a host admission policy refuses to deliver an event.

    The stage intentionally defaults to ``"source_admission"``: policy is
    evaluated after wire decoding so structured-mode source claims are visible,
    but before the event is handed to application code.
    """

    def __init__(
        self,
        message: str = "CloudEvent source admission denied",
        *,
        stage: Any = None,
        context: Any = None,
        decision: Any = None,
        event: Any = None,
        source: str | None = None,
    ) -> None:
        super().__init__(message)
        self.stage: Any = stage if stage is not None else "source_admission"
        self.context = context
        self.decision = decision
        self.event = event
        self.source = source
        self.phase = "after_decode"
        self.completed_stages: tuple[str, ...] = (
            "mode_selection",
            "decode",
        )


# Common semantic aliases used by host applications and acceptance tests.
SourceAdmissionDenied = AdmissionDeniedError
SourceAdmissionDeniedError = AdmissionDeniedError
SourceAdmissionError = AdmissionDeniedError
AdmissionError = AdmissionDeniedError
AdmissionDenied = AdmissionDeniedError
AdmissionRejectedError = AdmissionDeniedError
SourceNotAdmittedError = AdmissionDeniedError
SourceRejectedError = AdmissionDeniedError
BoundaryPolicyDeniedError = AdmissionDeniedError
PolicyDeniedError = AdmissionDeniedError
