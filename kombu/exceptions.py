"""Exceptions."""

from __future__ import annotations

from socket import timeout as TimeoutError
from types import TracebackType
from typing import TYPE_CHECKING, TypeVar

from amqp import ChannelError, ConnectionError, ResourceError

if TYPE_CHECKING:
    from kombu.asynchronous.http import Response

__all__ = (
    'reraise', 'KombuError', 'OperationalError', 'BatchPublishError',
    'RoutingPolicyError', 'BatchRoutingError', 'BatchRoutingPolicyError',
    'RoutingPolicyViolationError', 'BatchRoutingPolicyViolation',
    'RoutingValidationError', 'BatchRoutingValidationError',
    'NotBoundError', 'MessageStateError', 'TimeoutError',
    'LimitExceeded', 'ConnectionLimitExceeded',
    'ChannelLimitExceeded', 'ConnectionError', 'ChannelError',
    'VersionMismatch', 'SerializerNotInstalled', 'ResourceError',
    'SerializationError', 'EncodeError', 'DecodeError', 'HttpError',
    'InconsistencyError',
)

BaseExceptionType = TypeVar('BaseExceptionType', bound=BaseException)


def reraise(
    tp: type[BaseExceptionType],
    value: BaseExceptionType,
    tb: TracebackType | None = None
) -> BaseExceptionType:
    """Reraise exception."""
    if value.__traceback__ is not tb:
        raise value.with_traceback(tb)
    raise value


class KombuError(Exception):
    """Common subclass for all Kombu exceptions."""


class OperationalError(KombuError):
    """Recoverable message transport connection error."""


class BatchPublishError(KombuError):
    """Batch publication failed with an uncertain delivery outcome.

    ``delivered`` lists the entries the transport confirmed before the
    failure, ``unknown`` lists entries whose delivery could not be
    determined, and ``pending`` lists entries that were never attempted.
    """

    def __init__(
        self,
        *args,
        delivered=None,
        unknown=None,
        pending=None,
    ) -> None:
        super().__init__(*args)
        self.delivered = list(delivered or ())
        self.unknown = list(unknown or ())
        self.pending = list(pending or ())

    @property
    def confirmed(self):
        """Alias for :attr:`delivered`."""
        return self.delivered

    @property
    def uncertain(self):
        """Alias for :attr:`unknown`."""
        return self.unknown

    @property
    def delivered_count(self):
        """Return the number of confirmed entries."""
        return len(self.delivered)

    @property
    def unknown_count(self):
        """Return the number of entries with an uncertain outcome."""
        return len(self.unknown)

    @property
    def pending_count(self):
        """Return the number of entries that were not attempted."""
        return len(self.pending)


class RoutingPolicyError(BatchPublishError):
    """One or more batch entries do not satisfy the routing policy.

    No entry was sent and no entity was declared.  ``violations`` contains
    one :class:`~kombu.messaging.RoutingViolation` per rejected entry, in
    publication order.
    """

    def __init__(self, violations, message=None, **kwargs) -> None:
        self.violations = list(violations)
        if message is None:
            count = len(self.violations)
            verb = 'violates' if count == 1 else 'violate'
            summary = (
                f'{count} batch '
                f'{"entry" if count == 1 else "entries"} '
                f'{verb} the routing policy'
            )
            details = '; '.join(str(violation) for violation in self.violations)
            message = f'{summary}: {details}' if details else summary
        super().__init__(message, **kwargs)
        self.invalid_pending = list(self.violations)
        self.rejected_entries = [
            violation.entry for violation in self.violations
        ]
        self.reasons = [violation.reason for violation in self.violations]
        self.rejected_routing_keys = [
            violation.routing_key for violation in self.violations
        ]

    @property
    def entries(self):
        """Return the rejected batch entries."""
        return [violation.entry for violation in self.violations]

    @property
    def invalid_entries(self):
        """Alias for :attr:`entries`."""
        return self.entries

    @property
    def rejected(self):
        """Alias for :attr:`violations`."""
        return self.violations


#: Aliases kept for callers that describe the failure as a batch error.
BatchRoutingError = RoutingPolicyError
BatchRoutingPolicyError = RoutingPolicyError
RoutingPolicyViolationError = RoutingPolicyError
BatchRoutingPolicyViolation = RoutingPolicyError
RoutingValidationError = RoutingPolicyError
BatchRoutingValidationError = RoutingPolicyError


class SerializationError(KombuError):
    """Failed to serialize/deserialize content."""


class EncodeError(SerializationError):
    """Cannot encode object."""


class DecodeError(SerializationError):
    """Cannot decode object."""


class NotBoundError(KombuError):
    """Trying to call channel dependent method on unbound entity."""


class MessageStateError(KombuError):
    """The message has already been acknowledged."""


class LimitExceeded(KombuError):
    """Limit exceeded."""


class ConnectionLimitExceeded(LimitExceeded):
    """Maximum number of simultaneous connections exceeded."""


class ChannelLimitExceeded(LimitExceeded):
    """Maximum number of simultaneous channels exceeded."""


class VersionMismatch(KombuError):
    """Library dependency version mismatch."""


class SerializerNotInstalled(KombuError):
    """Support for the requested serialization type is not installed."""


class ContentDisallowed(SerializerNotInstalled):
    """Consumer does not allow this content-type."""


class InconsistencyError(ConnectionError):
    """Data or environment has been found to be inconsistent.

    Depending on the cause it may be possible to retry the operation.
    """


class HttpError(Exception):
    """HTTP Client Error."""

    def __init__(
        self,
        code: int,
        message: str | None = None,
        response: Response | None = None
    ) -> None:
        self.code = code
        self.message = message
        self.response = response
        super().__init__(code, message, response)

    def __str__(self) -> str:
        return 'HTTP {0.code}: {0.message}'.format(self)
