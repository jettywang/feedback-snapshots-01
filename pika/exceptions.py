"""Pika specific exceptions."""

from __future__ import annotations

import enum
import types
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from pika._utils import override

if TYPE_CHECKING:
    from typing import Protocol

    from pika import spec

    class ReturnedMessageLike(Protocol):
        """
        Structural type for a message returned by the broker via Basic.Return.

        Describes what a reader of `UnroutableError.messages` or `NackError.messages` can rely on.
        Two unrelated classes carry these messages: `blocking_connection.ReturnedMessage` and
        `twisted_connection.ReceivedMessage`, which adds a `channel` field. Neither can be named
        here without an import cycle, so the exceptions accept either shape.

        The exceptions themselves read only `len(messages)`; the members below are what their
        callers go on to use.

        The members are read-only because `ReceivedMessage` is a `namedtuple`.

        Declared under `TYPE_CHECKING`, so it is available to annotations but not importable at
        runtime. Import it inside a `TYPE_CHECKING` block, which `from __future__ import
        annotations` or a quoted annotation makes usable.
        """

        @property
        def method(self) -> spec.Basic.Return:
            ...

        @property
        def properties(self) -> spec.BasicProperties:
            ...

        @property
        def body(self) -> bytes:
            ...


class AMQPError(Exception):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: An unspecified AMQP error has occurred; {self.args}'


class AMQPConnectionError(AMQPError):

    @override
    def __init__(self,
                 *args,
                 host: str | None = None,
                 port: int | None = None) -> None:
        super().__init__(*args)
        self.host = host
        self.port = port

    def _host_port_suffix(self) -> str:
        """Return a ` (host=..., port=...)` repr suffix, or '' when unset."""
        if self.host is not None:
            return f' (host={self.host!r}, port={self.port})'
        return ''

    @override
    def __repr__(self) -> str:
        if len(self.args) == 2:
            base = f'{self.__class__.__name__}: ({self.args[0]}) {self.args[1]}'
        else:
            base = f'{self.__class__.__name__}: {self.args}'
        return f'{base}{self._host_port_suffix()}'


class ConnectionOpenAborted(AMQPConnectionError):
    """Client closed connection while opening."""


class StreamLostError(AMQPConnectionError):
    """Stream (TCP) connection lost."""


class IncompatibleProtocolError(AMQPConnectionError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: The protocol returned by the server is not supported: {self.args}'
            f'{self._host_port_suffix()}')


class AuthenticationError(AMQPConnectionError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: Server and client could not negotiate use of the {self.args[0]} '
            f'authentication mechanism{self._host_port_suffix()}')


class ProbableAuthenticationError(AMQPConnectionError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: Client was disconnected at a connection stage indicating a '
            f'probable authentication error: {self.args}{self._host_port_suffix()}'
        )


class ProbableAccessDeniedError(AMQPConnectionError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: Client was disconnected at a connection stage indicating a '
            f'probable denial of access to the specified virtual host: {self.args}'
            f'{self._host_port_suffix()}')


class NoFreeChannels(AMQPConnectionError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: The connection has run out of free channels'
            f'{self._host_port_suffix()}')


class ConnectionWrongStateError(AMQPConnectionError):
    """Connection is in wrong state for the requested operation."""

    @override
    def __repr__(self) -> str:
        if self.args:
            return super().__repr__()
        return (
            f'{self.__class__.__name__}: The connection is in wrong state for the requested '
            f'operation.{self._host_port_suffix()}')


class ConnectionClosed(AMQPConnectionError):

    def __init__(self,
                 reply_code: int,
                 reply_text: str | bytes,
                 host: str | None = None,
                 port: int | None = None) -> None:
        """

        :param reply_code: reply-code that was used in user's or broker's
            `Connection.Close` method. NEW in v1.0.0
        :param reply_text: reply-text that was used in user's or broker's
            `Connection.Close` method. Human-readable string corresponding to
            `reply_code`. A broker may send text that is not valid UTF-8, in
            which case it arrives as bytes and undecodable characters are
            replaced. NEW in v1.0.0
        :param host: hostname or IP of the broker
        :param port: port of the broker
        """
        if isinstance(reply_text, bytes):
            # `str(bytes)` would yield the repr, b-prefix and escapes
            # included, mangling the very text needed to diagnose the close.
            reply_text = reply_text.decode('utf-8', errors='replace')

        super().__init__(int(reply_code), str(reply_text), host=host, port=port)

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: ({self.reply_code}) {self.reply_text!r}'
            f'{self._host_port_suffix()}')

    @property
    def reply_code(self) -> int:
        """NEW in v1.0.0."""
        return int(self.args[0])

    @property
    def reply_text(self) -> str:
        """NEW in v1.0.0."""
        return str(self.args[1])


class ConnectionClosedByBroker(ConnectionClosed):
    """Connection.Close from broker."""


class ConnectionClosedByClient(ConnectionClosed):
    """Connection was closed at request of Pika client."""


class ConnectionBlockedTimeout(AMQPConnectionError):
    """RabbitMQ-specific: timed out waiting for connection.unblocked."""


class AMQPHeartbeatTimeout(AMQPConnectionError):
    """Connection was dropped as result of heartbeat timeout."""


class AMQPChannelError(AMQPError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: {self.args!r}'


class ChannelWrongStateError(AMQPChannelError):
    """Channel is in wrong state for the requested operation."""


class ChannelClosed(AMQPChannelError):
    """The channel closed by client or by broker."""

    def __init__(self, reply_code: int, reply_text: str) -> None:
        """

        :param reply_code: reply-code that was used in user's or broker's
            `Channel.Close` method. One of the AMQP-defined Channel Errors.
            NEW in v1.0.0
        :param reply_text: reply-text that was used in user's or broker's
            `Channel.Close` method. Human-readable string corresponding to
            `reply_code`;
            NEW in v1.0.0

        """
        super().__init__(int(reply_code), str(reply_text))

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: ({self.reply_code}) {self.reply_text!r}'

    @property
    def reply_code(self) -> int:
        """NEW in v1.0.0."""
        return int(self.args[0])

    @property
    def reply_text(self) -> str:
        """NEW in v1.0.0."""
        return str(self.args[1])


class ChannelClosedByBroker(ChannelClosed):
    """
    `Channel.Close` from broker; may be passed as reason to channel's on-closed callback of non-
    blocking connection adapters or raised by `BlockingConnection`.

    NEW in v1.0.0
    """


class ChannelClosedByClient(ChannelClosed):
    """
    Channel closed by client upon receipt of `Channel.CloseOk`; may be passed as reason to channel's
    on-closed callback of non-blocking connection adapters, but not raised by `BlockingConnection`.

    NEW in v1.0.0
    """


class DuplicateConsumerTag(AMQPChannelError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: The consumer tag specified already exists for this '
            f'channel: {self.args[0]}')


class ConsumerCancelled(AMQPChannelError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: Server cancelled consumer'


class PublishFailureKind(str, enum.Enum):
    """Why a publish did not reach a queue."""

    RETURNED = 'returned'
    """The broker accepted the publish but could not route it (`Basic.Return`)."""

    NACKED = 'nacked'
    """The broker refused the publish (`Basic.Nack`)."""

    CONNECTION_LOST = 'connection-lost'
    """The connection closed before the broker confirmed or refused the publish."""


#: AMQP Basic properties disclosed by `PublishFailure`. The header table and the
#: properties that can identify a person or a reply target (`user_id`, `reply_to`)
#: are excluded; a value in `headers` is disclosed only when its name is approved.
DISCLOSABLE_PROPERTIES = (
    'app_id',
    'content_encoding',
    'content_type',
    'correlation_id',
    'delivery_mode',
    'expiration',
    'message_id',
    'priority',
    'timestamp',
    'type',
)

#: The most a disclosed value contributes to a log line, in characters. It bounds
#: an `expiration` or `correlation_id` a caller filled with arbitrary data.
MAX_DISCLOSED_TEXT = 120


def _bounded(value: Any) -> str:
    """
    Render *value* for a log line, bounded so it cannot flood one.

    :param value: Any value from a message property
    :returns: Its `repr`, truncated to `MAX_DISCLOSED_TEXT`.
    """
    return repr(value)[:MAX_DISCLOSED_TEXT]


class PublishFailure:
    """
    A restricted view of one publish failure, safe to log or share externally.

    The business message itself stays on the exception that carries this view
    (`UnroutableError.messages` or `NackError.messages`), so a caller can republish
    it. This view is what a log or an alert should contain: it identifies the
    publish and the kind of failure without the body or the header table.

    Only the AMQP properties named in `DISCLOSABLE_PROPERTIES` are read, and only
    header entries whose names appear in *approved_headers* are copied; every other
    header contributes to `withheld_header_count` alone. `repr()` and `str()` of the
    view disclose nothing further and are what pika logs.

    The view is immutable. `headers` is a read-only mapping and every attribute is
    assigned once at construction, so a logging handler cannot widen what it holds.

    :param kind: Why the publish failed
    :param channel_number: Channel the publish was made on, if known
    :param exchange: Exchange the publish was addressed to
    :param routing_key: Routing key the publish used
    :param reply_code: AMQP reply code from `Basic.Return`, if any
    :param reply_text: AMQP reply text from `Basic.Return`, if any
    :param delivery_tag: Broker delivery tag of the failed publish, if known
    :param properties: The publish's `pika.spec.BasicProperties`, if available
    :param body_size: Length of the body in bytes, if known
    :param approved_headers: Header names whose values may be disclosed
    """

    __slots__ = (
        '_locked',
        'app_id',
        'approved_headers',
        'body_size',
        'channel_number',
        'content_encoding',
        'content_type',
        'correlation_id',
        'delivery_mode',
        'delivery_tag',
        'exchange',
        'expiration',
        'headers',
        'kind',
        'message_id',
        'priority',
        'reply_code',
        'reply_text',
        'routing_key',
        'timestamp',
        'type',
        'withheld_header_count',
    )

    # Annotations for `__slots__`; these declare no class attributes, so the slots
    # still hold the values assigned in `__init__`.
    _locked: bool
    app_id: Any
    approved_headers: tuple[str, ...]
    body_size: int | None
    channel_number: int | None
    content_encoding: Any
    content_type: Any
    correlation_id: Any
    delivery_mode: Any
    delivery_tag: int | None
    exchange: str | bytes | None
    expiration: Any
    headers: Mapping[str, Any]
    kind: PublishFailureKind
    message_id: Any
    priority: Any
    reply_code: int | None
    reply_text: str | bytes | None
    routing_key: str | bytes | None
    timestamp: Any
    type: Any
    withheld_header_count: int

    def __init__(
        self,
        kind: PublishFailureKind,
        *,
        channel_number: int | None = None,
        exchange: str | bytes | None = None,
        routing_key: str | bytes | None = None,
        reply_code: int | None = None,
        reply_text: str | bytes | None = None,
        delivery_tag: int | None = None,
        properties: Any = None,
        body_size: int | None = None,
        approved_headers: Sequence[str | bytes] = ()
    ) -> None:
        approved = {
            name.decode('utf-8', errors='replace')
            if isinstance(name, bytes) else str(name)
            for name in approved_headers
        }
        raw_headers = getattr(properties, 'headers', None) or {}
        disclosed = {}
        for name, value in raw_headers.items():
            text_name = (name.decode('utf-8', errors='replace') if isinstance(
                name, bytes) else str(name))
            if text_name in approved:
                disclosed[text_name] = value

        object.__setattr__(self, 'kind', kind)
        object.__setattr__(self, 'channel_number', channel_number)
        object.__setattr__(self, 'exchange', exchange)
        object.__setattr__(self, 'routing_key', routing_key)
        object.__setattr__(self, 'reply_code', reply_code)
        object.__setattr__(self, 'reply_text', reply_text)
        object.__setattr__(self, 'delivery_tag', delivery_tag)
        object.__setattr__(self, 'body_size', body_size)
        object.__setattr__(self, 'approved_headers', tuple(sorted(approved)))
        object.__setattr__(self, 'headers', types.MappingProxyType(disclosed))
        object.__setattr__(self, 'withheld_header_count',
                           len(raw_headers) - len(disclosed))
        for name in DISCLOSABLE_PROPERTIES:
            object.__setattr__(self, name, getattr(properties, name, None))
        object.__setattr__(self, '_locked', True)

    @classmethod
    def from_publish(cls,
                     kind: PublishFailureKind,
                     *,
                     exchange: str | bytes | None,
                     routing_key: str | bytes | None,
                     body: bytes | None,
                     properties: Any,
                     approved_headers: Sequence[str | bytes] = (),
                     channel_number: int | None = None,
                     delivery_tag: int | None = None,
                     method: Any = None) -> PublishFailure:
        """
        Build the view from what a publish and its failure reply carry.

        :param kind: Why the publish failed
        :param exchange: Exchange the publish was addressed to
        :param routing_key: Routing key the publish used
        :param body: The message body, used only to report its size
        :param properties: The publish's `pika.spec.BasicProperties`
        :param approved_headers: Header names whose values may be disclosed
        :param channel_number: Channel the publish was made on
        :param delivery_tag: Broker delivery tag, if known
        :param method: The `Basic.Return` reply, when the broker returned the message
        :returns: The restricted view
        """
        return cls(kind,
                   channel_number=channel_number,
                   exchange=exchange,
                   routing_key=routing_key,
                   reply_code=getattr(method, 'reply_code', None),
                   reply_text=getattr(method, 'reply_text', None),
                   delivery_tag=delivery_tag,
                   properties=properties,
                   body_size=None if body is None else len(body),
                   approved_headers=approved_headers)

    @override
    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, '_locked', False):
            raise AttributeError(f'{type(self).__name__} is read-only')
        object.__setattr__(self, name, value)

    @property
    def properties(self) -> dict[str, Any]:
        """The disclosed AMQP properties, without the header table."""
        return {
            name: getattr(self, name)
            for name in DISCLOSABLE_PROPERTIES
            if getattr(self, name) is not None
        }

    def as_dict(self) -> dict[str, Any]:
        """Return the view as a plain dict suitable for structured logging."""
        result: dict[str, Any] = {
            'kind': self.kind.value,
            'channel_number': self.channel_number,
            'exchange': self.exchange,
            'routing_key': self.routing_key,
            'reply_code': self.reply_code,
            'reply_text': self.reply_text,
            'delivery_tag': self.delivery_tag,
            'body_size': self.body_size,
            'withheld_header_count': self.withheld_header_count,
        }
        result.update(self.properties)
        result['headers'] = dict(self.headers)
        return result

    @override
    def __repr__(self) -> str:
        parts = [
            f'kind={self.kind.value}',
            f'channel={self.channel_number}',
            f'exchange={_bounded(self.exchange)}',
            f'routing_key={_bounded(self.routing_key)}',
        ]
        if self.reply_code is not None or self.reply_text is not None:
            parts.append(f'reply={self.reply_code}:{_bounded(self.reply_text)}')
        if self.delivery_tag is not None:
            parts.append(f'delivery_tag={self.delivery_tag}')
        if self.body_size is not None:
            parts.append(f'body_bytes={self.body_size}')
        for name in DISCLOSABLE_PROPERTIES:
            value = getattr(self, name)
            if value is not None:
                parts.append(f'{name}={_bounded(value)}')
        for name, value in self.headers.items():
            parts.append(f'header[{_bounded(name)}]={_bounded(value)}')
        parts.append(f'headers_withheld={self.withheld_header_count}')
        return f'PublishFailure({" ".join(parts)})'

    __str__ = __repr__


class FailedPublish:
    """
    The publish that failed, kept so the caller can republish it.

    This is business data, not a log record: it holds the body and the complete
    properties. Do not log it or hand it to an external service; log
    `PublishFailure` instead.

    :param exchange: Exchange the publish was addressed to
    :param routing_key: Routing key the publish used
    :param body: The message body
    :param properties: The `pika.spec.BasicProperties` sent with it
    :param delivery_tag: Broker delivery tag, if the broker assigned one
    :param mandatory: Whether the publish used the mandatory flag
    """

    __slots__ = ('body', 'delivery_tag', 'exchange', 'mandatory', 'properties',
                 'routing_key')

    def __init__(self,
                 exchange: str | bytes | None,
                 routing_key: str | bytes | None,
                 body: bytes,
                 properties: Any,
                 delivery_tag: int | None = None,
                 mandatory: bool = False) -> None:
        self.body = body
        self.delivery_tag = delivery_tag
        self.exchange = exchange
        self.mandatory = mandatory
        self.properties = properties
        self.routing_key = routing_key


def attach_publish_failure(
        error: BaseException,
        failure: PublishFailure,
        publish: FailedPublish | None = None) -> BaseException:
    """
    Return a copy of *error* carrying *failure* and optionally *publish*.

    The connection's close reason is shared by every caller rejected against it, so
    attaching one publish's view to that instance would disclose it to all of them.
    The caller raises the copy, which keeps the original type and args -- including
    host and port -- so existing ``except`` clauses still match.

    :param error: The exception describing the failure
    :param failure: The restricted view of the publish that failed
    :param publish: The publish itself, for the caller to republish
    :returns: A copy of *error* with `failure` and, when given, `publish` attributes
    """
    import copy  # local: pika.exceptions is imported during pika's own bootstrap

    copied = copy.copy(error)
    copied.failure = failure  # type: ignore[attr-defined]
    if publish is not None:
        copied.publish = publish  # type: ignore[attr-defined]
    return copied


def describe_publish_failure(error: BaseException) -> PublishFailure | None:
    """
    Return the restricted publish-failure view *error* carries, if any.

    This is what the logger does: the view, never the `publish` the exception also
    carries. An exception raised by pika before a publish was sent has no view, and
    one whose view was attached by an older pika is simply reported without it.

    :param error: Any exception a publish raised
    :returns: The attached `PublishFailure`, or None
    """
    failure = getattr(error, 'failure', None)
    return failure if isinstance(failure, PublishFailure) else None


class UnroutableError(AMQPChannelError):
    """
    Exception containing one or more unroutable messages returned by broker via Basic.Return.

    Used by BlockingChannel.

    In publisher-acknowledgements mode, this is raised upon receipt of Basic.Ack from broker; in the
    event of Basic.Nack from broker, `NackError` is raised instead
    """

    def __init__(self,
                 messages: Sequence[ReturnedMessageLike],
                 failure: PublishFailure | None = None,
                 publish: FailedPublish | None = None) -> None:
        """
        :param messages: Sequence of returned unroutable messages
        :param failure: Restricted view of the failed publish, safe to log
        :param publish: The publish that failed, for the caller to republish
        """
        super().__init__(f'{len(messages)} unroutable message(s) returned')

        # `Sequence[Any]` rather than the protocol so that existing code
        # annotating these against the concrete `ReturnedMessage` keeps checking.
        # A protocol is not assignable to the nominal class it describes.
        self.messages: Sequence[Any] = messages
        self.failure = failure
        self.publish = publish

    @override
    def __repr__(self) -> str:
        if self.failure is not None:
            return f'{self.__class__.__name__}: unroutable message returned; {self.failure!r}'
        return f'{self.__class__.__name__}: {len(self.messages)} unroutable messages returned by broker'


class NackError(AMQPChannelError):
    """
    This exception is raised when a message published in publisher-acknowledgements mode is Nack'ed
    by the broker.

    Used by BlockingChannel.
    """

    def __init__(self,
                 messages: Sequence[ReturnedMessageLike],
                 failure: PublishFailure | None = None,
                 publish: FailedPublish | None = None) -> None:
        """
        :param messages: Sequence of returned unroutable messages
        :param failure: Restricted view of the failed publish, safe to log
        :param publish: The publish that failed, for the caller to republish
        """
        super().__init__(f'{len(messages)} message(s) NACKed')

        # See the note in `UnroutableError.__init__`.
        self.messages: Sequence[Any] = messages
        self.failure = failure
        self.publish = publish

    @override
    def __repr__(self) -> str:
        if self.failure is not None:
            return f'{self.__class__.__name__}: publish refused by broker; {self.failure!r}'
        return f'{self.__class__.__name__}: {len(self.messages)} unroutable messages returned by broker'


class InvalidChannelNumber(AMQPError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: An invalid channel number has been specified: {self.args[0]}'


class ProtocolSyntaxError(AMQPError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: An unspecified protocol syntax error occurred'


class UnexpectedFrameError(ProtocolSyntaxError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: Received a frame out of sequence: {self.args[0]!r}'


class ProtocolVersionMismatch(ProtocolSyntaxError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: Protocol versions did not match: {self.args[0]!r} vs {self.args[1]!r}'


class FrameTooLargeError(AMQPConnectionError):
    """An inbound frame declared a payload above the connection's frame limit."""

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: Received a frame of {self.args[0]} bytes, above the '
            f'limit of {self.args[1]} bytes{self._host_port_suffix()}')


class MessageBodyTooLargeError(AMQPConnectionError):
    """An inbound message declared a body above ``max_inbound_message_body_size``."""

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: Received a message with a {self.args[0]}-byte body, '
            f'above the max_inbound_message_body_size of {self.args[1]} bytes'
            f'{self._host_port_suffix()}')


class BodyTooLongError(ProtocolSyntaxError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: Received too many bytes for a message delivery: '
            f'Received {self.args[0]}, expected {self.args[1]}')


class InvalidFrameError(ProtocolSyntaxError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: Invalid frame received: {self.args[0]!r}'


class InvalidFieldTypeException(ProtocolSyntaxError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: Unsupported field kind {self.args[0]}'


class UnsupportedAMQPFieldException(ProtocolSyntaxError):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: Unsupported field kind {type(self.args[1])}'


class MethodNotImplemented(AMQPError):
    pass


class ChannelError(Exception):

    @override
    def __repr__(self) -> str:
        return f'{self.__class__.__name__}: An unspecified error occurred with the Channel'


class ReentrancyError(Exception):
    """
    The requested operation would result in unsupported recursion or reentrancy.

    Used by BlockingConnection/BlockingChannel
    """


class WorkQueueFullError(AMQPConnectionError):
    """
    The work queue stayed full for longer than the configured ``work_queue_put_timeout``.

    Used by Connection/Channel.  Subclasses [`AMQPConnectionError`][pika.exceptions.AMQPConnectionError] because an overflow tears
    the connection down, so applications catching connection loss by base class see it too.
    """


class ShortStringTooLong(AMQPError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: AMQP Short String can contain up to 255 bytes: '
            f'{self.args[0]!s:.300}')


class UnencodableDecimalError(AMQPError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: decimal.Decimal value has no AMQP decimal '
            f'representation: {self.args[0]!s:.300}')


class UnencodableFloatError(AMQPError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: float value is not finite, which RabbitMQ '
            f'cannot decode: {self.args[0]!s:.300}')


class UnencodableLongError(AMQPError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: integer value has no AMQP field-table '
            f'representation (outside signed 64-bit): {self.args[0]!s:.300}')


class UnencodableTimestampError(AMQPError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: datetime value has no AMQP timestamp '
            f'representation (before the Unix epoch): {self.args[0]!s:.300}')


class DuplicateGetOkCallback(ChannelError):

    @override
    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}: basic_get can only be called again after the callback for '
            'the previous basic_get is executed')


#: Errors a publish raises about the caller's own input or channel, not the connection.
#: A publish reports one of these unchanged: it was not sent, so there is nothing to
#: correlate against the broker and nothing to retry.
PUBLISH_NOT_SENT_ERRORS = (
    TypeError,
    ValueError,
    ChannelWrongStateError,
    ChannelClosed,
    UnencodableDecimalError,
    UnencodableFloatError,
    UnencodableLongError,
    UnencodableTimestampError,
    UnsupportedAMQPFieldException,
)


def is_publish_transport_failure(exc: BaseException) -> bool:
    """
    Whether *exc* describes the connection failing rather than the publish.

    :param exc: What a publish raised
    :returns: True when the publish may have reached the broker
    """
    return not isinstance(exc, PUBLISH_NOT_SENT_ERRORS)
