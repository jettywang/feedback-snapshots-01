"""Sending and receiving messages."""

from __future__ import annotations

import inspect
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from itertools import count
from threading import local
from typing import TYPE_CHECKING, Any

from .common import maybe_declare
from .compression import compress
from .connection import PooledConnection, is_connection, maybe_channel
from .entity import Exchange, Queue, maybe_delivery_mode
from .exceptions import (
    BatchPublishError,
    ContentDisallowed,
    RoutingPolicyError,
)
from .serialization import dumps, prepare_accept_content
from .utils.functional import ChannelPromise, maybe_list

if TYPE_CHECKING:
    from types import TracebackType

__all__ = ('BatchEntry', 'Exchange', 'Queue', 'Producer', 'Consumer',
           'RoutingPolicyViolation', 'RoutingViolation')

DEFAULT_BATCH_SIZE = 1000


@dataclass(frozen=True)
class RoutingViolation:
    """A batch entry rejected by the routing policy.

    Attributes:
    ----------
        index (int): Zero-based position of the entry within the batch.
        routing_key (str): Routing key requested by the entry.
        exchange (str): Exchange requested by the entry.
        entry (BatchEntry): The rejected entry.
        reason (str): Explanation supplied by the policy.
    """

    index: int
    routing_key: str
    exchange: str
    entry: BatchEntry
    reason: str = 'routing key is not allowed by the routing policy'

    @property
    def message(self):
        """Alias for :attr:`reason`."""
        return self.reason

    @property
    def body(self):
        """Return the rejected entry's prepared body."""
        return self.entry.body

    def __str__(self):
        return (
            f'batch entry {self.index} '
            f'(exchange={self.exchange!r}, routing_key={self.routing_key!r}) '
            f'{self.reason}'
        )


@dataclass
class BatchEntry:
    """One publication staged in a :meth:`Producer.batch`."""

    index: int
    body: Any
    exchange: str
    routing_key: str
    declare: list
    priority: int
    content_type: str | None
    content_encoding: str | None
    headers: Mapping
    properties: dict
    mandatory: bool = False
    immediate: bool = False
    timeout: float | None = None
    confirm_timeout: float | None = None
    reply_to: Any = None
    retry: bool = False
    retry_policy: dict = field(default_factory=dict)
    result: Any = None
    _producer: Any = field(default=None, repr=False)
    _channel: Any = field(default=None, repr=False)
    _message: Any = field(default=None, repr=False)
    _state: str = field(default='pending', repr=False)

    @property
    def message(self):
        """Return the transport message for this entry, preparing it once."""
        if self._message is None:
            self.prepare()
        return self._message

    def prepare(self):
        """Prepare the transport message."""
        if isinstance(self.reply_to, Queue):
            self.properties['reply_to'] = self.reply_to.name
        if self._producer is not None:
            self._channel = self._producer.channel
        self._message = self._channel.prepare_message(
            self.body,
            self.priority,
            self.content_type,
            self.content_encoding,
            self.headers,
            self.properties,
        )
        return self._message

    @property
    def publish_kwargs(self):
        """Return the keyword arguments used for the final publication."""
        return {
            'exchange': self.exchange,
            'routing_key': self.routing_key,
            'mandatory': self.mandatory,
            'immediate': self.immediate,
            'timeout': self.timeout,
            'confirm_timeout': self.confirm_timeout,
        }

    def delivery_state(self):
        """Return the entry's delivery state.

        One of ``'pending'`` (not attempted), ``'buffered'`` (handed to a
        transport batch but not confirmed), ``'delivered'``, or
        ``'unknown'`` (the transport may or may not have received it).
        """
        return self._state

    @property
    def state(self):
        """Alias for the current delivery state."""
        return self._state

    @property
    def pending(self):
        return self._state == 'pending'

    @property
    def buffered(self):
        return self._state == 'buffered'

    @property
    def delivered(self):
        return self._state == 'delivered'

    @property
    def unknown(self):
        return self._state == 'unknown'


class _ProducerBatchState:
    """State shared by nested batch contexts in one producer thread."""

    def __init__(self, max_size, routing_policy=None,
                 maybe_declare=None):
        self.max_size = max_size
        self.routing_policy = routing_policy
        self._maybe_declare = maybe_declare
        self.aborted = False
        self.session = None
        self.immediate = False
        self.entries = []
        self._validated_entries = 0
        self._sent_entries = 0
        self._session_channel = None
        self._failure = None
        self._accepted = []

    @property
    def staged(self):
        """Return whether publications are validated before being sent."""
        return self.routing_policy is not None


    def _get_session(self, channel):
        if self.immediate:
            return None
        if self.session is None:
            create_batch = getattr(channel, 'create_publish_batch', None)
            supports_batch = getattr(channel, 'supports_batch_publish', True)
            if create_batch is None or not supports_batch:
                self.immediate = True
                return None
            self.session = create_batch(max_size=self.max_size)
            self._session_channel = channel
        elif self._session_channel is not channel:
            raise RuntimeError(
                'Producer channel changed while a publish batch was active',
            )
        return self.session

    def _check_usable(self):
        if self.aborted:
            raise RuntimeError('Cannot publish through an aborted batch')
        if self._failure is not None:
            raise BatchPublishError(
                'Publish batch cannot continue after a previous failure',
                **_delivery_details(self.entries),
            ) from self._failure

    def record_publish_failure(self, exc, entry=None, sent=False):
        """Mark the batch failed and annotate ``exc`` with entry states."""
        self._failure = exc
        if entry is not None:
            entry._state = 'unknown' if sent or entry.unknown else (
                'pending' if entry.pending else entry.state
            )
        _attach_delivery_details(exc, self.entries)

    def stage(self, producer, **entry_args):
        """Stage a publication until the whole batch has been validated."""
        self._check_usable()
        entry = BatchEntry(
            index=len(self.entries), _producer=producer, **entry_args,
        )
        self.entries.append(entry)
        return entry

    def record(self, channel, **entry_args):
        """Record an entry published immediately by the batch."""
        entry = BatchEntry(
            index=len(self.entries), _channel=channel, **entry_args,
        )
        self.entries.append(entry)
        return entry

    def publish(self, channel, message, entry=None, **kwargs):
        """Publish one message through the transport or its batch session."""
        self._check_usable()
        session = None
        try:
            session = self._get_session(channel)
            if session is None:
                result = channel.basic_publish(message, **kwargs)
            else:
                result = session.publish(message, **kwargs)
        except BaseException as exc:
            self.record_publish_failure(exc, entry, sent=session is not None)
            raise
        if entry is not None:
            if session is None:
                entry._state = 'delivered'
            else:
                entry._state = 'buffered'
                self._accepted.append(entry)
        return result

    def flush(self):
        if self.aborted:
            raise RuntimeError('Cannot flush an aborted batch')
        if self._failure is not None:
            raise BatchPublishError(
                'Publish batch cannot continue after a previous failure',
                **_delivery_details(self.entries),
            ) from self._failure
        if self.routing_policy is None:
            self._flush_accepted()
        else:
            self._validate_pending()
            self._flush_staged()

    def _flush_accepted(self):
        if self.session is None or not self._accepted:
            return
        accepted = list(self._accepted)
        try:
            self.session.flush()
        except BaseException as exc:
            self._failure = exc
            for entry in accepted:
                entry._state = 'unknown'
            self._accepted.clear()
            _attach_delivery_details(exc, self.entries)
            raise
        for entry in accepted:
            entry._state = 'delivered'
        self._accepted.clear()

    def _validate_pending(self):
        while self._validated_entries < len(self.entries):
            violations = []
            for entry in self.entries[self._validated_entries:]:
                reason = _routing_violation(self.routing_policy, entry)
                if reason is not None:
                    violations.append(RoutingViolation(
                        index=entry.index,
                        routing_key=entry.routing_key,
                        exchange=entry.exchange,
                        entry=entry,
                        reason=reason,
                    ))
            if violations:
                raise RoutingPolicyError(violations)
            self._validated_entries = len(self.entries)

    def _flush_staged(self):
        if self._sent_entries >= len(self.entries):
            return
        pending = self.entries[self._sent_entries:]
        accepted = []
        current = None
        attempting = False
        try:
            for entry in pending:
                current = entry
                attempting = False
                entry._state = 'unknown'
                self._declare_entry(entry)
                entry.prepare()
                session = self._get_session(entry._channel)
                attempting = True
                if session is None:
                    entry.result = entry._channel.basic_publish(
                        entry.message, **entry.publish_kwargs,
                    )
                    entry._state = 'delivered'
                else:
                    entry.result = session.publish(
                        entry.message, **entry.publish_kwargs,
                    )
                    entry._state = 'buffered'
                    accepted.append(entry)
                self._sent_entries = entry.index + 1
            if accepted:
                try:
                    self.session.flush()
                except BaseException:
                    for entry in accepted:
                        entry._state = 'unknown'
                    raise
                for entry in accepted:
                    entry._state = 'delivered'
        except BaseException as exc:
            self._failure = exc
            if not attempting and current is not None:
                current._state = 'pending'
            for entry in accepted:
                if entry._state != 'delivered':
                    entry._state = 'unknown'
            _attach_delivery_details(exc, self.entries)
            raise

    def _declare_entry(self, entry):
        maybe_declare = self._maybe_declare
        for entity in entry.declare:
            maybe_declare(entity, retry=entry.retry, **entry.retry_policy)

    def abort(self):
        if self.aborted:
            return
        self.aborted = True
        self._failure = self._failure or RuntimeError('batch aborted')
        if self.session is not None:
            self.session.discard()
        for entry in self.entries:
            if entry.delivered:
                continue
            if entry.buffered or entry.unknown:
                entry._state = 'unknown'
            else:
                entry._state = 'pending'

    def close(self):
        if self.session is not None:
            self.session.close()


def _delivery_details(entries):
    delivered = [entry for entry in entries if entry.delivered]
    unknown = [entry for entry in entries
               if entry.unknown or entry.buffered]
    pending = [entry for entry in entries if entry.pending]
    return {
        'delivered': delivered,
        'unknown': unknown,
        'pending': pending,
    }


def _attach_delivery_details(exc, entries):
    if not entries:
        return
    details = _delivery_details(entries)
    for name, value in details.items():
        try:
            setattr(exc, name, value)
        except (AttributeError, TypeError):  # pragma: no cover
            pass


def _routing_violation(policy, entry):
    """Return a reason string when ``entry`` violates ``policy``."""
    decision = getattr(policy, 'is_allowed', None)
    if decision is None:
        decision = getattr(policy, 'validate_route', None)
    if decision is None:
        decision = getattr(policy, 'allows', None)
    if decision is not None:
        return _policy_rejection(_call_routing_policy(decision, entry))

    if callable(policy):
        allowed = _call_routing_policy(policy, entry)
        return _policy_rejection(allowed)

    if isinstance(policy, Mapping):
        allow = policy.get('allow')
        deny = policy.get('deny')
        if allow is not None or deny is not None:
            if deny is not None and _policy_allows(deny, entry):
                return 'routing key is denied by the routing policy'
            if allow is not None and not _policy_allows(allow, entry):
                return 'routing key is not allowed by the routing policy'
            return None
        for key, value in policy.items():
            if key == entry.routing_key or key == (entry.exchange,
                                                   entry.routing_key):
                allowed = (
                    _call_routing_policy(value, entry)
                    if callable(value) else value
                )
                return _policy_rejection(allowed)
        wildcard = policy.get('*') or policy.get(('*', '*'))
        if wildcard is not None:
            allowed = (
                _call_routing_policy(wildcard, entry)
                if callable(wildcard) else wildcard
            )
            return _policy_rejection(allowed)
        return 'routing key is not allowed by the routing policy'

    if isinstance(policy, Collection) and not isinstance(policy, (str, bytes)):
        if entry.routing_key in policy:
            return None
        if (entry.exchange, entry.routing_key) in policy:
            return None
        for allowed in policy:
            if (isinstance(allowed, str) and allowed.endswith('.*') and
                    entry.routing_key.startswith(allowed[:-1])):
                return None
        return 'routing key is not allowed by the routing policy'

    raise TypeError(
        'routing_policy must be a callable, collection, or mapping',
    )


def _policy_allows(policy, entry):
    if callable(policy):
        return _policy_rejection(_call_routing_policy(policy, entry)) is None
    return _routing_violation(policy, entry) is None


def _same_policy(left, right):
    try:
        return left is right or left == right
    except Exception:  # pragma: no cover - defensive
        return False


def _policy_rejection(allowed):
    if allowed is None or allowed is True:
        return None
    if isinstance(allowed, str):
        return allowed
    if allowed:
        return None
    return 'routing key is not allowed by the routing policy'


def _call_routing_policy(policy, entry):
    """Call a routing policy, accepting one- or two-argument signatures."""
    try:
        parameters = inspect.signature(policy).parameters.values()
    except (TypeError, ValueError):
        parameters = ()
    positional = [
        parameter for parameter in parameters
        if parameter.kind in (
            parameter.POSITIONAL_ONLY,
            parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(positional) == 1:
        return policy(entry)
    return policy(entry.exchange, entry.routing_key)


class _ProducerBatch:
    """Context manager returned by :meth:`Producer.batch`."""

    def __init__(self, producer, max_size, routing_policy=None):
        self.producer = producer
        self.max_size = max_size
        self.routing_policy = routing_policy
        self.state = None
        self.is_outermost = False
        self.entered = False
        self.active = False

    def __enter__(self):
        if self.entered:
            raise RuntimeError('Publish batch context cannot be re-entered')
        self.entered = True
        self.active = True

        state = getattr(self.producer._batch_local, 'current', None)
        if state is None:
            state = _ProducerBatchState(
                self.max_size,
                self.routing_policy,
                self.producer.maybe_declare,
            )
            self.producer._batch_local.current = state
            self.is_outermost = True
        elif (self.routing_policy is not None and
              state.routing_policy is not None and
              not _same_policy(self.routing_policy, state.routing_policy)):
            raise RuntimeError(
                'Cannot change the routing policy inside a nested batch',
            )
        self.state = state
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        state = self.state
        if state is None:
            return None

        cleanup_error = None
        try:
            if self.is_outermost:
                del self.producer._batch_local.current

            if exc_type is not None:
                try:
                    state.abort()
                except BaseException as exc:
                    cleanup_error = exc

            if self.is_outermost:
                if exc_type is None and not state.aborted:
                    try:
                        state.flush()
                    except BaseException as exc:
                        cleanup_error = exc
                try:
                    state.close()
                except BaseException as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
        finally:
            self.active = False

        if exc_type is None and cleanup_error is not None:
            raise cleanup_error
        return None

    def flush(self):
        """Flush messages buffered by the active batch."""
        if not self.active:
            raise RuntimeError('Publish batch context is not active')
        self.state.flush()

    @property
    def entries(self):
        """Return the publications staged or sent by this batch."""
        if self.state is None:
            return []
        return list(self.state.entries)

    def delivery_states(self):
        """Return each entry's current delivery state, in batch order."""
        return [entry.delivery_state() for entry in self.entries]


class Producer:
    """Message Producer.

    Arguments:
    ---------
        channel (kombu.Connection, ChannelT): Connection or channel.
        exchange (kombu.entity.Exchange, str): Optional default exchange.
        routing_key (str): Optional default routing key.
        serializer (str): Default serializer. Default is `"json"`.
        compression (str): Default compression method.
            Default is no compression.
        auto_declare (bool): Automatically declare the default exchange
            at instantiation. Default is :const:`True`.
        on_return (Callable): Callback to call for undeliverable messages,
            when the `mandatory` or `immediate` arguments to
            :meth:`publish` is used. This callback needs the following
            signature: `(exception, exchange, routing_key, message)`.
            Note that the producer needs to drain events to use this feature.
    """

    #: Default exchange
    exchange = None

    #: Default routing key.
    routing_key = ''

    #: Default serializer to use. Default is JSON.
    serializer = None

    #: Default compression method.  Disabled by default.
    compression = None

    #: By default, if a default exchange is set,
    #: that exchange will be declare when publishing a message.
    auto_declare = True

    #: Basic return callback.
    on_return = None

    #: Set if channel argument was a Connection instance (using
    #: default_channel).
    __connection__ = None

    def __init__(self, channel, exchange=None, routing_key=None,
                 serializer=None, auto_declare=None, compression=None,
                 on_return=None):
        self._channel = channel
        self.exchange = exchange
        self.routing_key = routing_key or self.routing_key
        self.serializer = serializer or self.serializer
        self.compression = compression or self.compression
        self.on_return = on_return or self.on_return
        self._channel_promise = None
        self._batch_local = local()
        if self.exchange is None:
            self.exchange = Exchange('')
        if auto_declare is not None:
            self.auto_declare = auto_declare

        if self._channel:
            self.revive(self._channel)

    def __repr__(self):
        return f'<Producer: {self._channel}>'

    def __reduce__(self):
        return self.__class__, self.__reduce_args__()

    def __reduce_args__(self):
        return (None, self.exchange, self.routing_key, self.serializer,
                self.auto_declare, self.compression)

    def declare(self):
        """Declare the exchange.

        Note:
        ----
            This happens automatically at instantiation when
            the :attr:`auto_declare` flag is enabled.
        """
        if self.exchange.name:
            self.exchange.declare()

    def maybe_declare(self, entity, retry=False, **retry_policy):
        """Declare exchange if not already declared during this session."""
        if entity:
            if retry:
                connection = self.connection
                on_revive = retry_policy.get('on_revive')

                def revive(channel):
                    if channel.connection.client is connection:
                        self.revive(channel)
                    if on_revive:
                        on_revive(channel)

                retry_policy['on_revive'] = revive
            return maybe_declare(entity, self.channel, retry, **retry_policy)

    @property
    def supports_batch_publish(self):
        """Return whether the active transport can defer batched publishes."""
        connection = self.connection
        if connection is None:
            return False
        try:
            transport_support = connection.transport.implements.batch_publish
        except AttributeError:
            return False
        channel = self._channel
        if channel is not None and not isinstance(channel, ChannelPromise):
            configured_support = getattr(
                channel,
                'supports_batch_publish',
                transport_support,
            )
        else:
            configured_support = getattr(
                connection.transport,
                'supports_batch_publish',
                transport_support,
            )
        return bool(transport_support and configured_support)

    def batch(self, max_size=DEFAULT_BATCH_SIZE, routing_policy=None,
              validate=None, policy=None):
        """Group :meth:`publish` calls into transport-owned batches.

        Unsupported transports retain immediate publication.  A successful
        outermost context exit flushes pending messages; an exceptional exit
        discards messages that have not already been flushed.

        When ``routing_policy`` is given, publications are staged instead of
        sent as they are made.  Every staged entry is checked against the
        policy before the outermost exit (or an explicit :meth:`flush`)
        declares or sends anything.  If any entry is rejected, nothing is
        declared or published and :exc:`~kombu.exceptions.RoutingPolicyError`
        is raised with one
        :class:`~kombu.messaging.RoutingViolation` per rejected entry.

        A policy may also be an object with an ``is_allowed``, ``allows``, or
        ``validate_route`` method, and a mapping may use the ``'allow'`` and
        ``'deny'`` keys instead of individual routing keys.  Collection
        entries ending in ``.*`` match a routing-key prefix.

        ``routing_policy`` may be:

        * a callable taking ``(exchange, routing_key)`` (or a single
          :class:`~kombu.messaging.BatchEntry`) and returning ``True`` to
          allow the entry, ``False`` to reject it, or a string describing
          why it was rejected;
        * a collection of allowed routing keys; or
        * a mapping from a routing key (or ``(exchange, routing_key)``
          tuple) to a decision or a callable returning one.

        If sending fails, the raised error exposes ``delivered``,
        ``unknown``, and ``pending`` entry lists so callers can tell which
        entries were confirmed and which still have an uncertain outcome.

        :param max_size: Maximum transport operations to buffer before an
            automatic flush. Must be a positive integer.
        :type max_size: int
        :param routing_policy: Optional routing policy used to preflight the
            whole batch before anything is declared or sent.
        :param validate: Alias for ``routing_policy``.
        :param policy: Alias for ``routing_policy``.
        """
        options = [
            value for value in (routing_policy, validate, policy)
            if value is not None
        ]
        if len(options) > 1:
            raise TypeError('specify only one routing policy option')
        if options:
            routing_policy = options[0]
        if (isinstance(max_size, bool) or
                not isinstance(max_size, int) or max_size <= 0):
            raise ValueError('max_size must be a positive integer')
        if isinstance(routing_policy, (str, bytes)) or (
            routing_policy is not None and
            not (callable(routing_policy) or
                 isinstance(routing_policy, (Mapping, Collection)) or
                 any(hasattr(routing_policy, name) for name in (
                     'is_allowed', 'validate_route', 'allows',
                 )))
        ):
            raise TypeError(
                'routing_policy must be a callable, collection, mapping, '
                'or policy object',
            )
        return _ProducerBatch(self, max_size, routing_policy)

    def _delivery_details(self, exchange, delivery_mode=None,
                          maybe_delivery_mode=maybe_delivery_mode,
                          Exchange=Exchange):
        if isinstance(exchange, Exchange):
            return exchange.name, maybe_delivery_mode(
                delivery_mode or exchange.delivery_mode,
            )
        # exchange is string, so inherit the delivery
        # mode of our default exchange.
        return exchange, maybe_delivery_mode(
            delivery_mode or self.exchange.delivery_mode,
        )

    def publish(self, body, routing_key=None, delivery_mode=None,
                mandatory=False, immediate=False, priority=0,
                content_type=None, content_encoding=None, serializer=None,
                headers=None, compression=None, exchange=None, retry=False,
                retry_policy=None, declare=None, expiration=None, timeout=None,
                confirm_timeout=None,
                **properties):
        """Publish message to the specified exchange.

        Arguments:
        ---------
            body (Any): Message body.
            routing_key (str): Message routing key.
            delivery_mode (enum): See :attr:`delivery_mode`.
            mandatory (bool): Currently not supported.
            immediate (bool): Currently not supported.
            priority (int): Message priority. A number between 0 and 9.
            content_type (str): Content type. Default is auto-detect.
            content_encoding (str): Content encoding. Default is auto-detect.
            serializer (str): Serializer to use. Default is auto-detect.
            compression (str): Compression method to use.  Default is none.
            headers (Dict): Mapping of arbitrary headers to pass along
                with the message body.
            exchange (kombu.entity.Exchange, str): Override the exchange.
                Note that this exchange must have been declared.
            declare (Sequence[EntityT]): Optional list of required entities
                that must have been declared before publishing the message.
                The entities will be declared using
                :func:`~kombu.common.maybe_declare`.
            retry (bool): Retry publishing, or declaring entities if the
                connection is lost.
            retry_policy (Dict): Retry configuration, this is the keywords
                supported by :meth:`~kombu.Connection.ensure`.
            expiration (float): A TTL in seconds can be specified per message.
                Default is no expiration.
            timeout (float): Set timeout to wait maximum timeout second
                for message to publish.
            confirm_timeout (float): Set confirm timeout to wait maximum timeout second
                for message to confirm publishing if the channel is set to confirm publish mode.
            ``**properties`` (Any): Additional message properties, see AMQP spec.
        """
        _publish = self._publish

        declare = [] if declare is None else declare
        headers = {} if headers is None else headers
        retry_policy = {} if retry_policy is None else retry_policy
        routing_key = self.routing_key if routing_key is None else routing_key
        compression = self.compression if compression is None else compression

        exchange_name, properties['delivery_mode'] = self._delivery_details(
            exchange or self.exchange, delivery_mode,
        )

        if expiration is not None:
            properties['expiration'] = str(int(expiration * 1000))

        body, content_type, content_encoding = self._prepare(
            body, serializer, content_type, content_encoding,
            compression, headers)

        if self.auto_declare and self.exchange.name:
            if self.exchange not in declare:
                # XXX declare should be a Set.
                declare.append(self.exchange)

        if retry:
            self.connection.transport_options.update(retry_policy)
            _publish = self.connection.ensure(self, _publish, **retry_policy)
        return _publish(
            body, priority, content_type, content_encoding,
            headers, properties, routing_key, mandatory, immediate,
            exchange_name, declare, timeout, confirm_timeout, retry, retry_policy
        )

    def _publish(self, body, priority, content_type, content_encoding,
                 headers, properties, routing_key, mandatory,
                 immediate, exchange, declare, timeout=None, confirm_timeout=None, retry=False, retry_policy=None):
        retry_policy = {} if retry_policy is None else retry_policy
        batch = getattr(self._batch_local, 'current', None)
        if batch is not None and batch.staged:
            return batch.stage(
                self,
                body=body,
                exchange=exchange,
                routing_key=routing_key,
                declare=declare,
                priority=priority,
                content_type=content_type,
                content_encoding=content_encoding,
                headers=headers,
                properties=properties,
                mandatory=mandatory,
                immediate=immediate,
                timeout=timeout,
                confirm_timeout=confirm_timeout,
                reply_to=properties.get('reply_to'),
                retry=retry,
                retry_policy=retry_policy,
            )

        if declare:
            maybe_declare = self.maybe_declare
            for entity in declare:
                maybe_declare(entity, retry=retry, **retry_policy)

        channel = self.channel
        message = channel.prepare_message(
            body, priority, content_type,
            content_encoding, headers, properties,
        )

        # handle autogenerated queue names for reply_to
        reply_to = properties.get('reply_to')
        if isinstance(reply_to, Queue):
            properties['reply_to'] = reply_to.name
        publish_kwargs = {
            'exchange': exchange,
            'routing_key': routing_key,
            'mandatory': mandatory,
            'immediate': immediate,
            'timeout': timeout,
            'confirm_timeout': confirm_timeout,
        }
        if batch is not None:
            entry = batch.record(
                channel,
                body=body,
                exchange=exchange,
                routing_key=routing_key,
                declare=declare,
                priority=priority,
                content_type=content_type,
                content_encoding=content_encoding,
                headers=headers,
                properties=properties,
                mandatory=mandatory,
                immediate=immediate,
                timeout=timeout,
                confirm_timeout=confirm_timeout,
                retry=retry,
                retry_policy=retry_policy,
            )
            return batch.publish(channel, message, entry=entry,
                                 **publish_kwargs)
        return channel.basic_publish(message, **publish_kwargs)

    def _get_channel(self):
        channel = self._channel
        if isinstance(channel, ChannelPromise):
            channel = self._channel = channel()
            self.exchange.revive(channel)
            if self.on_return:
                channel.events['basic_return'].add(self.on_return)
        return channel

    def _set_channel(self, channel):
        self._channel = channel

    channel = property(_get_channel, _set_channel)

    def revive(self, channel):
        """Revive the producer after connection loss."""
        if is_connection(channel):
            connection = channel
            self.__connection__ = connection
            channel = ChannelPromise(lambda: connection.default_channel)
        if isinstance(channel, ChannelPromise):
            self._channel = channel
            self.exchange = self.exchange(channel)
        else:
            # Channel already concrete
            self._channel = channel
            if self.on_return:
                self._channel.events['basic_return'].add(self.on_return)
            self.exchange = self.exchange(channel)

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None
    ) -> None:
        # In case the connection is part of a pool it needs to be
        # replaced in case of an exception
        if self.__connection__ is not None and exc_type is not None:
            if isinstance(self.__connection__, PooledConnection):
                self.__connection__._pool.replace(self.__connection__)

        self.release()

    def release(self):
        pass

    close = release

    def _prepare(self, body, serializer=None, content_type=None,
                 content_encoding=None, compression=None, headers=None):

        # No content_type? Then we're serializing the data internally.
        if not content_type:
            serializer = serializer or self.serializer
            (content_type, content_encoding,
             body) = dumps(body, serializer=serializer)
        else:
            # If the programmer doesn't want us to serialize,
            # make sure content_encoding is set.
            if isinstance(body, str):
                if not content_encoding:
                    content_encoding = 'utf-8'
                body = body.encode(content_encoding)

            # If they passed in a string, we can't know anything
            # about it. So assume it's binary data.
            elif not content_encoding:
                content_encoding = 'binary'

        if compression:
            body, headers['compression'] = compress(body, compression)

        return body, content_type, content_encoding

    @property
    def connection(self):
        try:
            return self.__connection__ or self.channel.connection.client
        except AttributeError:
            pass


class Consumer:
    """Message consumer.

    Arguments:
    ---------
        channel (kombu.Connection, ChannelT): see :attr:`channel`.
        queues (Sequence[kombu.Queue]): see :attr:`queues`.
        no_ack (bool): see :attr:`no_ack`.
        auto_declare (bool): see :attr:`auto_declare`
        callbacks (Sequence[Callable]): see :attr:`callbacks`.
        on_message (Callable): See :attr:`on_message`
        on_decode_error (Callable): see :attr:`on_decode_error`.
        prefetch_count (int): see :attr:`prefetch_count`.
    """

    ContentDisallowed = ContentDisallowed

    #: The connection/channel to use for this consumer.
    channel = None

    #: A single :class:`~kombu.Queue`, or a list of queues to
    #: consume from.
    queues = None

    #: Flag for automatic message acknowledgment.
    #: If enabled the messages are automatically acknowledged by the
    #: broker.  This can increase performance but means that you
    #: have no control of when the message is removed.
    #:
    #: Disabled by default.
    no_ack = None

    #: By default all entities will be declared at instantiation, if you
    #: want to handle this manually you can set this to :const:`False`.
    auto_declare = True

    #: List of callbacks called in order when a message is received.
    #:
    #: The signature of the callbacks must take two arguments:
    #: `(body, message)`, which is the decoded message body and
    #: the :class:`~kombu.Message` instance.
    callbacks = None

    #: Optional function called whenever a message is received.
    #:
    #: When defined this function will be called instead of the
    #: :meth:`receive` method, and :attr:`callbacks` will be disabled.
    #:
    #: So this can be used as an alternative to :attr:`callbacks` when
    #: you don't want the body to be automatically decoded.
    #: Note that the message will still be decompressed if the message
    #: has the ``compression`` header set.
    #:
    #: The signature of the callback must take a single argument,
    #: which is the :class:`~kombu.Message` object.
    #:
    #: Also note that the ``message.body`` attribute, which is the raw
    #: contents of the message body, may in some cases be a read-only
    #: :class:`buffer` object.
    on_message = None

    #: Callback called when a message can't be decoded.
    #:
    #: The signature of the callback must take two arguments: `(message,
    #: exc)`, which is the message that can't be decoded and the exception
    #: that occurred while trying to decode it.
    on_decode_error = None

    #: List of accepted content-types.
    #:
    #: An exception will be raised if the consumer receives
    #: a message with an untrusted content type.
    #: By default all content-types are accepted, but not if
    #: :func:`kombu.disable_untrusted_serializers` was called,
    #: in which case only json is allowed.
    accept = None

    #: Initial prefetch count
    #:
    #: If set, the consumer will set the prefetch_count QoS value at startup.
    #: Can also be changed using :meth:`qos`.
    prefetch_count = None

    #: Mapping of queues we consume from.
    _queues = None

    _tags = count(1)  # global

    def __init__(self, channel, queues=None, no_ack=None, auto_declare=None,
                 callbacks=None, on_decode_error=None, on_message=None,
                 accept=None, prefetch_count=None, tag_prefix=None):
        self.channel = channel
        self.queues = maybe_list(queues or [])
        self.no_ack = self.no_ack if no_ack is None else no_ack
        self.callbacks = (self.callbacks or [] if callbacks is None
                          else callbacks)
        self.on_message = on_message
        self.tag_prefix = tag_prefix
        self._active_tags = {}
        self._active_queue_no_ack = {}
        if auto_declare is not None:
            self.auto_declare = auto_declare
        if on_decode_error is not None:
            self.on_decode_error = on_decode_error
        self.accept = prepare_accept_content(accept)
        self.prefetch_count = prefetch_count

        if self.channel:
            self.revive(self.channel)

    @property
    def queues(self):  # noqa
        return list(self._queues.values())

    @queues.setter
    def queues(self, queues):
        self._queues = {q.name: q for q in queues}

    def revive(self, channel):
        """Revive consumer after connection loss."""
        previous_no_ack = self._active_queue_no_ack.copy()
        self._active_tags.clear()
        self._active_queue_no_ack.clear()
        channel = self.channel = maybe_channel(channel)
        # modify dict size while iterating over it is not allowed
        for qname, queue in list(self._queues.items()):
            # name may have changed after declare
            self._queues.pop(qname, None)
            queue = self._queues[queue.name] = queue(self.channel)
            queue.revive(channel)

        if self.auto_declare:
            self.declare()

        if self.prefetch_count is not None:
            self.qos(prefetch_count=self.prefetch_count)

        # re-register the AMQP consumers, but only for queues that were
        # actually being consumed from before (not merely registered).
        self._consume_previously_active(previous_no_ack)

    def declare(self):
        """Declare queues, exchanges and bindings.

        Note:
        ----
            This is done automatically at instantiation
            when :attr:`auto_declare` is set.
        """
        for queue in self._queues.values():
            queue.declare()

    def register_callback(self, callback):
        """Register a new callback to be called when a message is received.

        Note:
        ----
            The signature of the callback needs to accept two arguments:
            `(body, message)`, which is the decoded message body
            and the :class:`~kombu.Message` instance.
        """
        self.callbacks.append(callback)

    def __enter__(self):
        self.consume()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None
    ) -> None:
        if self.channel and self.channel.connection:
            conn_errors = self.channel.connection.client.connection_errors
            if not isinstance(exc_val, conn_errors):
                try:
                    self.cancel()
                except Exception:
                    pass

    def add_queue(self, queue):
        """Add a queue to the list of queues to consume from.

        Note:
        ----
            This will not start consuming from the queue,
            for that you will have to call :meth:`consume` after.
        """
        queue = queue(self.channel)
        if self.auto_declare:
            queue.declare()
        self._queues[queue.name] = queue
        return queue

    def consume(self, no_ack=None):
        """Start consuming messages.

        Can be called multiple times, but note that while it
        will consume from new queues added since the last call,
        it will not cancel consuming from removed queues (
        use :meth:`cancel_by_queue`).

        Arguments:
        ---------
            no_ack (bool): See :attr:`no_ack`.
        """
        no_ack = self.no_ack if no_ack is None else no_ack
        self._consume_queues(
            {queue.name: no_ack for queue in self._queues.values()}
        )

    def _consume_previously_active(self, active_no_ack):
        """Start consuming only from the given, previously active queues.

        Unlike :meth:`consume`, this will not start consuming from
        queues that were registered (e.g. via :meth:`add_queue`) but
        never actually consumed from, and it restores each queue's
        own effective ``no_ack`` value instead of applying one value
        to every queue.

        Arguments:
        ---------
            active_no_ack (dict): Mapping of queue name to the
                ``no_ack`` value it was consumed with.
        """
        # thin wrapper kept for readability/intent at the revive() call site
        self._consume_queues(active_no_ack)

    def _consume_queues(self, no_ack_by_queue):
        queues = [
            q for q in self._queues.values() if q.name in no_ack_by_queue
        ]
        if not queues:
            return
        H, T = queues[:-1], queues[-1]
        for queue in H:
            self._basic_consume(
                queue, no_ack=no_ack_by_queue[queue.name], nowait=True
            )
        self._basic_consume(
            T, no_ack=no_ack_by_queue[T.name], nowait=False
        )

    def cancel(self):
        """End all active queue consumers.

        Note:
        ----
            This does not affect already delivered messages, but it does
            mean the server will not send any more messages for this consumer.
        """
        cancel = self.channel.basic_cancel
        for tag in self._active_tags.values():
            cancel(tag)
        self._active_tags.clear()
        self._active_queue_no_ack.clear()

    close = cancel

    def cancel_by_queue(self, queue):
        """Cancel consumer by queue name."""
        qname = queue.name if isinstance(queue, Queue) else queue
        self._active_queue_no_ack.pop(qname, None)
        try:
            tag = self._active_tags.pop(qname)
        except KeyError:
            pass
        else:
            self.channel.basic_cancel(tag)
        finally:
            self._queues.pop(qname, None)

    def consuming_from(self, queue):
        """Return :const:`True` if currently consuming from queue'."""
        name = queue
        if isinstance(queue, Queue):
            name = queue.name
        return name in self._active_tags

    def purge(self):
        """Purge messages from all queues.

        Warning:
        -------
            This will *delete all ready messages*, there is no undo operation.
        """
        return sum(queue.purge() for queue in self._queues.values())

    def flow(self, active):
        """Enable/disable flow from peer.

        This is a simple flow-control mechanism that a peer can use
        to avoid overflowing its queues or otherwise finding itself
        receiving more messages than it can process.

        The peer that receives a request to stop sending content
        will finish sending the current content (if any), and then wait
        until flow is reactivated.
        """
        self.channel.flow(active)

    def qos(self, prefetch_size=0, prefetch_count=0, apply_global=False):
        """Specify quality of service.

        The client can request that messages should be sent in
        advance so that when the client finishes processing a message,
        the following message is already held locally, rather than needing
        to be sent down the channel. Prefetching gives a performance
        improvement.

        The prefetch window is Ignored if the :attr:`no_ack` option is set.

        Arguments:
        ---------
            prefetch_size (int): Specify the prefetch window in octets.
                The server will send a message in advance if it is equal to
                or smaller in size than the available prefetch size (and
                also falls within other prefetch limits). May be set to zero,
                meaning "no specific limit", although other prefetch limits
                may still apply.

            prefetch_count (int): Specify the prefetch window in terms of
                whole messages.

            apply_global (bool): Apply new settings globally on all channels.
        """
        return self.channel.basic_qos(prefetch_size,
                                      prefetch_count,
                                      apply_global)

    def recover(self, requeue=False):
        """Redeliver unacknowledged messages.

        Asks the broker to redeliver all unacknowledged messages
        on the specified channel.

        Arguments:
        ---------
            requeue (bool): By default the messages will be redelivered
                to the original recipient. With `requeue` set to true, the
                server will attempt to requeue the message, potentially then
                delivering it to an alternative subscriber.
        """
        return self.channel.basic_recover(requeue=requeue)

    def receive(self, body, message):
        """Method called when a message is received.

        This dispatches to the registered :attr:`callbacks`.

        Arguments:
        ---------
            body (Any): The decoded message body.
            message (~kombu.Message): The message instance.

        Raises
        ------
            NotImplementedError: If no consumer callbacks have been
                registered.
        """
        callbacks = self.callbacks
        if not callbacks:
            raise NotImplementedError('Consumer does not have any callbacks')
        [callback(body, message) for callback in callbacks]

    def _basic_consume(self, queue, consumer_tag=None,
                       no_ack=no_ack, nowait=True):
        tag = self._active_tags.get(queue.name)
        if tag is None:
            no_ack = queue.no_ack if no_ack is None else no_ack
            tag = self._add_tag(queue, consumer_tag)
            self._active_queue_no_ack[queue.name] = no_ack
            queue.consume(tag, self._receive_callback,
                          no_ack=no_ack, nowait=nowait)
        return tag

    def _add_tag(self, queue, consumer_tag=None):
        tag = consumer_tag or '{}{}'.format(
            self.tag_prefix, next(self._tags))
        self._active_tags[queue.name] = tag
        return tag

    def _receive_callback(self, message):
        accept = self.accept
        on_m, channel, decoded = self.on_message, self.channel, None
        try:
            m2p = getattr(channel, 'message_to_python', None)
            if m2p:
                message = m2p(message)
            if accept is not None:
                message.accept = accept
            if message.errors:
                return message._reraise_error(self.on_decode_error)
            decoded = None if on_m else message.decode()
        except Exception as exc:
            if not self.on_decode_error:
                raise
            self.on_decode_error(message, exc)
        else:
            return on_m(message) if on_m else self.receive(decoded, message)

    def __repr__(self):
        return f'<{type(self).__name__}: {self.queues}>'

    @property
    def connection(self):
        try:
            return self.channel.connection.client
        except AttributeError:
            pass
