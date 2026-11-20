# Publish failure views

How a failed publish is reported, and which parts of it may leave the process. `pika/exceptions.py`
holds both the view and the object that carries the business message; the blocking and Twisted
adapters build the view at each of the three failure points.

## The two objects on the exception

A publish in publisher-confirms mode ends in one of three ways: the broker returns the message
because it matched no queue, the broker nacks it, or the connection closes before the broker
answers. `BlockingChannel.basic_publish` raises `UnroutableError`, `NackError`, or the exception
describing the close. Each carries:

- `publish`: `FailedPublish`, with the exact `exchange`, `routing_key`, `body`, `properties` and
  `mandatory` that the caller supplied, plus the broker's delivery tag where one exists. It is
  built from the caller's arguments rather than from the returned copy, because a caller needs the
  same object again, not a re-encoded one.
- `failure`: `PublishFailure`, described below.

The split exists because the two have different audiences. The first is business data and stays in
the process. The second is written to the log, which in this use case is read by an external
service, so it must be safe to forward without review.

## What the view may contain

`PublishFailure` copies an allowlist of AMQP properties (`DISCLOSABLE_PROPERTIES`): `app_id`,
`content_encoding`, `content_type`, `correlation_id`, `delivery_mode`, `expiration`, `message_id`,
`priority`, `timestamp` and `type`. Everything else is dropped:

- The body. Only `body_size` is reported.
- The header table. A header's value is copied only when its name is in
  `publish_failure_approved_headers`, the connection parameter that defaults to empty. The remainder
  is counted in `withheld_header_count`, so a reader can tell that headers existed.
- `user_id` and `reply_to`. Both can identify a person or a private destination, and neither is
  needed to locate the failed publish.

The view is immutable: attributes are assigned through `object.__setattr__` once, and `headers` is
a `MappingProxyType`. That is what makes `repr` and `as_dict` safe to treat as the disclosure
boundary rather than as one of several. Every disclosed value is rendered through
`MAX_DISCLOSED_TEXT` (120 characters), so a property a caller filled with a document cannot flood
the line.

There is no allowlist for property values. A string property such as `correlation_id` can hold
anything the publisher put there, so a deployment that treats these properties as sensitive should
not rely on this view to filter them; the approved-header list is the only per-value switch.

## Which failures carry it

- Returned: built in `BlockingChannel._on_puback_message_returned` for the log line, and again in
  `basic_publish` for the exception, where the delivery tag from the confirming ack is available.
  The log line therefore has no delivery tag, because the return arrives before the ack. The core
  `Channel._on_return` builds one too, for the case where nobody registered a return callback and
  the only record of the return is its debug line.
- Nacked: built once, in `basic_publish`, from the nack's delivery tag.
- Connection lost: built in `BlockingChannel._publish_connection_failure`, which wraps whichever
  exception the connection or channel raised. It raises a *copy* of that exception carrying the
  view.

Errors that do not describe the connection are re-raised unchanged.
`pika.exceptions.is_publish_transport_failure` classifies the errors that are the caller's own:
`TypeError` and `ValueError` from argument validation, `ChannelWrongStateError`/`ChannelClosed` from
a channel that is already gone, and the `Unencodable*Error`/`UnsupportedAMQPFieldException` set
from marshaling. Attaching a
`CONNECTION_LOST` view to one of those would tell a caller to retry a publish that cannot succeed;
it would also label a message that was never sent as lost on the wire.

## Why the close exception is copied

`pika.Connection` records one close reason per connection and raises that same instance to every
caller rejected after the close (`_closed_reason`, raised through `_with_close_traceback`). Setting
`failure` and `publish` on it would leave the first failing publish attached to every later caller,
which discloses one caller's message to another. `attach_publish_failure` therefore copies the
exception before attaching anything. `copy.copy` preserves the type, `args` and the `host` and
`port` attributes, so existing `except` clauses and log formatting are unaffected; only the
identity changes. Tests that assert `ctx.exception is reason` for methods other than publish still
hold, because they exercise the unwrapped paths.

The Twisted adapter uses the same helper. Its `_deliveries` mapping keys pending deferreds by
delivery tag; a parallel `_delivery_requests` mapping keeps the `FailedPublish` for each tag so a
nack or a close can build the view without retaining the body on the deferred itself. That mapping
is cleared wherever `_deliveries` is.

## Known gaps

- `pika.Connection` (the thread-safe adapter) is asynchronous: confirms arrive at the callback the
  caller registers, so there is no exception to attach a view to. `add_on_return_callback` there
  still delivers the full message. Lifting the view into that adapter would mean a new failure
  callback, which is a larger API change.
