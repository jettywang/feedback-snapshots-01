# Blocking Connection Adapter

!!! warning

    `BlockingConnection` is deprecated and will be removed in Pika 2.0. Because the calling thread *is* the IOLoop, any blocking user code stalls heartbeats unless `process_data_events()` is called periodically, and the adapter is not thread-safe. Use [`Connection`](thread_safe.md) instead, which runs its own IOLoop on a background thread and provides a thread-safe blocking API.

::: pika.adapters.blocking_connection

Be sure to check out examples in [examples](../../examples.md).

## Interacting with Pika from another thread

`pika.BlockingConnection` abstracts its I/O loop from the application and thus exposes `pika.BlockingConnection.add_callback_threadsafe()` to allow interacting with Pika from another thread.

## Publishing failures and what they disclose

When `basic_publish` fails in publisher-confirms mode, the raised exception carries two attributes:

- `publish`, a [`pika.exceptions.FailedPublish`][pika.exceptions.FailedPublish] with the original `exchange`, `routing_key`, `body`, `properties` and `mandatory`, so the caller can publish the business message again.
- `failure`, a [`pika.exceptions.PublishFailure`][pika.exceptions.PublishFailure], a restricted view for logs and alerts. Its `kind` separates a routing failure (`RETURNED`), a confirmation failure (`NACKED`) and a connection that closed first (`CONNECTION_LOST`); it also carries the channel number, delivery tag, exchange, routing key, reply code and text where available, and the body length.

A failure that happens before the message reaches the broker -- an unencodable property, or a channel that is already closed -- raises the original exception instead, since there is nothing for a log reader to correlate and the message was not sent.

`failure` never contains the body, the header table or the `user_id` and `reply_to` properties. Of the properties, only `app_id`, `content_encoding`, `content_type`, `correlation_id`, `delivery_mode`, `expiration`, `message_id`, `priority`, `timestamp` and `type` are copied. A header value is copied only when the header's name is listed in `Parameters.publish_failure_approved_headers`, which is empty by default, and the view reports how many headers it withheld instead.

Pika logs the failure with only that view, so its own warning is safe to forward to an external reader. Log `error.failure`, not `error.publish`; the latter is what holds the business message.

```python
parameters = pika.ConnectionParameters(
    publish_failure_approved_headers=('trace-id',))
```

The same list can be set in a URL query string as a Python literal: `?publish_failure_approved_headers=%28%27trace-id%27%2C%29`.

## Class Reference

::: pika.adapters.blocking_connection.BlockingConnection
    options:
      members: true
      inherited_members: true

::: pika.adapters.blocking_connection.BlockingChannel
    options:
      members: true
      inherited_members: true
