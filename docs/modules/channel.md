# Channel

## Closing a channel with active consumers

A `Basic.Cancel` does not stop the broker immediately. The specification allows it to keep dispatching for a cancelled consumer until it sends `Basic.CancelOk`, so there is a window in which further deliveries arrive for a consumer you have already cancelled. Pika passes those deliveries to the consumer callback, which is what the RabbitMQ Java client does.

!!! warning

    `Channel.close()` cancels each consumer without waiting for that confirmation, so any delivery the broker had already dispatched is discarded rather than passed to the callback. A callback could not acknowledge one anyway: the channel is closing and refuses the frame. A discarded delivery is redelivered to the next consumer when `auto_ack=False`, and **lost when `auto_ack=True`**, because an `auto_ack` delivery has no copy left at the broker. Pika logs a warning naming the count as the channel closes.

    This applies to `channel.close()` on `SelectConnection`, `AsyncioConnection`, `TornadoConnection` and `GeventConnection`. [`pika.Connection`](adapters/thread_safe.md) and [`BlockingConnection`](adapters/blocking.md) are unaffected, because both cancel their consumers and wait for the broker to confirm before closing anything.

To close a channel on one of the asynchronous adapters without losing those deliveries, cancel each consumer with a callback and close from the last `Basic.CancelOk`:

```python
def stop_consuming(channel, consumer_tags):
    """Close `channel` once the broker has confirmed every cancellation."""
    pending = set(consumer_tags)

    def on_cancelok(method_frame):
        pending.discard(method_frame.method.consumer_tag)
        if not pending:
            channel.close()

    for consumer_tag in consumer_tags:
        channel.basic_cancel(consumer_tag, callback=on_cancelok)
```

Each delivery that arrives before its `Basic.CancelOk` reaches the consumer callback, so a callback written on the assumption that cancelling is immediate may still run, and may still acknowledge.

Pika 2.0 removes the asynchronous adapters, leaving [`Connection`](adapters/thread_safe.md) and its `Channel` as the only close path, so the gap is retired rather than fixed.

## Binding a delivery to the channel that issued it

A delivery tag is scoped to a channel and restarts at 1, so after a reconnect tag 7 on the replacement channel is a different message from tag 7 on the old one. Code that finishes work on another thread can therefore acknowledge the wrong message: the completion arrives after the channel is gone, and the integer it carries is accepted by whatever channel now owns the number.

Pass `delivery_token=True` to `basic_consume` and the callback receives a [`DeliveryToken`][pika.channel.DeliveryToken] instead of the `spec.Basic.Deliver` method:

```python
def on_message(channel, token, properties, body):
    work_queue.put((token, body))       # handed off; the ack happens on another thread

def worker():
    token, body = work_queue.get()
    process(body)
    channel.basic_ack(token)            # refused if the channel was replaced meanwhile
```

The token exposes the delivery method as `token.method` and forwards `consumer_tag`, `delivery_tag`, `redelivered`, `exchange` and `routing_key`. `basic_ack`, `basic_nack` and `basic_reject` accept either an integer or a token. Given a token, they check it was issued by that same channel instance before writing anything:

- A token from another instance raises [`StaleDeliveryToken`][pika.exceptions.StaleDeliveryToken] and no frame is sent. This is the reconnect case: the tag may name a live delivery on the new channel, and it is left alone.
- A token from the same instance whose channel has since closed raises `ChannelWrongStateError`, as any acknowledgement on a closed channel does. That is a different outcome on purpose: the token was not reused, the channel is simply no longer usable.

The option is off by default, which keeps the existing contract: callbacks receive the method, and acknowledgements take a plain integer. A token never travels to the broker; the frame still carries the integer tag.

On [`BlockingChannel`](adapters/blocking.md) the same `delivery_token=True` argument applies, and the pending-delivery events it holds keep the token so a later dispatch hands your callback the same object.

::: pika.channel

## Channel

::: pika.channel.Channel
    options:
      members: true
      inherited_members: true
      members_order: source
