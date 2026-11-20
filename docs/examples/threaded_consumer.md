# Thread-Safe Consumer

This example demonstrates consuming messages with `Connection`. Consumer callbacks run on a dedicated worker thread, so blocking operations inside the callback do not stall heartbeats.

`Channel` methods (`basic_ack`, `basic_publish`, `queue_declare`, etc.) are safe to call directly from within the callback without using `add_callback_threadsafe`.

The consumer opts in to `delivery_token=True`, so `basic_ack` receives a token bound to the channel that delivered the message. If a reconnect replaces that channel while the callback is still working, the acknowledgement is refused with `StaleDeliveryToken` rather than acknowledging whatever message now holds that tag; see [acknowledging a delivery after its channel is gone](../modules/adapters/thread_safe.md#acknowledging-a-delivery-after-its-channel-is-gone).

Pairs with [Thread-Safe Publisher](threaded_publisher.md). Run this consumer first.

`examples/basic_consumer_threaded.py`:

```python
--8<-- "examples/basic_consumer_threaded.py"
```
