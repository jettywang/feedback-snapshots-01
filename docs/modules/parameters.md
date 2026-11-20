# Connection Parameters

To maintain flexibility in how you specify the connection information required for your applications to properly connect to RabbitMQ, pika implements two classes for encapsulating the information, `ConnectionParameters` and `URLParameters`.

## ConnectionParameters

The classic object for specifying all of the connection parameters required to connect to RabbitMQ, `ConnectionParameters` provides attributes for tweaking every possible connection option.

Example:

```python
import pika

# Set the connection parameters to connect to rabbit-server1 on port 5672
# on the / virtual host using the username "guest" and password "guest"
credentials = pika.PlainCredentials('guest', 'guest')
parameters = pika.ConnectionParameters('rabbit-server1',
                                       5672,
                                       '/',
                                       credentials)

```

::: pika.connection.ConnectionParameters
    options:
      members: ["__init__"]
      inherited_members: false

### Disclosing headers in a publish failure log

`publish_failure_approved_headers` names the AMQP header entries whose values [`PublishFailure`](exceptions.md) may report when a publish fails. It is empty by default, so a failure view names no header value and reports only how many it withheld. The body is never disclosed, and neither are the `user_id` and `reply_to` properties. See [Publishing failures and what they disclose](adapters/blocking.md#publishing-failures-and-what-they-disclose).

## URLParameters

The `URLParameters` class allows you to pass in an AMQP URL when creating the object and supports the host, port, virtual host, ssl, username and password in the base URL and other options are passed in via query parameters.

Example:

```python
import pika

# Set the connection parameters to connect to rabbit-server1 on port 5672
# on the / virtual host using the username "guest" and password "guest"
parameters = pika.URLParameters('amqp://guest:guest@rabbit-server1:5672/%2F')

```

::: pika.connection.URLParameters
    options:
      members: ["__init__"]
      inherited_members: false

## Properties

Both classes inherit these from `Parameters`.

::: pika.connection.Parameters
    options:
      members: true
      members_order: source
      show_root_heading: false
