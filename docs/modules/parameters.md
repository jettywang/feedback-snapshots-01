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

## Per-candidate TLS verification

A deployment that has more than one internal broker address usually also has more than one TLS identity: a load balancer whose certificate names the load-balancer domain, and an address whose certificate names something else. `Parameters.tls_rules` maps a candidate template to the verification name and trust source that candidate must use. The template is a hostname or IP address, with `*` standing for one or more characters in a label:

```python
import ssl

import pika

corp_ca = ssl.create_default_context(cafile='/etc/ssl/corp-ca.pem')
rotated_ca = ssl.create_default_context(cafile='/etc/ssl/rotated-ca.pem')

parameters = pika.ConnectionParameters(
    host='lb.internal.example',
    port=5671,
    tls_rules={
        '*.internal.example':
            pika.TLSVerificationRule(corp_ca, 'lb.internal.example', 'corp-ca'),
        '10.20.*.*':
            pika.TLSVerificationRule(rotated_ca, 'broker-10.internal', 'rotated-ca'),
    })
```

The configured host is matched first, then the resolved IP address, and the most specific template wins. The matched rule supplies that candidate's `ssl_options` for the attempt: `ssl.SSLContext.wrap_socket` receives its context and its `server_hostname`, so the certificate has to carry the rule's name rather than the address dialed. A `pika.ConnectionParameters` in a fallback sequence carries its own rules, so a first-hop load balancer and its standby can verify different names against different CAs. `TLSVerificationRule(server_hostname=..., cafile=...)` builds the verifying context for you.

A candidate that matches no template is refused before pika opens a socket to it. The workflow records it as `pika.adapters.utils.connection_workflow.AMQPConnectorCandidateNotCoveredError`, whose inner `pika.exceptions.CandidateNotCoveredByTLSRuleError` names the configured host, the resolved address and the templates that were configured. If workflow completion reports that error, the blocking adapter raises the inner exception from the connection call, so its reason is available without unwrapping the workflow. `AMQPConnectionWorkflow.candidate_rejections` keeps every refusal, including those followed by a successful fallback.

Leaving `tls_rules` as None keeps the previous behaviour: `ssl_options` applies to every candidate.

## Properties

Both classes inherit these from `Parameters`.

::: pika.connection.Parameters
    options:
      members: true
      members_order: source
      show_root_heading: false
