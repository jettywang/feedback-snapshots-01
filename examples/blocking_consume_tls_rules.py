"""
Consuming over TLS with a verification rule per candidate.

A deployment with two internal brokers commonly keys each one by what its certificate says. One
candidate is a load-balancer name whose certificate names the service, and the other is an address
whose certificate names a different host and is signed by a newer CA. `pika.ConnectionParameters(
tls_rules=...)` maps each candidate to its own `pika.TLSVerificationRule`, so whichever candidate
pika tries performs the handshake with that candidate's verification name and trust store.

The rules are per `Parameters`, so a fallback sequence can put a different mapping on every config.
A candidate that matches none of a config's templates is refused before pika opens a socket to it,
and its reason is available from the workflow's `candidate_rejections`.

Both rules here use the shipped test CA, and the certificate it signed names `shostakovich` and
`localhost`. The rule for the address dialed therefore verifies `localhost`, which is the point of a
rule: the name checked does not have to be the address dialed. The second template is a standby
address; it is not reached against this broker, and exists to show that each row can name its own
certificate and trust store. See `blocking_consume_tls.py` for the single-`ssl_options` form.
"""

import ssl
from pathlib import Path

import pika

_certs = Path(__file__).resolve().parent.parent / 'tests' / 'certs'

context = ssl.create_default_context(cafile=str(_certs / 'ca_certificate.pem'))
context.load_cert_chain(str(_certs / 'client_certificate.pem'),
                        str(_certs / 'client_key.pem'))

parameters = pika.ConnectionParameters(
    # The candidate pika dials first.
    host='127.0.0.1',
    port=5671,
    tls_rules={
        '127.0.0.1':
            pika.TLSVerificationRule(context, 'localhost', 'test-ca'),
        # A second candidate, reached only when the first is refused, and
        # verified against a different name.
        '10.20.*.*':
            pika.TLSVerificationRule(context, 'shostakovich', 'test-ca'),
    })

# A second config, tried after the first one fails, carries its own rules.
failover = pika.ConnectionParameters(
    host='127.0.0.1',
    port=5671,
    virtual_host='/',
    tls_rules={
        '127.0.0.1': pika.TLSVerificationRule(context, 'localhost', 'test-ca'),
    })

# A candidate no template covers is refused before a socket is opened to it,
# and `pika.exceptions.CandidateNotCoveredByTLSRuleError` says why.
try:
    connection = pika.BlockingConnection([parameters, failover])
except pika.exceptions.CandidateNotCoveredByTLSRuleError as error:
    raise SystemExit(f'no TLS rule for {error.host}: {error.reason}')

channel = connection.channel()

# `durable=True` is required by RabbitMQ 4.3; see examples/README.md.
channel.queue_declare(queue='test', durable=True)
channel.basic_publish(exchange='', routing_key='test', body=b'Hello World!')
connection.close()
