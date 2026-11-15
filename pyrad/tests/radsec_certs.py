"""In-memory test certificates for the RadSec tests.

Generates a small CA plus server and client certificates with the
``cryptography`` package (a test-only dependency) and writes them to a
temporary directory as PEM files, so the tests need neither an external CA
nor the ``openssl`` command. No network or fixed port is required: the tests
wire both TLS ends over a local connected socket pair.
"""
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(name, cn, issuer_cert, issuer_key, *, ca=False, dns=None,
          client=False):
    key = _key()
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
    names = []
    if dns:
        names.append(x509.DNSName(dns))
    if client:
        names.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
    if names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(names), critical=False)
    cert = builder.sign(issuer_key if issuer_key else key, hashes.SHA256())
    return cert, key


def _write(path, cert=None, key=None):
    if key is not None:
        with open(path + '.key', 'wb') as handle:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
    if cert is not None:
        with open(path + '.crt', 'wb') as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))


def create_cert_bundle(tmpdir):
    """Create a CA, a server cert and two client certs under ``tmpdir``.

    ``client`` is signed by the CA and trusted, ``rogue`` is self-signed by
    another CA and must be refused. Returns a dict of PEM file paths.
    """
    ca_cert, ca_key = _cert('ca', 'radsec-test-ca', None, None, ca=True)
    server_cert, server_key = _cert(
        'srv', 'radsec-server', ca_cert, ca_key, dns='localhost')
    client_cert, client_key = _cert(
        'cli', 'trusted-client', ca_cert, ca_key, client=True)

    # a second, unrelated CA and a client cert it signed
    rogue_ca_cert, rogue_ca_key = _cert(
        'rogue-ca', 'rogue-ca', None, None, ca=True)
    rogue_cert, rogue_key = _cert(
        'rogue', 'untrusted-client', rogue_ca_cert, rogue_ca_key,
        client=True)

    paths = {}
    for label, cert, key in (
        ('ca', ca_cert, ca_key),
        ('server', server_cert, server_key),
        ('client', client_cert, client_key),
        ('rogue_ca', rogue_ca_cert, rogue_ca_key),
        ('rogue', rogue_cert, rogue_key),
    ):
        base = tmpdir + '/' + label
        _write(base, cert, key)
        paths[label + '_crt'] = base + '.crt'
        paths[label + '_key'] = base + '.key'
    return paths
