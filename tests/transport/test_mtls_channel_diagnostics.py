# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Offline diagnostics for the Requests mTLS channel.

These tests do not make network calls and do not need a real client
certificate.  Synthetic certificates make the certificate selected for each
send visible, while request doubles record every business send and every
credential-refresh send.

The important distinction under test is:

* business requests use the adapter mounted on ``AuthorizedSession``;
* credential refresh uses ``AuthorizedSession._auth_request``, which by default
  is a ``Request`` backed by the separate ``_auth_request_session``.
"""

import collections
import datetime
import functools
import json
import sys
import types
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
import requests

from google.auth import _agent_identity_utils
from google.auth import _helpers
from google.auth import credentials as auth_credentials
from google.auth import environment_vars
from google.auth import exceptions
import google.auth.transport._mtls_helper as mtls_helper
import google.auth.transport.requests as requests_transport

_TEST_URL = "https://api.example.com/v1/resources"
_OTHER_HTTPS_URL = "https://storage.googleapis.com/v1/buckets"
_TOKEN_URL = "https://oauth2.googleapis.com/token"

_Sent = collections.namedtuple(
    "_Sent", ["method", "url", "headers", "body", "adapter_label"]
)


class _Response(requests.Response):
    def __init__(self, status_code):
        super(_Response, self).__init__()
        self.status_code = status_code
        self._content = b""
        self.headers = requests.structures.CaseInsensitiveDict()
        self.url = _TEST_URL


class _RecordingAdapter(requests.adapters.BaseAdapter):
    """A request double that keeps evidence for every send it receives."""

    def __init__(self, responses, label, cert=None, key=None):
        super(_RecordingAdapter, self).__init__()
        self.responses = list(responses)
        self.label = label
        self.cert = cert
        self.key = key
        self.sent = []

    def send(self, request, **kwargs):
        self.sent.append(
            _Sent(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                body=request.body,
                adapter_label=self.label,
            )
        )
        if not self.responses:
            raise AssertionError(
                "unexpected request through adapter {!r}: {} {}".format(
                    self.label, request.method, request.url
                )
            )
        return self.responses.pop(0)

    def close(self):
        return


class _RecordingCredentials(auth_credentials.Credentials):
    """Credentials that make the refresh transport observable."""

    def __init__(self, token="token"):
        super(_RecordingCredentials, self).__init__()
        self.token = token
        self.before_requests = []
        self.refreshes = []

    def apply(self, headers, token=None):
        headers["authorization"] = self.token if token is None else token

    def before_request(self, request, method, url, headers):
        self.before_requests.append((request, method, url))
        super(_RecordingCredentials, self).before_request(request, method, url, headers)

    def refresh(self, request):
        self.refreshes.append(request)
        self.token += "1"
        request(
            _TOKEN_URL,
            method="POST",
            body=b"grant_type=refresh_token",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    def with_quota_project(self, quota_project_id):
        raise NotImplementedError()


class _MtlsAdapterFactory:
    """Stands in for ``_MutualTlsAdapter`` and records each construction."""

    def __init__(self, scripts):
        self.scripts = list(scripts)
        self.created = []

    def __call__(self, cert, key):
        if not self.scripts:
            raise AssertionError("unexpected _MutualTlsAdapter construction")
        script = self.scripts.pop(0)
        if isinstance(script, BaseException):
            raise script
        label, responses = script
        adapter = _RecordingAdapter(responses, label, cert=cert, key=key)
        self.created.append(adapter)
        return adapter


@pytest.fixture(autouse=True)
def _clean_mtls_environment(monkeypatch):
    for name in (
        environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE,
        environment_vars.CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE,
        environment_vars.GOOGLE_API_CERTIFICATE_CONFIG,
        environment_vars.CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH,
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _fake_openssl(monkeypatch):
    """Keep the matrix independent of whether pyOpenSSL is installed.

    ``configure_mtls_channel`` only needs the module while importing it and
    while evaluating its exception tuple.  The actual adapter is replaced by
    the recording factory below.
    """

    openssl = types.ModuleType("OpenSSL")
    crypto = types.ModuleType("OpenSSL.crypto")

    class CryptoError(Exception):
        pass

    crypto.Error = CryptoError
    openssl.crypto = crypto
    monkeypatch.setitem(sys.modules, "OpenSSL", openssl)
    monkeypatch.setitem(sys.modules, "OpenSSL.crypto", crypto)
    return crypto


def _make_certificate(common_name, serial_number):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_bytes, key_bytes


@pytest.fixture(scope="module")
def certificate_a():
    return _make_certificate("diagnostic-cert-a", 1001)


@pytest.fixture(scope="module")
def certificate_b():
    return _make_certificate("diagnostic-cert-b", 1002)


def _fingerprint(cert_bytes):
    return _agent_identity_utils.calculate_certificate_fingerprint(
        _agent_identity_utils.parse_certificate(cert_bytes)
    )


def _new_session():
    credentials = _RecordingCredentials()
    session = requests_transport.AuthorizedSession(credentials)
    return session, credentials


def _install_request_doubles(session, default_responses=(), refresh_responses=()):
    default_adapter = _RecordingAdapter(default_responses, "plain-default")
    session.mount("https://", default_adapter)
    refresh_adapter = _RecordingAdapter(refresh_responses, "credential-refresh")
    session._auth_request_session.mount("https://", refresh_adapter)
    return default_adapter, refresh_adapter


def _install_mtls_factory(monkeypatch, scripts):
    factory = _MtlsAdapterFactory(scripts)
    monkeypatch.setattr(requests_transport, "_MutualTlsAdapter", factory)
    return factory


def _unwrap_request(request):
    while isinstance(request, functools.partial):
        request = request.func
    return request


def _enable_client_certificate(monkeypatch):
    monkeypatch.setenv(environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE, "true")


def _channel_snapshot(session, url):
    """The closest public-ish probe available at the send boundary.

    The adapter is the layer that owns the certificate for a request.  The
    session-level flag and cached bytes are kept alongside it to make
    disagreements visible.
    """

    adapter = session.get_adapter(url)
    cache = getattr(session, "_cached_cert", None)
    refresh_session = getattr(session, "_auth_request_session", None)
    return {
        "adapter": adapter,
        "adapter_type": type(adapter).__name__,
        "adapter_id": id(adapter),
        "is_mtls_flag": session.is_mtls,
        "cached_cert_fingerprint": _fingerprint(cache) if cache else None,
        "refresh_adapter_type": (
            type(refresh_session.get_adapter(_TOKEN_URL)).__name__
            if refresh_session is not None
            else None
        ),
    }


@pytest.mark.parametrize("switch_value", [None, "false", "FALSE", ""])
def test_config_switch_off_does_not_request_a_certificate(monkeypatch, switch_value):
    session, _ = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(200)]
    )
    if switch_value is not None:
        monkeypatch.setenv(
            environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE, switch_value
        )

    callback = mock.Mock(side_effect=AssertionError("certificate source was called"))
    factory = _install_mtls_factory(monkeypatch, [])

    session.configure_mtls_channel(callback)

    callback.assert_not_called()
    assert factory.created == []
    assert session.is_mtls is False
    assert session.get_adapter(_TEST_URL) is default_adapter

    response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(default_adapter.sent) == 1
    assert refresh_adapter.sent == []


def test_certificate_config_can_enable_channel_without_explicit_switch(
    monkeypatch, tmp_path, certificate_a
):
    config_path = tmp_path / "certificate_config.json"
    config_path.write_text(
        json.dumps(
            {
                "cert_configs": {
                    "workload": {
                        "cert_path": str(tmp_path / "cert.pem"),
                        "key_path": str(tmp_path / "key.pem"),
                    }
                }
            }
        )
    )
    monkeypatch.setenv(environment_vars.GOOGLE_API_CERTIFICATE_CONFIG, str(config_path))

    session, _ = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(200)]
    )
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(200)])])
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)

    assert session.is_mtls is True
    assert callback.call_count == 1
    assert len(factory.created) == 1
    assert factory.created[0].cert == certificate_a[0]

    response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(factory.created[0].sent) == 1
    assert default_adapter.sent == []
    assert refresh_adapter.sent == []


def test_initial_load_uses_certificate_a_for_business_request(
    monkeypatch, certificate_a
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, refresh_responses=[]
    )
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(200)])])
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)

    adapter_a = factory.created[0]
    snapshot = _channel_snapshot(session, _TEST_URL)

    assert snapshot["adapter"] is adapter_a
    assert snapshot["is_mtls_flag"] is True
    assert snapshot["cached_cert_fingerprint"] == _fingerprint(certificate_a[0])
    assert adapter_a.cert == certificate_a[0]
    assert session._cached_cert == certificate_a[0]

    response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(adapter_a.sent) == 1
    assert adapter_a.sent[0].url == _TEST_URL
    assert adapter_a.sent[0].headers["authorization"] == "token"
    assert default_adapter.sent == []
    assert refresh_adapter.sent == []
    assert credentials.refreshes == []


def test_401_after_initial_load_switches_to_certificate_b_from_default_source(
    monkeypatch, certificate_a, certificate_b
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, refresh_responses=[_Response(200)]
    )
    factory = _install_mtls_factory(
        monkeypatch,
        [("mtls-a", [_Response(401)]), ("mtls-b", [_Response(200)])],
    )
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)
    adapter_a = factory.created[0]

    with mock.patch.object(
        mtls_helper, "call_client_cert_callback", return_value=certificate_b
    ) as default_source:
        response = session.request("GET", _TEST_URL)

    adapter_b = factory.created[1]
    refresh_request = _unwrap_request(credentials.refreshes[0])

    assert response.status_code == 200
    # The original callback is not consulted again; the 401 path reads the
    # default certificate source instead.  This is why A can change to B.
    assert callback.call_count == 1
    default_source.assert_called_once_with()
    assert adapter_a.cert == certificate_a[0]
    assert adapter_b.cert == certificate_b[0]
    assert session.get_adapter(_TEST_URL) is adapter_b
    assert session._cached_cert == certificate_b[0]
    assert session.is_mtls is True
    assert _fingerprint(adapter_a.cert) != _fingerprint(adapter_b.cert)

    # Business evidence: one GET on A, then one GET on B after refresh.
    assert len(adapter_a.sent) == 1
    assert adapter_a.sent[0].headers["authorization"] == "token"
    assert len(adapter_b.sent) == 1
    assert adapter_b.sent[0].headers["authorization"] == "token1"
    assert default_adapter.sent == []

    # Refresh evidence: the token POST never touched either business adapter.
    assert len(refresh_adapter.sent) == 1
    assert refresh_adapter.sent[0].method == "POST"
    assert refresh_adapter.sent[0].url == _TOKEN_URL
    assert refresh_request.session is session._auth_request_session
    assert refresh_request.session is not session


def test_401_with_unchanged_certificate_keeps_adapter_a(monkeypatch, certificate_a):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, refresh_responses=[_Response(200)]
    )
    factory = _install_mtls_factory(
        monkeypatch, [("mtls-a", [_Response(401), _Response(200)])]
    )
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)
    adapter_a = factory.created[0]

    with mock.patch.object(
        mtls_helper, "call_client_cert_callback", return_value=certificate_a
    ) as default_source:
        response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(factory.created) == 1
    assert session.get_adapter(_TEST_URL) is adapter_a
    assert session._cached_cert == certificate_a[0]
    assert callback.call_count == 1
    default_source.assert_called_once_with()

    # Same final 200 as the rotation case, but the certificate identity and
    # adapter identity never changed.
    assert [sent.headers["authorization"] for sent in adapter_a.sent] == [
        "token",
        "token1",
    ]
    assert default_adapter.sent == []
    assert len(refresh_adapter.sent) == 1
    assert len(credentials.refreshes) == 1


def test_initial_certificate_load_failure_keeps_plain_adapter(monkeypatch):
    _enable_client_certificate(monkeypatch)
    session, _ = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(200)]
    )
    factory = _install_mtls_factory(monkeypatch, [])
    callback = mock.Mock(
        side_effect=exceptions.ClientCertError("certificate source failed")
    )

    with pytest.raises(exceptions.MutualTLSChannelError):
        session.configure_mtls_channel(callback)

    callback.assert_called_once_with()
    assert factory.created == []
    assert session.is_mtls is False
    assert getattr(session, "_cached_cert", None) is None
    assert session.get_adapter(_TEST_URL) is default_adapter

    response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(default_adapter.sent) == 1
    assert refresh_adapter.sent == []


def test_initial_adapter_construction_failure_leaves_is_mtls_true_without_adapter(
    monkeypatch, certificate_a, _fake_openssl
):
    _enable_client_certificate(monkeypatch)
    session, _ = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(200)]
    )
    factory = _install_mtls_factory(
        monkeypatch, [_fake_openssl.Error("invalid certificate or key")]
    )
    callback = mock.Mock(return_value=certificate_a)

    with pytest.raises(exceptions.MutualTLSChannelError):
        session.configure_mtls_channel(callback)

    # ``_is_mtls`` is assigned before the adapter is constructed.  A failure
    # here therefore leaves the flag true while the plain adapter still owns
    # the business channel.
    assert session.is_mtls is True
    assert factory.created == []
    assert getattr(session, "_cached_cert", None) is None
    assert session.get_adapter(_TEST_URL) is default_adapter

    response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(default_adapter.sent) == 1
    assert refresh_adapter.sent == []


def test_401_reconfiguration_failure_keeps_adapter_a_and_skips_refresh(
    monkeypatch, certificate_a, certificate_b, _fake_openssl
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(session)
    factory = _install_mtls_factory(
        monkeypatch,
        [
            ("mtls-a", [_Response(401)]),
            _fake_openssl.Error("invalid rotated certificate"),
        ],
    )
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)
    adapter_a = factory.created[0]

    with mock.patch.object(
        mtls_helper, "call_client_cert_callback", return_value=certificate_b
    ):
        with pytest.raises(exceptions.MutualTLSChannelError):
            session.request("GET", _TEST_URL)

    assert session.is_mtls is True
    assert session.get_adapter(_TEST_URL) is adapter_a
    assert session._cached_cert == certificate_a[0]
    assert len(adapter_a.sent) == 1
    assert default_adapter.sent == []
    # The token refresh happens after mTLS reconfiguration, so a failed
    # reconfiguration means no refresh request at all.
    assert credentials.refreshes == []
    assert refresh_adapter.sent == []


def test_401_certificate_read_failure_propagates_and_skips_refresh(
    monkeypatch, certificate_a
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(session)
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(401)])])
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)
    adapter_a = factory.created[0]

    with mock.patch.object(
        mtls_helper,
        "call_client_cert_callback",
        side_effect=exceptions.ClientCertError("cannot read rotated certificate"),
    ):
        with pytest.raises(exceptions.ClientCertError):
            session.request("GET", _TEST_URL)

    assert session.is_mtls is True
    assert session.get_adapter(_TEST_URL) is adapter_a
    assert session._cached_cert == certificate_a[0]
    assert len(adapter_a.sent) == 1
    assert default_adapter.sent == []
    assert credentials.refreshes == []
    assert refresh_adapter.sent == []


def test_401_when_default_source_disappears_fails_before_refresh(
    monkeypatch, certificate_a
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(session)
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(401)])])

    session.configure_mtls_channel(lambda: certificate_a)
    adapter_a = factory.created[0]

    with mock.patch.object(
        mtls_helper,
        "get_client_ssl_credentials",
        return_value=(False, None, None, None),
    ):
        with pytest.raises(TypeError):
            session.request("GET", _TEST_URL)

    # A missing default certificate source is not a ClientCertError, so it is
    # not wrapped in MutualTLSChannelError.  The TypeError escapes before the
    # credential refresh, leaving A mounted.
    assert session.get_adapter(_TEST_URL) is adapter_a
    assert session._cached_cert == certificate_a[0]
    assert len(adapter_a.sent) == 1
    assert default_adapter.sent == []
    assert credentials.refreshes == []
    assert refresh_adapter.sent == []


def test_disabling_switch_after_mount_does_not_unmount_adapter(
    monkeypatch, certificate_a
):
    _enable_client_certificate(monkeypatch)
    session, _ = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(session)
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(200)])])
    callback = mock.Mock(return_value=certificate_a)

    session.configure_mtls_channel(callback)
    adapter_a = factory.created[0]
    assert session.is_mtls is True
    assert session.get_adapter(_TEST_URL) is adapter_a

    monkeypatch.setenv(environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE, "false")
    session.configure_mtls_channel(callback)

    # The flag and the channel now disagree: the old mTLS adapter is still
    # mounted and still selected for the next business request.
    assert session.is_mtls is False
    assert session.get_adapter(_TEST_URL) is adapter_a

    response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert len(adapter_a.sent) == 1
    assert default_adapter.sent == []
    assert refresh_adapter.sent == []


def test_url_specific_adapter_can_shadow_the_global_mtls_channel(
    monkeypatch, certificate_a
):
    _enable_client_certificate(monkeypatch)
    session, _ = _new_session()
    default_adapter = _RecordingAdapter([], "plain-default")
    session.mount("https://", default_adapter)
    factory = _install_mtls_factory(
        monkeypatch,
        [("mtls-a", [_Response(200)]), ("mtls-a-other", [_Response(200)])],
    )

    session.configure_mtls_channel(lambda: certificate_a)
    adapter_a = factory.created[0]

    # requests resolves the longest matching prefix.  An application-level
    # mount at the exact URL therefore wins over the global mTLS channel.
    specific_adapter = _RecordingAdapter([_Response(200)], "per-url")
    session.mount(_TEST_URL, specific_adapter)

    assert session.get_adapter(_TEST_URL) is specific_adapter
    assert session.get_adapter(_OTHER_HTTPS_URL) is adapter_a

    response = session.request("GET", _TEST_URL)
    other_response = session.request("GET", _OTHER_HTTPS_URL)

    assert response.status_code == 200
    assert other_response.status_code == 200
    assert len(specific_adapter.sent) == 1
    assert len(adapter_a.sent) == 1
    assert adapter_a.sent[0].url == _OTHER_HTTPS_URL
    assert default_adapter.sent == []


def test_401_switch_turned_off_between_loads_keeps_adapter_a(
    monkeypatch, certificate_a, certificate_b
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, refresh_responses=[_Response(200)]
    )
    factory = _install_mtls_factory(
        monkeypatch, [("mtls-a", [_Response(401), _Response(200)])]
    )

    session.configure_mtls_channel(lambda: certificate_a)
    adapter_a = factory.created[0]

    monkeypatch.setenv(environment_vars.GOOGLE_API_USE_CLIENT_CERTIFICATE, "false")

    with mock.patch.object(
        mtls_helper, "call_client_cert_callback", return_value=certificate_b
    ) as default_source:
        response = session.request("GET", _TEST_URL)

    # The 401 path still reads the default source to compare fingerprints, but
    # configure_mtls_channel returns early because the switch is now off.  No
    # replacement adapter is mounted, so the retry still uses certificate A.
    assert response.status_code == 200
    default_source.assert_called_once_with()
    assert len(factory.created) == 1
    assert session.get_adapter(_TEST_URL) is adapter_a
    assert session._cached_cert == certificate_a[0]
    assert session.is_mtls is False
    assert [sent.headers["authorization"] for sent in adapter_a.sent] == [
        "token",
        "token1",
    ]
    assert default_adapter.sent == []
    assert len(refresh_adapter.sent) == 1
    assert len(credentials.refreshes) == 1


def test_401_skips_rotation_when_is_mtls_flag_is_false(
    monkeypatch, certificate_a, certificate_b
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, refresh_responses=[_Response(200)]
    )
    factory = _install_mtls_factory(
        monkeypatch, [("mtls-a", [_Response(401), _Response(200)])]
    )

    session.configure_mtls_channel(lambda: certificate_a)
    adapter_a = factory.created[0]

    # Simulate the flag drifting away from the mounted channel.
    session._is_mtls = False

    with mock.patch.object(
        mtls_helper, "call_client_cert_callback", return_value=certificate_b
    ) as default_source:
        response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    default_source.assert_not_called()
    assert len(factory.created) == 1
    assert session.get_adapter(_TEST_URL) is adapter_a
    # The 401 still refreshes the token, but never re-examines the certificate.
    assert [sent.headers["authorization"] for sent in adapter_a.sent] == [
        "token",
        "token1",
    ]
    assert len(refresh_adapter.sent) == 1
    assert len(credentials.refreshes) == 1


def test_refresh_session_uses_plain_https_adapter(monkeypatch, certificate_a):
    _enable_client_certificate(monkeypatch)
    session, _ = _new_session()
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [])])

    session.configure_mtls_channel(lambda: certificate_a)

    business_adapter = session.get_adapter(_TEST_URL)
    refresh_adapter = session._auth_request_session.get_adapter(_TOKEN_URL)

    assert business_adapter is factory.created[0]
    assert refresh_adapter is not business_adapter
    assert type(refresh_adapter) is requests.adapters.HTTPAdapter
    assert refresh_adapter.max_retries.total == 3


def test_first_business_request_refresh_uses_separate_session(
    monkeypatch, certificate_a
):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    credentials.expiry = _helpers.utcnow() - datetime.timedelta(minutes=5)
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(200)], refresh_responses=[_Response(200)]
    )
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(200)])])

    session.configure_mtls_channel(lambda: certificate_a)
    adapter_a = factory.created[0]

    response = session.request("GET", _TEST_URL)

    refresh_request = _unwrap_request(credentials.refreshes[0])

    assert response.status_code == 200
    # The business send happened exactly once, on the mTLS adapter.
    assert len(adapter_a.sent) == 1
    assert adapter_a.sent[0].headers["authorization"] == "token1"
    assert default_adapter.sent == []
    # The proactive refresh happened before the send and went elsewhere.
    assert len(refresh_adapter.sent) == 1
    assert refresh_adapter.sent[0].url == _TOKEN_URL
    assert refresh_request.session is session._auth_request_session
    assert refresh_request.session is not session


def test_401_without_mtls_refreshes_without_any_certificate_check(monkeypatch):
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(401), _Response(200)], [_Response(200)]
    )
    factory = _install_mtls_factory(monkeypatch, [])

    with mock.patch.object(mtls_helper, "call_client_cert_callback") as default_source:
        response = session.request("GET", _TEST_URL)

    assert response.status_code == 200
    assert session.is_mtls is False
    assert session.get_adapter(_TEST_URL) is default_adapter
    assert len(default_adapter.sent) == 2
    assert [sent.headers["authorization"] for sent in default_adapter.sent] == [
        "token",
        "token1",
    ]
    assert len(refresh_adapter.sent) == 1
    assert len(credentials.refreshes) == 1
    default_source.assert_not_called()
    assert factory.created == []


def test_403_does_not_refresh_or_check_certificate(monkeypatch):
    _enable_client_certificate(monkeypatch)
    session, credentials = _new_session()
    default_adapter, refresh_adapter = _install_request_doubles(
        session, [_Response(403)]
    )
    factory = _install_mtls_factory(monkeypatch, [("mtls-a", [_Response(403)])])
    session.configure_mtls_channel(lambda: _make_certificate("cert-a", 1001))

    with mock.patch.object(mtls_helper, "call_client_cert_callback") as default_source:
        response = session.request("GET", _TEST_URL)

    assert response.status_code == 403
    assert len(factory.created[0].sent) == 1
    assert default_adapter.sent == []
    assert refresh_adapter.sent == []
    assert credentials.refreshes == []
    default_source.assert_not_called()
