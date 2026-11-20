#!/usr/bin/env python
"""Offline acceptance tests for the constrained Vault failover (secure redirect) logic.

The Vault cluster exposes a small set of internal failover addresses and the business
application is only allowed to send credentials to those hosts. These tests prove that,
once the secure forwarding constraints are configured on an hvac adapter:

* allowed failover switches continue to work, with credentials attached at every hop;
* redirects to hosts outside the allowlist, chains longer than the hop limit, and
  unrecognizable proxy responses are rejected, based on the recorded evidence of where
  each request went and which headers it carried;
* request identity headers never leave the trust boundary and never come back on
  outbound responses;
* rejection decisions are logged (without the token) so the evidence remains available
  for troubleshooting.

No network access is required: a scripted in-memory session records every hop.
"""
import logging
from unittest import mock

import pytest
from requests_mock.response import create_response

from hvac import Client, adapters, exceptions

PRIMARY = "https://vault-primary.example:8200"
STANDBY = "https://vault-standby.example:8200"
DR_REPLICA = "https://vault-dr.example:8200"
UNTRUSTED = "https://attacker.example.internal:9999"
TOKEN = "s.offline-acceptance-token"
HEALTH_PATH = "v1/sys/health"
TRUSTED_HOSTS = {"vault-primary.example:8200", "vault-standby.example:8200", "vault-dr.example:8200"}


def _health_url(host):
    return f"{host}/{HEALTH_PATH}"


class HopRecordingSession:
    """Scripted ``requests.Session`` stand-in that records each hop's target and headers."""

    def __init__(self, routes):
        # routes maps (METHOD, url) to a list of response scripts; scripts are reused
        # for repeated hits once the list is exhausted.
        self.routes = routes
        self.hops = []
        self._hits = {}
        self.cert = None
        self.verify = True
        self.proxies = {}

    def request(self, method, url, headers=None, allow_redirects=True, **kwargs):
        self.hops.append(
            {
                "method": method.upper(),
                "url": url,
                "headers": dict(headers or {}),
                "allow_redirects": allow_redirects,
            }
        )
        scripts = self.routes[(method.upper(), url)]
        hit_count = self._hits.get((method.upper(), url), 0)
        self._hits[(method.upper(), url)] = hit_count + 1
        script = scripts[min(hit_count, len(scripts) - 1)]

        fake_request = mock.Mock(url=url, headers=dict(headers or {}), method=method.upper())
        return create_response(
            fake_request,
            status_code=script["status_code"],
            headers=script.get("headers", {}),
            json=script.get("json"),
        )

    def close(self):
        return None


def _redirect(status_code, location):
    return {"status_code": status_code, "headers": {"Location": location}}


def _ok(**headers):
    return {"status_code": 200, "headers": headers, "json": {"status": "ok"}}


def _make_adapter(session, **kwargs):
    kwargs.setdefault("base_uri", PRIMARY)
    kwargs.setdefault("token", TOKEN)
    kwargs.setdefault(
        "allowed_redirect_hosts",
        [STANDBY, "vault-dr.example:8200"],
    )
    return adapters.RawAdapter(session=session, **kwargs)


def _assert_credentials_stay_inside_trust_boundary(hops):
    """Evidence-based invariant: identity headers only ever reach allowed Vault hosts."""
    for hop in hops:
        host = hop["url"].split("/", 2)[2].split("/", 1)[0]
        assert host in TRUSTED_HOSTS
        if "X-Vault-Token" in hop["headers"]:
            assert host in TRUSTED_HOSTS
        assert hop["allow_redirects"] is False


def test_trusted_failover_follows_allowed_hop_with_credentials(caplog):
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [_ok()],
        }
    )
    adapter = _make_adapter(session)

    caplog.set_level(logging.INFO, logger="hvac.adapters")
    response = adapter.get(HEALTH_PATH)

    assert response.status_code == 200
    assert [hop["url"] for hop in session.hops] == [
        _health_url(PRIMARY),
        _health_url(STANDBY),
    ]
    for hop in session.hops:
        assert hop["headers"]["X-Vault-Token"] == TOKEN
        assert hop["headers"]["X-Vault-Request"] == "true"
    _assert_credentials_stay_inside_trust_boundary(session.hops)

    hop_log = caplog.text
    assert "vault secure failover hop 0" in hop_log
    assert _health_url(STANDBY) in hop_log
    assert TOKEN not in hop_log


def test_trusted_multi_hop_chain_works_under_default_hop_limit():
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [_redirect(307, _health_url(DR_REPLICA))],
            ("GET", _health_url(DR_REPLICA)): [_ok()],
        }
    )
    adapter = _make_adapter(session)

    response = adapter.get(HEALTH_PATH)

    assert response.status_code == 200
    assert len(session.hops) == 3
    _assert_credentials_stay_inside_trust_boundary(session.hops)


def test_relative_redirect_resolves_within_the_trusted_host():
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, f"/{HEALTH_PATH}?active=true")],
            ("GET", f"{_health_url(PRIMARY)}?active=true"): [_ok()],
        }
    )
    adapter = _make_adapter(session)

    response = adapter.get(HEALTH_PATH)

    assert response.status_code == 200
    assert session.hops[1]["url"] == f"{_health_url(PRIMARY)}?active=true"
    _assert_credentials_stay_inside_trust_boundary(session.hops)


def test_303_redirect_switches_post_to_get_on_the_next_hop():
    session = HopRecordingSession(
        {
            ("POST", _health_url(PRIMARY)): [_redirect(303, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [_ok()],
        }
    )
    adapter = _make_adapter(session)

    response = adapter.post(HEALTH_PATH)

    assert response.status_code == 200
    assert [hop["method"] for hop in session.hops] == ["POST", "GET"]
    assert session.hops[1]["headers"]["X-Vault-Token"] == TOKEN


def test_untrusted_redirect_host_is_rejected_without_sending_credentials(caplog):
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [
                _redirect(307, f"{UNTRUSTED}/{HEALTH_PATH}")
            ],
        }
    )
    adapter = _make_adapter(session)

    caplog.set_level(logging.WARNING, logger="hvac.adapters")
    with pytest.raises(exceptions.UntrustedRedirectHost) as exc_info:
        adapter.get(HEALTH_PATH)

    assert exc_info.value.url == f"{UNTRUSTED}/{HEALTH_PATH}"
    assert len(session.hops) == 1
    assert session.hops[0]["url"] == _health_url(PRIMARY)
    assert all(UNTRUSTED not in hop["url"] for hop in session.hops)
    _assert_credentials_stay_inside_trust_boundary(session.hops)
    assert "untrusted host" in caplog.text
    assert "attacker.example.internal" in caplog.text
    assert TOKEN not in caplog.text


def test_redirect_chain_exceeding_hop_limit_is_rejected(caplog):
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [_redirect(307, _health_url(DR_REPLICA))],
            ("GET", _health_url(DR_REPLICA)): [_ok()],
        }
    )
    adapter = _make_adapter(session, max_redirect_hops=1)

    caplog.set_level(logging.WARNING, logger="hvac.adapters")
    with pytest.raises(exceptions.RedirectLimitExceeded) as exc_info:
        adapter.get(HEALTH_PATH)

    assert "1 hop(s)" in str(exc_info.value)
    assert [hop["url"] for hop in session.hops] == [
        _health_url(PRIMARY),
        _health_url(STANDBY),
    ]
    assert all(hop["url"] != _health_url(DR_REPLICA) for hop in session.hops)
    _assert_credentials_stay_inside_trust_boundary(session.hops)
    assert "longer than 1 hop(s)" in caplog.text
    assert TOKEN not in caplog.text


def test_redirect_without_location_header_is_unrecognized_proxy_response(caplog):
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [
                {"status_code": 307, "headers": {}},
            ],
        }
    )
    adapter = _make_adapter(session)

    caplog.set_level(logging.WARNING, logger="hvac.adapters")
    with pytest.raises(exceptions.UnrecognizedProxyResponse):
        adapter.get(HEALTH_PATH)

    assert len(session.hops) == 1
    assert "Location header" in caplog.text
    assert TOKEN not in caplog.text


def test_redirect_with_unparseable_location_is_unrecognized_proxy_response(caplog):
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [
                _redirect(307, "http://[broken-ipv6"),
            ],
        }
    )
    adapter = _make_adapter(session)

    caplog.set_level(logging.WARNING, logger="hvac.adapters")
    with pytest.raises(exceptions.UnrecognizedProxyResponse):
        adapter.get(HEALTH_PATH)

    assert len(session.hops) == 1
    assert "unparseable redirect target" in caplog.text
    assert TOKEN not in caplog.text


def test_outbound_response_never_carries_request_identity_headers():
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [
                _ok(
                    **{
                        "X-Vault-Token": "echoed-token-must-be-stripped",
                        "Authorization": "Bearer echoed-credential-must-be-stripped",
                    }
                )
            ],
        }
    )
    adapter = _make_adapter(session)

    response = adapter.get(HEALTH_PATH)

    assert response.status_code == 200
    assert "X-Vault-Token" not in response.headers
    assert "Authorization" not in response.headers
    assert "echoed-token-must-be-stripped" not in str(dict(response.headers))


def test_identity_headers_are_stripped_from_failover_responses_too():
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [
                _ok(**{"X-Vault-Token": "echoed-on-standby"})
            ],
        }
    )
    adapter = _make_adapter(session)

    response = adapter.get(HEALTH_PATH)

    assert "X-Vault-Token" not in response.headers


@pytest.mark.parametrize(
    "routes, expected_exception",
    [
        (
            {
                ("GET", _health_url(PRIMARY)): [
                    _redirect(307, f"{UNTRUSTED}/{HEALTH_PATH}")
                ],
            },
            exceptions.UntrustedRedirectHost,
        ),
        (
            {
                ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
                ("GET", _health_url(STANDBY)): [_redirect(307, _health_url(DR_REPLICA))],
            },
            exceptions.RedirectLimitExceeded,
        ),
        (
            {
                ("GET", _health_url(PRIMARY)): [
                    {"status_code": 302, "headers": {}},
                ],
            },
            exceptions.UnrecognizedProxyResponse,
        ),
    ],
)
def test_every_rejection_keeps_credentials_inside_the_trust_boundary(
    routes, expected_exception
):
    session = HopRecordingSession(routes)
    adapter = _make_adapter(session, max_redirect_hops=1)

    with pytest.raises(expected_exception):
        adapter.get(HEALTH_PATH)

    for hop in session.hops:
        assert UNTRUSTED not in hop["url"]
        if hop["headers"].get("X-Vault-Token"):
            host = hop["url"].split("/", 2)[2].split("/", 1)[0]
            assert host in TRUSTED_HOSTS


def test_without_allowlist_the_adapter_keeps_its_legacy_redirect_behavior():
    session = mock.Mock()
    session.verify = True
    session.request.return_value = create_response(
        mock.Mock(url=_health_url(PRIMARY)),
        status_code=200,
        json={"status": "ok"},
    )
    adapter = adapters.RawAdapter(base_uri=PRIMARY, token=TOKEN, session=session)

    adapter.get(HEALTH_PATH)

    assert adapter.allowed_redirect_hosts is None
    _, request_kwargs = session.request.call_args
    assert request_kwargs["allow_redirects"] is True


def test_client_threads_secure_failover_configuration_through_to_the_adapter():
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [_ok()],
        }
    )
    client = Client(
        url=PRIMARY,
        token=TOKEN,
        adapter=adapters.RawAdapter,
        allowed_redirect_hosts=[STANDBY, "vault-dr.example:8200"],
        max_redirect_hops=3,
    )
    client.adapter.session = session

    response = client.adapter.get(HEALTH_PATH)

    assert client.adapter.max_redirect_hops == 3
    assert client.adapter._trusted_redirect_hosts() == TRUSTED_HOSTS
    assert response.status_code == 200
    assert [hop["url"] for hop in session.hops] == [
        _health_url(PRIMARY),
        _health_url(STANDBY),
    ]


def test_json_adapter_inherits_secure_failover_and_returns_json_body():
    session = HopRecordingSession(
        {
            ("GET", _health_url(PRIMARY)): [_redirect(307, _health_url(STANDBY))],
            ("GET", _health_url(STANDBY)): [
                {"status_code": 200, "json": {"initialized": True}}
            ],
        }
    )
    adapter = adapters.JSONAdapter(
        base_uri=PRIMARY,
        token=TOKEN,
        session=session,
        allowed_redirect_hosts=[STANDBY],
    )

    body = adapter.get(HEALTH_PATH)

    assert body == {"initialized": True}
    assert [hop["url"] for hop in session.hops] == [
        _health_url(PRIMARY),
        _health_url(STANDBY),
    ]
