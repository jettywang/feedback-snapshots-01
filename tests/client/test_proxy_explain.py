import logging

import pytest

import httpx
from httpx._proxy import (
    DIRECT,
    ENVIRONMENT_BYPASS,
    ENVIRONMENT_PROXY,
    EXPLICIT_BYPASS,
    EXPLICIT_PROXY,
    PROXIED,
    UNPARSEABLE_RULE,
)


def make_mock() -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, text="mock"))


@pytest.fixture
def clean_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)


def test_explain_uses_the_same_transport_as_the_send_chain(
    clean_proxy_env: None,
) -> None:
    direct = make_mock()
    proxied = make_mock()
    client = httpx.Client(
        transport=direct,
        mounts={"http://": proxied, "all://*.internal.example.com": direct},
    )

    decision = client.explain_proxy("http://api.example.com")
    assert decision.outcome == PROXIED
    assert decision.transport is proxied
    assert client._transport_for_url(httpx.URL("http://api.example.com")) is proxied

    response = client.get("http://api.example.com")
    assert response.text == "mock"
    client.close()


def test_conflicting_rules_preserve_priority_and_provenance(
    clean_proxy_env: None,
) -> None:
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("HTTP_PROXY", "http://env-proxy.example:9000")
    monkeypatch.setenv("NO_PROXY", ".example.com")

    explicit = make_mock()
    client = httpx.Client(
        mounts={
            "http://": explicit,
            "all://*.example.com": None,
        }
    )
    try:
        keys = [rule.key for rule in client._proxy_rules]
        # The more specific bypass rule sorts ahead of the scheme-level rules.
        assert keys.index("all://*.example.com") < keys.index("http://")

        decision = client.explain_proxy("http://www.example.com/path")
        assert decision.direct is True
        assert decision.outcome == DIRECT
        assert decision.matched_key == "all://*.example.com"
        assert decision.matched_rule is not None
        assert decision.matched_rule.kind == EXPLICIT_BYPASS
        assert decision.transport is client._transport

        other = client.explain_proxy("http://other.example.org")
        assert other.outcome == PROXIED
        assert other.transport is explicit
        assert other.matched_rule is not None
        assert other.matched_rule.kind == EXPLICIT_PROXY
        assert other.source == "mounts argument"
    finally:
        client.close()
        monkeypatch.undo()


def test_explicit_mount_overrides_environment_rule(clean_proxy_env: None) -> None:
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("HTTP_PROXY", "http://env-proxy.example:9000")

    explicit = make_mock()
    client = httpx.Client(mounts={"http://": explicit})
    try:
        decision = client.explain_proxy("http://example.com")
        assert decision.transport is explicit
        rule = decision.matched_rule
        assert rule is not None and rule.kind == EXPLICIT_PROXY
        # Only one rule remains for the overridden key.
        http_rules = [r for r in decision.rules if r.key == "http://"]
        assert len(http_rules) == 1
        assert http_rules[0].transport is explicit
    finally:
        client.close()
        monkeypatch.undo()


def test_environment_rules_record_their_source(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://secure-proxy.example:9000")
    monkeypatch.setenv("NO_PROXY", "internal.example.com,::1,127.0.0.1")

    client = httpx.Client()
    try:
        by_key = {rule.key: rule for rule in client._proxy_rules}
        assert by_key["https://"].kind == ENVIRONMENT_PROXY
        assert by_key["https://"].source == "HTTPS_PROXY"
        assert str(by_key["https://"].proxy_url) == "http://secure-proxy.example:9000"
        assert by_key["all://*internal.example.com"].kind == ENVIRONMENT_BYPASS
        assert by_key["all://*internal.example.com"].source == "NO_PROXY"
        assert by_key["all://[::1]"].kind == ENVIRONMENT_BYPASS
        assert by_key["all://127.0.0.1"].kind == ENVIRONMENT_BYPASS

        proxied = client.explain_proxy("https://example.com")
        assert proxied.outcome == PROXIED
        assert proxied.source == "HTTPS_PROXY"

        bypass = client.explain_proxy("https://internal.example.com")
        assert bypass.outcome == DIRECT
        assert bypass.source == "NO_PROXY"
        assert bypass.transport is client._transport
    finally:
        client.close()


def test_no_proxy_wildcard_bypasses_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("ALL_PROXY", "http://proxy.example:9000")
    monkeypatch.setenv("NO_PROXY", "*")

    client = httpx.Client()
    try:
        decision = client.explain_proxy("https://example.com")
        assert decision.outcome == DIRECT
        # The wildcard bypass rule is recorded for provenance, but selects the
        # default direct transport rather than a proxy.
        assert decision.matched_rule is not None
        assert decision.matched_rule.direct is True
        assert decision.matched_rule.source == "NO_PROXY"
        assert decision.transport is client._transport
        assert (
            client._transport_for_url(httpx.URL("https://example.com"))
            is client._transport
        )
    finally:
        client.close()


def test_trust_env_disabled_ignores_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:9000")

    client = httpx.Client(trust_env=False)
    try:
        decision = client.explain_proxy("http://example.com")
        assert decision.outcome == DIRECT
        assert decision.rules == []
        assert decision.trust_env is False
        assert (
            client._transport_for_url(httpx.URL("http://example.com"))
            is client._transport
        )
    finally:
        client.close()


def test_password_is_never_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://user:super-secret@proxy.example:9000")

    client = httpx.Client()
    try:
        decision = client.explain_proxy("http://example.com")
        rendered = repr(decision) + decision.masked_summary()
        for rule in decision.rules:
            rendered += repr(rule)
        assert "super-secret" not in rendered
        # Credentials are stripped from the rule URL entirely; the summary
        # therefore shows the bare proxy origin instead of the password.
        assert "proxy.example:9000" in decision.masked_summary()
        # The internal proxy URL keeps the credentials stripped as well.
        assert decision.proxy_url is not None
        assert decision.proxy_url.password == ""
        assert decision.proxy_url.username == ""
    finally:
        client.close()


def test_exact_host_subdomain_and_ipv6_are_distinct(
    clean_proxy_env: None,
) -> None:
    direct = make_mock()
    subdomain_mock = make_mock()
    client = httpx.Client(
        transport=direct,
        mounts={
            "http://example.com": direct,
            "http://*.example.com": subdomain_mock,
            "all://[::1]": direct,
        },
    )
    try:
        exact = client.explain_proxy("http://example.com")
        assert exact.matched_key == "http://example.com"

        sub = client.explain_proxy("http://www.example.com")
        assert sub.matched_key == "http://*.example.com"
        assert sub.transport is subdomain_mock

        # A suffix string match would wrongly route these; URLPattern does not.
        assert client.explain_proxy("http://notexample.com").matched_key is None
        ipv6 = client.explain_proxy("http://[::1]:8080/")
        assert ipv6.matched_key == "all://[::1]"
        assert client.explain_proxy("http://[::2]/").matched_key is None
    finally:
        client.close()


def test_unparseable_environment_rule_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.lower(), raising=False)
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:9000")
    monkeypatch.setenv("NO_PROXY", "http://[::1")

    client = httpx.Client()
    try:
        unparseable = [rule for rule in client._proxy_rules if rule.unparseable]
        assert unparseable
        assert unparseable[0].kind == UNPARSEABLE_RULE
        assert unparseable[0].source == "NO_PROXY"
        assert unparseable[0].error
        # Other rules keep working despite the broken entry.
        decision = client.explain_proxy("http://example.com")
        assert decision.outcome == PROXIED
        assert decision.matched_rule is not None
        assert not decision.matched_rule.unparseable
    finally:
        client.close()


def test_unparseable_explicit_mount_still_raises(clean_proxy_env: None) -> None:
    with pytest.raises(ValueError):
        httpx.Client(mounts={"plain-scheme": make_mock()})


def test_decision_log_matches_actual_transport(
    caplog: pytest.LogCaptureFixture, clean_proxy_env: None
) -> None:
    proxied = make_mock()
    client = httpx.Client(mounts={"http://": proxied})
    try:
        with caplog.at_level(logging.DEBUG, logger="httpx"):
            response = client.get("http://example.com")
        assert response.status_code == 200
        messages = [record.getMessage() for record in caplog.records]
        assert any("Proxy decision" in message for message in messages)
        assert all("super-secret" not in message for message in messages)
    finally:
        client.close()


@pytest.mark.parametrize("client_class", [httpx.Client, httpx.AsyncClient])
def test_explain_available_on_both_clients(
    client_class: type, clean_proxy_env: None
) -> None:
    client = client_class()
    try:
        decision = client.explain_proxy("http://example.com")
        assert decision.outcome == DIRECT
        assert decision.transport is client._transport
    finally:
        close = getattr(client, "aclose", None)
        if close is not None:
            import asyncio

            asyncio.run(close())
        else:
            client.close()
