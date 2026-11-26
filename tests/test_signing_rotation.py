import json
from urllib.parse import urlparse

import pytest

import msal
from msal.signing_rotation import (
    GenerationBoundAssertion,
    RecordingSigner,
    SigningRotationPolicy,
    UnboundClientAssertionError,
    public_key_tag,
)


SCOPES_OPEN = ["api://rotation/open/.default"]
SCOPES_CLOSED = ["api://rotation/closed/.default"]
SCOPES_RETRY = ["api://rotation/retry/.default"]


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP {}".format(self.status_code))


class TwoRegionTokenService:
    """Records exactly which generation the fake ESTS endpoint received."""

    def __init__(self, policy):
        self.policy = policy
        self.received = []
        self.access_tokens = {}

    def get(self, url, params=None, headers=None, **kwargs):
        parsed = urlparse(url)
        tenant = parsed.path.strip("/").split("/", 1)[0] or "contoso"
        base = "{}://{}/{}".format(parsed.scheme, parsed.netloc, tenant)
        metadata = {
            "token_endpoint": base + "/oauth2/v2.0/token",
            "authorization_endpoint": base + "/oauth2/v2.0/authorize",
            "device_authorization_endpoint": base + "/oauth2/v2.0/devicecode",
            "issuer": base + "/v2.0",
        }
        return FakeResponse(200, json.dumps(metadata))

    def post(self, url, params=None, data=None, headers=None, **kwargs):
        data = data or {}
        host = urlparse(url).hostname or ""
        region = host.split(".", 1)[0]
        assertion = data.get("client_assertion")
        generation = self.policy.generation_for_wire_value(assertion)
        row = {
            "region": region,
            "generation": generation,
            "scope": data.get("scope"),
            "same_bound_object": isinstance(assertion, GenerationBoundAssertion),
        }
        self.received.append(row)
        if region == "alpha":
            return FakeResponse(503, json.dumps({
                "error": "server_temporarily_unavailable",
            }))
        scope = data.get("scope") or "default"
        token = "AT-{}-{}".format(abs(hash(scope)), len(self.access_tokens))
        self.access_tokens[scope] = token
        return FakeResponse(200, json.dumps({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }))


class TwoRegionFallbackClient:
    """Try fictional alpha, then fictional beta, rechecking before each send."""

    def __init__(self, service, policy, before_beta=None):
        self.service = service
        self.policy = policy
        self.before_beta = before_beta

    def get(self, url, **kwargs):
        return self.service.get(url, **kwargs)

    def post(self, url, data=None, **kwargs):
        self.policy.review_request_data(data, phase="region:alpha:send")
        alpha_response = self.service.post(url, data=data, **kwargs)
        if alpha_response.status_code < 500:
            return alpha_response

        if self.before_beta is not None:
            self.before_beta()
        beta_url = url.replace(
            "alpha.login.microsoft.com", "beta.login.microsoft.com")
        self.policy.review_request_data(data, phase="region:beta:retry")
        return self.service.post(beta_url, data=data, **kwargs)

    def close(self):
        return None


def test_transition_window_allows_same_prepared_assertion_then_renews():
    current_time = [1000.0]
    policy = SigningRotationPolicy(
        transition_window=300, clock=lambda: current_time[0])
    old_signer = RecordingSigner("g1", "tag-g1")
    new_signer = RecordingSigner("g2", "tag-g2")
    policy.add_generation("g1", old_signer)

    prepared = policy.prepare("audience", phase="unit.prepare")
    assert prepared.generation == "g1"
    assert old_signer.records[0]["phase"] == "sign"

    policy.rotate("g2", new_signer, at=1000, transition_window=300)

    current_time[0] = 1299
    allowed = policy.review(prepared, phase="unit.send")
    assert allowed is prepared.assertion
    assert policy.generation_for_wire_value(allowed) == "g1"

    current_time[0] = 1301
    replaced = policy.review(prepared, phase="unit.send_after_window")
    assert replaced is not prepared.assertion
    assert policy.generation_for_wire_value(replaced) == "g2"
    assert len(new_signer.records) == 1

    for event in policy.diagnostics:
        assert set(event) == {"key_tag", "phase"}
        assert "private" not in event["key_tag"].lower()


def test_retirement_forces_redecision_even_within_configured_window():
    current_time = [50.0]
    policy = SigningRotationPolicy(clock=lambda: current_time[0])
    policy.add_generation("g1", RecordingSigner("g1", "tag-g1"))
    prepared = policy.prepare()
    policy.rotate("g2", RecordingSigner("g2", "tag-g2"), transition_window=600)
    policy.retire("g1", at=51)

    reviewed = policy.review(prepared, at=52, phase="retry")
    assert policy.generation_for_wire_value(reviewed) == "g2"


def test_changing_transition_window_config_closes_existing_window():
    current_time = [100.0]
    policy = SigningRotationPolicy(
        transition_window=30, clock=lambda: current_time[0])
    policy.add_generation("g1", RecordingSigner("g1", "tag-g1"))
    prepared = policy.prepare()
    policy.rotate("g2", RecordingSigner("g2", "tag-g2"))

    assert policy.allows_in_flight("g1", at=120, assertion=prepared.assertion)
    policy.configure_transition_window(0)
    assert not policy.allows_in_flight(
        "g1", at=120, assertion=prepared.assertion)
    reviewed = policy.review(prepared, at=120, phase="send.config_closed")
    assert policy.generation_for_wire_value(reviewed) == "g2"


def test_public_key_tag_is_public_fingerprint_only():
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tag = public_key_tag(key.public_key())

    assert tag.startswith("sha256:")
    assert len(tag) == len("sha256:") + 64
    assert public_key_tag(key.public_key()) == tag


def test_strict_policy_rejects_unbound_assertion():
    policy = SigningRotationPolicy(strict_unbound=True)
    with pytest.raises(UnboundClientAssertionError):
        policy.review("ordinary-jwt", phase="send")


def test_policy_can_supply_client_assertion_automatically():
    policy = SigningRotationPolicy()
    signer = RecordingSigner("g1", "public-tag-auto")
    policy.add_generation("g1", signer)
    service = TwoRegionTokenService(policy)
    http_client = TwoRegionFallbackClient(service, policy)
    app = msal.ConfidentialClientApplication(
        "client-id",
        authority="https://login.microsoftonline.com/contoso",
        azure_region="alpha",
        client_credential={"signing_rotation": policy},
        http_client=http_client,
    )

    result = app.acquire_token_for_client(["api://auto/.default"])

    assert "access_token" in result
    assert [row["generation"] for row in service.received] == ["g1", "g1"]
    assert len(signer.records) == 1


def test_region_fallback_cache_and_rotation_generation_ledger():
    current_time = [1_800_000_000.0]
    policy = SigningRotationPolicy(
        transition_window=300, clock=lambda: current_time[0])
    signers = {
        "g1": RecordingSigner("g1", "public-tag-1"),
        "g2": RecordingSigner("g2", "public-tag-2"),
        "g3": RecordingSigner("g3", "public-tag-3"),
        "g4": RecordingSigner("g4", "public-tag-4"),
    }
    policy.add_generation("g1", signers["g1"])

    service = TwoRegionTokenService(policy)

    # Each hook runs after the signer has constructed the short-lived assertion
    # but before MSAL/the HTTP boundary sends it.
    after_prepare_hooks = []

    def assertion_provider(context):
        prepared = policy.prepare(
            audience=context["token_endpoint"], expires_in=600)
        hook = after_prepare_hooks.pop(0)
        hook()
        return prepared.assertion

    def close_second_window_before_beta():
        # The second end-to-end case closes the whole old-generation window
        # before the first wire send.
        policy.rotate("g3", signers["g3"], transition_window=0)

    def close_third_generation_before_beta():
        policy.retire("g3")

    before_beta_actions = [
        lambda: None,  # Case 1: the window stays open through beta.
        lambda: None,  # Case 2: redecision already happened before alpha.
        close_third_generation_before_beta,
    ]

    def before_beta():
        before_beta_actions.pop(0)()

    fallback = TwoRegionFallbackClient(
        service, policy, before_beta=before_beta)
    app = msal.ConfidentialClientApplication(
        "client-id",
        authority="https://login.microsoftonline.com/contoso",
        azure_region="alpha",
        client_credential={"client_assertion": assertion_provider},
        http_client=fallback,
        token_cache=msal.SerializableTokenCache(),
        signing_rotation=policy,
    )

    # Case 1: g1 is prepared, then g2 becomes current while g1 remains inside
    # the configured window. Both fictional region attempts send the same g1
    # assertion generation.
    after_prepare_hooks.append(
        lambda: policy.rotate("g2", signers["g2"], transition_window=300))
    first = app.acquire_token_for_client(SCOPES_OPEN)
    assert "access_token" in first

    first_case_rows = service.received[-2:]
    assert [(row["region"], row["generation"]) for row in first_case_rows] == [
        ("alpha", "g1"), ("beta", "g1")]
    assert first_case_rows[0]["same_bound_object"]
    assert first_case_rows[1]["same_bound_object"]

    # The ordinary access token issued above is not partitioned by signing
    # generation. Repeated acquisition is an in-memory cache hit and produces
    # no new region HTTP records.
    received_before_cache_hit = len(service.received)
    cached = app.acquire_token_for_client(SCOPES_OPEN)
    assert cached["access_token"] == first["access_token"]
    assert len(service.received) == received_before_cache_hit

    # Case 2: g2 is prepared, but the transition window is closed before the
    # actual first send. The send boundary redecides and resigns as g3, so
    # neither region receives g2.
    after_prepare_hooks.append(close_second_window_before_beta)
    closed_case = app.acquire_token_for_client(SCOPES_CLOSED)
    assert "access_token" in closed_case
    closed_rows = service.received[-2:]
    assert [(row["region"], row["generation"]) for row in closed_rows] == [
        ("alpha", "g3"), ("beta", "g3")]

    # Case 3: the first region sends g3 legally in its window, but retirement
    # happens while the request is in flight. The beta retry must reassess and
    # use a newly signed g4 assertion.
    after_prepare_hooks.append(
        lambda: policy.rotate("g4", signers["g4"], transition_window=300))
    retry_case = app.acquire_token_for_client(SCOPES_RETRY)
    assert "access_token" in retry_case
    retry_rows = service.received[-2:]
    assert [(row["region"], row["generation"]) for row in retry_rows] == [
        ("alpha", "g3"), ("beta", "g4")]

    # The old ordinary access token remains a cache hit after all later
    # rotations and retirements, according to its own expires_in lifetime.
    received_before_final_cache_hit = len(service.received)
    final_cached = app.acquire_token_for_client(SCOPES_OPEN)
    assert final_cached["access_token"] == first["access_token"]
    assert len(service.received) == received_before_final_cache_hit

    # Every fallback produced exactly two wire observations, and the cache
    # contains no signing-generation/key-tag discriminator.
    assert [(row["region"], row["generation"]) for row in service.received] == [
        ("alpha", "g1"), ("beta", "g1"),
        ("alpha", "g3"), ("beta", "g3"),
        ("alpha", "g3"), ("beta", "g4"),
    ]
    serialized_cache = app.token_cache.serialize()
    assert "public-tag-" not in serialized_cache
    assert '"signing_generation"' not in serialized_cache

    # The recording signers distinguish prepared-only calls from wire use.
    assert len(signers["g1"].records) == 1
    assert len(signers["g2"].records) == 1  # Prepared, then rejected pre-send.
    assert len(signers["g3"].records) == 2  # Replacement + later case 3 prepare.
    assert len(signers["g4"].records) == 1

    # Diagnostics are deliberately limited to a public key marker and phase.
    assert policy.diagnostics
    for event in policy.diagnostics:
        assert set(event) == {"key_tag", "phase"}
        assert event["key_tag"].startswith("public-tag-")
