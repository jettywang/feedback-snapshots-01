#!/usr/bin/env python3
"""Reproduce Keystoneauth identity/session and discovery-cache boundaries.

The experiment is fully local. It uses requests_mock and fake auth plugins;
every identity/token value is a non-secret ``ph-*`` placeholder.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

import requests_mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from keystoneauth1 import adapter as ksa_adapter  # noqa: E402
from keystoneauth1 import discover  # noqa: E402
from keystoneauth1 import plugin as ksa_plugin  # noqa: E402
from keystoneauth1 import session as ksa_session  # noqa: E402
from keystoneauth1.identity import base as identity_base  # noqa: E402
import keystoneauth1  # noqa: E402


SERVICE_TYPE = "block-storage"
REGION_ONE = "RegionOne"
REGION_TWO = "RegionTwo"
INTERFACE = "public"
CATALOG_URLS = {
    REGION_ONE: "http://block-storage.region-one.example/",
    REGION_TWO: "http://block-storage.region-two.example/",
}
OP401_PATH = "/v3/op-401"
OPCACHE_PATH = "/v3/op-cache"


def discovery_document(region: str) -> dict[str, object]:
    endpoint = CATALOG_URLS[region]
    return {
        "versions": [
            {
                "status": "CURRENT",
                "id": "v3.0",
                "links": [{"href": f"{endpoint}v3/", "rel": "self"}],
            }
        ]
    }


class Recorder:
    def __init__(self, scenario: str) -> None:
        self.scenario = scenario
        self.phase = "initiation"
        self.events: list[dict[str, object]] = []
        self.discovery_http_count = 0

    def event(
        self, kind: str, phase: str | None = None, **data: object
    ) -> dict[str, object]:
        event: dict[str, object] = {
            "seq": len(self.events) + 1,
            "scenario": self.scenario,
            "phase": phase or self.phase,
            "kind": kind,
        }
        event.update(data)
        self.events.append(event)
        return event


class FakeAccessInfo:
    """Only implements the cache-freshness method used by the experiment."""

    def __init__(self, token: str) -> None:
        self.auth_token = token

    def will_expire_soon(self, _stale_duration: int | None = None) -> bool:
        return False


class InstrumentedPlugin(identity_base.BaseIdentityPlugin):
    """Identity plugin backed only by placeholder tokens."""

    def __init__(self, identity: str, recorder: Recorder) -> None:
        super().__init__(auth_url="http://identity.example.invalid/v3")
        self.identity = identity
        self.recorder = recorder
        self.generation = 0
        self._retry_next = False

    def get_auth_ref(
        self, session: ksa_session.Session, **kwargs: object
    ) -> FakeAccessInfo:
        self.generation += 1
        token = f"ph-token-{self.identity}-v{self.generation}"
        self.recorder.event(
            "plugin_get_auth_ref",
            identity=self.identity,
            token_cache="miss",
            sent_token=token,
        )
        return FakeAccessInfo(token)

    def get_headers(
        self, session: ksa_session.Session, **kwargs: object
    ) -> dict[str, str] | None:
        had_fresh_cache = (
            self.auth_ref is not None and not self._needs_reauthenticate()
        )
        if self._retry_next:
            phase = "retry"
            self.recorder.phase = phase
        else:
            phase = self.recorder.phase
        self._retry_next = False
        token = self.get_token(session)
        self.recorder.event(
            "plugin_get_headers",
            phase=phase,
            identity=self.identity,
            token_cache="hit" if had_fresh_cache else "miss",
            sent_token=token,
        )
        return {ksa_plugin.IDENTITY_AUTH_HEADER_NAME: token}

    def invalidate(self) -> bool:
        had_cached_token = self.auth_ref is not None
        result = super().invalidate()
        self._retry_next = result
        self.recorder.event(
            "plugin_invalidate",
            phase="invalidate",
            identity=self.identity,
            had_cached_token=had_cached_token,
            returned=result,
        )
        return result

    def get_endpoint_data(
        self,
        session: ksa_session.Session,
        *,
        region_name: str | None = None,
        **kwargs: object,
    ) -> discover.EndpointData | None:
        selection = {
            "service_type": kwargs.get("service_type"),
            "service_name": kwargs.get("service_name"),
            "interface": kwargs.get("interface"),
            "region_name": region_name,
        }
        catalog_url = CATALOG_URLS.get(
            region_name or "", CATALOG_URLS[REGION_ONE]
        )
        self.recorder.event(
            "catalog_lookup",
            phase="discovery",
            identity=self.identity,
            selection=selection,
            catalog_url=catalog_url,
        )

        before_discovery_http = self.recorder.discovery_http_count
        endpoint_data = discover.EndpointData(
            catalog_url=catalog_url,
            service_type=kwargs.get("service_type"),  # type: ignore[arg-type]
            service_name=kwargs.get("service_name"),  # type: ignore[arg-type]
            interface=kwargs.get("interface"),  # type: ignore[arg-type]
            region_name=region_name,
        )
        endpoint_data = endpoint_data.get_versioned_data(
            session,
            cache=self._discovery_cache,
            discover_versions=True,
        )
        http_delta = (
            self.recorder.discovery_http_count - before_discovery_http
        )
        cache_result = "miss" if http_delta else "hit"
        self.recorder.event(
            "discovery_cache",
            phase="discovery",
            identity=self.identity,
            result=cache_result,
            discovery_http_requests=http_delta,
            endpoint_url=endpoint_data.url,
            api_version=(
                ".".join(str(part) for part in endpoint_data.api_version)
                if endpoint_data.api_version
                else None
            ),
            session_cache_size=len(session._discovery_cache),
            plugin_cache_size=len(self._discovery_cache),
        )
        return endpoint_data


def warm_plugin(
    plugin: InstrumentedPlugin,
    session: ksa_session.Session,
    recorder: Recorder,
) -> None:
    original_phase = recorder.phase
    recorder.phase = "setup"
    plugin.get_headers(session)
    recorder.phase = original_phase


def add_check(
    checks: list[dict[str, object]],
    name: str,
    condition: bool,
    expected: object,
    observed: object,
) -> bool:
    checks.append(
        {
            "name": name,
            "ok": bool(condition),
            "expected": expected,
            "observed": observed,
        }
    )
    return condition


def operation_wire_events(recorder: Recorder) -> list[dict[str, object]]:
    return [
        event
        for event in recorder.events
        if event["kind"] == "wire_send"
        and event.get("endpoint_kind") == "operation"
    ]


def discovery_results(recorder: Recorder) -> list[object]:
    return [
        event["result"]
        for event in recorder.events
        if event["kind"] == "discovery_cache"
    ]


def invalidation_summary(recorder: Recorder) -> list[dict[str, object]]:
    return [
        {
            "identity": event["identity"],
            "had_cached_token": event["had_cached_token"],
            "returned": event["returned"],
        }
        for event in recorder.events
        if event["kind"] == "plugin_invalidate"
    ]


def mount_routes(
    mocker: requests_mock.Mocker,
    recorder: Recorder,
    on_unauthorized,
) -> None:
    unauthorized_seen = False

    def discovery_callback(request, context):
        recorder.discovery_http_count += 1
        region = (
            REGION_TWO
            if urlparse(request.url).hostname
            == "block-storage.region-two.example"
            else REGION_ONE
        )
        recorder.event(
            "wire_send",
            phase="discovery",
            endpoint_kind="discovery",
            method=request.method,
            path=urlparse(request.url).path,
            sent_token=request.headers.get("X-Auth-Token"),
        )
        context.status_code = 200
        return json.dumps(discovery_document(region))

    def operation_callback(request, context):
        nonlocal unauthorized_seen
        path = urlparse(request.url).path
        token = request.headers.get("X-Auth-Token")
        is_unauthorized_call = path == OP401_PATH and not unauthorized_seen
        status = 401 if is_unauthorized_call else 200
        recorder.event(
            "wire_send",
            phase=recorder.phase,
            endpoint_kind="operation",
            method=request.method,
            path=path,
            sent_token=token,
            response_status=status,
        )

        if is_unauthorized_call:
            unauthorized_seen = True
            context.status_code = 401
            recorder.event(
                "response_received",
                phase="response",
                status_code=401,
                path=path,
            )
            on_unauthorized()
            recorder.phase = "invalidate"
            return json.dumps(
                {"error": "mock-401-reauthentication-required"}
            )

        context.status_code = 200
        return json.dumps({"ok": True, "path": path})

    mocker.get(CATALOG_URLS[REGION_ONE], text=discovery_callback)
    mocker.get(CATALOG_URLS[REGION_TWO], text=discovery_callback)
    mocker.get(
        f"http://block-storage.region-one.example{OP401_PATH}",
        text=operation_callback,
    )
    mocker.get(
        f"http://block-storage.region-one.example{OPCACHE_PATH}",
        text=operation_callback,
    )


def adapter_kwargs() -> dict[str, object]:
    return {
        "service_type": SERVICE_TYPE,
        "region_name": REGION_ONE,
        "interface": INTERFACE,
    }


def run_shared_entry(entry: str) -> dict[str, object]:
    scenario_id = f"shared_session/{entry}"
    recorder = Recorder(scenario_id)
    checks: list[dict[str, object]] = []

    identity_a = InstrumentedPlugin("A", recorder)
    replacement_b = InstrumentedPlugin("B", recorder)
    override_o = InstrumentedPlugin("O", recorder)
    session = ksa_session.Session(auth=identity_a)

    warm_plugin(identity_a, session, recorder)
    warm_plugin(replacement_b, session, recorder)
    warm_plugin(override_o, session, recorder)
    session.auth = identity_a

    def switch_default_to_b() -> None:
        recorder.event(
            "session_default_switch",
            phase="response",
            old_default_identity="A",
            new_default_identity="B",
            trigger="experiment changes session.auth after 401",
        )
        session.auth = replacement_b

    client = ksa_adapter.Adapter(
        session, **adapter_kwargs()  # type: ignore[arg-type]
    )
    request_auth: dict[str, object] = {}
    expected_tokens = [
        "ph-token-A-v1",
        "ph-token-A-v2",
        "ph-token-A-v2",
    ]
    expected_invalidation = ["A"]

    if entry == "adapter_auth":
        client.auth = identity_a
    elif entry == "request_override":
        request_auth = {"auth": override_o}
        expected_tokens = [
            "ph-token-O-v1",
            "ph-token-O-v2",
            "ph-token-O-v2",
        ]
        expected_invalidation = ["O"]
    elif entry == "session_default":
        expected_tokens = [
            "ph-token-A-v1",
            "ph-token-B-v2",
            "ph-token-B-v2",
        ]
        expected_invalidation = ["B"]
    else:
        raise ValueError(entry)

    with requests_mock.Mocker() as mocker:
        mount_routes(mocker, recorder, switch_default_to_b)
        recorder.phase = "initiation"
        first_response = client.get(
            "/op-401", raise_exc=False, **request_auth
        )
        recorder.phase = "follow_up"
        second_response = client.get(
            "/op-cache", raise_exc=False, **request_auth
        )

    wire = operation_wire_events(recorder)
    tokens = [event["sent_token"] for event in wire]
    invalidations = invalidation_summary(recorder)
    invalidated_identities = [
        item["identity"] for item in invalidations
    ]
    discovery = discovery_results(recorder)

    add_check(
        checks,
        "first_operation_succeeds_after_one_retry",
        first_response.status_code == 200,
        200,
        first_response.status_code,
    )
    add_check(
        checks,
        "second_operation_succeeds",
        second_response.status_code == 200,
        200,
        second_response.status_code,
    )
    add_check(
        checks,
        "sent_identity_placeholders",
        tokens == expected_tokens,
        expected_tokens,
        tokens,
    )
    add_check(
        checks,
        "invalidated_plugin_identity",
        invalidated_identities == expected_invalidation,
        expected_invalidation,
        invalidated_identities,
    )
    add_check(
        checks,
        "same_service_region_discovery_cache",
        discovery == ["miss", "hit"],
        ["miss", "hit"],
        discovery,
    )

    return {
        "id": scenario_id,
        "topology": "shared_session_with_runtime_session_auth_switch",
        "identity_entry": entry,
        "sent_identity_placeholders": tokens,
        "plugin_invalidations": invalidations,
        "discovery_cache_results": discovery,
        "checks": checks,
        "passed": all(check["ok"] for check in checks),
        "events": recorder.events,
    }


def run_cold_replacement() -> dict[str, object]:
    scenario_id = "shared_session/session_default_cold_replacement"
    recorder = Recorder(scenario_id)
    checks: list[dict[str, object]] = []

    identity_a = InstrumentedPlugin("A", recorder)
    cold_b = InstrumentedPlugin("B-cold", recorder)
    session = ksa_session.Session(auth=identity_a)
    warm_plugin(identity_a, session, recorder)
    session.auth = identity_a

    def switch_to_cold_b() -> None:
        recorder.event(
            "session_default_switch",
            phase="response",
            old_default_identity="A",
            new_default_identity="B-cold",
            trigger="replacement plugin has no cached auth_ref",
        )
        session.auth = cold_b

    client = ksa_adapter.Adapter(
        session, **adapter_kwargs()  # type: ignore[arg-type]
    )

    with requests_mock.Mocker() as mocker:
        mount_routes(mocker, recorder, switch_to_cold_b)
        recorder.phase = "initiation"
        first_response = client.get("/op-401", raise_exc=False)
        recorder.phase = "follow_up"
        second_response = client.get("/op-cache", raise_exc=False)

    wire = operation_wire_events(recorder)
    tokens = [event["sent_token"] for event in wire]
    invalidations = invalidation_summary(recorder)
    discovery = discovery_results(recorder)

    add_check(
        checks,
        "cold_replacement_does_not_retry",
        first_response.status_code == 401,
        401,
        first_response.status_code,
    )
    add_check(
        checks,
        "original_and_followup_tokens",
        tokens
        == ["ph-token-A-v1", "ph-token-B-cold-v1"],
        ["ph-token-A-v1", "ph-token-B-cold-v1"],
        tokens,
    )
    add_check(
        checks,
        "invalidation_returns_false",
        invalidations
        == [
            {
                "identity": "B-cold",
                "had_cached_token": False,
                "returned": False,
            }
        ],
        "one false B-cold invalidation",
        invalidations,
    )
    add_check(
        checks,
        "followup_uses_shared_discovery_cache",
        discovery == ["miss", "hit"],
        ["miss", "hit"],
        discovery,
    )
    add_check(
        checks,
        "followup_succeeds_after_cold_mint",
        second_response.status_code == 200,
        200,
        second_response.status_code,
    )

    return {
        "id": scenario_id,
        "topology": "shared_session_with_cold_default_replacement",
        "identity_entry": "session_default",
        "sent_identity_placeholders": tokens,
        "plugin_invalidations": invalidations,
        "discovery_cache_results": discovery,
        "checks": checks,
        "passed": all(check["ok"] for check in checks),
        "events": recorder.events,
    }


def run_partitioned_sessions() -> dict[str, object]:
    scenario_id = (
        "identity_sessions/two_identities_shared_discovery_cache"
    )
    recorder = Recorder(scenario_id)
    checks: list[dict[str, object]] = []

    shared_discovery_cache: dict[str, object] = {}
    identity_a = InstrumentedPlugin("A", recorder)
    identity_b = InstrumentedPlugin("B", recorder)
    session_a = ksa_session.Session(
        auth=identity_a, discovery_cache=shared_discovery_cache
    )
    session_b = ksa_session.Session(
        auth=identity_b, discovery_cache=shared_discovery_cache
    )
    warm_plugin(identity_a, session_a, recorder)
    warm_plugin(identity_b, session_b, recorder)

    def do_not_cross_switch() -> None:
        recorder.event(
            "isolation_decision",
            phase="response",
            action=(
                "keep session_a.auth=A; use session_b for B operation"
            ),
        )

    adapter_a = ksa_adapter.Adapter(
        session_a, **adapter_kwargs()  # type: ignore[arg-type]
    )
    adapter_b = ksa_adapter.Adapter(
        session_b, **adapter_kwargs()  # type: ignore[arg-type]
    )

    with requests_mock.Mocker() as mocker:
        mount_routes(mocker, recorder, do_not_cross_switch)
        recorder.phase = "initiation"
        first_response = adapter_a.get("/op-401", raise_exc=False)
        recorder.phase = "follow_up"
        second_response = adapter_b.get("/op-cache", raise_exc=False)

    wire = operation_wire_events(recorder)
    tokens = [event["sent_token"] for event in wire]
    invalidations = invalidation_summary(recorder)
    discovery = discovery_results(recorder)

    add_check(
        checks,
        "a_retries_with_a_and_b_uses_b",
        tokens
        == [
            "ph-token-A-v1",
            "ph-token-A-v2",
            "ph-token-B-v1",
        ],
        ["A v1", "A v2", "B v1"],
        tokens,
    )
    add_check(
        checks,
        "only_a_is_invalidated",
        [item["identity"] for item in invalidations] == ["A"],
        ["A"],
        invalidations,
    )
    add_check(
        checks,
        "b_reuses_discovery_cache",
        discovery == ["miss", "hit"],
        ["miss", "hit"],
        discovery,
    )
    add_check(
        checks,
        "sessions_keep_identity_bindings",
        session_a.auth is identity_a and session_b.auth is identity_b,
        True,
        {"session_a_auth": "A", "session_b_auth": "B"},
    )
    add_check(
        checks,
        "shared_cache_contains_one_key",
        len(shared_discovery_cache) == 1,
        1,
        len(shared_discovery_cache),
    )
    add_check(
        checks,
        "both_http_calls_succeed",
        first_response.status_code == 200
        and second_response.status_code == 200,
        [200, 200],
        [first_response.status_code, second_response.status_code],
    )

    return {
        "id": scenario_id,
        "topology": (
            "one_session_per_identity_with_explicit_shared_"
            "discovery_cache"
        ),
        "identity_entry": "session_default_on_each_identity_session",
        "sent_identity_placeholders": tokens,
        "plugin_invalidations": invalidations,
        "discovery_cache_results": discovery,
        "shared_discovery_cache_keys": len(shared_discovery_cache),
        "checks": checks,
        "passed": all(check["ok"] for check in checks),
        "events": recorder.events,
    }


def run_discovery_probe(
    share_cache: bool, same_region: bool
) -> dict[str, object]:
    region_two = REGION_ONE if same_region else REGION_TWO
    scenario_id = (
        "discovery_conditions/"
        f"share_cache={str(share_cache).lower()}/"
        f"second_region={'same' if same_region else 'different'}"
    )
    recorder = Recorder(scenario_id)
    checks: list[dict[str, object]] = []

    shared_cache: dict[str, object] | None = {} if share_cache else None
    plugin_a = InstrumentedPlugin("probe-A", recorder)
    plugin_b = InstrumentedPlugin("probe-B", recorder)
    if shared_cache is not None:
        session_a = ksa_session.Session(
            auth=plugin_a, discovery_cache=shared_cache
        )
        session_b = ksa_session.Session(
            auth=plugin_b, discovery_cache=shared_cache
        )
    else:
        session_a = ksa_session.Session(auth=plugin_a)
        session_b = ksa_session.Session(auth=plugin_b)

    with requests_mock.Mocker() as mocker:
        mount_routes(mocker, recorder, lambda: None)
        session_a.get_endpoint(
            auth=plugin_a,
            service_type=SERVICE_TYPE,
            region_name=REGION_ONE,
            interface=INTERFACE,
        )
        session_b.get_endpoint(
            auth=plugin_b,
            service_type=SERVICE_TYPE,
            region_name=region_two,
            interface=INTERFACE,
        )

    discovery = discovery_results(recorder)
    expected_second = "hit" if share_cache and same_region else "miss"
    add_check(
        checks,
        "second_discovery_cache_result",
        discovery == ["miss", expected_second],
        ["miss", expected_second],
        discovery,
    )

    return {
        "id": scenario_id,
        "share_session_discovery_cache": share_cache,
        "same_service_region_interface": same_region,
        "discovery_cache_results": discovery,
        "checks": checks,
        "passed": all(check["ok"] for check in checks),
        "events": recorder.events,
    }


def git_revision() -> str:
    try:
        output = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return output.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(
            Path(__file__).with_name("identity_session_transcript.json")
        ),
        help="JSON transcript output path",
    )
    args = parser.parse_args()

    scenarios = [
        run_shared_entry("adapter_auth"),
        run_shared_entry("session_default"),
        run_shared_entry("request_override"),
        run_cold_replacement(),
        run_partitioned_sessions(),
        run_discovery_probe(True, True),
        run_discovery_probe(False, True),
        run_discovery_probe(True, False),
    ]

    failed_checks = [
        check
        for scenario in scenarios
        for check in scenario["checks"]
        if not check["ok"]
    ]
    report = {
        "keystoneauth_version": getattr(
            keystoneauth1, "__version__", "unknown"
        ),
        "git_revision": git_revision(),
        "python": sys.version.split()[0],
        "credential_material": (
            "none; all identity headers are ph-token-* placeholders"
        ),
        "all_checks_passed": not failed_checks,
        "failed_check_count": len(failed_checks),
        "scenarios": scenarios,
    }

    output = Path(args.output)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    )

    print(
        f"keystoneauth {report['keystoneauth_version']} "
        f"@ {report['git_revision']}"
    )
    for scenario in scenarios:
        checks = scenario["checks"]
        passed = sum(1 for check in checks if check["ok"])
        print(
            f"{scenario['id']}: "
            f"tokens={scenario.get('sent_identity_placeholders', '-')} "
            f"discovery={scenario.get('discovery_cache_results', '-')} "
            f"checks={passed}/{len(checks)}"
        )
    print(f"\nWrote placeholder-only transcript: {output}")

    if failed_checks:
        print(
            f"FAILED: {len(failed_checks)} check(s)", file=sys.stderr
        )
        for check in failed_checks:
            print(f"- {check}", file=sys.stderr)
        return 1
    print("All experiment invariants passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
