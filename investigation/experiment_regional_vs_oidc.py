#!/usr/bin/env python3
"""Repeatable, fully-offline experiment for the MSAL Python authority paths.

Question behind this script
---------------------------
Two support logs both show token work "completed via another authority".
Is that the expected Entra regional derivative of a configured authority, or a
discovery record steering MSAL to a host/issuer whose attribution cannot be
proven?

This file exercises, against an in-process recording HTTP transport:

  R0   Entra authority + azure_region ............ normal regional timeline
  T1   Timeline 1: pinned regional discovery is incomplete
  T1b  Branch: a complete regional document names an off-host token_endpoint
  O0   Standalone oidc_authority, valid document .. baseline
  T2   Timeline 2: lookalike issuer cannot support the issuer conclusion
  T2b  Timeline 2 variant: issuer missing entirely
  TRUTH  has_valid_issuer() boundary vectors (offline string checks)
  ID   Entra instance-discovery steering + invalid_instance + incomplete payload
  X1   Extra: oidc_authority combined with a region (issuer gate gap)

Every routed destination uses a reserved ".example" name (RFC 2606).
No real network connection is made: MSAL is given a fake http_client.
The one hard-coded link-local IMDS URL in msal/region.py is avoided by
pinning REGION_NAME for the cases that intentionally use a region.

Run:
    .venv/bin/python investigation/experiment_regional_vs_oidc.py
"""
import contextlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import msal  # noqa: E402
from msal.authority import Authority  # noqa: E402

# ---------------------------------------------------------------------------
# Fictional constants.  All routable-looking names are under ".example".
# ---------------------------------------------------------------------------
TENANT = "tenant-7777"
ENTRA_HOST = "login.tailwind-demo.example"
REGION = "region-a"
REGIONAL_HOST = "%s.%s" % (REGION, ENTRA_HOST)

OIDC_TENANT = "tenant-9"
OIDC_HOST = "id.tailwind-demo.example"
OIDC_BASE = "https://%s/%s" % (OIDC_HOST, OIDC_TENANT)

DELEGATE_TOKEN = "https://token.delegate-demo.example/v9/token"

ID_EP = "https://discovery.tailwind-demo.example/common/discovery/instance"
DISCOVERED_HOST = "discovered.tailwind-demo.example"

RESULTS = []
CHECKS_FAILED = []


# ---------------------------------------------------------------------------
# Recording transport (stands in for requests.Session)
# ---------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, status_code=200, obj=None):
        self.status_code = status_code
        self.text = json.dumps(obj if obj is not None else {})
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("faked transport HTTP %s" % self.status_code)


class RecordingTransport:
    """Routes GETs from an in-memory table; records every attempted request."""

    _SECRET_KEYS = ("client_secret", "assertion", "client_assertion")

    def __init__(self, routes, post_response=None):
        self.routes = routes
        self._post_response = post_response
        self.calls = []

    def get(self, url, params=None, headers=None, **kwargs):
        self.calls.append({
            "method": "GET", "url": url,
            "query": params or None,
        })
        return self.routes.get(url.split("?")[0],
                               FakeResponse(404, {"error": "no fake route"}))

    def post(self, url, params=None, data=None, headers=None, **kwargs):
        body_summary = self._summarize_body(data)
        self.calls.append({
            "method": "POST", "url": url,
            "query": params or None,
            "body": body_summary,
        })
        if self._post_response is not None:
            return self._post_response
        return FakeResponse(200, {
            "access_token": "fictional-access-token",
            "token_type": "Bearer", "expires_in": 3600,
        })

    @classmethod
    def _summarize_body(cls, data):
        if isinstance(data, dict):
            summary = {"keys": sorted(data.keys())}
            for key in cls._SECRET_KEYS:
                if key in data:
                    summary[key] = "<redacted-present>"
            return summary
        if isinstance(data, str):
            return {"encoding": "urlencoded-string",
                    "contains_client_secret": "client_secret=" in data}
        return {"type": type(data).__name__}

    def close(self):
        pass


def entra_doc(host):
    return {
        "issuer": "https://%s/%s/v2.0" % (host, TENANT),
        "authorization_endpoint":
            "https://%s/%s/oauth2/v2.0/authorize" % (host, TENANT),
        "token_endpoint":
            "https://%s/%s/oauth2/v2.0/token" % (host, TENANT),
    }


def oidc_doc(issuer, token_endpoint=None):
    return {
        "issuer": issuer,
        "authorization_endpoint": OIDC_BASE + "/oauth2/authorize",
        "token_endpoint": token_endpoint or OIDC_BASE + "/oauth2/token",
    }


ENTRA_CENTRAL_DISCOVERY = (
    "https://%s/%s/v2.0/.well-known/openid-configuration"
    % (ENTRA_HOST, TENANT))
ENTRA_REGIONAL_DISCOVERY = (
    "https://%s/%s/v2.0/.well-known/openid-configuration"
    % (REGIONAL_HOST, TENANT))


@contextlib.contextmanager
def pinned_env(**values):
    """Pin env vars for one scenario; None means remove the variable."""
    snapshot = {k: os.environ.get(k) for k in values}
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, old in snapshot.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


def check(case_id, name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print("    [%s] %s%s" % (status, name, (" -- " + detail) if detail else ""))
    RESULTS.append({"case": case_id, "check": name,
                    "pass": bool(condition), "detail": detail})
    if not condition:
        CHECKS_FAILED.append("%s: %s" % (case_id, name))


def record_case(case_id, title, transport, exc=None, extra=None):
    print("\n" + "=" * 78)
    print("%s -- %s" % (case_id, title))
    print("-" * 78)
    for i, call in enumerate(transport.calls, 1):
        line = "  %2d. %s %s" % (i, call["method"], call["url"])
        if call.get("query"):
            line += "\n      query=%s" % json.dumps(
                call["query"], ensure_ascii=False, sort_keys=True)
        if call.get("body"):
            line += "\n      body=%s" % json.dumps(
                call["body"], ensure_ascii=False, sort_keys=True)
        print(line)
    if exc is not None:
        print("  >> RAISED %s.%s: %s" % (
            type(exc).__module__, type(exc).__name__, str(exc)[:240]))
        cause = exc.__context__
        if cause is not None:
            print("  >> caused by %s: %s" % (
                type(cause).__name__, str(cause)[:200]))
    if extra:
        print("  >> %s" % extra)
    return {
        "id": case_id, "title": title,
        "calls": transport.calls,
        "exception": (None if exc is None else {
            "type": "%s.%s" % (type(exc).__module__, type(exc).__name__),
            "message": str(exc),
            "cause": (None if exc.__context__ is None else {
                "type": type(exc.__context__).__name__,
                "message": str(exc.__context__)[:400]}),
        }),
        "extra": extra,
    }


def build_cca(transport, **kwargs):
    kwargs.setdefault("client_id", "00000000-0000-4000-8000-000000000001")
    kwargs.setdefault("client_credential", "fictional-client-secret")
    kwargs["http_client"] = transport
    return msal.ConfidentialClientApplication(**kwargs)


# ---------------------------------------------------------------------------
# R0: normal Entra regional path on a fictional custom authority host
# ---------------------------------------------------------------------------
def case_r0():
    routes = {
        ENTRA_CENTRAL_DISCOVERY: FakeResponse(200, entra_doc(ENTRA_HOST)),
        ENTRA_REGIONAL_DISCOVERY: FakeResponse(200, entra_doc(REGIONAL_HOST)),
    }
    transport = RecordingTransport(routes)
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=REGION):
        app = build_cca(
            transport,
            authority="https://%s/%s" % (ENTRA_HOST, TENANT),
            azure_region=REGION, instance_discovery=False)
        result = app.acquire_token_for_client(
            scopes=["api://tailwind-demo/.default"])
    evidence = record_case("R0", "Entra regional baseline (expected path)",
                           transport,
                           extra="token returned: %s"
                                 % ("access_token" in result))
    urls = [c["url"] for c in transport.calls]
    check("R0", "central discovery queried first",
          urls[0] == ENTRA_CENTRAL_DISCOVERY, urls[0])
    check("R0", "regional discovery host is locally derived "
                "'<region>.<configured-host>'",
          ENTRA_REGIONAL_DISCOVERY in urls)
    check("R0", "token POST goes to the regional token_endpoint",
          any(c["method"] == "POST" and c["url"] == entra_doc(REGIONAL_HOST)[
              "token_endpoint"] for c in transport.calls))
    check("R0", "no IMDS link-local query (REGION_NAME pinned)",
          not any("169.254.169.254" in u for u in urls))
    check("R0", "fictional token acquired", "access_token" in result)
    return evidence


# ---------------------------------------------------------------------------
# Timeline 1: the approved/pinned regional discovery is incomplete
# ---------------------------------------------------------------------------
def case_t1():
    incomplete = entra_doc(REGIONAL_HOST)
    del incomplete["token_endpoint"]  # 200 OK, but the record is incomplete
    routes = {
        ENTRA_CENTRAL_DISCOVERY: FakeResponse(200, entra_doc(ENTRA_HOST)),
        ENTRA_REGIONAL_DISCOVERY: FakeResponse(200, incomplete),
    }
    transport = RecordingTransport(routes)
    exc = None
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=REGION):
        try:
            build_cca(
                transport,
                authority="https://%s/%s" % (ENTRA_HOST, TENANT),
                azure_region=REGION, instance_discovery=False)
        except Exception as e:  # noqa: BLE001 - we record the exact feedback
            exc = e
    evidence = record_case(
        "T1", "Timeline 1: pinned regional discovery incomplete "
              "(200, token_endpoint missing)", transport, exc)
    check("T1", "fails closed with KeyError('token_endpoint')",
          isinstance(exc, KeyError) and exc.args == ("token_endpoint",),
          repr(exc))
    check("T1", "regional discovery was actually queried",
          ENTRA_REGIONAL_DISCOVERY in [c["url"] for c in transport.calls])
    check("T1", "no token POST attempted",
          not any(c["method"] == "POST" for c in transport.calls))
    return evidence


def case_t1b():
    """Same regional channel, but the document steers token_endpoint off-host."""
    regional = entra_doc(REGIONAL_HOST)
    regional["token_endpoint"] = DELEGATE_TOKEN
    routes = {
        ENTRA_CENTRAL_DISCOVERY: FakeResponse(200, entra_doc(ENTRA_HOST)),
        ENTRA_REGIONAL_DISCOVERY: FakeResponse(200, regional),
    }
    transport = RecordingTransport(routes)
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=REGION):
        app = build_cca(
            transport,
            authority="https://%s/%s" % (ENTRA_HOST, TENANT),
            azure_region=REGION, instance_discovery=False)
        result = app.acquire_token_for_client(
            scopes=["api://tailwind-demo/.default"])
    evidence = record_case(
        "T1b", "Branch: regional document names an off-host token_endpoint",
        transport, extra="token returned: %s" % ("access_token" in result))
    posts = [c for c in transport.calls if c["method"] == "POST"]
    check("T1b", "MSAL POSTs to the document-named off-host endpoint",
          len(posts) == 1 and posts[0]["url"] == DELEGATE_TOKEN,
          posts[0]["url"] if posts else "no POST")
    check("T1b", "credential material is carried to that endpoint",
          posts and posts[0]["body"].get("client_secret")
          == "<redacted-present>")
    return evidence


# ---------------------------------------------------------------------------
# OIDC standalone path
# ---------------------------------------------------------------------------
def case_o0():
    discovery = OIDC_BASE + "/.well-known/openid-configuration"
    transport = RecordingTransport(
        {discovery: FakeResponse(200, oidc_doc(OIDC_BASE + "/v2.0"))})
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=None):
        app = build_cca(transport, authority=None, oidc_authority=OIDC_BASE)
        result = app.acquire_token_for_client(
            scopes=["api://tailwind-demo/.default"])
    evidence = record_case("O0", "Standalone oidc_authority baseline",
                           transport,
                           extra="token returned: %s"
                                 % ("access_token" in result))
    get_urls = [c["url"] for c in transport.calls if c["method"] == "GET"]
    check("O0", "exactly the OIDC discovery document is queried",
          get_urls == [discovery], str(get_urls))
    check("O0", "POST stays on the configured OIDC host",
          any(c["method"] == "POST"
              and c["url"] == OIDC_BASE + "/oauth2/token"
              for c in transport.calls))
    return evidence


def _run_oidc_rejection(case_id, title, issuer):
    discovery = OIDC_BASE + "/.well-known/openid-configuration"
    transport = RecordingTransport(
        {discovery: FakeResponse(200, oidc_doc(issuer))})
    exc = None
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=None):
        try:
            build_cca(transport, authority=None, oidc_authority=OIDC_BASE)
        except Exception as e:  # noqa: BLE001
            exc = e
    evidence = record_case(case_id, title, transport, exc)
    check(case_id, "ValueError from has_valid_issuer gate",
          isinstance(exc, ValueError) and "does not match the authority"
          in str(exc), type(exc).__name__ if exc else "no exception")
    check(case_id, "only the OIDC discovery GET happened",
          len(transport.calls) == 1
          and transport.calls[0]["url"] == discovery)
    check(case_id, "no token POST attempted",
          not any(c["method"] == "POST" for c in transport.calls))
    return evidence


def case_t2():
    lookalike = "https://%s.lookalike.example/%s/v2.0" % (
        OIDC_HOST, OIDC_TENANT)
    return _run_oidc_rejection(
        "T2", "Timeline 2: suffix-lookalike issuer cannot be bound", lookalike)


def case_t2b():
    return _run_oidc_rejection(
        "T2b", "Timeline 2 variant: issuer claim missing", None)


# ---------------------------------------------------------------------------
# has_valid_issuer boundary vectors (pure offline string checks)
# ---------------------------------------------------------------------------
def case_truth_table():
    print("\n" + "=" * 78)
    print("TRUTH -- has_valid_issuer() boundary vectors (no network)")
    print("-" * 78)
    vectors = [
        (OIDC_BASE, OIDC_BASE, True, "exact authority match"),
        (OIDC_BASE, OIDC_BASE + "/v2.0", True,
         "same scheme+host, different path (case 4)"),
        (OIDC_BASE,
         "https://%s.%s/%s/v2.0" % (REGION, OIDC_HOST, OIDC_TENANT), True,
         "one-label region prefix of configured host (case 3b)"),
        (OIDC_BASE,
         "https://%s.lookalike.example/%s/v2.0"
         % (OIDC_HOST, OIDC_TENANT), False,
         "suffix lookalike: trusted name is only a prefix label"),
        (OIDC_BASE,
         "https://id-tailwind-demo.example/%s/v2.0" % OIDC_TENANT, False,
         "typosquat: hyphen instead of dot hierarchy"),
        (OIDC_BASE, None, False, "missing issuer cannot support a conclusion"),
        (OIDC_BASE,
         "https://login.microsoftonline.com/%s/v2.0" % OIDC_TENANT, True,
         "OFFLINE RULE VECTOR ONLY: any well-known Entra host passes "
         "(case 2); this is an allowlist string rule, not a contacted "
         "destination here"),
    ]
    rows = []
    for oidc_url, issuer, expected, label in vectors:
        authority_obj = object.__new__(Authority)
        authority_obj._oidc_authority_url = oidc_url
        authority_obj._issuer = issuer
        actual = Authority.has_valid_issuer(authority_obj)
        print("  expected=%-5s actual=%-5s | %-52s issuer=%s"
              % (expected, actual, label, issuer))
        check("TRUTH", label, actual is expected)
        rows.append({"oidc_authority": oidc_url, "issuer": issuer,
                     "expected": expected, "actual": actual, "label": label,
                     "network": False})
    return {"id": "TRUTH", "vectors": rows}


# ---------------------------------------------------------------------------
# Entra instance-discovery steering
# ---------------------------------------------------------------------------
def case_instance_discovery():
    tde = "https://%s/%s/v2.0/.well-known/openid-configuration" % (
        DISCOVERED_HOST, TENANT)
    transport = RecordingTransport({
        ID_EP: FakeResponse(200, {"tenant_discovery_endpoint": tde}),
        tde: FakeResponse(200, entra_doc(DISCOVERED_HOST)),
    })
    exc = None
    try:
        authority = Authority(
            "https://%s/%s" % (ENTRA_HOST, TENANT), transport,
            instance_discovery=ID_EP)
        extra = "final token_endpoint=%s" % authority.token_endpoint
    except Exception as e:  # noqa: BLE001
        exc = e
        extra = None
    evidence = record_case(
        "ID1", "Entra instance discovery steers the next GET and the "
               "token host", transport, exc, extra)
    first = transport.calls[0]
    check("ID1", "instance-discovery query carries "
                "authorization_endpoint + api-version=1.0",
          first["method"] == "GET" and first["url"] == ID_EP
          and first["query"].get("api-version") == "1.0"
          and first["query"].get("authorization_endpoint")
          == "https://%s/%s/oauth2/v2.0/authorize" % (ENTRA_HOST, TENANT))
    check("ID1", "tenant_discovery_endpoint from payload is followed verbatim",
          len(transport.calls) >= 2 and transport.calls[1]["url"] == tde)
    check("ID1", "final token endpoint lives on the payload-named host",
          exc is None and authority.token_endpoint
          == entra_doc(DISCOVERED_HOST)["token_endpoint"])

    # invalid_instance feedback
    bad = RecordingTransport(
        {ID_EP: FakeResponse(200, {"error": "invalid_instance"})})
    exc2 = None
    try:
        Authority("https://%s/%s" % (ENTRA_HOST, TENANT), bad,
                  instance_discovery=ID_EP)
    except Exception as e:  # noqa: BLE001
        exc2 = e
    record_case("ID2", "Instance discovery answers invalid_instance",
                bad, exc2)
    check("ID2", "invalid_instance raises the explicit rollback hint",
          isinstance(exc2, ValueError)
          and "invalid_instance" in str(exc2))

    # incomplete instance-discovery payload
    incomplete = RecordingTransport(
        {ID_EP: FakeResponse(200, {"metadata": []})})
    exc3 = None
    try:
        Authority("https://%s/%s" % (ENTRA_HOST, TENANT), incomplete,
                  instance_discovery=ID_EP)
    except Exception as e:  # noqa: BLE001
        exc3 = e
    record_case("ID3", "Instance discovery payload lacks "
                       "tenant_discovery_endpoint", incomplete, exc3)
    check("ID3", "missing key surfaces as KeyError "
                 "('tenant_discovery_endpoint')",
          isinstance(exc3, KeyError)
          and exc3.args == ("tenant_discovery_endpoint",), repr(exc3))
    return {"id": "ID", "cases": [evidence]}


# ---------------------------------------------------------------------------
# X1: oidc_authority + explicit region crosses the two paths
# ---------------------------------------------------------------------------
def case_x1():
    discovery = OIDC_BASE + "/.well-known/openid-configuration"
    regional_discovery = (
        "https://%s.%s/%s/v2.0/.well-known/openid-configuration"
        % (REGION, OIDC_HOST, OIDC_TENANT))
    transport = RecordingTransport({
        discovery: FakeResponse(200, oidc_doc(OIDC_BASE + "/v2.0")),
        regional_discovery: FakeResponse(200, {
            # Deliberately unbound issuer and off-host token endpoint:
            "issuer": "https://unverified-regional-record.example/%s/v2.0"
                      % OIDC_TENANT,
            "authorization_endpoint":
                "https://%s.%s/%s/oauth2/authorize"
                % (REGION, OIDC_HOST, OIDC_TENANT),
            "token_endpoint": DELEGATE_TOKEN,
        }),
    })
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=REGION):
        app = build_cca(transport, authority=None, oidc_authority=OIDC_BASE,
                        azure_region=REGION)
        result = app.acquire_token_for_client(
            scopes=["api://tailwind-demo/.default"])
    evidence = record_case(
        "X1", "Cross-path: oidc_authority + region prefers an Entra-style "
              "regional client with NO issuer gate", transport,
              extra="token returned: %s" % ("access_token" in result))
    urls = [c["url"] for c in transport.calls]
    check("X1", "primary OIDC document passed the issuer gate",
          discovery in urls)
    check("X1", "Entra-style regional derivative was additionally fetched",
          regional_discovery in urls)
    check("X1", "token POST follows the regional document off-host without "
                "issuer rejection",
          any(c["method"] == "POST" and c["url"] == DELEGATE_TOKEN
              for c in transport.calls))
    return evidence


def case_feedback():
    """Discovery 4xx wrapping and token-endpoint OAuth error feedback."""
    # F1: regional discovery answers 400
    transport = RecordingTransport({
        ENTRA_CENTRAL_DISCOVERY: FakeResponse(200, entra_doc(ENTRA_HOST)),
        ENTRA_REGIONAL_DISCOVERY: FakeResponse(
            400, {"error": "invalid_tenant"}),
    })
    exc = None
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=REGION):
        try:
            build_cca(
                transport,
                authority="https://%s/%s" % (ENTRA_HOST, TENANT),
                azure_region=REGION, instance_discovery=False)
        except Exception as e:  # noqa: BLE001
            exc = e
    evidence = record_case(
        "F1", "Failure feedback: regional discovery HTTP 400",
        transport, exc)
    check("F1", "outer ValueError names the regional authority",
          isinstance(exc, ValueError)
          and "Unable to get authority configuration for https://%s/%s"
          % (REGIONAL_HOST, TENANT) in str(exc))
    check("F1", "chained cause names the exact discovery URL + HTTP 400",
          exc is not None and exc.__context__ is not None
          and "OIDC Discovery failed on %s" % ENTRA_REGIONAL_DISCOVERY
          in str(exc.__context__)
          and "400" in str(exc.__context__))

    # F2: regional document is fine, token endpoint returns an OAuth error
    token_url = entra_doc(REGIONAL_HOST)["token_endpoint"]
    transport2 = RecordingTransport(
        {ENTRA_CENTRAL_DISCOVERY: FakeResponse(200, entra_doc(ENTRA_HOST)),
         ENTRA_REGIONAL_DISCOVERY: FakeResponse(200, entra_doc(REGIONAL_HOST))},
        post_response=FakeResponse(400, {
            "error": "invalid_client",
            "error_description":
                "AADSTS7000215: fictional invalid client secret",
        }))
    with pinned_env(MSAL_FORCE_REGION=None, REGION_NAME=REGION):
        app = build_cca(
            transport2,
            authority="https://%s/%s" % (ENTRA_HOST, TENANT),
            azure_region=REGION, instance_discovery=False)
        outcome = app.acquire_token_for_client(
            scopes=["api://tailwind-demo/.default"])
    evidence2 = record_case(
        "F2", "Failure feedback: token endpoint returns invalid_client",
        transport2,
        extra="returned dict keys=%s" % sorted(outcome.keys()))
    check("F2", "OAuth error is returned as a dict (no exception)",
          outcome.get("error") == "invalid_client"
          and "AADSTS7000215" in outcome.get("error_description", ""))
    check("F2", "the failed POST destination is the regional token_endpoint",
          any(c["method"] == "POST" and c["url"] == token_url
              for c in transport2.calls))
    return [evidence, evidence2]


def main():
    print("MSAL %s at %s" % (msal.__version__, ROOT))
    print("All destinations are fictional *.example names; transport is "
          "in-process.")
    evidence = {
        "msal_version": msal.__version__,
        "repo_root": str(ROOT),
        "cases": [],
    }
    for fn in (case_r0, case_t1, case_t1b, case_o0, case_t2, case_t2b,
               case_truth_table, case_instance_discovery, case_x1,
               case_feedback):
        produced = fn()
        if isinstance(produced, list):
            evidence["cases"].extend(produced)
        else:
            evidence["cases"].append(produced)

    out = Path(__file__).with_name("evidence.json")
    out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2,
                              default=str))
    print("\n" + "#" * 78)
    if CHECKS_FAILED:
        print("RESULT: %d check(s) FAILED" % len(CHECKS_FAILED))
        for item in CHECKS_FAILED:
            print("  - " + item)
        print("Evidence written to %s" % out)
        return 1
    print("RESULT: all checks passed. Evidence written to %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
