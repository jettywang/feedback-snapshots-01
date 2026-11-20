"""In-process fake Vault that records which token authorized every request.

Local port binding is unavailable in this environment, so the fake server is a
``requests_mock`` catch-all.  The cooperating adapter stamps every request with
``X-Sim-Stage`` and ``X-Sim-Request-Id``.  The server keeps the token it
received, the identity that token resolved to, whether the request committed
state, and what it returned.  Those server-side records are the ground truth
for the timelines and the decision table.
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import requests_mock

from hvac.adapters import JSONAdapter, RawAdapter

VAULT_ORIGIN = "http://vault.internal:8200"
COLLECTOR_ORIGIN = "http://collector.internal:8200"

POOL_TOKEN = "hvs.pool-resting-0001"
MANAGER_TOKEN = "hvs.controller-manager-0001"
AUDITOR_TOKEN = "hvs.auditor-0001"

ROOT_CAPS = {"create", "read", "update", "delete", "list", "sudo"}
POLICY_CAPS = {
    "root": ROOT_CAPS,
    "default": {"read", "list"},
    "deploy-reuse": {"read", "list"},
    "deploy-task": {"read", "update"},
    "deploy-apply": {"read"},  # deliberately cannot update
    "audit": {"read", "list", "sudo"},
}

_STAGE: contextvars.ContextVar[str] = contextvars.ContextVar("sim_stage", default="unspecified")


@contextlib.contextmanager
def stage(name: str) -> Iterator[None]:
    """Label every request made inside this block."""
    token = _STAGE.set(name)
    try:
        yield
    finally:
        _STAGE.reset(token)


def new_request_id() -> str:
    return str(uuid.uuid4())


class StageAdapter(JSONAdapter):
    """A JSONAdapter that carries the simulation's stage/request correlation.

    ``requests_mock`` intercepts ``HTTPAdapter.send``, which is the layer where
    ``requests.Session.send`` normally extracts ``Set-Cookie`` into the session
    jar.  Restore that one behavior here so the simulated transport has the
    same cookie semantics as a real ``requests.Session``.
    """

    def request(self, method, url, headers=None, **kwargs):
        headers = dict(headers or {})
        headers["X-Sim-Stage"] = _STAGE.get()
        headers["X-Sim-Request-Id"] = new_request_id()
        response = RawAdapter.request(self, method, url, headers=headers, **kwargs)
        if response.cookies:
            self.session.cookies.update(response.cookies)
        if response.status_code == 200:
            try:
                return response.json()
            except ValueError:
                pass
        return response


@dataclass
class TokenIdentity:
    token: str
    bucket: str
    policies: Tuple[str, ...]
    accessor: str
    display_name: str = ""
    role: str = ""
    ttl: int = 300
    ordinal: int = 0
    revoked: bool = False


@dataclass
class ServerRecord:
    request_id: str
    stage: str
    method: str
    host: str
    path: str
    token_received: Optional[str]
    resolved: str
    status: int = 0
    outcome: str = "pending"
    committed: bool = False
    note: str = ""

    def as_row(self, seq: int, labels: Dict[str, str]) -> Dict[str, Any]:
        return {
            "seq": seq,
            "stage": self.stage,
            "method": self.method,
            "host_path": f"{self.host}{self.path}",
            "token_sent": labels.get(self.token_received or "", self.token_received or "none"),
            "resolved": self.resolved,
            "status": self.status or "-",
            "outcome": self.outcome,
            "committed": "yes" if self.committed else "no",
        }


@dataclass
class Fault:
    """One-shot fault injected into a named stage."""

    stage: str
    mode: str  # reject | lost_before_commit | lost_after_commit
    note: str = ""
    fired: bool = False


@dataclass
class FakeVault:
    issue_task_cookie: bool = False
    revoke_is_noop: bool = False
    tokens: Dict[str, TokenIdentity] = field(default_factory=dict)
    records: List[ServerRecord] = field(default_factory=list)
    commits: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    fault: Optional[Fault] = None
    issued: int = 0
    pending_cookies: List[Dict[str, str]] = field(default_factory=list)
    _mocker: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.tokens = {
            POOL_TOKEN: TokenIdentity(POOL_TOKEN, "pool", ("deploy-reuse", "default"), "hvsacc-pool"),
            MANAGER_TOKEN: TokenIdentity(
                MANAGER_TOKEN, "manager", ("root",), "hvsacc-manager", display_name="controller"
            ),
            AUDITOR_TOKEN: TokenIdentity(
                AUDITOR_TOKEN, "auditor", ("audit", "default"), "hvsacc-auditor", display_name="auditor"
            ),
        }
        self._mocker = requests_mock.Mocker()

    # -- lifecycle --------------------------------------------------------
    def start(self) -> "FakeVault":
        self._mocker.start()
        self._mocker.register_uri(requests_mock.ANY, requests_mock.ANY, text=self._handle)
        return self

    def stop(self) -> None:
        self._mocker.stop()

    def __enter__(self) -> "FakeVault":
        return self.start()

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def inject(self, fault: Optional[Fault]) -> None:
        self.fault = fault

    # -- tokens -----------------------------------------------------------
    def issue_task(self, display_name: str, ttl: int = 120, policy: str = "deploy-task") -> TokenIdentity:
        self.issued += 1
        token = f"hvs.task-{self.issued:04d}"
        identity = TokenIdentity(
            token=token,
            bucket="task",
            policies=(policy, "default"),
            accessor=f"hvsacc-task-{self.issued:04d}",
            display_name=display_name,
            role="deploy-runner",
            ttl=ttl,
            ordinal=self.issued,
        )
        self.tokens[token] = identity
        return identity

    def revoke(self, token: str) -> None:
        if self.revoke_is_noop:
            return
        identity = self.tokens.get(token)
        if identity:
            identity.revoked = True

    def capabilities(self, identity: Optional[TokenIdentity]) -> List[str]:
        if identity is None or identity.revoked:
            return ["deny"]
        caps = set()
        for policy in identity.policies:
            caps.update(POLICY_CAPS.get(policy, set()))
        return sorted(caps)

    def _authorize(self, identity: Optional[TokenIdentity], path: str) -> Tuple[bool, str]:
        # The redirect fixture intentionally accepts any bearer so it can
        # demonstrate what the real transport does with that header.
        if path in ("/v1/redirect", "/collect"):
            return True, "redirect test"
        if identity is None:
            return False, "missing X-Vault-Token"
        if identity.revoked:
            return False, "token revoked"

        if path == "/v1/sys/health":
            return True, "health"
        if path == "/v1/auth/token/create":
            required, reason = {"create"}, "token create requires create or root"
        elif path in ("/v1/auth/token/revoke", "/v1/auth/token/revoke-accessor"):
            required, reason = {"update", "sudo"}, "revocation requires sudo+update"
        elif path in (
            "/v1/auth/token/lookup",
            "/v1/auth/token/lookup-accessor",
            "/v1/auth/token/accessors",
        ):
            required, reason = {"sudo", "read"}, "token inspection requires sudo+read"
        elif path == "/v1/sys/capabilities-self":
            return True, "self capability query"
        elif path == "/v1/sys/capabilities":
            required, reason = {"sudo"}, "capabilities about another token requires sudo"
        elif path == "/v1/deploy/preflight":
            required, reason = {"read", "update"}, "preflight requires read+update"
        elif path == "/v1/deploy/run":
            required, reason = {"update"}, "deploy requires update"
        elif path.startswith("/v1/deploy/state/"):
            required, reason = {"read"}, "state read requires read"
        elif path == "/v1/pool/health":
            if identity.bucket != "pool":
                return False, "pool canary only accepts the resting pool identity"
            return True, "pool canary"
        else:
            return False, "no route policy"

        missing = required - set(self.capabilities(identity))
        if missing:
            return False, f"{reason}; missing {sorted(missing)}"
        return True, reason

    # -- server -----------------------------------------------------------
    def _handle(self, request: requests.Request, context: Any) -> str:
        path = request.path
        stage_name = request.headers.get("X-Sim-Stage") or "unspecified"
        rid = request.headers.get("X-Sim-Request-Id") or new_request_id()
        token = request.headers.get("X-Vault-Token")
        identity = self.tokens.get(token) if token else None
        if identity is None:
            resolved = "unknown" if token else "none"
        elif identity.revoked:
            resolved = f"revoked:{identity.bucket}"
        else:
            resolved = identity.bucket

        record = ServerRecord(
            request_id=rid,
            stage=stage_name,
            method=request.method.upper(),
            host=urlparse(request.url).hostname or "",
            path=path,
            token_received=token,
            resolved=resolved,
        )
        self.records.append(record)

        fault = self.fault
        fault_here = bool(fault and not fault.fired and fault.stage == stage_name)
        if fault_here:
            fault.fired = True
            if fault.mode == "reject":
                record.status = 403
                record.outcome = "rejected"
                record.note = fault.note or "injected service refusal"
                return _json_response(context, 403, {"errors": [record.note]})
            if fault.mode == "lost_before_commit":
                record.outcome = "lost_before_commit"
                record.note = fault.note or "transport failed before commit"
                raise requests.exceptions.ConnectionError(record.note)

        authorized, reason = self._authorize(identity, path)
        if not authorized:
            record.status = 403
            record.outcome = "denied"
            record.note = reason
            return _json_response(context, 403, {"errors": [reason]})

        status, payload, committed = self._execute(request, context, identity)
        record.committed = committed
        if status == 302:
            context.status_code = 302
            context.headers["Location"] = f"{COLLECTOR_ORIGIN}/collect"
            record.status = 302
            record.outcome = "redirect"
            return ""

        if fault_here and fault.mode == "lost_after_commit":
            record.status = status
            record.outcome = "committed_response_lost"
            record.note = fault.note or "server committed, response never arrived"
            raise requests.exceptions.ConnectionError(record.note)

        record.status = status
        record.outcome = "ok" if status < 400 else "denied"
        if status >= 400 and isinstance(payload, dict):
            record.note = "; ".join(payload.get("errors") or [])
        response_text = _json_response(context, status, payload)
        if self.pending_cookies:
            # requests_mock applies Set-Cookie through its cookie jar if the
            # header is present; mirror that for the fake transport.
            existing = context.headers.get("Set-Cookie", "")
            pairs = [f"{c['name']}={c['value']}; Path={c['path']}" for c in self.pending_cookies]
            context.headers["Set-Cookie"] = ", ".join(filter(None, [existing] + pairs))
            self.pending_cookies.clear()
        return response_text

    def _execute(
        self, request: requests.Request, context: Any, identity: Optional[TokenIdentity]
    ) -> Tuple[int, Any, bool]:
        path = request.path
        body: Dict[str, Any] = {}
        if request.text:
            try:
                body = request.json()
            except ValueError:
                body = {}

        if path == "/v1/sys/health":
            return 200, {"initialized": True}, False

        if path == "/v1/auth/token/create":
            policy = (body.get("policies") or ["deploy-task"])[0]
            issued = self.issue_task(body.get("display_name", "token"), ttl=body.get("ttl", 120), policy=policy)
            return (
                200,
                {
                    "auth": {
                        "client_token": issued.token,
                        "accessor": issued.accessor,
                        "policies": list(issued.policies),
                        "lease_duration": issued.ttl,
                        "display_name": issued.display_name,
                    }
                },
                True,
            )

        if path == "/v1/auth/token/revoke":
            target = body.get("token")
            if target:
                self.revoke(target)
            return 204, {}, True

        if path == "/v1/auth/token/revoke-self":
            if identity:
                self.revoke(identity.token)
            return 204, {}, True

        if path == "/v1/auth/token/lookup":
            target = self.tokens.get(body.get("token") or "")
            if target is None or target.revoked:
                return 403, {"errors": ["token not found or revoked"]}, False
            return 200, {"data": self._token_data(target)}, False

        if path == "/v1/auth/token/lookup-accessor":
            target = next(
                (t for t in self.tokens.values() if t.accessor == body.get("accessor")), None
            )
            if target is None or target.revoked:
                return 403, {"errors": ["accessor not found or revoked"]}, False
            return 200, {"data": self._token_data(target)}, False

        if path == "/v1/auth/token/accessors":
            keys = sorted(t.accessor for t in self.tokens.values() if not t.revoked)
            return 200, {"data": {"keys": keys}}, False

        if path == "/v1/auth/token/revoke-accessor":
            for item in self.tokens.values():
                if item.accessor == body.get("accessor"):
                    self.revoke(item.token)
            return 204, {}, True

        if path == "/v1/sys/capabilities-self":
            return 200, {"data": {"capabilities": self.capabilities(identity)}}, False

        if path == "/v1/sys/capabilities":
            target = self.tokens.get(body.get("token") or "")
            return 200, {"data": {"capabilities": self.capabilities(target)}}, False

        if path == "/v1/deploy/preflight":
            return 200, {"data": {"allowed": True, "capabilities": self.capabilities(identity)}}, False

        if path == "/v1/deploy/run":
            key = body.get("idempotency_key") or "default"
            if key in self.commits:
                return 200, dict(self.commits[key], replayed=True), False
            commit = {
                "idempotency_key": key,
                "revision": body.get("revision", "rev-42"),
                "committed": True,
                "authorized_by": identity.token if identity else None,
                "bucket": identity.bucket if identity else "none",
                "policies": list(identity.policies) if identity else [],
            }
            self.commits[key] = commit
            if self.issue_task_cookie and identity is not None:
                # Per-response cookie queue consumed by the fake transport.
                self.pending_cookies.append(
                    {
                        "domain": "vault.internal",
                        "path": "/",
                        "name": "deploy-session",
                        "value": identity.token,
                    }
                )
            return 200, commit, True

        if path.startswith("/v1/deploy/state/"):
            key = path.rsplit("/", 1)[-1]
            commit = self.commits.get(key)
            return 200, {"data": {"found": bool(commit), "commit": commit}}, False

        if path == "/v1/pool/health":
            return 200, {"data": {"status": "healthy", "identity": identity.bucket}}, False

        if path == "/v1/redirect":
            return 302, None, False

        if path == "/collect":
            return 200, {"collected": True, "token": identity.token if identity else None}, False

        return 404, {"errors": ["no handler"]}, False

    @staticmethod
    def _token_data(identity: TokenIdentity) -> Dict[str, Any]:
        return {
            "accessor": identity.accessor,
            "display_name": identity.display_name,
            "policies": list(identity.policies),
            "ttl": identity.ttl,
            "type": "service",
            "path": f"auth/token/create/{identity.role}" if identity.role else "auth/token/create",
        }

    # -- reporting --------------------------------------------------------
    def labels(self) -> Dict[str, str]:
        labels = {
            POOL_TOKEN: "pool:resting",
            MANAGER_TOKEN: "manager:controller",
            AUDITOR_TOKEN: "auditor:readonly",
        }
        for item in self.tokens.values():
            if item.bucket == "task":
                labels[item.token] = f"task:{item.ordinal:04d}"
        return labels

    def rows(self) -> List[Dict[str, Any]]:
        labels = self.labels()
        return [record.as_row(seq, labels) for seq, record in enumerate(self.records, start=1)]

    def stage_record(self, stage_name: str) -> ServerRecord:
        matches = [r for r in self.records if r.stage == stage_name]
        if not matches:
            raise AssertionError(f"no server record for stage {stage_name!r}")
        return matches[-1]


def _json_response(context: Any, status: int, payload: Any) -> str:
    context.status_code = status
    if status == 204:
        return ""
    context.headers["Content-Type"] = "application/json"
    return json.dumps(payload)


TIMELINE_COLUMNS = (
    "#",
    "stage",
    "method",
    "host/path",
    "token sent",
    "server resolved",
    "status",
    "outcome",
    "committed",
)


def render_timeline(rows: List[Dict[str, Any]], title: str, note: str = "") -> str:
    lines = [f"### {title}", ""]
    if note:
        lines.extend([note, ""])
    lines.append("| " + " | ".join(TIMELINE_COLUMNS) + " |")
    lines.append("|" + "|".join(["---"] * len(TIMELINE_COLUMNS)) + "|")
    for row in rows:
        lines.append(
            "| " + " | ".join(str(row[key]) for key in (
                "seq", "stage", "method", "host_path", "token_sent",
                "resolved", "status", "outcome", "committed",
            )) + " |"
        )
    return "\n".join(lines)
