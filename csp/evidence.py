from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from django.conf import settings
from django.utils.encoding import force_bytes, force_str
from django.utils.functional import empty

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE
from csp.middleware import CSPMiddleware, PolicyParts
from csp.utils import build_policy, default_config

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


_FINGERPRINT_LABEL = b"django-csp:policy-evidence:v1"
_CSP_KEYWORD_RE = re.compile(r"^'[^']*'$")
_NONCE_SOURCE_RE = re.compile(r"^'nonce-(?P<value>[^']+)'$")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:$")

_DEFAULT_PRIVATE_SUFFIXES = (
    ".cluster.local",
    ".corp",
    ".home",
    ".home.arpa",
    ".internal",
    ".intranet",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
    ".private",
    ".svc",
)


@dataclass(frozen=True)
class PolicyEvidence:
    """A public report paired with its internal receipt.

    ``public`` is safe to send to an external reviewer. ``receipt`` is internal
    only: it contains the values behind public fingerprints and the exact
    policies and response headers that were observed.
    """

    public: dict[str, Any]
    receipt: dict[str, Any] = field(repr=False)

    @property
    def public_report(self) -> dict[str, Any]:
        return self.public

    @property
    def internal_receipt(self) -> dict[str, Any]:
        return self.receipt

    def public_json(self) -> str:
        return json.dumps(self.public, indent=2, sort_keys=True, ensure_ascii=False)

    def receipt_json(self) -> str:
        return json.dumps(self.receipt, indent=2, sort_keys=True, ensure_ascii=False)


@dataclass(frozen=True)
class _Source:
    value: str
    origin: str
    nonce: bool = False


@dataclass
class _Directive:
    name: str
    sources: list[_Source]
    boolean: bool
    settings_used: bool
    declared_in_settings: bool
    declared_in_view: bool
    defaults_applied: bool
    base_present: bool
    in_replace: bool
    in_update: bool
    direct_config: bool
    nonce_declared: bool = False
    removed: bool = False


class _Builder:
    def __init__(
        self,
        key: str | bytes | None,
        private_hosts: Iterable[str] | None,
        private_suffixes: Iterable[str] | None,
    ) -> None:
        self.key = _derive_key(key)
        self.private_hosts = frozenset(_normalise_host(host) for host in (private_hosts or ()))
        suffixes = set(_DEFAULT_PRIVATE_SUFFIXES)
        suffixes.update(_normalise_suffix(suffix) for suffix in (private_suffixes or ()))
        self.private_suffixes = tuple(sorted(suffix for suffix in suffixes if suffix))
        self.redactions: list[dict[str, Any]] = []

    def fingerprint(self, value: str) -> str:
        digest = hmac.new(self.key, force_bytes(value), hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"

    def public_source(self, source: _Source, directive: str, mode: str) -> dict[str, Any]:
        kind = "dynamic-nonce" if source.nonce else self._kind(source.value)
        rendered: dict[str, Any] = {
            "value": source.value,
            "kind": kind,
            "origin": source.origin,
            "redacted": False,
            "available": True,
        }
        if kind == "dynamic-nonce" and not source.value:
            rendered.update(
                {
                    "value": "<runtime-nonce>",
                    "placeholder": "<runtime-nonce>",
                    "redacted": True,
                    "available": False,
                }
            )
            self.redactions.append(
                {
                    "marker": None,
                    "kind": kind,
                    "value": None,
                    "pending": True,
                    "directive": directive,
                    "mode": mode,
                    "origin": source.origin,
                    "note": "Nonce was not generated when the evidence was exported.",
                }
            )
            return rendered
        if kind not in {"dynamic-nonce", "private-network"}:
            return rendered

        marker = self.fingerprint(source.value)
        rendered["value"] = marker
        rendered["redacted"] = True
        rendered["placeholder"] = "<runtime-nonce>" if kind == "dynamic-nonce" else "<private-network>"

        receipt_entry: dict[str, Any] = {
            "marker": marker,
            "kind": kind,
            "value": source.value,
            "pending": False,
            "directive": directive,
            "mode": mode,
            "origin": source.origin,
        }
        host = _host_from_source(source.value)
        if host is not None:
            receipt_entry["host"] = host
        self.redactions.append(receipt_entry)
        return rendered

    def _kind(self, value: str) -> str:
        if _NONCE_SOURCE_RE.match(value):
            return "dynamic-nonce"
        if _CSP_KEYWORD_RE.match(value):
            return "keyword"
        if value == "*":
            return "wildcard"
        host = _host_from_source(value)
        if host is not None:
            return "private-network" if self._is_private_host(host) else "host"
        if _SCHEME_RE.match(value):
            return "scheme"
        if value.startswith(("/", "./", "../")):
            return "path"
        return "value"

    def _is_private_host(self, host: str) -> bool:
        host = _normalise_host(host)
        if not host:
            return False
        if host in self.private_hosts:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            # ``is_global`` covers private, loopback, link-local, reserved,
            # unspecified, and carrier-grade NAT ranges.
            return not address.is_global
        if host == "localhost" or host.endswith(".localhost"):
            return True
        if "." not in host:
            # A single-label host is not resolvable on the public internet.
            return True
        return any(host.endswith(suffix) for suffix in self.private_suffixes)


def _derive_key(key: str | bytes | None) -> bytes:
    if key is None:
        raw_key = force_bytes(getattr(settings, "SECRET_KEY", "") or "")
        if not raw_key:
            raise ValueError("A Django SECRET_KEY or an explicit key is required to fingerprint policy values.")
    else:
        raw_key = force_bytes(key)
    return hmac.new(raw_key, _FINGERPRINT_LABEL, hashlib.sha256).digest()


def _normalise_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    return host


def _normalise_suffix(suffix: str) -> str:
    suffix = suffix.strip().lower().rstrip(".")
    if not suffix:
        return ""
    return suffix if suffix.startswith(".") else f".{suffix}"


def _host_from_source(value: str) -> str | None:
    text = value.strip()
    if not text or text in {"*", "'self'"} or text.startswith("'"):
        return None
    if "://" in text:
        host = _url_hostname(text)
        return _normalise_host(host) if host else None
    if text.startswith("//"):
        host = _url_hostname(f"https:{text}")
        return _normalise_host(host) if host else None
    if _SCHEME_RE.match(text):
        return None

    hostport = text.split("/", 1)[0]
    if not hostport:
        return None
    if hostport.startswith("[") and (end := hostport.find("]")) != -1:
        return _normalise_host(hostport[1:end]) or None
    if hostport.count(":") == 1:
        host, port = hostport.rsplit(":", 1)
        if port.isdigit():
            hostport = host
    return _normalise_host(hostport) or None


def _url_hostname(value: str) -> str | None:
    try:
        return urlsplit(value).hostname
    except ValueError:
        return None


def _normalise_values(value: Any) -> tuple[Any, ...]:
    if isinstance(value, set):
        return tuple(sorted(value))
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _resolve_nonce(nonce: Any) -> tuple[str | None, str]:
    """Read the nonce without triggering lazy generation."""

    if isinstance(nonce, str):
        return (nonce or None), "available"
    if nonce is None:
        return None, "not-generated"
    wrapped = getattr(nonce, "_wrapped", empty)
    if wrapped is empty or wrapped is None:
        return None, "not-generated"
    if isinstance(wrapped, str):
        return (wrapped or None), "available"
    return None, "unavailable"


def _expand_sources(values: Iterable[Any], origin: str, nonce: str | None) -> tuple[list[_Source], bool]:
    sources: list[_Source] = []
    nonce_declared = False
    for value in values:
        if value is NONCE:
            nonce_declared = True
            sources.append(_Source(f"'nonce-{nonce}'" if nonce is not None else "", origin, nonce=True))
            continue
        try:
            rendered = force_str(value)
        except Exception:
            # A broken lazy value should not prevent the rest of the evidence
            # from being reviewed.
            sources.append(_Source("<unavailable-value>", origin))
            continue
        sources.append(_Source(rendered, origin))
    return sources, nonce_declared


def _dedupe_sources(sources: list[_Source]) -> list[_Source]:
    seen: set[str] = set()
    result: list[_Source] = []
    for source in sources:
        if source.value in seen:
            continue
        seen.add(source.value)
        result.append(source)
    return result


def _resolve_directives(
    parts: PolicyParts,
    report_only: bool,
    nonce: str | None,
) -> tuple[list[_Directive], bool, bool, str, Mapping[str, Any]]:
    setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
    policy = getattr(settings, setting_name, None)
    raw_settings: dict[str, Any] = {}
    configured_directives = policy.get("DIRECTIVES") if isinstance(policy, Mapping) else None
    if isinstance(configured_directives, Mapping):
        raw_settings = {force_str(key): value for key, value in configured_directives.items()}

    settings_used = parts.config is None
    direct_config = parts.config is not None

    if direct_config:
        base_values = {key: _normalise_values(value) for key, value in parts.config.items() if value is not None}  # type: ignore[union-attr]
    elif policy:
        resolved = default_config(dict(raw_settings)) or {}
        base_values = {key: _normalise_values(value) for key, value in resolved.items() if value is not None}
    else:
        base_values = {}

    replace = parts.replace or {}
    update = parts.update or {}
    directives: dict[str, _Directive] = {}

    names = list(dict.fromkeys([*base_values, *replace]))
    for name in names:
        in_replace = name in replace
        if in_replace:
            if replace[name] is None:
                directives[name] = _Directive(
                    name=name,
                    sources=[],
                    boolean=False,
                    settings_used=settings_used,
                    declared_in_settings=settings_used and name in raw_settings,
                    declared_in_view=True,
                    defaults_applied=False,
                    base_present=name in base_values,
                    in_replace=True,
                    in_update=False,
                    direct_config=direct_config,
                    removed=True,
                )
                continue
            values = _normalise_values(replace[name])
            base_origin = "view:csp_replace"
            defaults_applied = False
            base_present = False
        else:
            if name not in base_values:
                continue
            values = base_values[name]
            if settings_used:
                base_origin = "settings" if name in raw_settings else "default"
                defaults_applied = name not in raw_settings
            else:
                base_origin = "view:csp"
                defaults_applied = False
            base_present = True

        if len(values) == 1 and isinstance(values[0], bool) and values[0] is False:
            continue

        boolean = len(values) == 1 and isinstance(values[0], bool) and values[0] is True
        sources, nonce_declared = _expand_sources(values, base_origin, nonce) if not boolean else ([], False)
        directives[name] = _Directive(
            name=name,
            sources=sources,
            boolean=boolean,
            settings_used=settings_used,
            declared_in_settings=settings_used and name in raw_settings,
            declared_in_view=direct_config or in_replace,
            defaults_applied=defaults_applied,
            base_present=base_present,
            in_replace=in_replace,
            in_update=False,
            direct_config=direct_config,
            nonce_declared=nonce_declared,
        )

    for name, value in update.items():
        if value is None:
            continue
        values = _normalise_values(value)
        if len(values) == 1 and isinstance(values[0], bool) and values[0] is False:
            continue
        if name in directives:
            directive = directives[name]
            sources, nonce_declared = _expand_sources(values, "view:csp_update", nonce) if not directive.boolean else ([], False)
            directive.boolean = False
            directive.sources.extend(sources)
            directive.nonce_declared = directive.nonce_declared or nonce_declared
            directive.in_update = True
            directive.declared_in_view = True
        else:
            boolean = len(values) == 1 and isinstance(values[0], bool) and values[0] is True
            sources, nonce_declared = _expand_sources(values, "view:csp_update", nonce) if not boolean else ([], False)
            directives[name] = _Directive(
                name=name,
                sources=sources,
                boolean=boolean,
                settings_used=settings_used,
                declared_in_settings=False,
                declared_in_view=True,
                defaults_applied=False,
                base_present=False,
                in_replace=False,
                in_update=True,
                direct_config=direct_config,
                nonce_declared=nonce_declared,
            )

    for directive in directives.values():
        directive.sources = _dedupe_sources(directive.sources)

    return list(directives.values()), settings_used, direct_config, setting_name, raw_settings


def _change_sources(directive: _Directive) -> list[str]:
    changes: list[str] = []
    if directive.direct_config:
        changes.append("view:csp")
    if directive.in_replace:
        changes.append("view:csp_replace")
    if directive.in_update:
        changes.append("view:csp_update")
    return changes


def _basis_description(directive: _Directive, setting_name: str) -> str:
    if directive.removed:
        return f"view csp_replace removed the directive; {setting_name} value is not used"
    changes = _change_sources(directive)
    if changes:
        if directive.in_replace and directive.in_update:
            return f"view csp_replace supplied the directive and csp_update appended sources; {setting_name} value is not used"
        if directive.in_replace:
            return f"view csp_replace supplied the directive; {setting_name} value is not used"
        if directive.direct_config:
            return f"view csp supplied the policy; {setting_name} directives are not used"
        if directive.base_present:
            return f"{setting_name} directive extended by view csp_update"
        return "directive supplied only by view csp_update"
    if directive.defaults_applied:
        return "django-csp default value; no explicit setting"
    return f"declared in {setting_name}.DIRECTIVES"


def _policy_string(parts: PolicyParts, report_only: bool) -> str:
    nonce, _ = _resolve_nonce(parts.nonce)
    return build_policy(
        config=parts.config,
        update=parts.update,
        replace=parts.replace,
        nonce=nonce,
        report_only=report_only,
    )


def _redacted_policy(directives: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for directive in sorted(directives, key=lambda item: item["directive"]):
        name = directive["directive"]
        if directive["removed"]:
            continue
        if directive["boolean"]:
            parts.append(name)
            continue
        values = [source["value"] for source in directive["sources"]]
        parts.append(f"{name} {' '.join(values)}".strip())
    return "; ".join(parts)


def _policy_exists(setting_name: str) -> bool:
    return getattr(settings, setting_name, None) is not None


def export_policy_evidence(
    request: HttpRequest,
    response: HttpResponseBase,
    *,
    middleware: CSPMiddleware | None = None,
    key: str | bytes | None = None,
    private_hosts: Iterable[str] | None = None,
    private_suffixes: Iterable[str] | None = None,
) -> PolicyEvidence:
    """Export a CSP policy review package without changing the response.

    The public report contains directive names, policy modes, source origins,
    and keyed fingerprints for private or dynamic values. The internal receipt
    contains the values behind those fingerprints plus the exact observed
    policies and response headers.

    ``middleware`` should match the middleware class used by the site (for
    example ``RateLimitedCSPMiddleware``). ``private_hosts`` and
    ``private_suffixes`` can identify site-specific internal names that are not
    recognizable from the source string alone. Fingerprints use ``key`` when
    supplied, otherwise the Django ``SECRET_KEY``.
    """

    middleware = middleware or CSPMiddleware(lambda request: response)
    builder = _Builder(key=key, private_hosts=private_hosts, private_suffixes=private_suffixes)

    public_policies: list[dict[str, Any]] = []
    receipt_policies: list[dict[str, Any]] = []

    for report_only, mode in ((False, "enforced"), (True, "report-only")):
        parts = middleware.get_policy_parts(request=request, response=response, report_only=report_only)
        nonce, nonce_status = _resolve_nonce(parts.nonce)
        policy_string = _policy_string(parts, report_only)
        directives, settings_used, direct_config, setting_name, raw_settings = _resolve_directives(
            parts, report_only, nonce
        )

        public_directives: list[dict[str, Any]] = []
        for directive in sorted(directives, key=lambda item: item.name):
            changes = _change_sources(directive)
            public_directives.append(
                {
                    "directive": directive.name,
                    "mode": mode,
                    "setting": setting_name,
                    "from_approved_settings": not changes,
                    "changed": bool(changes),
                    "change_source": "+".join(changes) if changes else ("default" if directive.defaults_applied else "settings"),
                    "change_sources": changes,
                    "boolean": directive.boolean,
                    "present": not directive.removed,
                    "removed": directive.removed,
                    "runtime_nonce": directive.nonce_declared,
                    "runtime_nonce_available": directive.nonce_declared and nonce_status == "available",
                    "basis": {
                        "setting": setting_name,
                        "setting_path": f"DIRECTIVES[{directive.name!r}]" if directive.settings_used else None,
                        "declared_in_settings": directive.declared_in_settings,
                        "declared_in_view": directive.declared_in_view,
                        "defaults_applied": directive.defaults_applied,
                        "view_decorators": [change.split(":", 1)[1] for change in changes],
                        "description": _basis_description(directive, setting_name),
                    },
                    "sources": [builder.public_source(source, directive.name, mode) for source in directive.sources],
                }
            )

        header_name = HEADER_REPORT_ONLY if report_only else HEADER
        public_policies.append(
            {
                "mode": mode,
                "setting": setting_name,
                "configured": bool(direct_config or _policy_exists(setting_name)),
                "policy_present": bool(policy_string),
                "policy_redacted": _redacted_policy(public_directives),
                "header_present": header_name in response.headers,
                "directives": public_directives,
                "changed_directives": [item["directive"] for item in public_directives if item["changed"]],
            }
        )

        receipt_policies.append(
            {
                "mode": mode,
                "setting": setting_name,
                "policy": policy_string,
                "response_header": response.headers.get(header_name),
                "directives": sorted(raw_settings) if settings_used else [],
            }
        )

    public: dict[str, Any] = {
        "kind": "csp-policy-evidence",
        "version": 1,
        "fingerprint": {
            "algorithm": "hmac-sha256",
            "purpose": "Private network sources and runtime-generated values are replaced by keyed identifiers.",
        },
        "policies": public_policies,
    }

    canonical_public = json.dumps(public, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    receipt: dict[str, Any] = {
        "kind": "csp-policy-evidence-receipt",
        "version": 1,
        "public_report_fingerprint": builder.fingerprint(canonical_public),
        "redactions": builder.redactions,
        "policies": receipt_policies,
    }

    return PolicyEvidence(public=public, receipt=receipt)
