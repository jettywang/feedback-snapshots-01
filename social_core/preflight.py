"""Read-only pre-release checks for OIDC and SAML login configuration.

The module answers one operational question for each configured provider:
which identity provider, site (issuer/entity), and callback address would the
real login flow select, and where did each effective value come from?

The check never performs a login, never writes through the strategy, and
never opens a network connection. OIDC discovery documents and SAML IdP
metadata are supplied by the caller as fake fixtures, so the whole verification
runs with placeholder credentials. It deliberately does not import the SAML
toolkit, keeping the check available without the optional ``saml`` extra.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, cast
from xml.etree.ElementTree import ParseError

from defusedxml.ElementTree import fromstring as parse_xml

from social_core.exceptions import SocialAuthBaseException
from social_core.utils import setting_name

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from social_core.backends.base import BaseAuth
    from social_core.strategy import BaseStrategy

Protocol = Literal["oidc", "saml"]
CheckStatus = Literal["ok", "unconfigured", "conflict", "invalid"]
Severity = Literal["error", "warning"]

SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata"

_SENSITIVE_MARKERS = ("SECRET", "PRIVATE_KEY", "DECRYPTION_KEY")
_SETTING_MARKER = "setting"
_DISCOVERY_MARKER = "oidc_discovery"
_DEFAULT_MARKER = "class_default"


@dataclass(frozen=True)
class SettingSource:
    """Where a single effective configuration value came from."""

    kind: str
    label: str

    @property
    def is_setting(self) -> bool:
        return self.kind == _SETTING_MARKER


def setting_sources(backend: BaseAuth[object], name: str) -> list[SettingSource]:
    """Return the candidate setting names consulted for ``name``, in order.

    Mirrors ``BaseStrategy.setting`` precedence without evaluating the values:
    backend-scoped setting, global setting, then the bare name.
    """
    names = [setting_name(backend.name, name), setting_name(name), name]
    return [SettingSource(_SETTING_MARKER, candidate) for candidate in names]


def resolve_setting(
    backend: BaseAuth[object], name: str, default: Any = None
) -> tuple[Any, SettingSource, list[SettingSource]]:
    """Resolve a setting while recording the winning and consulted sources."""
    candidates = setting_sources(backend, name)
    for candidate in candidates:
        try:
            value = backend.strategy.get_setting(candidate.label)
        except (AttributeError, KeyError):
            continue
        return value, candidate, candidates
    return default, SettingSource(_DEFAULT_MARKER, "class default"), candidates


def _is_sensitive(name: str) -> bool:
    return any(marker in name for marker in _SENSITIVE_MARKERS)


@dataclass(frozen=True)
class Finding:
    """A single configuration problem reported by a preflight check."""

    severity: Severity
    code: str
    message: str


@dataclass(frozen=True)
class ResolvedSetting:
    """One effective value, its provenance, and any fixture-provided intent."""

    key: str
    value: Any
    source: SettingSource
    consulted: tuple[SettingSource, ...]
    sensitive: bool
    metadata_value: Any = None
    metadata_source: str | None = None

    def display_value(self) -> str:
        if self.sensitive:
            return "<redacted>" if self.value else "<not set>"
        if self.value is None:
            return "<not set>"
        return str(self.value)

    def display_metadata_value(self) -> Any:
        if self.sensitive:
            return "<redacted>" if self.metadata_value else None
        return self.metadata_value


@dataclass
class BackendReport:
    """Pre-release view of everything a login flow would select for a backend."""

    backend: str
    protocol: Protocol
    status: CheckStatus
    callback_url: str
    findings: list[Finding] = field(default_factory=list)
    settings: list[ResolvedSetting] = field(default_factory=list)
    target: str | None = None

    def add(self, severity: Severity, code: str, message: str) -> None:
        self.findings.append(Finding(severity, code, message))
        if severity == "error" and self.status == "ok":
            self.status = "invalid"

    def mark_conflict(self) -> None:
        if self.status == "ok":
            self.status = "conflict"

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "protocol": self.protocol,
            "status": self.status,
            "target": self.target,
            "callback_url": self.callback_url,
            "findings": [
                {
                    "severity": item.severity,
                    "code": item.code,
                    "message": item.message,
                }
                for item in self.findings
            ],
            "settings": [
                {
                    "key": item.key,
                    "value": item.display_value(),
                    "source": item.source.label,
                    "source_kind": item.source.kind,
                    "consulted": [source.label for source in item.consulted],
                    "sensitive": item.sensitive,
                    "metadata_value": item.display_metadata_value(),
                    "metadata_source": item.metadata_source,
                }
                for item in self.settings
            ],
        }


@contextmanager
def _fake_oidc_discovery(
    backend: BaseAuth[object], document: dict[str, Any] | None
) -> Iterator[None]:
    """Serve a local discovery fixture instead of fetching it over the network."""
    if document is None:
        yield
        return
    original = backend.get_openid_configuration

    def serve_document(url: str) -> dict[str, Any]:
        return document

    backend.get_openid_configuration = serve_document  # type: ignore[method-assign]
    try:
        yield
    finally:
        backend.get_openid_configuration = original  # type: ignore[method-assign]


_OIDC_ENDPOINTS: tuple[tuple[str, str, str], ...] = (
    ("AUTHORIZATION_URL", "authorization_endpoint", "authorization_url"),
    ("ACCESS_TOKEN_URL", "token_endpoint", "access_token_url"),
    ("USERINFO_URL", "userinfo_endpoint", "userinfo_url"),
    ("JWKS_URI", "jwks_uri", "jwks_uri"),
    ("ID_TOKEN_ISSUER", "issuer", "id_token_issuer"),
)

_OIDC_REQUIRED = ("KEY", "SECRET")


def inspect_oidc_backend(
    backend: BaseAuth[object],
    discovery_document: dict[str, Any] | None = None,
    *,
    redirect_uri: str | None = None,
) -> BackendReport:
    """Check one OIDC backend against an optional fake discovery document.

    No network access happens: when ``discovery_document`` is omitted the check
    only evaluates explicitly configured values and reports anything that would
    require a live discovery fetch as unconfigured.
    """
    if redirect_uri is not None:
        backend.redirect_uri = backend.strategy.absolute_uri(redirect_uri)

    report = BackendReport(
        backend=backend.name,
        protocol="oidc",
        status="ok",
        callback_url=cast("str", backend.redirect_uri),
    )

    for name in _OIDC_REQUIRED:
        value, source, consulted = resolve_setting(backend, name)
        report.settings.append(
            ResolvedSetting(
                key=name,
                value=value,
                source=source,
                consulted=tuple(consulted),
                sensitive=_is_sensitive(name),
            )
        )
        if not value:
            report.add(
                "error",
                "missing_setting",
                f"Required OIDC setting {name} is not configured",
            )

    endpoint_value, endpoint_source, endpoint_consulted = resolve_setting(
        backend, "OIDC_ENDPOINT"
    )
    report.settings.append(
        ResolvedSetting(
            key="OIDC_ENDPOINT",
            value=endpoint_value,
            source=endpoint_source,
            consulted=tuple(endpoint_consulted),
            sensitive=False,
        )
    )
    if not endpoint_value:
        report.status = "unconfigured"
        report.add(
            "error",
            "tenant_unconfigured",
            "No OIDC_ENDPOINT is set; the tenant has no discoverable provider",
        )
        return report

    discovery_url = cast("str", backend.oidc_config_url())
    for name, claim, accessor in _OIDC_ENDPOINTS:
        value, source, consulted = resolve_setting(backend, name)
        metadata_value = (
            discovery_document.get(claim) if discovery_document is not None else None
        )
        metadata_source = (
            f"discovery fixture {discovery_url}#{claim}"
            if discovery_document is not None
            else None
        )

        if not value and discovery_document is None:
            report.settings.append(
                ResolvedSetting(
                    key=name,
                    value=value,
                    source=source,
                    consulted=tuple(consulted),
                    sensitive=False,
                )
            )
            report.status = "unconfigured"
            report.add(
                "error",
                "discovery_required",
                f"{name} is unset and would require a live discovery fetch "
                f"from {discovery_url}",
            )
            continue

        with _fake_oidc_discovery(backend, discovery_document):
            try:
                effective = getattr(backend, accessor)()
            except SocialAuthBaseException as error:
                report.settings.append(
                    ResolvedSetting(
                        key=name,
                        value=value,
                        source=source,
                        consulted=tuple(consulted),
                        sensitive=False,
                        metadata_value=metadata_value,
                        metadata_source=metadata_source,
                    )
                )
                if error.code == "missing_claim":
                    # Optional endpoints such as userinfo_endpoint may be absent.
                    report.add(
                        "warning",
                        "endpoint_unavailable",
                        f"{name} is neither configured nor advertised by the "
                        f"discovery metadata",
                    )
                else:
                    report.add(
                        "error",
                        "resolution_failed",
                        f"{name} cannot be resolved: {error.code}",
                    )
                continue

        effective_source = (
            source
            if source.is_setting
            else SettingSource(_DISCOVERY_MARKER, metadata_source or "")
        )
        report.settings.append(
            ResolvedSetting(
                key=name,
                value=effective,
                source=effective_source,
                consulted=tuple(consulted),
                sensitive=False,
                metadata_value=metadata_value,
                metadata_source=metadata_source,
            )
        )

        if (
            discovery_document is not None
            and source.is_setting
            and metadata_value is not None
            and effective != metadata_value
        ):
            report.mark_conflict()
            report.add(
                "warning",
                "intent_conflict",
                f"{name} resolves to {effective!r} but discovery metadata "
                f"advertises {metadata_value!r}",
            )

    return report


def _saml_metadata_entities(xml: str) -> list[dict[str, Any]]:
    """Parse a fake IdP metadata document without the SAML toolkit."""
    document = parse_xml(xml)
    descriptors = document.findall(f".//{{{SAML_METADATA_NS}}}IDPSSODescriptor")
    if not descriptors:
        return []
    parent_map = {child: parent for parent in document.iter() for child in parent}
    entities: list[dict[str, Any]] = []
    for descriptor in descriptors:
        entity = parent_map.get(descriptor, document)
        sso = next(
            (
                node
                for node in descriptor.iter(
                    f"{{{SAML_METADATA_NS}}}SingleSignOnService"
                )
                if node.get("Location")
            ),
            None,
        )
        cert_nodes = [
            node
            for node in descriptor.iter()
            if node.tag.endswith("}X509Certificate") and node.text
        ]
        entities.append(
            {
                "entity_id": entity.get("entityID"),
                "sso_url": sso.get("Location") if sso is not None else None,
                "x509cert": cert_nodes[0].text.strip() if cert_nodes else None,
            }
        )
    return entities


def _saml_idp_report(
    backend: BaseAuth[object],
    idp_name: str,
    idp_config: dict[str, Any],
    metadata: dict[str, Any] | None,
) -> BackendReport:
    report = BackendReport(
        backend=backend.name,
        protocol="saml",
        status="ok",
        callback_url=cast("str", backend.redirect_uri),
        target=idp_name,
    )

    sp_entity_id, sp_source, sp_consulted = resolve_setting(backend, "SP_ENTITY_ID")
    report.settings.append(
        ResolvedSetting(
            key="SP_ENTITY_ID",
            value=sp_entity_id,
            source=sp_source,
            consulted=tuple(sp_consulted),
            sensitive=False,
        )
    )
    if not sp_entity_id:
        report.add(
            "error",
            "missing_setting",
            "Required SAML setting SP_ENTITY_ID is not configured",
        )

    for name in ("SP_PUBLIC_CERT", "SP_PRIVATE_KEY"):
        value, source, consulted = resolve_setting(backend, name)
        report.settings.append(
            ResolvedSetting(
                key=name,
                value=value,
                source=source,
                consulted=tuple(consulted),
                sensitive=_is_sensitive(name),
            )
        )
        if not value:
            report.add(
                "error",
                "missing_setting",
                f"Required SAML setting {name} is not configured",
            )

    idp_values = (
        ("entity_id", "entity_id"),
        ("url", "sso_url"),
        ("x509cert", "x509cert"),
    )
    for conf_key, metadata_key in idp_values:
        value = idp_config.get(conf_key)
        metadata_value = metadata.get(metadata_key) if metadata is not None else None
        source = SettingSource(
            _SETTING_MARKER,
            f"{setting_name(backend.name, 'ENABLED_IDPS')}[{idp_name}].{conf_key}",
        )
        report.settings.append(
            ResolvedSetting(
                key=f"IDP_{conf_key.upper()}",
                value=value,
                source=source,
                consulted=(source,),
                sensitive=conf_key == "x509cert",
                metadata_value=metadata_value,
                metadata_source=(
                    f"SAML metadata fixture for IdP {idp_name}#{metadata_key}"
                    if metadata is not None
                    else None
                ),
            )
        )
        if not value:
            report.add(
                "error",
                "missing_setting",
                f"IdP {idp_name!r} is missing required entry {conf_key!r}",
            )

    if metadata is None:
        report.status = "unconfigured"
        report.add(
            "error",
            "metadata_required",
            f"No SAML metadata fixture supplied for IdP {idp_name!r}; "
            "provider intent cannot be compared offline",
        )
        return report

    for conf_key, metadata_key, code in (
        ("entity_id", "entity_id", "entity_id_conflict"),
        ("url", "sso_url", "sso_url_conflict"),
    ):
        configured = idp_config.get(conf_key)
        intended = metadata.get(metadata_key)
        if configured and intended and configured != intended:
            report.mark_conflict()
            report.add(
                "warning",
                code,
                f"IdP {idp_name!r} {conf_key} is {configured!r} but metadata "
                f"advertises {intended!r}",
            )

    configured_cert = idp_config.get("x509cert")
    intended_cert = metadata.get("x509cert")
    if configured_cert and intended_cert and configured_cert != intended_cert:
        report.mark_conflict()
        report.add(
            "warning",
            "certificate_conflict",
            f"IdP {idp_name!r} x509cert does not match the metadata certificate",
        )

    return report


def inspect_saml_backend(
    backend: BaseAuth[object],
    metadata_fixtures: dict[str, str] | None = None,
    *,
    redirect_uri: str | None = None,
) -> list[BackendReport]:
    """Check every IdP enabled on a SAML backend against fake metadata XML.

    ``metadata_fixtures`` maps IdP names (as used in ``ENABLED_IDPS``) to
    metadata XML strings. IdPs without a fixture are reported as unconfigured
    rather than fetched.
    """
    if redirect_uri is not None:
        backend.redirect_uri = backend.strategy.absolute_uri(redirect_uri)

    enabled, _, _ = resolve_setting(backend, "ENABLED_IDPS", default={})
    if not isinstance(enabled, dict) or not enabled:
        report = BackendReport(
            backend=backend.name,
            protocol="saml",
            status="unconfigured",
            callback_url=cast("str", backend.redirect_uri),
        )
        report.add(
            "error",
            "tenant_unconfigured",
            "SAML ENABLED_IDPS is empty; no identity provider is configured",
        )
        return [report]

    fixtures = metadata_fixtures or {}
    reports: list[BackendReport] = []
    for idp_name in enabled:
        fixture = fixtures.get(idp_name)
        metadata: dict[str, Any] | None = None
        if fixture is not None:
            try:
                metadata = _saml_metadata_entities(fixture)[0]
            except (ParseError, IndexError, AttributeError) as error:
                report = BackendReport(
                    backend=backend.name,
                    protocol="saml",
                    status="invalid",
                    callback_url=cast("str", backend.redirect_uri),
                    target=idp_name,
                )
                report.add(
                    "error",
                    "invalid_metadata",
                    f"Metadata fixture for IdP {idp_name!r} cannot be parsed: "
                    f"{type(error).__name__}",
                )
                reports.append(report)
                continue
        reports.append(_saml_idp_report(backend, idp_name, enabled[idp_name], metadata))
    return reports


def is_oidc_backend(backend: BaseAuth[object]) -> bool:
    """Return whether the backend participates in OIDC discovery."""
    return callable(getattr(backend, "oidc_config_url", None)) and callable(
        getattr(backend, "get_openid_configuration", None)
    )


def inspect_backend(
    backend: BaseAuth[object],
    *,
    oidc_discovery_document: dict[str, Any] | None = None,
    saml_metadata_fixtures: dict[str, str] | None = None,
    redirect_uri: str | None = None,
) -> list[BackendReport]:
    """Run the appropriate read-only check for one backend instance.

    OIDC backends produce one report; SAML backends produce one report per
    enabled IdP. The strategy and storage are never written to and no HTTP
    request is issued.
    """
    if is_oidc_backend(backend):
        return [
            inspect_oidc_backend(
                backend,
                oidc_discovery_document,
                redirect_uri=redirect_uri,
            )
        ]
    return inspect_saml_backend(
        backend,
        saml_metadata_fixtures,
        redirect_uri=redirect_uri,
    )


def inspect_strategy(
    strategy: BaseStrategy[object],
    backend_paths: Sequence[str],
    *,
    oidc_documents: dict[str, dict[str, Any]] | None = None,
    saml_metadata: dict[str, dict[str, str]] | None = None,
    redirect_uris: dict[str, str] | None = None,
) -> list[BackendReport]:
    """Load backends through a strategy and check each one.

    ``backend_paths`` uses the same dotted module paths as
    ``AUTHENTICATION_BACKENDS``. Fixture and callback arguments are keyed by
    backend name, keeping per-tenant fixtures explicit.
    """
    from social_core.backends.utils import load_backends

    classes = load_backends(list(backend_paths), force_load=True)
    oidc_documents = oidc_documents or {}
    saml_metadata = saml_metadata or {}
    redirect_uris = redirect_uris or {}
    reports: list[BackendReport] = []
    for name in classes:
        backend = strategy.get_backend(name, redirect_uri=redirect_uris.get(name))
        reports.extend(
            inspect_backend(
                backend,
                oidc_discovery_document=oidc_documents.get(name),
                saml_metadata_fixtures=saml_metadata.get(name),
            )
        )
    return reports


def render_text_report(reports: Sequence[BackendReport]) -> str:
    """Render reports as a plain-text pre-release verification summary."""
    lines: list[str] = []
    for report in reports:
        target = f" [{report.target}]" if report.target else ""
        lines.append(
            f"{report.backend}{target} ({report.protocol}): {report.status.upper()}"
        )
        lines.append(f"  callback: {report.callback_url}")
        for item in report.settings:
            suffix = ""
            if item.metadata_source and item.metadata_value is not None:
                suffix = f" | metadata intent: {item.display_metadata_value()}"
            lines.append(
                f"  - {item.key} = {item.display_value()} "
                f"[source: {item.source.label}]{suffix}"
            )
        for finding in report.findings:
            lines.append(
                f"  {finding.severity.upper()} {finding.code}: {finding.message}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()
