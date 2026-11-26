# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Target-specific TLS configuration and safe certificate rotation.

A single Keystoneauth :class:`~keystoneauth1.session.Session` can talk to
several services.  Each service gets an immutable :class:`TLSBinding`
(one generation of its TLS configuration).  Rotation creates a new generation
and a new connection adapter; the old generation remains available to the
request that already selected it and can be closed only when its recorded
exit condition is approved.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping
import contextvars
import dataclasses
import hashlib
import os
import socket
import ssl
import threading
import time
from typing import Any
import urllib.parse
import weakref

import requests.adapters

from keystoneauth1 import _utils as utils


__all__ = (
    'UNSET',
    'TLSConfig',
    'TLSBinding',
    'TLSTarget',
    'TargetTLSRegistry',
    'TLSRegistry',
    'TLSGeneration',
    'TLSTransition',
    'TLSConnectionLedger',
    'TargetTLSAdapter',
    'CURRENT_TLS_BINDING',
)

TLSVersionT = str
CertT = str | tuple[str, str] | tuple[str, str, str] | None
VerifyT = bool | str | None
AdapterFactoryT = Callable[['TLSBinding'], requests.adapters.BaseAdapter]
MountT = Callable[[str, requests.adapters.BaseAdapter], None]
ExitConditionT = (
    str | Callable[['TLSGeneration'], bool | None] | None
)

#: Sentinel for "value not supplied".  ``None`` means an explicit no-cert
#: policy, which must override a Session-wide client certificate.
UNSET: Any = object()
_UNSET: Any = UNSET

#: Binding selected by Session for the duration of one outer request.
CURRENT_TLS_BINDING: contextvars.ContextVar[TLSBinding | None] = (
    contextvars.ContextVar('keystoneauth_tls_binding', default=None)
)

_TLS_VERSION_MAP = {
    '1.2': ssl.TLSVersion.TLSv1_2,
    '1.3': ssl.TLSVersion.TLSv1_3,
}


@dataclasses.dataclass(frozen=True)
class TLSTarget:
    """A normalized network target.

    TLS selection is based on the URL origin.  A non-default port is retained
    in :attr:`prefix`; default ports are normalized away.
    """

    scheme: str
    host: str
    port: int

    def __post_init__(self) -> None:
        object.__setattr__(self, 'scheme', self.scheme.lower())
        object.__setattr__(self, 'host', self.host.lower())

    @classmethod
    def parse(cls, value: 'TLSTarget | str') -> 'TLSTarget':
        if isinstance(value, TLSTarget):
            return value

        text = str(value).strip()
        if '://' not in text:
            text = 'https://' + text

        parsed = urllib.parse.urlsplit(text)
        if not parsed.hostname:
            raise ValueError(f'TLS target {value!r} has no host')

        scheme = (parsed.scheme or 'https').lower()
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(
                f'TLS target {value!r} has an invalid port'
            ) from exc
        if port is None:
            port = 443 if scheme == 'https' else 80

        return cls(scheme=scheme, host=parsed.hostname, port=port)

    @property
    def default_port(self) -> int:
        return 443 if self.scheme == 'https' else 80

    @property
    def authority(self) -> str:
        if self.port == self.default_port:
            return self.host
        return f'{self.host}:{self.port}'

    @property
    def origin(self) -> str:
        return f'{self.scheme}://{self.authority}'

    @property
    def prefix(self) -> str:
        return self.origin + '/'

    def matches_url(self, url: str) -> bool:
        try:
            other = self.parse(url)
        except ValueError:
            return False
        return (
            other.scheme == self.scheme
            and other.host == self.host
            and other.port == self.port
        )


# Readable aliases for callers who think in terms of "target" or "profile".
Target = TLSTarget


@dataclasses.dataclass(frozen=True)
class TLSConfig:
    """Immutable TLS material for one target generation.

    ``cert`` and ``verify`` use the usual requests forms.  Leaving either as
    :data:`UNSET` means inherit the Session/request/auth-plugin value.  Pass
    ``cert=None`` explicitly to prove that a target uses no client certificate.
    """

    cert: Any = _UNSET
    verify: Any = _UNSET
    tls_ciphers: str | None = None
    tls_min_version: TLSVersionT | None = None
    label: str | None = None
    metadata: Mapping[str, Any] = dataclasses.field(default_factory=dict)
    ssl_context: ssl.SSLContext | None = None

    @classmethod
    def from_value(cls, value: Any) -> 'TLSConfig':
        if isinstance(value, TLSConfig):
            return value
        if value is None:
            # A mapping value of None means "this target uses no client cert".
            return cls(cert=None)
        if isinstance(value, (str, tuple)):
            return cls(cert=value)
        if isinstance(value, Mapping):
            return cls(**dict(value))
        raise TypeError(
            f'Unsupported TLS configuration {value!r}; expected TLSConfig, '
            'a cert path/tuple, a mapping, or None'
        )

    @property
    def has_cert(self) -> bool:
        return self.cert is not _UNSET

    @property
    def has_verify(self) -> bool:
        return self.verify is not _UNSET

    def effective_verify(self, default: VerifyT = True) -> VerifyT:
        if self.verify is _UNSET or self.verify is None:
            return default
        return self.verify

    def transport_kwargs(
        self, default_verify: VerifyT = True
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if self.cert is not _UNSET:
            params['cert'] = self.cert
        verify = self.effective_verify(default_verify)
        if self.has_verify:
            params['verify'] = verify
        return params

    def fingerprint(self) -> str:
        """Return a stable fingerprint of configured paths and file contents.

        Hashing file contents means replacing a certificate at the same path
        still produces a new generation/fingerprint.  Missing fake/test paths
        contribute their path only.
        """

        digest = hashlib.sha256()
        digest.update(b'keystoneauth-tls-config-v1')
        digest.update(repr(self.label).encode())
        digest.update(repr(self.tls_ciphers).encode())
        digest.update(repr(self.tls_min_version).encode())
        digest.update(repr(id(self.ssl_context)).encode())
        for name, value in (('cert', self.cert), ('verify', self.verify)):
            digest.update(name.encode())
            self._hash_value(digest, value)
        return digest.hexdigest()

    @staticmethod
    def _hash_value(digest: Any, value: Any) -> None:
        if value is _UNSET:
            digest.update(b'<unset>')
            return
        if value is None:
            digest.update(b'<none>')
            return
        if isinstance(value, (bool, int, float)):
            digest.update(repr(value).encode('ascii'))
            return
        if isinstance(value, (tuple, list)):
            for item in value:
                TLSConfig._hash_value(digest, item)
            return
        if isinstance(value, str):
            text = value
        else:
            try:
                text = os.fspath(value)
            except TypeError:
                text = repr(value)
        if isinstance(text, bytes):
            digest.update(text)
            return
        digest.update(text.encode('utf-8', 'surrogateescape'))
        if isinstance(text, str) and os.path.isfile(text):
            try:
                with open(text, 'rb') as handle:
                    for chunk in iter(lambda: handle.read(65536), b''):
                        digest.update(chunk)
            except OSError:
                # The path itself is already in the fingerprint.  Unreadable
                # material will fail later in the real TLS handshake.
                pass

    def create_ssl_context(
        self,
        *,
        default_verify: VerifyT = True,
        default_ciphers: str | None = None,
        default_min_version: TLSVersionT | None = None,
    ) -> ssl.SSLContext:
        if self.ssl_context is not None:
            return self.ssl_context

        context = ssl.create_default_context()
        verify = self.effective_verify(default_verify)

        if verify is False:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif isinstance(verify, str):
            if os.path.isdir(verify):
                context.load_verify_locations(capath=verify)
            else:
                context.load_verify_locations(cafile=verify)

        cert = self.cert if self.cert is not _UNSET else None
        if cert:
            if isinstance(cert, tuple):
                if len(cert) == 3:
                    cert_file, key_file, password = cert
                    context.load_cert_chain(
                        certfile=cert_file,
                        keyfile=key_file,
                        password=password,
                    )
                elif len(cert) == 2:
                    context.load_cert_chain(
                        certfile=cert[0], keyfile=cert[1]
                    )
                else:
                    context.load_cert_chain(certfile=cert[0])
            else:
                context.load_cert_chain(certfile=cert)

        minimum = self.tls_min_version or default_min_version
        if minimum:
            if minimum not in _TLS_VERSION_MAP:
                raise ValueError(
                    'Unknown TLS version: {}. Supported values are {}'.format(
                        minimum, ', '.join(sorted(_TLS_VERSION_MAP))
                    )
                )
            context.minimum_version = _TLS_VERSION_MAP[minimum]

        ciphers = self.tls_ciphers or default_ciphers
        if ciphers:
            context.set_ciphers(ciphers)

        return context


# Friendly aliases.
TargetTLSConfig = TLSConfig
TLSProfile = TLSConfig
TargetTLSProfile = TLSConfig


@dataclasses.dataclass(frozen=True)
class TLSBinding:
    """An immutable, numbered configuration selection for one target."""

    target: TLSTarget
    config: TLSConfig
    generation: int
    fingerprint: str
    created_at: float = dataclasses.field(default_factory=time.time)
    source: str = 'target'

    @property
    def prefix(self) -> str:
        return self.target.prefix

    @property
    def label(self) -> str | None:
        return self.config.label

    def transport_kwargs(
        self, default_verify: VerifyT = True
    ) -> dict[str, Any]:
        return self.config.transport_kwargs(default_verify=default_verify)

    def matches(self, url: str) -> bool:
        return self.target.matches_url(url)

    def to_record(self) -> dict[str, Any]:
        return {
            'target': self.target.origin,
            'prefix': self.prefix,
            'generation': self.generation,
            'fingerprint': self.fingerprint,
            'label': self.config.label,
            'cert': self.config.cert
            if self.config.cert is not _UNSET
            else None,
            'cert_configured': self.config.has_cert,
            'verify': self.config.verify
            if self.config.verify is not _UNSET
            else None,
            'verify_configured': self.config.has_verify,
            'tls_ciphers': self.config.tls_ciphers,
            'tls_min_version': self.config.tls_min_version,
            'source': self.source,
        }


class TLSConnectionLedger:
    """Thread-safe record of selected transports and connection reuse."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: list[dict[str, Any]] = []
        self._sequence = 0

    def record(self, kind: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            self._sequence += 1
            event = {
                'seq': self._sequence,
                'time': time.time(),
                'kind': kind,
                **data,
            }
            self._events.append(event)
            return dict(event)

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(event) for event in self._events]

    @property
    def transport_records(self) -> list[dict[str, Any]]:
        return [event for event in self.events if event['kind'] == 'transport']

    @property
    def reuse_records(self) -> list[dict[str, Any]]:
        return [event for event in self.events if event['kind'] == 'checkout']

    @property
    def close_records(self) -> list[dict[str, Any]]:
        return [event for event in self.events if event['kind'] == 'close']

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._sequence = 0


class TLSGeneration:
    """A active or retired target generation and its connection adapter."""

    def __init__(
        self,
        binding: TLSBinding,
        adapter: requests.adapters.BaseAdapter | None = None,
        *,
        exit_condition: ExitConditionT = None,
        approved: bool = False,
        ledger: TLSConnectionLedger | None = None,
    ) -> None:
        self.binding = binding
        self.adapter = adapter
        self.exit_condition = exit_condition
        self.approved = approved
        self.ledger = ledger
        self.active_sends = 0
        self.checkouts = 0
        self.reuses = 0
        self.closes = 0
        self.closed = False
        self.closed_at: float | None = None
        self._lock = threading.RLock()

    @property
    def generation(self) -> int:
        return self.binding.generation

    @property
    def target(self) -> TLSTarget:
        return self.binding.target

    def begin_send(self) -> None:
        with self._lock:
            self.active_sends += 1

    def end_send(self) -> None:
        with self._lock:
            self.active_sends = max(0, self.active_sends - 1)

    def can_exit(self) -> bool:
        condition = self.exit_condition
        if condition is None:
            return False
        if isinstance(condition, str):
            if condition in ('immediate', 'now', 'force'):
                return True
            if condition in ('return', 'return-to-pool', 'idle', 'safe'):
                return self.active_sends == 0
            raise ValueError(f'Unknown TLS exit condition {condition!r}')
        result = condition(self)
        return bool(result)

    def approve_exit(self) -> bool:
        """Mark the transition approved and close if its condition is met."""

        self.approved = True
        return self.close_if_allowed()

    def close_if_allowed(self) -> bool:
        if self.closed or not self.approved or not self.can_exit():
            return False
        self.close()
        return True

    def close(self) -> None:
        """Close this generation's idle pooled connections.

        Requests/urllib3 pool close is safe for an in-flight connection: the
        active socket is not in the idle queue and is closed/discarded when it
        is returned.  Calling this method repeatedly is harmless.
        """

        with self._lock:
            if self.closed:
                return
            self.closed = True
            self.closed_at = time.time()
            self.closes += 1
            adapter = self.adapter

        if adapter is not None:
            try:
                adapter.close()
                if isinstance(adapter, TargetTLSAdapter):
                    adapter._ssl_contexts.clear()
            except Exception as exc:  # pragma: no cover - defensive audit path
                if self.ledger is not None:
                    self.ledger.record(
                        'close-error',
                        generation=self.generation,
                        target=self.target.origin,
                        error=repr(exc),
                    )
                raise

        if self.ledger is not None:
            self.ledger.record(
                'close',
                generation=self.generation,
                target=self.target.origin,
                active_sends=self.active_sends,
            )

    def to_record(self) -> dict[str, Any]:
        record = self.binding.to_record()
        record.update(
            {
                'active_sends': self.active_sends,
                'checkouts': self.checkouts,
                'reuses': self.reuses,
                'closed': self.closed,
                'closed_at': self.closed_at,
                'approved': self.approved,
                'exit_condition': (
                    self.exit_condition
                    if isinstance(self.exit_condition, str)
                    else callable(self.exit_condition)
                ),
            }
        )
        return record


class TLSTransition:
    """Result of rotating one target; links old and new generations."""

    def __init__(
        self,
        target: TLSTarget,
        old: TLSGeneration | None,
        new: TLSGeneration,
        registry: 'TargetTLSRegistry',
    ) -> None:
        self.target = target
        self.old = old
        self.new = new
        self._registry = registry

    @property
    def old_binding(self) -> TLSBinding | None:
        return self.old.binding if self.old else None

    @property
    def new_binding(self) -> TLSBinding:
        return self.new.binding

    def approve_exit(self) -> bool:
        if self.old is None:
            return False
        return self.old.approve_exit()

    def close_old(self) -> bool:
        if self.old is None:
            return False
        self.old.close()
        return True

    def close_if_allowed(self) -> bool:
        if self.old is None:
            return False
        return self.old.close_if_allowed()

    approve = approve_exit
    close = close_old
    drain = close_if_allowed


class _Registration:
    def __init__(self, target: TLSTarget) -> None:
        self.target = target
        self.current: TLSGeneration | None = None
        self.generations: list[TLSGeneration] = []


class TargetTLSRegistry:
    """Registry of target TLS generations and their transition history."""

    def __init__(
        self,
        configs: Mapping[str, Any] | None = None,
        *,
        default_verify: VerifyT = True,
        tls_ciphers: str | None = None,
        tls_min_version: str | None = None,
        adapter_factory: AdapterFactoryT | None = None,
        ledger: TLSConnectionLedger | None = None,
    ) -> None:
        self.default_verify = default_verify
        self.tls_ciphers = tls_ciphers
        self.tls_min_version = tls_min_version
        self.ledger = ledger or TLSConnectionLedger()
        self.adapter_factory = adapter_factory or self._default_adapter_factory
        self._mount: weakref.WeakMethod[MountT] | None = None
        self._lock = threading.RLock()
        self._rules: OrderedDict[str, _Registration] = OrderedDict()
        self.retired: list[TLSGeneration] = []
        if configs:
            self.configure_many(configs)

    def bind_mounter(self, mounter: MountT) -> None:
        with self._lock:
            self._mount = weakref.WeakMethod(mounter)  # type: ignore[arg-type]
            mount = self._mount()
            if mount is None:
                return
            for registration in self._rules.values():
                generation = registration.current
                if generation and generation.adapter is not None:
                    mount(registration.target.prefix, generation.adapter)

    def _mount_adapter(
        self, prefix: str, adapter: requests.adapters.BaseAdapter
    ) -> None:
        if self._mount is None:
            return
        mount = self._mount()
        if mount is not None:
            mount(prefix, adapter)

    def _default_adapter_factory(
        self, binding: TLSBinding
    ) -> requests.adapters.BaseAdapter:
        return TargetTLSAdapter(
            binding=binding,
            ledger=self.ledger,
            tls_ciphers=self.tls_ciphers,
            tls_min_version=self.tls_min_version,
        )

    def configure_many(self, configs: Mapping[str, Any]) -> None:
        for target, config in dict(configs).items():
            self.configure(target, config)

    def configure(
        self,
        target: str | TLSTarget,
        config: Any = UNSET,
        /,
        **fields: Any,
    ) -> TLSBinding:
        parsed = TLSTarget.parse(target)
        if config is UNSET and not fields:
            tls_config = TLSConfig()
        elif fields:
            if config is not UNSET:
                base = TLSConfig.from_value(config)
            else:
                base = TLSConfig()
            tls_config = dataclasses.replace(base, **fields)
        else:
            tls_config = TLSConfig.from_value(config)

        with self._lock:
            registration = self._rules.get(parsed.prefix)
            if registration is None:
                registration = _Registration(parsed)
                self._rules[parsed.prefix] = registration
                generation_number = 1
            else:
                generation_number = (
                    registration.current.generation + 1
                    if registration.current
                    else len(registration.generations) + 1
                )

            binding = TLSBinding(
                target=parsed,
                config=tls_config,
                generation=generation_number,
                fingerprint=tls_config.fingerprint(),
            )
            adapter = self.adapter_factory(binding)
            generation = TLSGeneration(
                binding, adapter=adapter, ledger=self.ledger
            )
            try:
                adapter.tls_generation = (  # type: ignore[attr-defined]
                    generation
                )
            except Exception:
                # Third-party adapters may use __slots__; registry state still
                # tracks the transition and can be closed through close().
                pass
            registration.current = generation
            registration.generations.append(generation)
            self._rules[parsed.prefix] = registration
            if adapter is not None:
                self._mount_adapter(parsed.prefix, adapter)
            return binding

    # Common verb aliases.
    register = configure
    set = configure
    put = configure
    add = configure

    def rotate(
        self,
        target: str | TLSTarget,
        config: Any = UNSET,
        /,
        *,
        exit_condition: ExitConditionT = None,
        approved: bool = False,
        close_old: bool | None = None,
        **fields: Any,
    ) -> TLSTransition:
        if exit_condition is None:
            for name in (
                'condition',
                'when',
                'exit_when',
                'close_when',
                'predicate',
                'exit_policy',
                'retire_condition',
                'is_safe_to_close',
            ):
                candidate = fields.pop(name, None)
                if candidate is not None:
                    exit_condition = candidate
                    break
        if not approved:
            approval_names = (
                'approve',
                'approved_exit',
                'allow_close',
                'accepted',
            )
            for name in approval_names:
                if fields.pop(name, False):
                    approved = True
        if close_old is None and fields.pop('close', None):
            close_old = True

        parsed = TLSTarget.parse(target)
        with self._lock:
            prefix = parsed.prefix
            existing = self._rules.get(prefix)
            old = existing.current if existing else None

            # Rotation with no explicit material reloads the previous paths so
            # replacing file contents at the same location still yields a new
            # fingerprint/generation.
            if config is UNSET and not fields and old is not None:
                config = old.binding.config
            elif fields and config is UNSET and old is not None:
                config = dataclasses.replace(old.binding.config, **fields)
                fields = {}

            binding = self.configure(target, config, **fields)
            registration = self._rules[prefix]
            new = registration.current
            assert new is not None

            if old is not None:
                old.exit_condition = exit_condition
                old.approved = approved
                self.retired.append(old)

                if close_old is True:
                    old.close()
                elif approved and exit_condition == 'immediate':
                    old.close()
                elif approved:
                    old.close_if_allowed()

            return TLSTransition(parsed, old, new, self)

    rotate_tls = rotate
    rotate_certificate = rotate

    def _registrations_for_url(self, url: str) -> list[_Registration]:
        parsed = TLSTarget.parse(url)
        matches: list[_Registration] = []
        with self._lock:
            for prefix, registration in self._rules.items():
                if prefix == parsed.prefix:
                    matches.append(registration)
                elif prefix.startswith('*.'):
                    # Mounted wildcard support is intentionally conservative:
                    # only one label is accepted for a host wildcard.
                    domain = prefix[2:].rstrip('/')
                    if parsed.host == domain or parsed.host.endswith(
                        '.' + domain
                    ):
                        matches.append(registration)
        return matches

    def binding_for_url(self, url: str) -> TLSBinding | None:
        matches = self._registrations_for_url(url)
        if not matches:
            return None
        current = matches[-1].current
        return current.binding if current else None

    def generation_for_url(self, url: str) -> TLSGeneration | None:
        matches = self._registrations_for_url(url)
        if not matches:
            return None
        return matches[-1].current

    def get(self, target: str | TLSTarget) -> TLSConfig | None:
        parsed = TLSTarget.parse(target)
        with self._lock:
            registration = self._rules.get(parsed.prefix)
            if registration and registration.current:
                return registration.current.binding.config
        return None

    def get_binding(self, target: str | TLSTarget) -> TLSBinding | None:
        parsed = TLSTarget.parse(target)
        with self._lock:
            registration = self._rules.get(parsed.prefix)
            if registration and registration.current:
                return registration.current.binding
        return None

    def check(self, target_or_url: str) -> dict[str, Any]:
        """Return an auditable snapshot of current and retired target TLS."""

        binding = self.binding_for_url(target_or_url)
        parsed = TLSTarget.parse(target_or_url)
        with self._lock:
            registration = self._rules.get(parsed.prefix)
            generations = [
                generation.to_record()
                for generation in registration.generations
            ] if registration else []
            retired = [
                generation.to_record()
                for generation in self.retired
                if generation.target == parsed
            ]
        return {
            'target': parsed.origin,
            'matched': binding is not None,
            'current': binding.to_record() if binding else None,
            'generations': generations,
            'retired': retired,
            'transport_records': [
                record
                for record in self.ledger.transport_records
                if record.get('target') == parsed.origin
            ],
            'reuse_records': [
                record
                for record in self.ledger.reuse_records
                if record.get('target') == parsed.origin
            ],
        }

    check_tls = check
    inspect = check
    inspect_tls = check

    def close_retired(
        self, condition: ExitConditionT = None
    ) -> list[TLSGeneration]:
        closed: list[TLSGeneration] = []
        with self._lock:
            generations = list(self.retired)
        for generation in generations:
            if generation.closed:
                continue
            if condition is not None:
                generation.exit_condition = condition
                generation.approved = True
            if generation.close_if_allowed():
                closed.append(generation)
        return closed

    drain_retired = close_retired
    close_old_generations = close_retired
    reap = close_retired

    def close_all(self) -> None:
        with self._lock:
            generations = [
                generation
                for registration in self._rules.values()
                for generation in registration.generations
            ] + list(self.retired)
        for generation in generations:
            generation.close()


TLSRegistry = TargetTLSRegistry
TargetTLSPolicy = TargetTLSRegistry
TLSPolicy = TargetTLSRegistry


class TargetTLSAdapter(requests.adapters.HTTPAdapter):
    """HTTP adapter that records the effective target TLS transport."""

    def __init__(
        self,
        *args: Any,
        binding: TLSBinding | None = None,
        ledger: TLSConnectionLedger | None = None,
        tls_ciphers: str | None = None,
        tls_min_version: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.tls_binding = binding
        self.tls_generation: TLSGeneration | None = None
        self.tls_ledger = ledger
        self.tls_ciphers = tls_ciphers
        self.tls_min_version = tls_min_version
        self._tracked_pools: set[int] = set()
        self._ssl_contexts: dict[tuple[Any, ...], ssl.SSLContext] = {}
        super().__init__(*args, **kwargs)

    def _context_for_binding(
        self, binding: TLSBinding, verify: VerifyT
    ) -> ssl.SSLContext:
        effective_verify = binding.config.effective_verify(verify)
        key = (
            binding.generation,
            binding.fingerprint,
            repr(effective_verify),
            self.tls_ciphers,
            self.tls_min_version,
        )
        context = self._ssl_contexts.get(key)
        if context is None:
            context = binding.config.create_ssl_context(
                default_verify=verify,
                default_ciphers=self.tls_ciphers,
                default_min_version=self.tls_min_version,
            )
            self._ssl_contexts[key] = context
        return context

    def _effective_binding(self) -> TLSBinding | None:
        return CURRENT_TLS_BINDING.get() or self.tls_binding

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        if 'socket_options' not in kwargs:
            socket_options = [
                (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            ]
            if hasattr(socket, 'TCP_KEEPIDLE'):
                socket_options.append(
                    (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                )
            if (
                hasattr(socket, 'TCP_KEEPCNT')
                and not utils.is_windows_linux_subsystem
            ):
                socket_options.append(
                    (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
                )
            if hasattr(socket, 'TCP_KEEPINTVL'):
                socket_options.append(
                    (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
                )
            kwargs['socket_options'] = socket_options

        binding = self.tls_binding
        if binding is not None and 'ssl_context' not in kwargs:
            try:
                kwargs['ssl_context'] = self._context_for_binding(
                    binding, True
                )
            except Exception:
                # Requests can still build its usual context from cert/verify.
                pass
        elif (self.tls_ciphers or self.tls_min_version) and (
            'ssl_context' not in kwargs
        ):
            context = ssl.create_default_context()
            if self.tls_min_version:
                if self.tls_min_version not in _TLS_VERSION_MAP:
                    raise ValueError(
                        'Unknown TLS version: {}. Supported values are '
                        '{}'.format(
                            self.tls_min_version,
                            ', '.join(sorted(_TLS_VERSION_MAP)),
                        )
                    )
                context.minimum_version = _TLS_VERSION_MAP[
                    self.tls_min_version
                ]
            if self.tls_ciphers:
                context.set_ciphers(self.tls_ciphers)
            kwargs['ssl_context'] = context
        super().init_poolmanager(*args, **kwargs)

    def build_connection_pool_key_attributes(
        self,
        request: requests.PreparedRequest,
        verify: VerifyT,
        cert: CertT = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        host_params, pool_kwargs = (
            super().build_connection_pool_key_attributes(request, verify, cert)
        )
        binding = self._effective_binding()
        if binding is not None:
            context = None
            try:
                context = self._context_for_binding(binding, verify)
            except Exception:
                # Let requests perform its normal validation later.
                context = None
            if context is not None:
                pool_kwargs['ssl_context'] = context
                for key in (
                    'cert_file',
                    'key_file',
                    'key_password',
                    'ca_certs',
                    'ca_cert_dir',
                    'ca_cert_data',
                    'cert_reqs',
                ):
                    pool_kwargs.pop(key, None)
        return host_params, pool_kwargs

    def send(  # type: ignore[override]
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: VerifyT = True,
        cert: CertT = None,
        proxies: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        binding = self._effective_binding()
        generation = self.tls_generation
        if (
            generation is not None
            and binding is not None
            and generation.generation != binding.generation
        ):
            # The request pinned an older binding even though Requests selected
            # a newer prefix adapter during a rotation race.
            generation = None
        if self.tls_ledger is not None:
            target = TLSTarget.parse(request.url or '')
            record_binding = binding.to_record() if binding else None
            self.tls_ledger.record(
                'transport',
                url=request.url,
                method=request.method,
                target=target.origin,
                verify=verify,
                cert=cert,
                binding=record_binding,
                adapter_generation=(
                    self.tls_binding.generation if self.tls_binding else None
                ),
            )

        if generation is not None:
            generation.begin_send()
        if binding is not None and self.tls_ledger is not None:
            # The registry generation object is looked up by fingerprint via
            # the session-owned registry only when this adapter belongs to one.
            ledger = self.tls_ledger
            original_get_connection = self.get_connection_with_tls_context

            def tracked_get_connection(
                prepared: requests.PreparedRequest,
                verify_value: VerifyT,
                proxies_value: dict[str, str] | None = None,
                cert_value: CertT = None,
            ) -> Any:
                pool = original_get_connection(
                    prepared, verify_value, proxies_value, cert_value
                )
                self._track_pool(pool, binding, ledger)
                return pool

            self.get_connection_with_tls_context = (
                tracked_get_connection  # type: ignore[method-assign]
            )

        try:
            return super().send(
                request,
                stream=stream,
                timeout=timeout,
                verify=verify,
                cert=cert,
                proxies=proxies,
                **kwargs,
            )
        finally:
            if generation is not None:
                generation.end_send()
                generation.close_if_allowed()
            if binding is not None and self.tls_ledger is not None:
                # Restore is not strictly needed because the wrapper is bound
                # to this send call, but avoids nesting on retries.
                try:
                    del self.get_connection_with_tls_context
                except AttributeError:
                    pass

    def _track_pool(
        self, pool: Any, binding: TLSBinding, ledger: TLSConnectionLedger
    ) -> None:
        pool_id = id(pool)
        if pool_id in self._tracked_pools:
            return
        self._tracked_pools.add(pool_id)

        original_get = pool._get_conn
        original_put = pool._put_conn

        def tracked_get_conn(*args: Any, **kwargs: Any) -> Any:
            idle_before = 0
            try:
                idle_before = pool.pool.qsize() if pool.pool is not None else 0
            except Exception:
                pass
            connection = original_get(*args, **kwargs)
            reused = False
            local_port = None
            sock = getattr(connection, 'sock', None)
            if sock is not None:
                reused = idle_before > 0
                local_port = getattr(sock, 'getsockname', lambda: None)()
            ledger.record(
                'checkout',
                target=binding.target.origin,
                generation=binding.generation,
                pool_id=pool_id,
                connection_id=id(connection),
                reused=reused,
                idle_before=idle_before,
                local_port=local_port[1] if local_port else None,
            )
            return connection

        def tracked_put_conn(connection: Any) -> None:
            ledger.record(
                'checkin',
                target=binding.target.origin,
                generation=binding.generation,
                pool_id=pool_id,
                connection_id=id(connection),
            )
            return original_put(connection)

        pool._get_conn = tracked_get_conn
        pool._put_conn = tracked_put_conn
