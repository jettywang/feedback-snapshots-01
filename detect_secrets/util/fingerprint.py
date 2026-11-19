"""
Outbound fingerprints for multi-tenant secret aggregation.

Different companies may scan their codebases with ``detect-secrets`` and ship the
results to the same aggregation system. The aggregation system wants to notice when
the *same* secret shows up more than once, but only within the boundaries that each
company has approved -- never across unrelated tenants, and never with enough
information to recover the original secret.

This module provides a second, deliberately distinct identifier on top of the
local ``hashed_secret`` (which remains an unsalted SHA-1, so that existing
baselines and the local audit workflow keep working unchanged):

* ``hashed_secret`` stays the local identity: same value on every scan, used by
  ``audit`` / baseline merge / trim.
* ``outbound_fingerprint`` is what leaves the company: an HMAC-SHA256 keyed by a
  per-company secret, domain-separated by an approved ``scope``.

Because the fingerprint is computed from ``hashed_secret`` (rather than from the
plaintext), it can be (re)generated from an old baseline that no longer contains
the secret values themselves.

Key rotation is supported through versioned keys. A config may declare several
keys; the highest version produces new fingerprints while older keys are retained
so that fingerprints produced during a rotation can still be verified. Two
companies only ever produce the same fingerprint for the same secret when they
share both a key and a scope.
"""
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from ..exceptions import InvalidFile

# Domain separator, so material signed for outbound aggregation can never be
# confused with any other HMAC usage of the same key.
_DOMAIN = 'detect-secrets.outbound-fingerprint'
_VERSION = 1


class FingerprintConfigError(InvalidFile):
    """Raised when an outbound fingerprint config cannot be used."""


@dataclass(frozen=True)
class Fingerprint:
    """The outbound representation of a single discovered secret."""

    fingerprint: str
    key_version: int
    scope: str

    def json(self) -> Dict[str, str]:
        return {
            'outbound_fingerprint': self.fingerprint,
            'fingerprint_key_version': str(self.key_version),
            'fingerprint_scope': self.scope,
        }


@dataclass(frozen=True)
class _Key:
    version: int
    value: str


class FingerprintConfig:
    """
    Parsed view of an outbound fingerprint config file.

    Config schema (JSON)::

        {
            "scopes": ["company-alpha"],
            "keys": [
                {"version": 1, "value": "base64-or-utf8-secret"},
                {"version": 2, "value": "rotated-secret"}
            ]
        }

    The highest key version is the *active* key used to mint new fingerprints.
    Every listed key is accepted when verifying existing fingerprints, which is
    what makes rolling the config forward safe during a rotation window.
    """

    def __init__(self, scopes: List[str], keys: List[_Key]) -> None:
        if not scopes:
            raise FingerprintConfigError('At least one scope must be configured.')
        if not keys:
            raise FingerprintConfigError('At least one key must be configured.')

        versions = [key.version for key in keys]
        if len(set(versions)) != len(versions):
            raise FingerprintConfigError('Duplicate key versions in fingerprint config.')
        if any(version < 1 for version in versions):
            raise FingerprintConfigError('Key versions must be positive integers.')
        if any(not key.value for key in keys):
            raise FingerprintConfigError('Fingerprint keys must be non-empty strings.')

        self.scopes = scopes
        self._keys = sorted(keys, key=lambda key: key.version)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FingerprintConfig':
        try:
            scopes = [str(scope) for scope in data['scopes']]
            raw_keys = data['keys']
        except (KeyError, TypeError) as e:
            raise FingerprintConfigError(
                'Config must contain "scopes" and "keys" entries.',
            ) from e

        if not isinstance(raw_keys, list):
            raise FingerprintConfigError('"keys" must be a list.')

        keys: List[_Key] = []
        for entry in raw_keys:
            try:
                keys.append(
                    _Key(version=int(entry['version']), value=str(entry['value'])),
                )
            except (KeyError, TypeError, ValueError) as e:
                raise FingerprintConfigError(
                    'Each key must have integer "version" and string "value".',
                ) from e

        return cls(scopes=scopes, keys=keys)

    @classmethod
    def from_file(cls, filename: str) -> 'FingerprintConfig':
        try:
            with open(filename) as f:
                data = json.loads(f.read())
        except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
            raise FingerprintConfigError(f'Unable to read fingerprint config: {filename}') from e

        if not isinstance(data, dict):
            raise FingerprintConfigError('Fingerprint config must be a JSON object.')

        return cls.from_dict(data)

    @property
    def active_key(self) -> _Key:
        return self._keys[-1]

    @property
    def active_version(self) -> int:
        return self.active_key.version

    def key_for(self, version: int) -> Optional[_Key]:
        for key in self._keys:
            if key.version == version:
                return key
        return None

    def _resolve_scope(self, scope: Optional[str]) -> str:
        if scope is not None:
            if scope not in self.scopes:
                raise FingerprintConfigError(
                    f'Scope "{scope}" is not approved. Allowed: {", ".join(self.scopes)}'
                )
            return scope

        if len(self.scopes) != 1:
            raise FingerprintConfigError(
                'Multiple scopes are configured; an explicit scope is required.',
            )
        return self.scopes[0]

    def create_fingerprint(
        self,
        hashed_secret: str,
        scope: Optional[str] = None,
        key_version: Optional[int] = None,
    ) -> Fingerprint:
        """Mint a new outbound fingerprint for a locally-hashed secret."""
        resolved_scope = self._resolve_scope(scope)
        key = self.active_key if key_version is None else self.key_for(key_version)
        if key is None:
            raise FingerprintConfigError(f'Unknown key version: {key_version}')

        return Fingerprint(
            fingerprint=_compute(hashed_secret, resolved_scope, key),
            key_version=key.version,
            scope=resolved_scope,
        )

    def verify_fingerprint(self, hashed_secret: str, candidate: Fingerprint) -> bool:
        """
        Constant-time check that ``candidate`` matches one of the configured keys.

        Returns ``False`` (rather than raising) when the candidate's key version or
        scope is no longer present in the config, so callers can simply report the
        match result.
        """
        key = self.key_for(candidate.key_version)
        if key is None or candidate.scope not in self.scopes:
            return False

        expected = _compute(hashed_secret, candidate.scope, key)
        return hmac.compare_digest(expected, candidate.fingerprint)


def _compute(hashed_secret: str, scope: str, key: _Key) -> str:
    message = json.dumps(
        {
            'domain': _DOMAIN,
            'version': _VERSION,
            'scope': scope,
            'hashed_secret': hashed_secret,
        },
        sort_keys=True,
        separators=(',', ':'),
    ).encode('utf-8')

    return hmac.new(
        key=key.value.encode('utf-8'),
        msg=message,
        digestmod=hashlib.sha256,
    ).hexdigest()


def annotate_baseline(
    baseline: Dict[str, Any],
    config: FingerprintConfig,
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return a copy of ``baseline`` with an outbound fingerprint attached to every
    discovered secret. The baseline itself is never mutated, and its local
    ``hashed_secret`` values are left untouched.
    """
    output = {key: value for key, value in baseline.items() if key != 'results'}
    output['results'] = {}

    for filename, secrets in baseline.get('results', {}).items():
        output['results'][filename] = []
        for secret in secrets:
            annotated = dict(secret)
            fingerprint = config.create_fingerprint(
                hashed_secret=str(annotated['hashed_secret']),
                scope=scope,
            )
            annotated.update(fingerprint.json())
            output['results'][filename].append(annotated)

    return output


def verify_baseline(
    baseline: Dict[str, Any],
    config: FingerprintConfig,
) -> Tuple[int, int, List[Dict[str, str]]]:
    """
    Check every outbound fingerprint already present in a baseline.

    :returns: (number matched, number checked, descriptions of failures)
    """
    matched = 0
    total = 0
    failures: List[Dict[str, str]] = []

    for filename, secrets in baseline.get('results', {}).items():
        for secret in secrets:
            if 'outbound_fingerprint' not in secret:
                continue

            total += 1
            candidate = Fingerprint(
                fingerprint=str(secret['outbound_fingerprint']),
                key_version=int(secret['fingerprint_key_version']),
                scope=str(secret['fingerprint_scope']),
            )

            if config.verify_fingerprint(str(secret['hashed_secret']), candidate):
                matched += 1
            else:
                failures.append(
                    {
                        'filename': filename,
                        'hashed_secret': str(secret['hashed_secret']),
                        'key_version': str(candidate.key_version),
                        'scope': candidate.scope,
                    },
                )

    return matched, total, failures
