"""Shared value objects for the MFA discharge example."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Tuple, Union


def new_token(prefix: str) -> str:
    """Return an unguessable URL-safe token with a readable prefix."""
    return '{}_{}'.format(prefix, secrets.token_urlsafe(24))


class Denied(Exception):
    """A policy refusal with a stable reason code for demos and tests."""

    def __init__(self, reason: str, detail: str = '') -> None:
        self.reason = reason
        self.detail = detail
        message = reason if not detail else '{}: {}'.format(reason, detail)
        super().__init__(message)


DetailValue = Union[str, int]


@dataclass(frozen=True)
class Operation:
    """The exact operation for which a second factor is requested."""

    action: str
    resource: str
    details: Tuple[Tuple[str, DetailValue], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, 'details', tuple(sorted(self.details)))

    def canonical_payload(self) -> dict:
        return {
            'action': self.action,
            'resource': self.resource,
            'details': [
                {'name': name, 'value': value}
                for name, value in self.details
            ],
        }

    def digest(self) -> str:
        """Hash every operation field; services compare only this digest."""
        canonical = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False,
        )
        return 'sha256:{}'.format(
            hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        )

    def describe(self) -> str:
        details = ', '.join(
            '{}={}'.format(name, value) for name, value in self.details
        )
        suffix = ' ({})'.format(details) if details else ''
        return '{}:{}{}'.format(self.action, self.resource, suffix)
