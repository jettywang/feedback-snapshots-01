"""Restricted connection diagnostics.

This module implements a sanitized view of connection failures and
failover routing.  Broker URLs in production often embed project names,
credentials and other access parameters, so alert output must never be
built from them.  Instead the integrator explicitly chooses a safe alias
for the connection, and every diagnostic event records only that alias
plus progress information (attempt index, event kind, failure category).
"""

from __future__ import annotations

__all__ = (
    'CANDIDATE_CONNECTED', 'CANDIDATE_REJECTED', 'FAILOVER_SWITCH',
    'DiagnosticEvent', 'RestrictedDiagnostics',
)

#: Event kinds emitted by :class:`RestrictedDiagnostics`.
CANDIDATE_REJECTED = 'candidate_rejected'
FAILOVER_SWITCH = 'failover_switch'
CANDIDATE_CONNECTED = 'candidate_connected'

#: Transport failure categories reported to the business side.
CATEGORY_CONNECTION = 'connection'
CATEGORY_CHANNEL = 'channel'
CATEGORY_OPERATIONAL = 'operational'
CATEGORY_UNKNOWN = 'unknown'


class DiagnosticEvent:
    """One sanitized step in a connection attempt sequence.

    Only ever carries the operator-chosen safe alias and progress
    metadata; never hostnames, credentials or virtual hosts.
    """

    __slots__ = ('alias', 'event', 'attempt', 'category')

    def __init__(self, alias, event, attempt, category=None):
        self.alias = alias
        self.event = event
        self.attempt = attempt
        self.category = category

    def as_dict(self):
        """Return the alert-safe representation of this event."""
        return {
            'alias': self.alias,
            'event': self.event,
            'attempt': self.attempt,
            'category': self.category,
        }

    def __repr__(self):
        return (
            f'<DiagnosticEvent: {self.alias} {self.event} '
            f'attempt={self.attempt} category={self.category}>'
        )

    def __eq__(self, other):
        if isinstance(other, DiagnosticEvent):
            return self.as_dict() == other.as_dict()
        return NotImplemented


class RestrictedDiagnostics:
    """Records sanitized failure/failover events for one connection.

    The *alias* is the only identifier that may appear in alerts, and it
    must be explicitly chosen by the integrator; it is never derived
    from the broker URL.
    """

    def __init__(self, alias):
        if not isinstance(alias, str) or not alias:
            raise ValueError(
                'safe alias must be a non-empty string chosen by the '
                'integrator')
        self.alias = alias
        self.events = []
        #: 1-based index of the candidate currently being attempted.
        self.attempt = 1
        self.last_failure_category = None

    def candidate_rejected(self, category=CATEGORY_UNKNOWN):
        """Record that the current candidate refused the connection."""
        self.last_failure_category = category
        self.events.append(DiagnosticEvent(
            self.alias, CANDIDATE_REJECTED, self.attempt, category))

    def failover_switch(self):
        """Record that routing moved to the next failover candidate."""
        self.events.append(DiagnosticEvent(
            self.alias, FAILOVER_SWITCH, self.attempt))
        self.attempt += 1

    def candidate_connected(self):
        """Record that the current candidate accepted the connection."""
        self.events.append(DiagnosticEvent(
            self.alias, CANDIDATE_CONNECTED, self.attempt))

    def public_report(self):
        """Return alert-safe dicts for every recorded event.

        The report contains only the safe alias, event kind, attempt
        index and failure category -- no private markers.
        """
        return [event.as_dict() for event in self.events]
