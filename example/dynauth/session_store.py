"""In-memory session table for the Dynamic Authorization policy adapter."""

from copy import deepcopy
from dataclasses import dataclass, field

from .constants import (
    ACCT_SESSION_ID,
    CALLED_STATION_ID,
    CALLING_STATION_ID,
    FRAMED_IP_ADDRESS,
    USER_NAME,
)


@dataclass
class Session:
    """One authorization session registered on a NAS.

    ``attributes`` holds the authorization attributes currently applied to
    the session (Filter-Id, Session-Timeout, ...). ``active`` is cleared by a
    successful Disconnect; a Disconnect against an inactive session is a
    protocol error, not a success.
    """

    session_id: str
    nas_ip: str
    user_name: str
    framed_ip: str
    calling_station: str
    called_station: str
    nas_identifier: str
    attributes: dict = field(default_factory=dict)
    active: bool = True

    def snapshot(self):
        """Return a deep, standalone copy for audit before/after states."""
        return {
            "session_id": self.session_id,
            "nas_ip": self.nas_ip,
            "user_name": self.user_name,
            "framed_ip": self.framed_ip,
            "calling_station": self.calling_station,
            "called_station": self.called_station,
            "nas_identifier": self.nas_identifier,
            "active": self.active,
            "attributes": deepcopy(self.attributes),
        }


class SessionStore:
    """In-memory table of sessions, keyed by (NAS-IP, Acct-Session-Id)."""

    def __init__(self, sessions=None):
        self._sessions = {}
        for session in sessions or ():
            self.add(session)

    def add(self, session):
        self._sessions[(session.nas_ip, session.session_id)] = session

    def get(self, nas_ip, session_id):
        return self._sessions.get((nas_ip, session_id))

    def all(self):
        return list(self._sessions.values())

    def locate(self, nas_ip, criteria):
        """Return the unique active session matching ``criteria`` on a NAS.

        ``criteria`` maps a :mod:`dynauth.constants` locator code to the
        value the request supplied. Only active sessions are considered.

        :returns: ``(session, matches)``; ``session`` is the match when
                  ``matches`` has exactly one element, otherwise ``None``.
        """
        matches = []
        for session in self._sessions.values():
            if not session.active or session.nas_ip != nas_ip:
                continue
            if self._matches(session, criteria):
                matches.append(session)
        if len(matches) == 1:
            return matches[0], matches
        return None, matches

    @staticmethod
    def _matches(session, criteria):
        if ACCT_SESSION_ID in criteria and \
                session.session_id != criteria[ACCT_SESSION_ID]:
            return False
        if FRAMED_IP_ADDRESS in criteria and \
                session.framed_ip != criteria[FRAMED_IP_ADDRESS]:
            return False
        if CALLING_STATION_ID in criteria and \
                session.calling_station != criteria[CALLING_STATION_ID]:
            return False
        if CALLED_STATION_ID in criteria and \
                session.called_station != criteria[CALLED_STATION_ID]:
            return False
        if USER_NAME in criteria and \
                session.user_name != criteria[USER_NAME]:
            return False
        return True
