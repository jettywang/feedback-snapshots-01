"""Demo fixtures: an in-memory session table and sender authorization.

Two NASes are simulated. Each authenticated sender is bound to the NASes and
operations (CoA / Disconnect) it may control, independently of the shared
secret which only proves the packet origin.
"""

import os

from .constants import COA_REQUEST, DISCONNECT_REQUEST
from .session_store import Session
from .transport import AuthenticatedSender
from .policy import SenderPolicy

DICTIONARY_PATH = os.path.join(os.path.dirname(__file__), "dictionary")

NAS_1 = "10.0.1.1"
NAS_2 = "10.0.2.1"

# Loopback source addresses stand in for distinct management senders.
SENDER_OPS = "127.0.1.10"        # full control of NAS-1
SENDER_SUPPORT = "127.0.1.11"    # CoA only, on both NASes
SENDER_GUEST = "127.0.1.12"      # known secret, but no policy
SENDER_UNKNOWN = "127.0.1.13"    # no client entry at all

SECRET_OPS = b"ops-coa-secret"
SECRET_SUPPORT = b"support-coa-secret"
SECRET_GUEST = b"guest-coa-secret"


def build_sessions():
    """Return sessions covering unique, duplicated and cross-NAS cases."""
    return [
        Session(
            session_id="sess-1001", nas_ip=NAS_1, user_name="alice",
            framed_ip="192.0.2.11", calling_station="AA-BB-00-00-00-11",
            called_station="SSID-CORP", nas_identifier="nas-1",
            attributes={"Filter-Id": "default", "Session-Timeout": 3600}),
        Session(
            session_id="sess-1002", nas_ip=NAS_1, user_name="bob",
            framed_ip="192.0.2.12", calling_station="AA-BB-00-00-00-12",
            called_station="SSID-CORP", nas_identifier="nas-1",
            attributes={"Filter-Id": "default", "Session-Timeout": 3600}),
        # Two sessions share a Calling-Station-Id: a locator using only that
        # attribute is ambiguous and must be refused.
        Session(
            session_id="sess-1003", nas_ip=NAS_1, user_name="carol",
            framed_ip="192.0.2.13", calling_station="AA-BB-SHARED-0001",
            called_station="SSID-GUEST", nas_identifier="nas-1",
            attributes={"Filter-Id": "guest", "Session-Timeout": 1800}),
        Session(
            session_id="sess-1004", nas_ip=NAS_1, user_name="carol",
            framed_ip="192.0.2.14", calling_station="AA-BB-SHARED-0001",
            called_station="SSID-GUEST", nas_identifier="nas-1",
            attributes={"Filter-Id": "guest", "Session-Timeout": 1800}),
        # Alice also has a session on NAS-2: User-Name alone cannot pick one,
        # and the ops sender is not authorized for NAS-2 at all.
        Session(
            session_id="sess-2001", nas_ip=NAS_2, user_name="alice",
            framed_ip="198.51.100.21", calling_station="AA-BB-00-00-00-21",
            called_station="SSID-CORP", nas_identifier="nas-2",
            attributes={"Filter-Id": "default", "Session-Timeout": 7200}),
    ]


def build_sender_policies():
    return {
        "ops": SenderPolicy(
            sender_id="ops", name="Network Operations",
            allowed_nas={
                NAS_1: (COA_REQUEST, DISCONNECT_REQUEST),
            }),
        "support": SenderPolicy(
            sender_id="support", name="Support Desk (CoA only)",
            allowed_nas={
                NAS_1: (COA_REQUEST,),
                NAS_2: (COA_REQUEST,),
            }),
    }


def build_senders():
    # The guest has a valid shared secret and is a known transport client,
    # but has no entry in build_sender_policies(): authentication succeeds,
    # authorization fails with a NAK. The unknown address is not registered
    # here at all and is silently dropped by the transport.
    return [
        AuthenticatedSender(SENDER_OPS, SECRET_OPS, "ops", "Network Ops"),
        AuthenticatedSender(SENDER_SUPPORT, SECRET_SUPPORT, "support",
                            "Support Desk"),
        AuthenticatedSender(SENDER_GUEST, SECRET_GUEST, "guest",
                            "Authenticated but unauthorized"),
    ]
