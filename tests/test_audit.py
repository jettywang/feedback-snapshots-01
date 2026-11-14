"""
Tests for the structured security-audit hook (paramiko.audit).

Each test runs a real handshake (and rekey) against a local in-process
peer over LoopSocket pairs, records the emitted AuditEvents, and checks
them against the transport's actual negotiated state.
"""

import threading
import time
import unittest
from base64 import b64encode
from hashlib import sha256

from pytest import raises

from paramiko import (
    AUDIT_HANDSHAKE_COMPLETE,
    AUDIT_HANDSHAKE_FAILED,
    AUDIT_HOST_KEY,
    AUDIT_KEX_AGREEMENT,
    AUDIT_KEX_PROPOSALS,
    AUDIT_KEYS_ACTIVATED,
    RSAKey,
    SSHException,
    Transport,
)
from paramiko.auth_handler import AuthHandler

from ._loop import LoopSocket
from ._util import TestServer as NullServer, _support


class AuditRecorder:
    """Thread-safe event sink usable as a Transport audit hook."""

    def __init__(self):
        self._lock = threading.Lock()
        self.events = []

    def __call__(self, event):
        with self._lock:
            self.events.append(event)

    def of_type(self, event_type):
        with self._lock:
            return [e for e in self.events if e.type == event_type]

    def types(self):
        with self._lock:
            return [e.type for e in self.events]

    def wait_for(self, event_type, count=1, timeout=5.0, phase=None):
        deadline = time.time() + timeout
        while time.time() < deadline:
            matches = self.of_type(event_type)
            if phase is not None:
                matches = [e for e in matches if e.phase == phase]
            if len(matches) >= count:
                return matches
            time.sleep(0.05)
        raise AssertionError(
            "timed out waiting for {} x{} (phase={}); got {}".format(
                event_type, count, phase, self.types()
            )
        )


def assert_no_secret_material(recorder):
    """Events must only carry names, flags, fingerprints and the session
    id -- never byte strings (key material, shared secrets, session keys).
    """
    for event in recorder.events:
        for key, value in event.details.items():
            assert not isinstance(value, (bytes, bytearray)), (
                "event {} field {} leaks raw bytes".format(event.type, key)
            )
            if isinstance(value, list):
                for item in value:
                    assert isinstance(item, str)
            elif isinstance(value, dict):
                for sub in value.values():
                    assert isinstance(sub, list)
                    for item in sub:
                        assert isinstance(item, str)
            else:
                assert isinstance(value, (str, bool, int, type(None))), (
                    "event {} field {} has unexpected type".format(
                        event.type, key
                    )
                )


class AuditHookTest(unittest.TestCase):
    _auth_handler_class = AuthHandler

    def setUp(self):
        self.socks = LoopSocket()
        self.sockc = LoopSocket()
        self.sockc.link(self.socks)
        self.tc = Transport(self.sockc)
        self.ts = Transport(self.socks)
        self.client_audit = AuditRecorder()
        self.server_audit = AuditRecorder()
        self.tc.set_audit_hook(self.client_audit)
        self.ts.set_audit_hook(self.server_audit)
        self.host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        self.public_host_key = RSAKey(data=self.host_key.asbytes())
        self.ts.add_server_key(self.host_key)

    def tearDown(self):
        self.tc.close()
        self.ts.close()
        self.socks.close()
        self.sockc.close()

    def start(self, client_options=None, server_options=None):
        if client_options is not None:
            client_options(self.tc.get_security_options())
        if server_options is not None:
            server_options(self.ts.get_security_options())
        event = threading.Event()
        self.server = NullServer()
        self.ts.start_server(event, self.server)
        self.tc.connect(
            hostkey=self.public_host_key,
            username="slowdive",
            password="pygmalion",
        )
        event.wait(1.0)
        self.assertTrue(event.is_set())
        self.assertTrue(self.ts.is_active())

    def expected_fingerprint(self):
        digest = sha256(self.public_host_key.asbytes()).digest()
        return "SHA256:" + b64encode(digest).decode("ascii").rstrip("=")

    def test_successful_handshake_events(self):
        self.start()
        types = self.client_audit.types()
        # full pipeline, in wire order
        self.assertEqual(
            types,
            [
                AUDIT_KEX_PROPOSALS,
                AUDIT_KEX_AGREEMENT,
                AUDIT_HOST_KEY,
                AUDIT_KEYS_ACTIVATED,
                AUDIT_KEYS_ACTIVATED,
                AUDIT_HANDSHAKE_COMPLETE,
            ],
        )
        for event in self.client_audit.events:
            self.assertEqual(event.phase, "initial")

        # candidates actually offered by both sides
        proposals = self.client_audit.of_type(AUDIT_KEX_PROPOSALS)[0]
        self.assertIn(
            "curve25519-sha256@libssh.org",
            proposals.details["local"]["kex_algo_list"],
        )
        self.assertEqual(
            proposals.details["remote"]["kex_algo_list"][0],
            self.ts.preferred_kex[0],
        )

        # final agreement matches the transport's real negotiated state
        agreement = self.client_audit.of_type(AUDIT_KEX_AGREEMENT)[0]
        self.assertEqual(
            agreement.details["cipher_outbound"], self.tc.local_cipher
        )
        self.assertEqual(
            agreement.details["cipher_inbound"], self.tc.remote_cipher
        )
        self.assertEqual(agreement.details["mac_outbound"], self.tc.local_mac)
        self.assertEqual(agreement.details["mac_inbound"], self.tc.remote_mac)
        self.assertEqual(
            agreement.details["host_key_type"], self.tc.host_key_type
        )

        # host identity: fingerprint of the server's public key, verified
        host_key_events = self.client_audit.of_type(AUDIT_HOST_KEY)
        self.assertEqual(len(host_key_events), 1)
        self.assertEqual(
            host_key_events[0].details["fingerprint"],
            self.expected_fingerprint(),
        )
        self.assertIs(host_key_events[0].details["verified"], True)

        # per-direction activation matches the agreement, outbound first
        activations = self.client_audit.of_type(AUDIT_KEYS_ACTIVATED)
        self.assertEqual(
            [a.details["direction"] for a in activations],
            ["outbound", "inbound"],
        )
        self.assertEqual(
            activations[0].details["cipher"],
            agreement.details["cipher_outbound"],
        )
        self.assertEqual(
            activations[1].details["cipher"],
            agreement.details["cipher_inbound"],
        )

        # completion carries the first-exchange session identifier
        complete = self.client_audit.of_type(AUDIT_HANDSHAKE_COMPLETE)[0]
        self.assertEqual(
            complete.details["session_id"], self.tc.session_id.hex()
        )
        self.assertEqual(self.tc.H, self.tc.session_id)

        # server side agrees on the same session and algorithms
        server_complete = self.server_audit.wait_for(
            AUDIT_HANDSHAKE_COMPLETE
        )[0]
        self.assertEqual(
            server_complete.details["session_id"], self.ts.session_id.hex()
        )
        self.assertEqual(self.ts.session_id, self.tc.session_id)
        server_agreement = self.server_audit.of_type(AUDIT_KEX_AGREEMENT)[0]
        self.assertEqual(
            server_agreement.details["cipher_outbound"],
            agreement.details["cipher_inbound"],
        )

        # an application message now travels under the recorded state:
        # build the audit explanation for one concrete channel write.
        chan = self.tc.open_session()
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)
        self.assertIsNotNone(schan)
        crypto_state = {
            "cipher": agreement.details["cipher_outbound"],
            "mac": agreement.details["mac_outbound"],
            "host_key": host_key_events[0].details["fingerprint"],
            "host_key_verified": host_key_events[0].details["verified"],
            "session_id": complete.details["session_id"],
        }
        chan.send(b"audit-me")
        data = schan.recv(8)
        self.assertEqual(data, b"audit-me")
        report = (
            "message sent under {cipher} with {mac}, host {host_key} "
            "(verified={host_key_verified}), session {session_id}".format(
                **crypto_state
            )
        )
        self.assertIn(self.tc.local_cipher, report)
        self.assertIn("verified=True", report)
        chan.close()
        schan.close()
        assert_no_secret_material(self.client_audit)
        assert_no_secret_material(self.server_audit)

    def test_incompatible_algorithms_produce_failure_not_success(self):
        def client_only_aes128cbc(options):
            options.ciphers = ("aes128-cbc",)

        def server_only_aes256cbc(options):
            options.ciphers = ("aes256-cbc",)

        event = threading.Event()
        self.server = NullServer()
        client_options = client_only_aes128cbc
        server_options = server_only_aes256cbc
        client_options(self.tc.get_security_options())
        server_options(self.ts.get_security_options())
        self.ts.start_server(event, self.server)
        with raises(SSHException):
            self.tc.connect(
                hostkey=self.public_host_key,
                username="slowdive",
                password="pygmalion",
            )

        types = self.client_audit.types()
        # candidates were exchanged, then negotiation died: no agreement,
        # no key activation, and crucially no completion event.
        self.assertIn(AUDIT_KEX_PROPOSALS, types)
        self.assertNotIn(AUDIT_KEX_AGREEMENT, types)
        self.assertNotIn(AUDIT_KEYS_ACTIVATED, types)
        self.assertNotIn(AUDIT_HANDSHAKE_COMPLETE, types)
        failures = self.client_audit.of_type(AUDIT_HANDSHAKE_FAILED)
        self.assertEqual(len(failures), 1)
        failure = failures[0]
        self.assertEqual(failure.phase, "initial")
        self.assertEqual(
            failure.details["last_confirmed_stage"], "kexinit-received"
        )
        self.assertIn("IncompatiblePeer", failure.details["error"])
        # the failure is the final word on this connection
        self.assertEqual(types[-1], AUDIT_HANDSHAKE_FAILED)
        assert_no_secret_material(self.client_audit)

    def test_rekey_events_keep_original_session_id(self):
        self.start()
        initial_session_id = self.tc.session_id.hex()
        self.tc.packetizer.REKEY_BYTES = 16384
        chan = self.tc.open_session()
        chan.exec_command("yes")
        schan = self.ts.accept(1.0)
        self.assertIsNotNone(schan)

        for _ in range(20):
            chan.send(b"x" * 1024)

        # wait for the rekey to actually complete on the client
        rekey_complete = self.client_audit.wait_for(
            AUDIT_HANDSHAKE_COMPLETE, count=1, phase="rekey"
        )[-1]

        # first session identifier is reused verbatim; the new exchange
        # hash never replaces it in the audit trail
        self.assertEqual(
            rekey_complete.details["session_id"], initial_session_id
        )
        self.assertEqual(self.tc.session_id.hex(), initial_session_id)
        self.assertNotEqual(self.tc.H, self.tc.session_id)

        # a full second pipeline ran, tagged as rekey
        rekey_events = [
            e for e in self.client_audit.events if e.phase == "rekey"
        ]
        self.assertEqual(
            [e.type for e in rekey_events],
            [
                AUDIT_KEX_PROPOSALS,
                AUDIT_KEX_AGREEMENT,
                AUDIT_HOST_KEY,
                AUDIT_KEYS_ACTIVATED,
                AUDIT_KEYS_ACTIVATED,
                AUDIT_HANDSHAKE_COMPLETE,
            ],
        )
        for event in self.client_audit.events:
            session_id = event.details.get("session_id")
            if session_id is not None:
                self.assertEqual(session_id, initial_session_id)

        # traffic after the rekey flows under the re-audited agreement
        rekey_agreement = [
            e
            for e in rekey_events
            if e.type == AUDIT_KEX_AGREEMENT
        ][0]
        self.assertEqual(
            rekey_agreement.details["cipher_outbound"], self.tc.local_cipher
        )
        chan.send(b"post-rekey")
        received = b""
        while not received.endswith(b"post-rekey"):
            chunk = schan.recv(1024)
            if not chunk:
                break
            received += chunk
        self.assertTrue(received.endswith(b"post-rekey"))
        chan.close()
        schan.close()
        assert_no_secret_material(self.client_audit)
        assert_no_secret_material(self.server_audit)

    def test_raising_hook_cannot_break_transport(self):
        def bad_hook(event):
            raise RuntimeError("auditor exploded")

        self.tc.set_audit_hook(bad_hook)
        self.start()
        self.assertTrue(self.tc.is_active())
        self.assertTrue(self.tc.initial_kex_done)


if __name__ == "__main__":
    unittest.main()
