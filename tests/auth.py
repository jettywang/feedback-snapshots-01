"""
Tests focusing primarily on the authentication step.

Thus, they concern AuthHandler and AuthStrategy, with a side of Transport.
"""

from logging import Logger
from unittest.mock import Mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pytest import raises

from paramiko import (
    AgentKey,
    AuthenticationException,
    AuthFailure,
    AuthResult,
    AuthSource,
    AuthStrategy,
    BadAuthenticationType,
    Ed25519Key,
    InMemoryPrivateKey,
    Message,
    NoneAuth,
    OnDiskPrivateKey,
    Password,
    PKey,
    PrivateKey,
    RSAKey,
    SourceResult,
    SSHException,
    Transport,
)
from paramiko.agent import (
    SSH2_AGENT_SIGN_RESPONSE,
    SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512,
    cSSH2_AGENTC_SIGN_REQUEST,
)
from paramiko.common import cMSG_USERAUTH_REQUEST

from ._util import (
    _support,
    server,
    unicodey,
)


class AuthHandler_:
    """
    Most of these tests are explicit about the auth method they call.

    This is because not too many other tests do so (they rely on the implicit
    auth trigger of various connect() kwargs).
    """

    def bad_auth_type(self):
        """
        verify that we get the right exception when an unsupported auth
        type is requested.
        """
        # Server won't allow password auth for this user, so should fail
        # and return just publickey allowed types
        with server(
            connect=dict(username="unknown", password="error"),
            catch_error=True,
        ) as (_, _, err):
            assert isinstance(err, BadAuthenticationType)
            assert err.allowed_types == ["publickey"]

    def bad_password(self):
        """
        verify that a bad password gets the right exception, and that a retry
        with the right password works.
        """
        # NOTE: Transport.connect doesn't do any auth upfront if no userauth
        # related kwargs given.
        with server(defer=True) as (tc, ts):
            # Auth once, badly
            with raises(AuthenticationException):
                tc.auth_password(username="slowdive", password="error")
            # And again, correctly
            tc.auth_password(username="slowdive", password="pygmalion")

    def multipart_auth(self):
        """
        verify that multipart auth works.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password(
                username="paranoid", password="paranoid"
            ) == ["publickey"]
            key = Ed25519Key.from_private_key_file(_support("ed25519.key"))
            assert tc.auth_publickey(username="paranoid", key=key) == []

    def interactive_auth(self):
        """
        verify keyboard-interactive auth works.
        """

        def handler(title, instructions, prompts):
            self.got_title = title
            self.got_instructions = instructions
            self.got_prompts = prompts
            return ["cat"]

        with server(defer=True) as (tc, ts):
            assert tc.auth_interactive("commie", handler) == []
            assert self.got_title == "password"
            assert self.got_prompts == [("Password", False)]

    def interactive_fallback(self):
        """
        verify that a password auth attempt will fallback to "interactive"
        if password auth isn't supported but interactive is.
        """
        with server(defer=True) as (tc, ts):
            # This username results in an allowed_auth of just kbd-int,
            # and has a configured interactive->response on the server.
            assert tc.auth_password("commie", "cat") == []

    def utf8(self):
        """
        verify that utf-8 encoding happens in authentication.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("utf8", unicodey) == []

    def non_utf8(self):
        """
        verify that non-utf-8 encoded passwords can be used for broken
        servers.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("non-utf8", "\xff") == []

    def auth_exception_when_disconnected(self):
        """
        verify that we catch a server disconnecting during auth, and report
        it as an auth failure.
        """
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(AuthenticationException),
        ):
            tc.auth_password("bad-server", "hello")

    def non_responsive_triggers_auth_exception(self):
        """
        verify that authentication times out if server takes to long to
        respond (or never responds).
        """
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(AuthenticationException) as info,
        ):
            tc.auth_timeout = 1  # 1 second, to speed up test
            tc.auth_password("unresponsive-server", "hello")
            assert "Authentication timeout" in str(info.value)


class SHA2SignaturePubkeys:
    def pubkey_auth_honors_disabled_algorithms(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(
                disabled_algorithms=dict(
                    pubkeys=["rsa-sha2-256", "rsa-sha2-512"]
                )
            ),
            catch_error=True,
        ) as (_, _, err):
            assert isinstance(err, SSHException)
            assert "no RSA pubkey algorithms" in str(err)

    def first_client_preferred_algo_used_when_no_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            server_init=dict(
                disabled_algorithms=dict(
                    # Disable both SHA2 just to keep previous theme of this
                    # test alive (auth failure but w/ proof we tried offering
                    # something)
                    pubkeys=["rsa-sha2-256", "rsa-sha2-512"]
                ),
                # Don't publish server-sig-algs, forcing use of fallback on the
                # client side
                server_sig_algs=False,
            ),
            # Incidentally prove we're using the filtered algorithm list on the
            # client side - taking out 512 means we should offer 256
            client_init=dict(
                disabled_algorithms=dict(pubkeys=["rsa-sha2-512"])
            ),
            catch_error=True,
        ) as (tc, ts, err):
            # There was no agreement, we threw an exception...
            assert not tc.is_authenticated()
            assert isinstance(err, AuthenticationException)
            # ...but we can observe the client did their best guess at what an
            # agreement /could/ have been, and it was 256
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"

    def sha2_512(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(disabled_algorithms=dict(pubkeys=["rsa-sha2-256"])),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-512"

    def sha2_256(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(disabled_algorithms=dict(pubkeys=["rsa-sha2-512"])),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"


class _RecordingClientTransport(Transport):
    """
    Client-side Transport recording every raw userauth request it sends.

    This lets tests assert on what actually went over the wire, instead of
    trusting log output or other display-layer names.
    """

    def __init__(self, *args, **kwargs):
        self.recorded_userauth_requests = []
        super().__init__(*args, **kwargs)

    def _send_message(self, data):
        raw = data.asbytes()
        if raw[:1] == cMSG_USERAUTH_REQUEST:
            self.recorded_userauth_requests.append(raw)
        return super()._send_message(data)


def _server_advertising(pubkeys):
    """
    Build a server Transport class advertising a custom server-sig-algs list.
    """

    class CustomServerTransport(Transport):
        @property
        def preferred_pubkeys(self):
            return pubkeys

    return CustomServerTransport


def _parse_publickey_request(raw):
    """
    Parse a raw SSH_MSG_USERAUTH_REQUEST into its publickey-auth fields.
    """
    msg = Message(raw)
    msg.get_byte()  # SSH_MSG_USERAUTH_REQUEST
    request = dict(
        username=msg.get_text(),
        service=msg.get_text(),
        method=msg.get_text(),
        has_signature=msg.get_boolean(),
        algorithm=msg.get_text(),
        key_blob=msg.get_binary(),
    )
    request["signature"] = (
        msg.get_binary() if request["has_signature"] else None
    )
    return request


def _single_signed_request(tc):
    signed = [
        _parse_publickey_request(raw)
        for raw in tc.recorded_userauth_requests
    ]
    signed = [
        request
        for request in signed
        if request["method"] == "publickey" and request["has_signature"]
    ]
    assert len(signed) == 1
    return signed[0]


def _rsa_public_key_from_blob(key_blob):
    """
    Extract the RSA public key straight out of a wire-format key blob.

    Works for both plain ``ssh-rsa`` blobs and
    ``ssh-rsa-cert-v01@openssh.com`` blobs (where e/n follow the nonce), so
    verification uses the key the client actually sent, not test fixtures.
    """
    msg = Message(key_blob)
    blob_type = msg.get_text()
    if blob_type.endswith("-cert-v01@openssh.com"):
        msg.get_string()  # nonce
    public_numbers = rsa.RSAPublicNumbers(e=msg.get_mpint(), n=msg.get_mpint())
    return blob_type, public_numbers.public_key(default_backend())


def _session_blob(session_id, request):
    """
    Rebuild the signed session blob (RFC 4253 section 7) from wire fields.
    """
    blob = Message()
    blob.add_string(session_id)
    blob.add_byte(cMSG_USERAUTH_REQUEST)
    blob.add_string(request["username"])
    blob.add_string(request["service"])
    blob.add_string("publickey")
    blob.add_boolean(True)
    blob.add_string(request["algorithm"])
    blob.add_string(request["key_blob"])
    return blob.asbytes()


def _verify_independently(public_key, signature, data, hash_algorithm):
    """
    Verify a signature using ``cryptography`` directly (no Paramiko code).
    """
    public_key.verify(
        signature, data, padding.PKCS1v15(), hash_algorithm
    )


class _SigningFakeAgent:
    """
    Minimal in-process agent which really signs, recording request flags.

    Flag semantics per RFC 8332: 0 means "default" (SHA-1 for RSA keys),
    so a SHA-1-free client must always send a nonzero flag for RSA.
    """

    FLAG_HASHES = {
        0: hashes.SHA1,
        SSH_AGENT_RSA_SHA2_256: hashes.SHA256,
        SSH_AGENT_RSA_SHA2_512: hashes.SHA512,
    }
    FLAG_NAMES = {
        0: "ssh-rsa",
        SSH_AGENT_RSA_SHA2_256: "rsa-sha2-256",
        SSH_AGENT_RSA_SHA2_512: "rsa-sha2-512",
    }

    def __init__(self, pkey):
        self.pkey = pkey
        self.sign_requests = []

    def _send_message(self, msg):
        msg.rewind()
        assert msg.get_byte() == cSSH2_AGENTC_SIGN_REQUEST
        self.sign_requests.append(
            dict(
                key_blob=msg.get_string(),
                data=msg.get_string(),
                flags=msg.get_int(),
            )
        )
        request = self.sign_requests[-1]
        signature = self.pkey.key.sign(
            request["data"],
            padding.PKCS1v15(),
            self.FLAG_HASHES[request["flags"]](),
        )
        blob = Message()
        blob.add_string(self.FLAG_NAMES[request["flags"]])
        blob.add_string(signature)
        response = Message()
        response.add_string(bytes(blob))
        response.rewind()
        return SSH2_AGENT_SIGN_RESPONSE, response


class SHA1FreeRSAUserauth:
    """
    Proof that RSA userauth never silently falls back to SHA-1 (ssh-rsa).

    Every scenario inspects the actual wire traffic - the algorithm field of
    the userauth request, the algorithm name inside the signature blob, and
    agent sign-request flags - and then independently verifies the emitted
    signature with ``cryptography`` at the local peer. Log messages are never
    consulted, and the legacy ``ssh-rsa`` name inside the public key blob is
    explicitly distinguished from the signature algorithm in use.
    """

    _SIG_HASHES = {
        "rsa-sha2-256": hashes.SHA256,
        "rsa-sha2-512": hashes.SHA512,
    }

    def _assert_sha2_userauth(
        self, tc, ts, algorithm, sig_name, blob_type
    ):
        request = _single_signed_request(tc)
        # The algorithm field of the request is a SHA2 variant, never ssh-rsa
        assert request["algorithm"] == algorithm
        assert request["algorithm"] != "ssh-rsa"
        # The public key blob still uses its legacy ssh-rsa key-type name;
        # that name identifies the key, NOT the signature algorithm
        wire_blob_type, public_key = _rsa_public_key_from_blob(
            request["key_blob"]
        )
        assert wire_blob_type == blob_type
        # The signature blob's inner name carries the real algorithm
        sig_message = Message(request["signature"])
        wire_sig_name = sig_message.get_text()
        assert wire_sig_name == sig_name
        signature = sig_message.get_binary()
        # Internal bookkeeping agrees with what went over the wire
        assert tc._agreed_pubkey_algorithm == algorithm
        # Independent cryptographic verification at the local peer: the
        # signature is genuine RSA-SHA2...
        blob = _session_blob(ts.session_id, request)
        _verify_independently(
            public_key, signature, blob, self._SIG_HASHES[sig_name]()
        )
        # ...and is positively NOT SHA-1
        with raises(InvalidSignature):
            _verify_independently(
                public_key, signature, blob, hashes.SHA1()
            )

    def local_key_with_full_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            transport_factory=_RecordingClientTransport,
        ) as (tc, ts):
            self._assert_sha2_userauth(
                tc,
                ts,
                algorithm="rsa-sha2-512",
                sig_name="rsa-sha2-512",
                blob_type="ssh-rsa",
            )

    def local_cert_with_full_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        privkey.load_certificate(_support("rsa.key-cert.pub"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            transport_factory=_RecordingClientTransport,
        ) as (tc, ts):
            self._assert_sha2_userauth(
                tc,
                ts,
                algorithm="rsa-sha2-512-cert-v01@openssh.com",
                sig_name="rsa-sha2-512",
                blob_type="ssh-rsa-cert-v01@openssh.com",
            )

    def agent_key_with_full_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        agent = _SigningFakeAgent(privkey)
        agent_key = AgentKey(agent=agent, blob=privkey.asbytes())
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=agent_key),
            transport_factory=_RecordingClientTransport,
        ) as (tc, ts):
            self._assert_sha2_userauth(
                tc,
                ts,
                algorithm="rsa-sha2-512",
                sig_name="rsa-sha2-512",
                blob_type="ssh-rsa",
            )
            # Agent was explicitly asked for SHA2-512; never the legacy
            # default (flags=0, i.e. SHA-1)
            assert [r["flags"] for r in agent.sign_requests] == [
                SSH_AGENT_RSA_SHA2_512
            ]

    def agent_cert_with_full_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        privkey.load_certificate(_support("rsa.key-cert.pub"))
        agent = _SigningFakeAgent(privkey)
        agent_key = AgentKey(
            agent=agent, blob=privkey.public_blob.key_blob
        )
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=agent_key),
            transport_factory=_RecordingClientTransport,
        ) as (tc, ts):
            self._assert_sha2_userauth(
                tc,
                ts,
                algorithm="rsa-sha2-512-cert-v01@openssh.com",
                sig_name="rsa-sha2-512",
                # NOTE: agent-held certs send the plain key blob on the wire
                # (AgentKey.asbytes prefers the inner key; cf the RSA-CERT
                # degradation comment in AgentKey.sign_ssh_data). The
                # signature algorithm is still SHA2, which is what matters.
                blob_type="ssh-rsa",
            )
            assert [r["flags"] for r in agent.sign_requests] == [
                SSH_AGENT_RSA_SHA2_512
            ]

    def missing_server_sig_algs_still_sha2(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            transport_factory=_RecordingClientTransport,
            server_init=dict(server_sig_algs=False),
        ) as (tc, ts):
            # No server-sig-algs at all: client falls back to its own first
            # preferred RSA algorithm, which is SHA2-512, not legacy ssh-rsa
            self._assert_sha2_userauth(
                tc,
                ts,
                algorithm="rsa-sha2-512",
                sig_name="rsa-sha2-512",
                blob_type="ssh-rsa",
            )

    def only_legacy_algorithms_advertised_fails_before_any_signature(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            transport_factory=_RecordingClientTransport,
            server_transport_factory=_server_advertising(("ssh-rsa",)),
            catch_error=True,
        ) as (tc, ts, err):
            # Server only allows the disabled ssh-rsa: no agreement exists
            assert isinstance(err, AuthenticationException)
            assert "Unable to agree" in str(err)
            # ...and the client failed BEFORE sending any signed request,
            # rather than emitting a non-compliant SHA-1 signature
            assert tc.recorded_userauth_requests == []

    def conflicting_server_list_fails_before_any_signature(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            transport_factory=_RecordingClientTransport,
            # Server demands exactly the algorithm the client has disabled
            server_transport_factory=_server_advertising(("rsa-sha2-256",)),
            client_init=dict(
                disabled_algorithms=dict(pubkeys=["rsa-sha2-256"])
            ),
            catch_error=True,
        ) as (tc, ts, err):
            assert isinstance(err, AuthenticationException)
            assert "Unable to agree" in str(err)
            assert tc.recorded_userauth_requests == []

    def legacy_explicitly_allowed_uses_sha1_compat_control(self, monkeypatch):
        # Compat control: explicitly re-enable legacy ssh-rsa/SHA-1 on both
        # peers (the moral equivalent of `PubkeyAcceptedAlgorithms +ssh-rsa`
        # in OpenSSH). This proves the wire-level assertions above are not
        # vacuous: when SHA-1 IS used, these exact checks detect it.
        monkeypatch.setitem(RSAKey.HASHES, "ssh-rsa", hashes.SHA1)
        monkeypatch.setitem(Transport._key_info, "ssh-rsa", RSAKey)
        monkeypatch.setattr(
            Transport,
            "_preferred_pubkeys",
            ("ssh-rsa",) + Transport._preferred_pubkeys,
        )
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            transport_factory=_RecordingClientTransport,
        ) as (tc, ts):
            request = _single_signed_request(tc)
            # With legacy explicitly allowed, the old algorithm really does
            # show up on the wire...
            assert request["algorithm"] == "ssh-rsa"
            assert tc._agreed_pubkey_algorithm == "ssh-rsa"
            sig_message = Message(request["signature"])
            assert sig_message.get_text() == "ssh-rsa"
            signature = sig_message.get_binary()
            _, public_key = _rsa_public_key_from_blob(request["key_blob"])
            blob = _session_blob(ts.session_id, request)
            # ...and the independent verifier positively identifies it as
            # SHA-1 (so "SHA-1 does not verify" in the other tests is a real
            # signal, not a broken verifier)...
            _verify_independently(
                public_key, signature, blob, hashes.SHA1()
            )
            # ...while SHA-2 correctly fails against a SHA-1 signature
            with raises(InvalidSignature):
                _verify_independently(
                    public_key, signature, blob, hashes.SHA512()
                )


class AuthSource_:
    class base_class:
        def init_requires_and_saves_username(self):
            with raises(TypeError):
                AuthSource()
            assert AuthSource(username="foo").username == "foo"

        def dunder_repr_delegates_to_helper(self):
            source = AuthSource("foo")
            source._repr = Mock(wraps=lambda: "whatever")
            repr(source)
            source._repr.assert_called_once_with()

        def repr_helper_prints_basic_kv_pairs(self):
            assert repr(AuthSource("foo")) == "AuthSource()"
            assert (
                AuthSource("foo")._repr(bar="open") == "AuthSource(bar='open')"
            )

        def authenticate_takes_transport_and_is_abstract(self):
            # TODO: this test kinda just goes away once we're typed?
            with raises(TypeError):
                AuthSource("foo").authenticate()
            with raises(NotImplementedError):
                AuthSource("foo").authenticate(None)

    class NoneAuth_:
        def authenticate_auths_none(self):
            trans = Mock()
            result = NoneAuth("foo").authenticate(trans)
            trans.auth_none.assert_called_once_with("foo")
            assert result is trans.auth_none.return_value

        def repr_shows_class(self):
            assert repr(NoneAuth("foo")) == "NoneAuth()"

    class Password_:
        def init_takes_and_stores_password_getter(self):
            with raises(TypeError):
                Password("foo")
            getter = Mock()
            pw = Password("foo", password_getter=getter)
            assert pw.password_getter is getter

        def repr_adds_username(self):
            pw = Password("foo", password_getter=Mock())
            assert repr(pw) == "Password(user='foo')"

        def authenticate_gets_and_supplies_password(self):
            getter = Mock(return_value="bar")
            trans = Mock()
            pw = Password("foo", password_getter=getter)
            result = pw.authenticate(trans)
            trans.auth_password.assert_called_once_with("foo", "bar")
            assert result is trans.auth_password.return_value

    class PrivateKey_:
        def authenticate_calls_publickey_with_pkey(self):
            source = PrivateKey(username="foo")
            source.pkey = Mock()  # set by subclasses
            trans = Mock()
            result = source.authenticate(trans)
            trans.auth_publickey.assert_called_once_with("foo", source.pkey)
            assert result is trans.auth_publickey.return_value

    class InMemoryPrivateKey_:
        def init_takes_pkey_object(self):
            with raises(TypeError):
                InMemoryPrivateKey("foo")
            pkey = Mock()
            source = InMemoryPrivateKey(username="foo", pkey=pkey)
            assert source.pkey is pkey

        def repr_shows_pkey_repr(self):
            pkey = PKey.from_path(_support("ed25519.key"))
            source = InMemoryPrivateKey("foo", pkey)
            assert (
                repr(source)
                == "InMemoryPrivateKey(pkey=PKey(alg=ED25519, bits=256, fp=SHA256:J6VESFdD3xSChn8y9PzWzeF+1tl892mOy2TqkMLO4ow))"  # noqa
            )

        def repr_appends_agent_flag_when_AgentKey(self):
            real_key = PKey.from_path(_support("ed25519.key"))
            pkey = AgentKey(agent=None, blob=bytes(real_key))
            source = InMemoryPrivateKey("foo", pkey)
            assert (
                repr(source)
                == "InMemoryPrivateKey(pkey=PKey(alg=ED25519, bits=256, fp=SHA256:J6VESFdD3xSChn8y9PzWzeF+1tl892mOy2TqkMLO4ow)) [agent]"  # noqa
            )

    class OnDiskPrivateKey_:
        def init_takes_source_path_and_pkey(self):
            with raises(TypeError):
                OnDiskPrivateKey("foo")
            with raises(TypeError):
                OnDiskPrivateKey("foo", "bar")
            with raises(TypeError):
                OnDiskPrivateKey("foo", "bar", "biz")
            source = OnDiskPrivateKey(
                username="foo",
                source="ssh-config",
                path="of-exile",
                pkey="notreally",
            )
            assert source.username == "foo"
            assert source.source == "ssh-config"
            assert source.path == "of-exile"
            assert source.pkey == "notreally"

        def init_requires_specific_value_for_source(self):
            with raises(
                ValueError,
                match=r"source argument must be one of: \('ssh-config', 'python-config', 'implicit-home'\)",  # noqa
            ):
                OnDiskPrivateKey("foo", source="what?", path="meh", pkey="no")

        def repr_reflects_source_path_and_pkey(self):
            source = OnDiskPrivateKey(
                username="foo",
                source="ssh-config",
                path="of-exile",
                pkey="notreally",
            )
            assert (
                repr(source)
                == "OnDiskPrivateKey(key='notreally', source='ssh-config', path='of-exile')"  # noqa
            )


class AuthResult_:
    def setup_method(self):
        self.strat = AuthStrategy(None)

    def acts_like_list_with_strategy_attribute(self):
        with raises(TypeError):
            AuthResult()
        # kwarg works by itself
        AuthResult(strategy=self.strat)
        # or can be given as posarg w/ regular list() args after
        result = AuthResult(self.strat, [1, 2, 3])
        assert result.strategy is self.strat
        assert result == [1, 2, 3]
        assert isinstance(result, list)

    def repr_is_list_repr_untouched(self):
        result = AuthResult(self.strat, [1, 2, 3])
        assert repr(result) == "[1, 2, 3]"

    class dunder_str:
        def is_multiline_display_of_sourceresult_tuples(self):
            result = AuthResult(self.strat)
            result.append(SourceResult("foo", "bar"))
            result.append(SourceResult("biz", "baz"))
            assert str(result) == "foo -> bar\nbiz -> baz"

        def shows_str_not_repr_of_auth_source_and_result(self):
            result = AuthResult(self.strat)
            result.append(
                SourceResult(NoneAuth("foo"), ["password", "pubkey"])
            )
            assert str(result) == "NoneAuth() -> ['password', 'pubkey']"

        def empty_list_result_values_show_success_string(self):
            result = AuthResult(self.strat)
            result.append(SourceResult(NoneAuth("foo"), []))
            assert str(result) == "NoneAuth() -> success"


class AuthFailure_:
    def is_an_AuthenticationException(self):
        assert isinstance(AuthFailure(None), AuthenticationException)

    def init_requires_result(self):
        with raises(TypeError):
            AuthFailure()
        result = AuthResult(None)
        fail = AuthFailure(result=result)
        assert fail.result is result

    def str_is_newline_plus_result_str(self):
        result = AuthResult(None)
        result.append(SourceResult(NoneAuth("foo"), Exception("onoz")))
        fail = AuthFailure(result)
        assert str(fail) == "\nNoneAuth() -> onoz"


class AuthStrategy_:
    def init_requires_ssh_config_param_and_sets_up_a_logger(self):
        with raises(TypeError):
            AuthStrategy()
        conf = object()
        strat = AuthStrategy(ssh_config=conf)
        assert strat.ssh_config is conf
        assert isinstance(strat.log, Logger)
        assert strat.log.name == "paramiko.auth_strategy"

    def get_sources_is_abstract(self):
        with raises(NotImplementedError):
            AuthStrategy(None).get_sources()

    class authenticate:
        def setup_method(self):
            self.strat = AuthStrategy(None)  # ssh_config not used directly
            self.source, self.transport = NoneAuth(None), Mock()
            self.source.authenticate = Mock()
            self.strat.get_sources = Mock(return_value=[self.source])

        def requires_and_uses_transport_with_methods_returning_result(self):
            with raises(TypeError):
                self.strat.authenticate()
            result = self.strat.authenticate(self.transport)
            self.strat.get_sources.assert_called_once_with()
            self.source.authenticate.assert_called_once_with(self.transport)
            assert isinstance(result, AuthResult)
            assert result.strategy is self.strat
            assert len(result) == 1
            source_res = result[0]
            assert isinstance(source_res, SourceResult)
            assert source_res.source is self.source
            assert source_res.result is self.source.authenticate.return_value

        def logs_sources_attempted(self):
            self.strat.log = Mock()
            self.strat.authenticate(self.transport)
            self.strat.log.debug.assert_called_once_with("Trying NoneAuth()")

        def raises_AuthFailure_if_no_successes(self):
            self.strat.log = Mock()
            oops = Exception("onoz")
            self.source.authenticate.side_effect = oops
            with raises(AuthFailure) as info:
                self.strat.authenticate(self.transport)
            result = info.value.result
            assert isinstance(result, AuthResult)
            assert len(result) == 1
            source_res = result[0]
            assert isinstance(source_res, SourceResult)
            assert source_res.source is self.source
            assert source_res.result is oops
            self.strat.log.info.assert_called_once_with(
                "Authentication via NoneAuth() failed with Exception"
            )

        def short_circuits_on_successful_auth(self):
            kaboom = Mock(authenticate=Mock(side_effect=Exception("onoz")))
            self.strat.get_sources.return_value = [self.source, kaboom]
            result = self.strat.authenticate(self.transport)
            # No exception, and it's just a regular ol Result
            assert isinstance(result, AuthResult)
            # And it did not capture any attempt to execute the 2nd source
            assert len(result) == 1
            assert result[0].source is self.source
