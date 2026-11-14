"""
Tests focusing primarily on the authentication step.

Thus, they concern AuthHandler and AuthStrategy, with a side of Transport.
"""

from logging import Logger
from unittest.mock import Mock

from pytest import raises

from paramiko import (
    AgentKey,
    AuthenticationException,
    AuthFailure,
    AuthResult,
    AuthSource,
    AuthStrategy,
    BadAuthenticationType,
    CredentialResponse,
    CredentialType,
    Ed25519Key,
    InMemoryPrivateKey,
    InteractiveAuthPolicy,
    InteractiveAuthPolicyError,
    InteractivePrompt,
    NoneAuth,
    OnDiskPrivateKey,
    Password,
    PKey,
    PrivateKey,
    RSAKey,
    ServiceRequestingTransport,
    SourceResult,
    SSHException,
    StaticCredentialProvider,
    password_fallback_policy,
    reject_unknown_prompt,
)

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


def _mfa_provider(challenge):
    """
    Provider that distinguishes a password prompt from an OTP prompt by the
    verbatim prompt text -- never by the echo flag alone.
    """
    prompt = challenge.prompts[0]
    text = prompt.text.lower()
    if "verification code" in text:
        return [CredentialResponse("123456", CredentialType.OTP)]
    if "password" in text:
        return [CredentialResponse("secret-pw", CredentialType.PASSWORD)]
    reject_unknown_prompt(prompt)


class InteractiveAuthPolicy_:
    """
    End-to-end tests for the explicit keyboard-interactive policy machinery.

    These run over the in-process LoopSocket server, so no real network socket
    is needed. Each test records which credential *type* was actually put on
    the wire and at which round the exchange was rejected, and asserts that a
    refusal never leaves the client marked authenticated.
    """

    def mfa_password_then_otp_succeeds(self):
        """
        a local service that asks for a password and then an OTP is answered
        with the distinct credential types, in order.
        """
        policy = InteractiveAuthPolicy(
            StaticCredentialProvider(_mfa_provider)
        )
        with server(defer=True) as (tc, ts):
            assert tc.auth_interactive("mfa", None, policy=policy) == []
            # The transport really is authenticated at both ends.
            assert tc.is_authenticated()
            assert ts.is_authenticated()
        # Two rounds observed, bound to the verified session context.
        assert [ch.round_number for ch in policy.challenges] == [0, 1]
        assert all(ch.username == "mfa" for ch in policy.challenges)
        assert policy.challenges[0].prompts[0].text == "Password: "
        assert policy.challenges[1].prompts[0].text == "Verification code: "
        # And the credential types match the prompt semantics exactly.
        sent = [
            response.credential_type
            for round_ in policy.responses
            for response in round_
        ]
        assert sent == [CredentialType.PASSWORD, CredentialType.OTP]
        secrets = [
            response.secret
            for round_ in policy.responses
            for response in round_
        ]
        assert secrets == ["secret-pw", "123456"]

    def echo_flag_alone_never_implies_password(self):
        """
        a non-echoing OTP prompt must not be answered with the password just
        because echo=False.
        """
        seen = []

        def provider(challenge):
            seen.append(challenge.prompts[0])
            # Both prompts here arrive with echo=False; classification is by
            # text, so the OTP round still yields an OTP credential.
            return _mfa_provider(challenge)

        policy = InteractiveAuthPolicy(StaticCredentialProvider(provider))
        with server(defer=True) as (tc, ts):
            tc.auth_interactive("mfa", None, policy=policy)
        assert [prompt.echo for prompt in seen] == [False, False]
        assert [
            response.credential_type
            for round_ in policy.responses
            for response in round_
        ] == [CredentialType.PASSWORD, CredentialType.OTP]

    def unknown_single_prompt_rejects_and_sends_nothing(self):
        """
        a single malicious/unrecognized prompt aborts before any response and
        is never fed the saved password.
        """
        policy = password_fallback_policy("secret-pw")
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(InteractiveAuthPolicyError) as info,
        ):
            tc.auth_password("malicious", "secret-pw")
        assert info.value.reason == InteractiveAuthPolicyError.UNKNOWN_PROMPT
        # Nothing was put on the wire and the client is not authenticated.
        assert policy.responses == []
        assert not tc.is_authenticated()
        assert not ts.is_authenticated()

    def repeated_challenge_hits_round_budget(self):
        """
        a server that keeps re-issuing the same challenge is cut off at the
        configured round budget, without ever authenticating.
        """
        policy = password_fallback_policy("secret-pw", max_rounds=2)
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(InteractiveAuthPolicyError) as info,
        ):
            tc.auth_interactive("repeater", None, policy=policy)
        assert info.value.reason == InteractiveAuthPolicyError.ROUND_BUDGET
        # Only the budgeted number of rounds were answered, then it stopped.
        assert policy.rounds == 2
        assert len(policy.challenges) == 2
        assert not tc.is_authenticated()
        assert not ts.is_authenticated()

    def response_count_mismatch_rejects(self):
        """
        a provider returning the wrong number of responses is refused and no
        mismatched payload is sent.
        """

        def provider(challenge):
            return [
                CredentialResponse("a", CredentialType.OTHER),
                CredentialResponse("b", CredentialType.OTHER),
            ]

        policy = InteractiveAuthPolicy(StaticCredentialProvider(provider))
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(InteractiveAuthPolicyError) as info,
        ):
            tc.auth_interactive("commie", None, policy=policy)
        assert (
            info.value.reason == InteractiveAuthPolicyError.RESPONSE_MISMATCH
        )
        assert policy.responses == []
        assert not tc.is_authenticated()

    def provider_cancellation_rejects(self):
        """
        a provider returning None (user cancel) aborts the exchange.
        """
        policy = InteractiveAuthPolicy(
            StaticCredentialProvider(lambda challenge: None)
        )
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(InteractiveAuthPolicyError) as info,
        ):
            tc.auth_interactive("commie", None, policy=policy)
        assert info.value.reason == InteractiveAuthPolicyError.CANCELLED
        assert policy.responses == []
        assert not tc.is_authenticated()

    def provider_exception_is_treated_as_cancellation(self):
        def provider(challenge):
            raise RuntimeError("no UI available")

        policy = InteractiveAuthPolicy(StaticCredentialProvider(provider))
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(InteractiveAuthPolicyError) as info,
        ):
            tc.auth_interactive("commie", None, policy=policy)
        assert info.value.reason == InteractiveAuthPolicyError.CANCELLED
        assert not tc.is_authenticated()

    def fallback_can_be_disabled(self):
        """
        fallback=False must prevent any keyboard-interactive attempt and
        surface the server's BadAuthenticationType instead.
        """
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(BadAuthenticationType) as info,
        ):
            tc.auth_password("commie", "cat", fallback=False)
        assert info.value.allowed_types == ["keyboard-interactive"]
        assert not tc.is_authenticated()

    def policy_fallback_still_handles_plain_password_prompt(self):
        """
        the policy-based fallback still succeeds for a legitimate password
        prompt (preserving the historical use case).
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("commie", "cat") == []
            assert tc.is_authenticated()

    def challenge_is_bound_to_session_context(self):
        captured = []

        def provider(challenge):
            captured.append(challenge)
            return _mfa_provider(challenge)

        policy = InteractiveAuthPolicy(StaticCredentialProvider(provider))
        with server(defer=True) as (tc, ts):
            tc.auth_interactive("mfa", None, policy=policy)
        first = captured[0]
        assert first.username == "mfa"
        assert first.round_number == 0
        assert first.title == "login"
        assert first.instructions == "Enter your password."
        # Verbatim prompt text and the raw peer address are carried along.
        assert first.prompts[0].text == "Password: "
        assert isinstance(first.peer_address, tuple)

    def requires_credential_provider_instance(self):
        with raises(TypeError):
            InteractiveAuthPolicy(provider=object())

    def max_rounds_must_be_positive(self):
        with raises(ValueError):
            InteractiveAuthPolicy(
                StaticCredentialProvider(_mfa_provider), max_rounds=0
            )

    def works_through_service_requesting_transport(self):
        """
        the policy drives the AuthOnlyHandler code path too, including the
        password-fallback entry point and round-budget enforcement.
        """
        # Happy MFA path over the newer service-requesting transport.
        policy = InteractiveAuthPolicy(
            StaticCredentialProvider(_mfa_provider)
        )
        with server(
            defer=True,
            transport_factory=ServiceRequestingTransport,
        ) as (tc, ts):
            assert tc.auth_interactive("mfa", None, policy=policy) == []
            assert tc.is_authenticated()
            assert ts.is_authenticated()
        assert policy.rounds == 2

        # Adversarial repeated challenge is still cut off on that path.
        budget = password_fallback_policy("secret-pw", max_rounds=1)
        with (
            server(
                defer=True,
                skip_verify=True,
                transport_factory=ServiceRequestingTransport,
            ) as (tc, ts),
            raises(InteractiveAuthPolicyError) as info,
        ):
            tc.auth_interactive("repeater", None, policy=budget)
        assert info.value.reason == InteractiveAuthPolicyError.ROUND_BUDGET
        assert not tc.is_authenticated()


class LegacyInteractiveHandler_:
    """
    The plain callable handler keeps working, but response-count mismatches
    are now refused rather than sent.
    """

    def plain_handler_still_supported(self):
        def handler(title, instructions, prompts):
            return ["cat"]

        with server(defer=True) as (tc, ts):
            assert tc.auth_interactive("commie", handler) == []
            assert tc.is_authenticated()

    def mismatched_handler_response_count_rejected(self):
        def handler(title, instructions, prompts):
            # One prompt on the wire, but two answers.
            return ["cat", "dog"]

        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(SSHException),
        ):
            tc.auth_interactive("commie", handler)
        assert not tc.is_authenticated()
        assert not ts.is_authenticated()


class InteractiveAuthPolicyUnit_:
    """
    Transport-free unit tests for the policy's own enforcement logic.
    """

    def _transport(self):
        transport = Mock()
        transport.hostname = "mfa.example.com"
        transport.getpeername.return_value = ("10.0.0.9", 22)
        return transport

    def challenge_binds_verified_host_user_round_and_prompts(self):
        policy = InteractiveAuthPolicy(
            StaticCredentialProvider(_mfa_provider)
        )
        transport = self._transport()
        policy.respond(
            transport,
            "alice",
            "login",
            "enter password",
            [("Password: ", False)],
        )
        challenge = policy.challenges[0]
        assert challenge.host == "mfa.example.com"
        assert challenge.peer_address == ("10.0.0.9", 22)
        assert challenge.username == "alice"
        assert challenge.round_number == 0
        assert challenge.prompts == (
            InteractivePrompt(text="Password: ", echo=False),
        )

    def echo_true_unknown_prompt_is_still_rejected(self):
        # An echoing prompt (echo=True) the provider cannot map must be
        # rejected -- and echo alone never decides credential type.
        policy = password_fallback_policy("pw")
        transport = self._transport()
        with raises(InteractiveAuthPolicyError) as info:
            policy.respond(
                transport, "alice", "t", "i", [("First pet? ", True)]
            )
        assert info.value.reason == InteractiveAuthPolicyError.UNKNOWN_PROMPT
        assert policy.responses == []

    def fallback_policy_matches_password_prompt_regardless_of_echo(self):
        policy = password_fallback_policy("pw")
        transport = self._transport()
        # Even an *echoing* password-named prompt is answered, proving the
        # decision is text-based rather than driven by the echo flag.
        secrets = policy.respond(
            transport, "alice", "t", "i", [("PASSWORD", True)]
        )
        assert secrets == ["pw"]
        assert policy.responses[0][0].credential_type == (
            CredentialType.PASSWORD
        )

    def round_budget_enforced_without_a_transport_round_trip(self):
        policy = InteractiveAuthPolicy(
            StaticCredentialProvider(_mfa_provider), max_rounds=1
        )
        transport = self._transport()
        policy.respond(
            transport, "alice", "t", "i", [("Password: ", False)]
        )
        with raises(InteractiveAuthPolicyError) as info:
            policy.respond(
                transport, "alice", "t", "i", [("Password: ", False)]
            )
        assert info.value.reason == InteractiveAuthPolicyError.ROUND_BUDGET

    def wrong_response_count_raises_before_recording_response(self):
        def provider(challenge):
            return [CredentialResponse("x", CredentialType.OTHER)]

        policy = InteractiveAuthPolicy(StaticCredentialProvider(provider))
        transport = self._transport()
        with raises(InteractiveAuthPolicyError) as info:
            policy.respond(
                transport,
                "alice",
                "t",
                "i",
                [("one", False), ("two", False)],
            )
        assert (
            info.value.reason == InteractiveAuthPolicyError.RESPONSE_MISMATCH
        )
        assert policy.responses == []
        assert policy.rounds == 0

    def non_credential_response_value_is_rejected(self):
        def provider(challenge):
            return ["bare-string-not-allowed"]

        policy = InteractiveAuthPolicy(StaticCredentialProvider(provider))
        transport = self._transport()
        with raises(InteractiveAuthPolicyError) as info:
            policy.respond(
                transport, "alice", "t", "i", [("one", False)]
            )
        assert (
            info.value.reason == InteractiveAuthPolicyError.RESPONSE_MISMATCH
        )


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
