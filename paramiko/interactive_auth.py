"""
Explicit policy machinery for ``keyboard-interactive`` authentication.

The historical behavior of `.Transport.auth_password` was to silently fall
back to ``keyboard-interactive`` when plain password auth was disallowed, and
to answer *any* single non-echoing prompt with the saved password.  That is
unsafe for multi-factor authentication (MFA): a one-time password (OTP) is not
interchangeable with a password, and the ``echo`` flag of a prompt only says
whether the typed response should be echoed -- it does not prove the prompt is
asking for a password.

This module provides:

- `.CredentialType` -- the distinct kinds of secrets a prompt may request,
- `.InteractivePrompt` / `.InteractiveChallenge` -- structured, context-bound
  descriptions of each server round (including the *verbatim* prompt text),
- `.CredentialProvider` -- an interface whose implementer decides which
  credential answers which prompt, and
- `.InteractiveAuthPolicy` -- the object that drives an exchange, enforces a
  round budget and response-count matching, and never emits a saved password
  on its own initiative.
"""

from dataclasses import dataclass, field
from enum import Enum

from paramiko.ssh_exception import InteractiveAuthPolicyError


class CredentialType(Enum):
    """
    The kind of credential a server prompt is asking for.

    The provider -- not the policy, and not the prompt's ``echo`` flag --
    decides which type applies to a given prompt.
    """

    #: A long-lived password / passphrase.
    PASSWORD = "password"
    #: A short-lived one-time password / token (TOTP, HOTP, push code...).
    OTP = "otp"
    #: A response that is neither a password nor an OTP (e.g. a security
    #: question); the provider alone knows how to answer it.
    OTHER = "other"


@dataclass(frozen=True)
class InteractivePrompt:
    """
    A single prompt within a keyboard-interactive challenge.

    :param str text:
        The verbatim prompt text sent by the server, e.g. ``"Password:"`` or
        ``"Verification code:"``.  It is never interpreted or normalized.
    :param bool echo:
        Whether the user's response should be echoed while typed, exactly as
        carried by the SSH ``boolean`` field.  Note that ``echo=False`` does
        **not** mean the prompt is a password prompt; only the provider may
        draw that conclusion.
    """

    text: str
    echo: bool


@dataclass(frozen=True)
class InteractiveChallenge:
    """
    One full ``keyboard-interactive`` request, bound to a verified session.

    Every attribute describes the exact, already-established session the
    challenge arrived on, so a provider never has to guess which host or user a
    credential is being handed to.

    :param str host:
        The peer hostname (or socket address) of the transport.  The host key
        of this peer has already been validated by the normal host-key policy
        before authentication begins.
    :param object peer_address:
        The raw result of `.Transport.getpeername`, for audit/display.
    :param str username:
        The username being authenticated.
    :param int round_number:
        Zero-based index of this challenge within the exchange.
    :param str title:
        The verbatim ``name``/title field from the server.
    :param str instructions:
        The verbatim instructions field from the server.
    :param prompts:
        Tuple of `.InteractivePrompt`, preserving the server's ordering and
        verbatim prompt text.
    :type prompts: tuple[InteractivePrompt, ...]
    """

    host: str
    peer_address: object
    username: str
    round_number: int
    title: str
    instructions: str
    prompts: tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class CredentialResponse:
    """
    A single answer to an `.InteractivePrompt`.

    :param str secret:
        The response text to send back to the server.
    :param CredentialType credential_type:
        Which kind of credential the provider decided this was.  This is
        recorded for auditing and testing; the wire protocol itself only
        carries the secret text.
    """

    secret: str
    credential_type: CredentialType


class CredentialProvider:
    """
    Interface for objects able to answer interactive authentication prompts.

    Implementations receive the full, context-bound `.InteractiveChallenge`
    and decide, based on the verbatim prompt text, which credential answers
    each prompt.  They are explicitly *not* told to treat non-echoing prompts
    as password prompts.

    A provider may:

    - return a list of `.CredentialResponse` (one per prompt),
    - return ``None`` to cancel the exchange (e.g. an unrecognized prompt), or
    - raise any exception, which aborts the exchange without sending anything.
    """

    def provide(self, challenge):
        """
        Answer one challenge round.

        :param InteractiveChallenge challenge:
            The bound description of this round.
        :return:
            One `.CredentialResponse` per ``challenge.prompts``, or ``None`` to
            cancel.
        :rtype: list[CredentialResponse] | None
        """
        raise NotImplementedError


class StaticCredentialProvider(CredentialProvider):
    """
    A `.CredentialProvider` driven by a user-supplied callback.

    The callback is invoked with the same `.InteractiveChallenge` and must
    return a list of `.CredentialResponse` (or ``None`` to cancel).  This keeps
    the security decision -- what each prompt means and which secret answers
    it -- entirely in application code.

    :param callable callback:
        ``callback(challenge) -> list[CredentialResponse] | None``.
    """

    def __init__(self, callback):
        self.callback = callback

    def provide(self, challenge):
        return self.callback(challenge)


def reject_unknown_prompt(prompt):
    """
    Raise `.InteractiveAuthPolicyError` for a prompt the provider cannot map.

    Providers should call this (or raise the same error themselves) rather than
    guessing which credential fits an unrecognized prompt.

    :param InteractivePrompt prompt:
        The prompt that could not be classified.
    """
    raise InteractiveAuthPolicyError(
        InteractiveAuthPolicyError.UNKNOWN_PROMPT,
        "no credential available for prompt {!r}".format(prompt.text),
    )


class InteractiveAuthPolicy:
    """
    Drives one ``keyboard-interactive`` exchange under explicit rules.

    A policy instance is used for a single authentication attempt
    (`.Transport.auth_interactive` or the opt-in password fallback) and is
    handed each server challenge as it arrives.

    Guarantees:

    - every round is delegated to `.provider`, bound to the verified host,
      username, round number and verbatim prompt text;
    - a prompt the provider cannot answer, an exceeded ``max_rounds`` budget,
      a response count that does not match the prompt count, or a provider
      cancellation aborts the exchange with
      `.InteractiveAuthPolicyError` before any further response is sent;
    - the policy never substitutes a saved password on its own.

    :param CredentialProvider provider:
        The object that maps prompts to credentials.
    :param int max_rounds:
        Maximum number of challenge rounds permitted.  Defaults to 3, which
        comfortably covers password-then-OTP style MFA while bounding a
        malicious server.
    """

    def __init__(self, provider, max_rounds=3):
        if not isinstance(provider, CredentialProvider):
            raise TypeError(
                "provider must be a CredentialProvider instance, got {!r}"
                .format(type(provider))
            )
        if max_rounds < 1:
            raise ValueError("max_rounds must be a positive integer")
        self.provider = provider
        self.max_rounds = max_rounds
        #: Number of challenge rounds observed so far.
        self.rounds = 0
        #: Every `.InteractiveChallenge` observed, in order.
        self.challenges = []
        #: Every response actually sent, in order.
        self.responses = []

    def build_challenge(
        self, transport, username, title, instructions, prompt_list
    ):
        """
        Construct the context-bound `.InteractiveChallenge` for this round.
        """
        peer_address = transport.getpeername()
        # getpeername() falls back to ("unknown", 0) for socket-like objects
        # without a real peer address.
        host = transport.hostname or peer_address[0]
        prompts = tuple(
            InteractivePrompt(text=text, echo=echo)
            for text, echo in prompt_list
        )
        return InteractiveChallenge(
            host=host,
            peer_address=peer_address,
            username=username,
            round_number=self.rounds,
            title=title,
            instructions=instructions,
            prompts=prompts,
        )

    def respond(self, transport, username, title, instructions, prompt_list):
        """
        Resolve one server round into plain string responses for the wire.

        This is the method invoked by the auth handler.  It performs all policy
        enforcement and returns the list of response strings the handler will
        send; it never returns a saved password unless the provider explicitly
        produced one for this exact challenge.
        """
        if self.rounds >= self.max_rounds:
            raise InteractiveAuthPolicyError(
                InteractiveAuthPolicyError.ROUND_BUDGET,
                "round {} exceeds max_rounds={}".format(
                    self.rounds, self.max_rounds
                ),
            )
        challenge = self.build_challenge(
            transport, username, title, instructions, prompt_list
        )
        self.challenges.append(challenge)
        try:
            provided = self.provider.provide(challenge)
        except InteractiveAuthPolicyError:
            raise
        except Exception as error:
            # A provider that raises is treated as a cancellation: nothing is
            # sent and the exchange stops.
            raise InteractiveAuthPolicyError(
                InteractiveAuthPolicyError.CANCELLED,
                "provider raised {}: {}".format(
                    type(error).__name__, error
                ),
            ) from error
        if provided is None:
            raise InteractiveAuthPolicyError(
                InteractiveAuthPolicyError.CANCELLED,
                "provider returned no response for round {}".format(
                    self.rounds
                ),
            )
        if len(provided) != len(prompt_list):
            raise InteractiveAuthPolicyError(
                InteractiveAuthPolicyError.RESPONSE_MISMATCH,
                "provider returned {} response(s) for {} prompt(s)".format(
                    len(provided), len(prompt_list)
                ),
            )
        secrets = []
        for item in provided:
            if not isinstance(item, CredentialResponse):
                raise InteractiveAuthPolicyError(
                    InteractiveAuthPolicyError.RESPONSE_MISMATCH,
                    "provider returned non-CredentialResponse value {!r}"
                    .format(item),
                )
            secrets.append(item.secret)
        self.responses.append(tuple(provided))
        self.rounds += 1
        return secrets


def password_fallback_policy(password, max_rounds=3):
    """
    Build an explicit policy that may supply a saved password.

    This is the security-conscious replacement for the old implicit
    ``auth_password`` -> ``keyboard-interactive`` fallback.  The saved password
    is only returned for a prompt the *callback* classifies as
    `CredentialType.PASSWORD`; the prompt's ``echo`` flag is ignored for that
    decision.  An OTP prompt, an unknown prompt, a round-budget overflow or a
    response mismatch all abort the exchange via
    `.InteractiveAuthPolicyError` instead of guessing.

    The returned policy accepts prompts whose text contains one of
    ``"password"`` or ``"passcode"`` (case-insensitive) as password prompts;
    anything else is rejected as unknown.  Applications doing real MFA should
    construct their own `.InteractiveAuthPolicy` with a provider that
    distinguishes password and OTP prompts explicitly.

    :param str password:
        The password to offer, and only on a positively identified password
        prompt.
    :param int max_rounds:
        Maximum number of challenge rounds permitted.
    :rtype: InteractiveAuthPolicy
    """

    def callback(challenge):
        answers = []
        for prompt in challenge.prompts:
            lowered = prompt.text.lower()
            if "password" in lowered or "passcode" in lowered:
                answers.append(
                    CredentialResponse(
                        secret=password,
                        credential_type=CredentialType.PASSWORD,
                    )
                )
            else:
                reject_unknown_prompt(prompt)
        return answers

    return InteractiveAuthPolicy(
        provider=StaticCredentialProvider(callback), max_rounds=max_rounds
    )
