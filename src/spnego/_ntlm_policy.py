import os
import typing

from spnego.exceptions import ErrorCode, SpnegoError


class NTLMPolicy:
    """Instance level NTLM protocol policy.

    This policy controls, for a single NTLM context instance, which response
    types the initiator side will generate and which response types the
    acceptor side will allow, as well as the session security options the
    context will negotiate. It replaces the process wide ``LM_COMPAT_LEVEL``
    environment variable with an explicit per-context object so that strict
    and compatible endpoints can safely run in the same process.

    The policy is captured when the context is created. Changing the
    ``LM_COMPAT_LEVEL`` environment variable afterwards does not affect
    contexts that already exist, and an explicit policy always takes
    precedence over the environment variable.

    A policy is validated on construction, an invalid policy raises a
    ``ValueError`` instead of producing a context that silently behaves
    differently from what was requested. Providers that cannot enforce a
    policy (for example SSPI or GSSAPI) fail explicitly when one is supplied
    rather than returning a context that only claims to be strict.

    Migrating from the legacy environment variable configuration is done by
    deriving an explicit policy from the old level and passing it to each
    context instead::

        # Old, process wide configuration:
        # os.environ["LM_COMPAT_LEVEL"] = "5"
        # client = spnego.client(..., protocol="ntlm")

        # New, per-instance configuration:
        policy = spnego.NTLMPolicy.from_compat_level(5)
        client = spnego.client(..., protocol="ntlm", ntlm_policy=policy)
        server = spnego.server(protocol="ntlm", ntlm_policy=policy)

    Args:
        generate_lm: The initiator will include an LM response in the
            NTLMv1 authentication message it generates.
        generate_ntlmv1: The initiator may generate NTLMv1 responses.
        generate_ntlmv2: The initiator may generate NTLMv2 responses.
        accept_lm: The acceptor will allow LM responses.
        accept_ntlmv1: The acceptor will allow NTLMv1 responses.
        accept_ntlmv2: The acceptor will allow NTLMv2 responses.
        extended_session_security: Negotiate NTLM extended session security
            (NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY).
        lm_key: Allow the LM key to be used for session key material
            (NTLMSSP_NEGOTIATE_LM_KEY).
    """

    def __init__(
        self,
        *,
        generate_lm: bool = False,
        generate_ntlmv1: bool = False,
        generate_ntlmv2: bool = True,
        accept_lm: bool = False,
        accept_ntlmv1: bool = False,
        accept_ntlmv2: bool = True,
        extended_session_security: bool = True,
        lm_key: bool = False,
    ) -> None:
        self.generate_lm = bool(generate_lm)
        self.generate_ntlmv1 = bool(generate_ntlmv1)
        self.generate_ntlmv2 = bool(generate_ntlmv2)
        self.accept_lm = bool(accept_lm)
        self.accept_ntlmv1 = bool(accept_ntlmv1)
        self.accept_ntlmv2 = bool(accept_ntlmv2)
        self.extended_session_security = bool(extended_session_security)
        self.lm_key = bool(lm_key)

        if not (self.generate_ntlmv1 or self.generate_ntlmv2):
            raise ValueError("NTLM policy must allow the initiator to generate NTLMv1 and/or NTLMv2 responses")

        if self.generate_lm and not self.generate_ntlmv1:
            raise ValueError("NTLM policy cannot generate LM responses without allowing NTLMv1 generation")

        if not (self.accept_lm or self.accept_ntlmv1 or self.accept_ntlmv2):
            raise ValueError("NTLM policy must allow the acceptor to accept LM, NTLMv1, and/or NTLMv2 responses")

        if self.accept_lm and not self.accept_ntlmv1:
            raise ValueError("NTLM policy cannot accept LM responses without allowing NTLMv1")

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, NTLMPolicy):
            return NotImplemented

        return all(
            getattr(self, attr) == getattr(other, attr)
            for attr in (
                "generate_lm",
                "generate_ntlmv1",
                "generate_ntlmv2",
                "accept_lm",
                "accept_ntlmv1",
                "accept_ntlmv2",
                "extended_session_security",
                "lm_key",
            )
        )

    def __repr__(self) -> str:
        return (
            "NTLMPolicy(generate_lm=%r, generate_ntlmv1=%r, generate_ntlmv2=%r, accept_lm=%r, accept_ntlmv1=%r, "
            "accept_ntlmv2=%r, extended_session_security=%r, lm_key=%r)"
            % (
                self.generate_lm,
                self.generate_ntlmv1,
                self.generate_ntlmv2,
                self.accept_lm,
                self.accept_ntlmv1,
                self.accept_ntlmv2,
                self.extended_session_security,
                self.lm_key,
            )
        )

    @classmethod
    def strict(cls) -> "NTLMPolicy":
        """Creates a policy that only allows NTLMv2 with extended session security."""
        return cls()

    @classmethod
    def from_compat_level(cls, level: int) -> "NTLMPolicy":
        """Creates a policy from a legacy LM compatibility level.

        Maps the levels 0-5 documented at `Network security: LAN Manager
        authentication level
        <https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level>`_
        to an equivalent instance level policy. Level 5 is equivalent to
        :meth:`strict`.

        Args:
            level: The LM compatibility level, must be between 0 and 5.

        Returns:
            NTLMPolicy: The policy equivalent to the compatibility level.
        """
        if not 0 <= level <= 5:
            raise ValueError("Invalid LM compatibility level %d, must be between 0 and 5" % level)

        return cls(
            generate_lm=level < 2,
            generate_ntlmv1=level < 3,
            generate_ntlmv2=level > 2,
            accept_lm=level < 4,
            accept_ntlmv1=level < 5,
            accept_ntlmv2=True,
            extended_session_security=level != 0,
            lm_key=level <= 1,
        )

    @classmethod
    def from_env(cls) -> "NTLMPolicy":
        """Creates a policy from the LM_COMPAT_LEVEL environment variable.

        This is the fallback used when a context is created without an
        explicit policy. The variable is read once at call time, later
        changes to the environment do not affect the returned policy.

        Returns:
            NTLMPolicy: The policy derived from the environment, defaulting
            to level 3 when the variable is not set.
        """
        raw_level = os.environ.get("LM_COMPAT_LEVEL", "3")
        try:
            level = int(raw_level)
        except ValueError:
            raise SpnegoError(
                ErrorCode.failure, context_msg="Invalid LM_COMPAT_LEVEL %r, must be an integer" % raw_level
            ) from None

        if level < 0 or level > 5:
            raise SpnegoError(
                ErrorCode.failure, context_msg="Invalid LM_COMPAT_LEVEL %d, must be between 0 and 5" % level
            )

        return cls.from_compat_level(level)
