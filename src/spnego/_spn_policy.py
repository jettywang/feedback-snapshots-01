# Copyright: (c) 2026, Jordan Borean (@jborean93) <jborean93@example.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""SPN target name admission policy for NTLM.

NTLMv2 authenticators embed the SPN of the service the client targeted in the
``MSV_AV_TARGET_NAME`` AV pair of the NT challenge response. The response only
proves the client knows the password; on its own it does not prove the token was
minted for the service that is validating it. A credential presented to service
A can otherwise be replayed against service B as long as B shares the same
credential store.

The :class:`SPNTargetPolicy` in this module lets an acceptor define, through
local configuration, the names and trusted aliases it is willing to accept. The
policy never learns names from the wire - a name supplied by the client is only
ever compared against the locally configured set.
"""

import dataclasses
import enum
import typing

from spnego.exceptions import OperationNotAvailableError


def reject_unsupported_spn_target_policy(
    provider: str,
    kwargs: typing.Dict[str, typing.Any],
) -> None:
    """Fail fast when a provider cannot enforce an SPN target policy.

    Only the pure Python NTLM provider can inspect and admit the
    ``MSV_AV_TARGET_NAME`` AV pair on the acceptor. Native GSSAPI/SSPI and
    CredSSP wrapped contexts do not expose the hook required to enforce the
    local policy, so accepting the configuration would give the caller a false
    sense of enforcement.

    Args:
        provider: A human readable name of the rejecting provider.
        kwargs: The keyword arguments passed to the provider constructor.

    Raises:
        OperationNotAvailableError: When an ``spn_target_policy`` value was
            supplied to a provider that cannot enforce it.
    """
    policy = kwargs.get("spn_target_policy")
    if policy is not None:
        raise OperationNotAvailableError(
            context_msg=(
                "The %s provider does not support enforcing an SPN target policy; use the pure Python NTLM provider "
                "(protocol='ntlm', options=NegotiateOptions.use_ntlm) instead" % provider
            )
        )


class SPNTargetPolicyMode(enum.Enum):
    """How an acceptor should react to a target name that is not allowed.

    Attributes:
        permissive: A missing, unknown, or malformed target name does not fail
            authentication. A :class:`UserWarning` is emitted instead so the
            event remains visible while keeping the legacy behaviour.
        strict: Any target name that is not one of the configured allowed names
            or trusted aliases fails the authentication exchange.
    """

    permissive = "permissive"
    strict = "strict"


class SPNTargetNameStatus(enum.Enum):
    """The outcome of matching a client supplied target name against the policy.

    Attributes:
        missing: The NTLMv2 response did not contain a ``MSV_AV_TARGET_NAME``
            AV pair or the value was empty.
        mismatch: The target name was present but does not match any allowed
            name or trusted alias configured for this service.
        allowed_name: The target name matches one of the configured allowed
            names exactly (after name canonicalization).
        trusted_alias: The target name matches one of the locally configured
            trusted aliases.
        representation: The target name only differs from an allowed name or
            alias in its textual representation, for example letter case or a
            trailing DNS dot.
    """

    missing = "missing"
    mismatch = "mismatch"
    mismatch_malformed = "mismatch_malformed"
    allowed_name = "allowed_name"
    trusted_alias = "trusted_alias"
    representation = "representation"


@dataclasses.dataclass(frozen=True)
class SPNTargetValidationResult:
    """The result of validating an NTLMv2 target name.

    Attributes:
        status: The classification of the match attempt.
        presented: The raw target name extracted from the client response, or
            None when no target name AV pair was present.
        matched: The configured name or alias that accepted the presentation,
            or None when no entry matched.
        allowed: Whether the presentation is admitted by the policy.
    """

    status: SPNTargetNameStatus
    presented: typing.Optional[str]
    matched: typing.Optional[str]
    allowed: bool


def canonicalize_spn(name: typing.Optional[str]) -> typing.Optional[str]:
    """Canonicalize an SPN for policy comparison.

    SPNs are case insensitive and the host component may carry a trailing DNS
    dot. Both variations are reduced to a common form so they are treated as a
    representation difference rather than a different service. Names that do not
    look like ``service/host`` entries are returned lower cased but otherwise
    untouched, letting the caller report them as malformed rather than silently
    accepting them.

    Args:
        name: The SPN value to canonicalize.

    Returns:
        Optional[str]: The canonicalized SPN or None when the input was None or
            contained no usable value.
    """
    if name is None:
        return None

    value = name.strip()
    if not value:
        return None

    if "/" not in value:
        return value.lower()

    service, host = value.split("/", 1)
    service = service.strip().lower()
    host = host.strip().lower().rstrip(".")
    if not service or not host:
        return value.lower()

    return f"{service}/{host}"


class SPNTargetPolicy:
    """Local admission policy for the NTLMv2 ``MSV_AV_TARGET_NAME`` value.

    Every name accepted by the policy is sourced from local configuration. The
    target name sent by the client is only compared against this configuration
    and is never used to extend it.

    Args:
        allowed_names: The SPNs this service answers to, for example
            ``["http/server.example.com"]``. A single string is also accepted.
            The service's own ``service`` and ``hostname`` derived SPN should
            normally be present here.
        trusted_aliases: Additional locally configured SPNs that are known to
            refer to the same service. A single string is also accepted. A
            client cannot register an alias by simply presenting it.
        mode: Whether a rejected presentation fails the exchange
            (:attr:`SPNTargetPolicyMode.strict`) or only emits a warning
            (:attr:`SPNTargetPolicyMode.permissive`, the default).

    Attributes:
        allowed_names: The canonicalized allowed SPNs as a tuple.
        trusted_aliases: The canonicalized trusted alias SPNs as a tuple.
        mode: The configured enforcement mode.
    """

    def __init__(
        self,
        allowed_names: typing.Union[str, typing.Sequence[str]],
        trusted_aliases: typing.Optional[typing.Union[str, typing.Sequence[str]]] = None,
        mode: SPNTargetPolicyMode = SPNTargetPolicyMode.permissive,
    ) -> None:
        allowed = self._normalize(allowed_names)
        if not allowed:
            raise ValueError("SPNTargetPolicy requires at least one allowed name")

        aliases = self._normalize(trusted_aliases)

        overlap = sorted(set(allowed) & set(aliases))
        if overlap:
            raise ValueError(
                "SPNTargetPolicy trusted aliases must not duplicate allowed names: %s" % ", ".join(overlap)
            )

        if not isinstance(mode, SPNTargetPolicyMode):
            raise ValueError("SPNTargetPolicy mode must be a SPNTargetPolicyMode value, got %r" % type(mode).__name__)

        self.allowed_names: typing.Tuple[str, ...] = tuple(allowed)
        self.trusted_aliases: typing.Tuple[str, ...] = tuple(aliases)
        self.mode = mode

    def __repr__(self) -> str:
        return "SPNTargetPolicy(allowed_names=%r, trusted_aliases=%r, mode=%r)" % (
            list(self.allowed_names),
            list(self.trusted_aliases),
            self.mode,
        )

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, SPNTargetPolicy):
            return NotImplemented

        return (
            self.allowed_names == other.allowed_names
            and self.trusted_aliases == other.trusted_aliases
            and self.mode == other.mode
        )

    def __hash__(self) -> int:
        return hash((self.allowed_names, self.trusted_aliases, self.mode))

    @staticmethod
    def _normalize(values: typing.Union[str, typing.Sequence[str], None]) -> typing.List[str]:
        if values is None:
            return []

        if isinstance(values, str):
            values = [values]

        normalized: typing.List[str] = []
        seen: typing.Set[str] = set()
        for raw in values:
            if not isinstance(raw, str):
                raise ValueError("SPNTargetPolicy names must be strings, got %r" % type(raw).__name__)

            canonical = canonicalize_spn(raw)
            if canonical is None:
                raise ValueError("SPNTargetPolicy names must not be empty")

            if canonical not in seen:
                seen.add(canonical)
                normalized.append(canonical)

        return normalized

    @property
    def strict(self) -> bool:
        """Whether the policy rejects non admitting presentations."""
        return self.mode == SPNTargetPolicyMode.strict

    def validate(self, presented: typing.Optional[str]) -> SPNTargetValidationResult:
        """Match a client supplied target name against the local policy.

        Args:
            presented: The ``MSV_AV_TARGET_NAME`` value extracted from the
                NTLMv2 client challenge, or None when the AV pair was absent.

        Returns:
            SPNTargetValidationResult: The classification of the presentation.
        """
        canonical_presented = canonicalize_spn(presented)
        if canonical_presented is None:
            return SPNTargetValidationResult(
                status=SPNTargetNameStatus.missing,
                presented=presented or None,
                matched=None,
                allowed=False,
            )

        # Remember the raw configured entries so the result can report which
        # local name admitted the presentation without trusting client data.
        for entry in self.allowed_names:
            result = self._compare(canonical_presented, entry, presented, SPNTargetNameStatus.allowed_name)
            if result:
                return result

        for entry in self.trusted_aliases:
            result = self._compare(canonical_presented, entry, presented, SPNTargetNameStatus.trusted_alias)
            if result:
                return result

        status = SPNTargetNameStatus.mismatch
        if "/" not in canonical_presented:
            status = SPNTargetNameStatus.mismatch_malformed

        return SPNTargetValidationResult(
            status=status,
            presented=presented,
            matched=None,
            allowed=False,
        )

    @staticmethod
    def _compare(
        canonical_presented: str,
        canonical_entry: str,
        raw_presented: typing.Optional[str],
        exact_status: SPNTargetNameStatus,
    ) -> typing.Optional[SPNTargetValidationResult]:
        if canonical_presented == canonical_entry:
            status = exact_status
            if raw_presented is not None and raw_presented != canonical_entry:
                # Same service/host once canonicalized but the spelling differed,
                # e.g. "HTTP/Server.Example.COM." vs "http/server.example.com".
                status = SPNTargetNameStatus.representation

            return SPNTargetValidationResult(
                status=status,
                presented=raw_presented,
                matched=canonical_entry,
                allowed=True,
            )

        return None
