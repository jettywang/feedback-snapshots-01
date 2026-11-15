# Copyright 2014-2026 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Envelope-sender authorization for authenticated submission clients.

The reusable pieces are:

``parse_envelope_address``
    Turn the addr-spec aiosmtpd delivered to ``handle_MAIL`` into one
    canonical identity, or raise :class:`AddressError`.

``SenderPolicy``
    Decide whether an authenticated user may use that identity as the
    envelope sender.

``SenderAuthorizedHandler``
    A ``handle_MAIL`` hook that applies the policy and is safe to mix into a
    larger handler.  It writes ``envelope.mail_from`` only after the decision
    succeeds and clears it on every rejection.

Design boundaries
-----------------

* The input is already an addr-spec parsed by aiosmtpd.  This module does not
  re-run a lenient RFC 5322 header parser over the wire command; doing so would
  lose the distinction between quoted and unquoted local-parts.
* The local-part is identity material: it is never case-folded, never Unicode
  normalized, and never plus-address-normalized.  Only the RFC 5321 rule that
  quoted and unquoted forms of the same local-part are equivalent is applied.
* The domain is case-insensitive DNS data.  ASCII letters are lowercased and
  the result is mapped with strict IDNA2008 (``uts46=False``).  Compatibility
  mappings such as UTS #46 full-width folding are deliberately not used: a
  homoglyph must not become the legitimate alias during authorization.
* Non-ASCII envelope material requires the client to assert SMTPUTF8 on the
  MAIL command.  Merely enabling SMTPUTF8 on the server is not consent for a
  client that did not negotiate it.
* The null reverse-path is not a mailbox identity.  It is decided separately
  and is denied unless the policy explicitly opts in.
"""

from __future__ import annotations

import logging
import string
import unicodedata
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Collection, Dict, Iterable, Mapping, Optional, Tuple, Union

import idna
from idna import IDNAError

from aiosmtpd.smtp import Envelope, Session, SMTP

log = logging.getLogger("mail.log")

#: The parsed representation of the null reverse-path (``MAIL FROM:<>``).
NULL_ADDRESS = "<>"

_ATEXT = frozenset(
    string.ascii_letters + string.digits + "!#$%&'*+-/=?^_`{|}~"
)
_ASCII_DOMAIN_UPPER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

#: Characters that cannot appear in a domain passed to the IDNA mapper.  IDNA
#: does the real validation; this set only rejects SMTP/header structure.
_FORBIDDEN_DOMAIN_CHARS = frozenset('<>()[]\\",;:@')

#: Unicode general categories that must never be part of an identity: controls,
#: format characters (including bidi overrides), surrogates, private use and
#: unassigned code points.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


class AddressError(ValueError):
    """An envelope address cannot be assigned a trustworthy identity."""

    basis = "invalid-address"


class SMTPUTF8Required(AddressError):
    """The address contains Unicode but SMTPUTF8 was not negotiated."""

    basis = "smtputf8-not-negotiated"


class SMTPUTF8Disabled(AddressError):
    """The address contains Unicode but the server does not offer SMTPUTF8."""

    basis = "smtputf8-disabled"


@dataclass(frozen=True)
class ParsedAddress:
    """A canonical mailbox identity.

    ``local`` is the semantic local-part with quoting removed, but case and
    Unicode code points are preserved.  ``domain`` is an A-label or a
    validated address literal (including its brackets).
    """

    local: str
    domain: str
    quoted: bool = False
    address_literal: bool = False

    @property
    def null(self) -> bool:
        return False

    @property
    def identity(self) -> str:
        return f"{_quote_local(self.local)}@{self.domain}"

    @property
    def match_key(self) -> Tuple[str, str, str]:
        return ("mailbox", _quote_local(self.local), self.domain)

    def __str__(self) -> str:
        return self.identity


@dataclass(frozen=True)
class NullReversePath:
    """The null reverse-path, kept distinct from an empty local-part."""

    @property
    def null(self) -> bool:
        return True

    @property
    def identity(self) -> str:
        return NULL_ADDRESS

    @property
    def match_key(self) -> Tuple[str]:
        return ("null",)

    def __str__(self) -> str:
        return NULL_ADDRESS


AddressIdentity = Union[ParsedAddress, NullReversePath]
MatchKey = Tuple[Union[str, Tuple[str]]]


@dataclass(frozen=True)
class AuthIdentity:
    """The authenticated identity attached to ``session.auth_data``.

    The submission username is not a mailbox and has no local-part semantics;
    treat it as an opaque key into :class:`SenderPolicy`.
    """

    username: str


def _quote_local(local: str) -> str:
    """Render a local-part in a wire-safe form, preserving its code points.

    A dot-string is emitted as-is only when every atom is valid SMTP atext.
    Unicode local-parts are emitted as a quoted-string instead: RFC 6531
    permits UTF-8 in a quoted-string without inventing new atom rules, and the
    quoted form is unambiguous when the exact code points are what matter.
    """
    if local and not local.startswith(".") and not local.endswith("."):
        atoms = local.split(".")
        if all(atom and all(ch in _ATEXT for ch in atom) for atom in atoms):
            return local
    escaped = local.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _has_unsafe_unicode(text: str) -> Optional[str]:
    for ch in text:
        if unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            return f"unsafe U+{ord(ch):04X} ({unicodedata.category(ch)})"
    return None


def _has_non_ascii(text: str) -> bool:
    return any(ord(ch) > 127 for ch in text)


class IdnaPolicy:
    """One explicit, immutable IDNA mapping policy.

    Strict IDNA2008 (``uts46=False``) with STD3 rules is used.  ASCII domain
    letters are lowercased first because DNS is case-insensitive.  U-labels
    must already be lowercase NFC; uppercase or compatibility forms are
    rejected instead of being folded onto another identity.
    """

    def __init__(
        self,
        *,
        uts46: bool = False,
        transitional: bool = False,
        std3_rules: bool = True,
    ) -> None:
        self.uts46 = uts46
        self.transitional = transitional
        self.std3_rules = std3_rules

    def canonicalize(self, domain: str) -> str:
        if not domain:
            raise AddressError("empty domain")
        problem = _has_unsafe_unicode(domain)
        if problem is not None:
            raise AddressError(f"domain contains {problem}")
        if any(ch.isspace() or ch in _FORBIDDEN_DOMAIN_CHARS for ch in domain):
            raise AddressError("domain contains a forbidden character")
        # A single trailing dot is the explicit FQDN form and is equivalent to
        # the bare name.  Any other empty label is rejected by idna below.
        if domain.endswith("."):
            # Only one trailing dot (the explicit FQDN form) is accepted.
            # A second empty label is malformed, and idna itself would
            # otherwise treat both spellings as the same name.
            domain = domain[:-1]
            if domain.endswith("."):
                raise AddressError("empty domain label")
        if not domain:
            raise AddressError("empty domain")
        ascii_lowered = domain.translate(_ASCII_DOMAIN_UPPER)
        try:
            wire = idna.encode(
                ascii_lowered,
                uts46=self.uts46,
                transitional=self.transitional,
                std3_rules=self.std3_rules,
            ).decode("ascii")
        except (IDNAError, UnicodeError) as error:
            raise AddressError(f"domain failed IDNA: {error}") from error
        return wire.rstrip(".")


DEFAULT_IDNA_POLICY = IdnaPolicy()


def _parse_address_literal(domain: str) -> str:
    if not (domain.startswith("[") and domain.endswith("]")):
        raise AddressError("unbalanced address literal")
    body = domain[1:-1]
    try:
        if body.startswith("IPv6:"):
            parsed = ip_address(body[5:])
            if parsed.version != 6:
                raise AddressError("IPv6 literal contains an IPv4 address")
            # RFC 5321 spells the tag case-insensitively; the canonical
            # spelling used in identities is the standard uppercase tag.
            return f"[IPv6:{parsed.compressed}]"
        parsed = ip_address(body)
        if parsed.version != 4:
            raise AddressError("address literal is not IPv4")
        return f"[{parsed.compressed}]"
    except ValueError as error:
        raise AddressError(f"invalid address literal: {error}") from error


def _split_local_domain(address: str) -> Tuple[str, str, bool]:
    """Split an addr-spec without decoding a quoted local-part."""
    if address.startswith('"'):
        escaped = False
        closing = -1
        for index, ch in enumerate(address[1:], start=1):
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                closing = index
                break
        if closing < 0:
            raise AddressError("unterminated quoted local-part")
        if closing + 1 >= len(address) or address[closing + 1] != "@":
            raise AddressError("quoted local-part is not followed by '@'")
        return address[: closing + 1], address[closing + 2:], True

    if address.count("@") != 1:
        raise AddressError("address does not have exactly one unquoted '@'")
    local, domain = address.split("@")
    return local, domain, False


def _unquote_local(raw: str) -> str:
    if not (raw.startswith('"') and raw.endswith('"')):
        raise AddressError("malformed quoted local-part")
    body = raw[1:-1]
    chars = []
    escaped = False
    for ch in body:
        if escaped:
            # RFC 5321 quoted-pairSMTP is backslash plus an ASCII graphic or
            # space.  Non-ASCII quoted-pairs are not permitted by SMTPUTF8's
            # mailbox ABNF, so they are rejected rather than reinterpreted.
            if ord(ch) > 126:
                raise AddressError("non-ASCII quoted-pair in local-part")
            chars.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            raise AddressError("unescaped quote in quoted local-part")
        else:
            chars.append(ch)
    if escaped:
        raise AddressError("trailing escape in quoted local-part")
    return "".join(chars)


def _validate_unquoted_local(local: str) -> None:
    if not local:
        raise AddressError("empty local-part")
    atoms = local.split(".")
    if any(not atom for atom in atoms):
        raise AddressError("empty atom in local-part")
    for atom in atoms:
        for ch in atom:
            if ch in _ATEXT:
                continue
            if ord(ch) > 127 and not ch.isspace():
                continue
            raise AddressError(f"invalid character U+{ord(ch):04X} in local-part")


def _parse_local(raw_local: str, quoted: bool) -> str:
    local = _unquote_local(raw_local) if quoted else raw_local
    problem = _has_unsafe_unicode(local)
    if problem is not None:
        raise AddressError(f"local-part contains {problem}")
    if quoted:
        # Quoted-string permits spaces and most graphics, but never the SMTP
        # line delimiters.  Everything else keeps its exact code points.
        if any(ch in "\r\n" for ch in local):
            raise AddressError("newline in local-part")
    else:
        _validate_unquoted_local(local)
    # Both forms must be non-empty; notably `""@example.com` is not the null
    # reverse-path and has no sender identity.
    if not local:
        raise AddressError("empty local-part")
    return local


def parse_envelope_address(
    address: str,
    *,
    smtp_utf8: bool,
    smtp_utf8_enabled: bool = True,
    idna_policy: IdnaPolicy = DEFAULT_IDNA_POLICY,
) -> AddressIdentity:
    """Parse the address delivered to ``handle_MAIL`` into an identity.

    ``smtp_utf8`` must be the MAIL command's SMTPUTF8 assertion, not merely
    the server's capability.  Non-ASCII local or domain text is rejected when
    that assertion is absent, even if the protocol layer already decoded it.

    ``<>`` is the null reverse-path; ``""@example.com`` is an empty local-part
    and is rejected as malformed.
    """
    if not isinstance(address, str):
        raise AddressError("address is not text")
    if address == NULL_ADDRESS:
        return NullReversePath()
    if not address:
        raise AddressError("empty address")
    if address.startswith("<") or address.endswith(">"):
        raise AddressError("unexpected angle-address form")
    problem = _has_unsafe_unicode(address)
    if problem is not None:
        raise AddressError(f"address contains {problem}")

    non_ascii = _has_non_ascii(address)
    if non_ascii and not smtp_utf8_enabled:
        raise SMTPUTF8Disabled("SMTPUTF8 is not enabled on this server")

    raw_local, raw_domain, quoted = _split_local_domain(address)
    local = _parse_local(raw_local, quoted)

    if non_ascii and not smtp_utf8:
        raise SMTPUTF8Required(
            "non-ASCII envelope address requires the SMTPUTF8 parameter"
        )

    if raw_domain.startswith("[") or raw_domain.endswith("]"):
        domain = _parse_address_literal(raw_domain)
        return ParsedAddress(
            local=local, domain=domain, quoted=quoted, address_literal=True
        )

    domain = idna_policy.canonicalize(raw_domain)
    return ParsedAddress(local=local, domain=domain, quoted=quoted)


@dataclass(frozen=True)
class SenderDecision:
    """The result of sender authorization, including the match basis."""

    allowed: bool
    identity: Optional[AddressIdentity]
    basis: str
    reason: str = ""
    status: str = "250 OK"

    @property
    def canonical(self) -> Optional[str]:
        return None if self.identity is None else self.identity.identity

    @property
    def is_null(self) -> bool:
        return self.identity is not None and self.identity.null


def _deny(
    basis: str,
    reason: str,
    status: str,
    identity: Optional[AddressIdentity] = None,
) -> SenderDecision:
    return SenderDecision(
        allowed=False,
        identity=identity,
        basis=basis,
        reason=reason,
        status=status,
    )


class SenderPolicy:
    """Map authenticated users to exact envelope-sender identities.

    ``allowed_senders`` is ``{authenticated_username: [authorized address,
    ...]}``.  Every configured address is parsed with the same rules as wire
    input, so aliases may be written as U-labels or A-labels and still match
    the same canonical identity.  There are no prefix, domain-wide, case-folded
    local-part, or plus-address matches.
    """

    def __init__(
        self,
        allowed_senders: Mapping[str, Iterable[str]],
        *,
        allow_null_reverse_path: bool = False,
        idna_policy: IdnaPolicy = DEFAULT_IDNA_POLICY,
    ) -> None:
        self.idna_policy = idna_policy
        self.allow_null_reverse_path = allow_null_reverse_path
        self._aliases: Dict[str, Dict[MatchKey, str]] = {}
        for username, addresses in allowed_senders.items():
            if not isinstance(username, str) or not username:
                raise ValueError("authenticated usernames must be non-empty strings")
            table: Dict[MatchKey, str] = {}
            for address in addresses:
                identity = parse_envelope_address(
                    address,
                    smtp_utf8=True,
                    smtp_utf8_enabled=True,
                    idna_policy=idna_policy,
                )
                # First configured spelling becomes the audit basis; matching
                # itself uses only the canonical key.
                table.setdefault(identity.match_key, identity.identity)
            self._aliases[username] = table

    def allowed_aliases(self, username: str) -> Tuple[str, ...]:
        return tuple(self._aliases.get(username, {}).values())

    def _null_allowed_for(self, username: str) -> bool:
        return self.allow_null_reverse_path or ("null",) in self._aliases.get(
            username, {}
        )

    def null_allowed_for(self, username: str) -> bool:
        """Whether the null reverse-path is allowed for this user.

        Kept public so deployment code can render its policy (and tests can
        assert the exact effective decision) without duplicating the trigger
        conditions of :meth:`authorize`.
        """
        return self._null_allowed_for(username)

    def authorize(
        self,
        username: Optional[str],
        address: str,
        *,
        smtp_utf8: bool,
        smtp_utf8_enabled: bool = True,
        authenticated: bool = True,
    ) -> SenderDecision:
        """Authorize one ``MAIL FROM`` value for an authenticated user."""
        if not authenticated or username is None:
            return _deny(
                "unauthenticated",
                "no authenticated submission identity",
                "530 5.7.0 Authentication required",
            )
        try:
            identity = parse_envelope_address(
                address,
                smtp_utf8=smtp_utf8,
                smtp_utf8_enabled=smtp_utf8_enabled,
                idna_policy=self.idna_policy,
            )
        except SMTPUTF8Disabled as error:
            return _deny(error.basis, str(error), "550 5.6.7 SMTPUTF8 not enabled")
        except SMTPUTF8Required as error:
            return _deny(
                error.basis,
                str(error),
                "550 5.6.7 Non-ASCII address requires SMTPUTF8",
            )
        except AddressError as error:
            return _deny(error.basis, str(error), "553 5.1.3 Error: malformed address")

        if identity.null:
            if self._null_allowed_for(username):
                return SenderDecision(
                    allowed=True,
                    identity=identity,
                    basis="null-reverse-path",
                )
            return _deny(
                "null-reverse-path-denied",
                "the null reverse-path has no sender identity to authorize",
                "550 5.7.1 Null reverse-path not authorized",
                identity=identity,
            )

        aliases = self._aliases.get(username, {})
        if identity.match_key in aliases:
            return SenderDecision(
                allowed=True,
                identity=identity,
                basis=f"alias:{aliases[identity.match_key]}",
            )
        return _deny(
            "no-authorized-alias",
            "canonical identity does not match an authorized sender alias",
            "550 5.7.1 Sender address not authorized",
            identity=identity,
        )


def safe_log_value(value: object, *, limit: int = 256) -> str:
    """Return a bounded, control-character-free rendering for logs.

    The original input is still visible in ordinary cases, but newlines, bidi
    overrides, surrogates and other non-printing characters are escaped so a
    single MAIL command cannot forge another log line.
    """
    text = "<none>" if value is None else str(value)
    truncated = len(text) > limit
    if truncated:
        text = text[:limit]
    parts = []
    for ch in text:
        if unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            code = ord(ch)
            parts.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            parts.append(ch)
    if truncated:
        parts.append("...<truncated>")
    return "".join(parts)


def authenticated_username(session: object) -> Optional[str]:
    """Extract the authenticated username without trusting client text.

    The new ``AuthResult.auth_data`` API is preferred.  ``bytes`` are decoded
    strictly (never with replacement characters), so invalid UTF-8 cannot
    collapse two logins onto one user.
    """
    if getattr(session, "authenticated", None) is not True:
        return None
    auth_data = getattr(session, "auth_data", None)
    username = getattr(auth_data, "username", None)
    if username is None:
        username = getattr(auth_data, "login", None)
    if username is None:
        # Legacy auth_callback stores the value in the private slot; reading
        # the public deprecated property would emit a warning on every MAIL.
        username = getattr(session, "_login_data", None)
    if isinstance(username, bytes):
        try:
            return username.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(username, str) and username:
        return username
    return None


def log_sender_decision(
    username: Optional[str],
    original_address: object,
    decision: SenderDecision,
) -> None:
    """Log the safe original input and the basis that actually matched."""
    log.info(
        "sender-authorization user=%s original=%s identity=%s allowed=%s "
        "basis=%s reason=%s",
        safe_log_value(username),
        safe_log_value(original_address),
        safe_log_value(decision.canonical),
        decision.allowed,
        safe_log_value(decision.basis),
        safe_log_value(decision.reason),
    )


class SenderAuthorizedHandler:
    """Reusable ``handle_MAIL`` hook implementing envelope-sender policy.

    Mix this into a handler that implements the rest of the transaction, or
    subclass it.  ``envelope.mail_from`` is written only after authorization
    succeeds.  Every rejection explicitly clears it, so a later RCPT or DATA
    cannot inherit a sender from a rejected MAIL.
    """

    def __init__(self, policy: SenderPolicy) -> None:
        self.sender_policy = policy

    async def handle_MAIL(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: Collection[str],
    ) -> str:
        username = authenticated_username(session)
        decision = self.sender_policy.authorize(
            username,
            address,
            smtp_utf8=bool(getattr(envelope, "smtp_utf8", False)),
            smtp_utf8_enabled=bool(getattr(server, "enable_SMTPUTF8", False)),
            authenticated=getattr(session, "authenticated", None) is True,
        )
        log_sender_decision(username, address, decision)
        if not decision.allowed:
            # Single mutation boundary for rejection.  Do not rely on the
            # caller's "mail_from is still unset" invariant.
            envelope.mail_from = None
            return decision.status

        assert decision.canonical is not None
        envelope.mail_from = decision.canonical
        envelope.mail_options.extend(mail_options)
        return "250 OK"


# Deployers sometimes prefer these names; keep one implementation.
EnvelopeSenderAuthorizer = SenderPolicy
EnvelopeSenderGuard = SenderAuthorizedHandler

# Convenience export: the canonical result of parsing, for type checks and
# tests that need to distinguish a mailbox from the null reverse-path.
__all__ = (
    "AddressError",
    "AddressIdentity",
    "AuthIdentity",
    "EnvelopeSenderAuthorizer",
    "EnvelopeSenderGuard",
    "IdnaPolicy",
    "NULL_ADDRESS",
    "NullReversePath",
    "ParsedAddress",
    "SMTPUTF8Disabled",
    "SMTPUTF8Required",
    "SenderAuthorizedHandler",
    "SenderDecision",
    "SenderPolicy",
    "authenticated_username",
    "log_sender_decision",
    "parse_envelope_address",
    "safe_log_value",
)
