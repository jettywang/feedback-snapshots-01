# Copyright: (c) 2024, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Instance level NTLM acceptor credential resolution.

The NTLM acceptor needs access to the LM/NT hashes of the accounts it
authenticates. Historically these were only available through a single flat
file pointed at by the ``NTLM_USER_FILE`` environment variable which made it
impossible to host more than one tenant, each with its own credential set, in
the same process.

The classes in this module provide an explicit per-context resolution path. A
resolver looks credentials up by the exact domain and username advertised in
the NTLM ``AUTHENTICATE`` message and never falls back to another tenant or a
process wide default when no match is found. Every resolution is tagged with a
:class:`NTLMCredentialVersion` so an acceptor can detect a credential rotation
that happens while a handshake is in flight.
"""

import abc
import base64
import dataclasses
import enum
import os
import typing

from spnego._context import split_username
from spnego._ntlm_raw.crypto import lmowfv1, ntowfv1
from spnego._text import to_text
from spnego.exceptions import NoCredentialError


@dataclasses.dataclass(frozen=True)
class NTLMCredentialVersion:
    """Opaque revision marker for a resolved credential.

    The value only identifies which revision of the backing store a
    credential came from. It is safe to log and surface in error messages as it
    never contains password or hash material. Two versions compare equal when
    they describe the same store revision.
    """

    source: str
    revision: str

    def __str__(self) -> str:
        return f"{self.source}@{self.revision}"


@dataclasses.dataclass(frozen=True)
class ResolvedNTLMCredential:
    """The credential a resolver matched for a single NTLM identity.

    Attributes:
        domain: The domain the account belongs to. An empty string represents
            an account that advertised no domain.
        username: The username the account was matched on.
        lm_hash: The LM hash used for legacy NTLMv1 responses.
        nt_hash: The NT hash used for NTLMv1/NTLMv2 responses.
        version: The revision of the backing store this credential came from.
    """

    domain: str
    username: str
    lm_hash: bytes = dataclasses.field(repr=False)
    nt_hash: bytes = dataclasses.field(repr=False)
    version: NTLMCredentialVersion = dataclasses.field(repr=False)

    def __post_init__(self) -> None:
        if not self.username:
            raise ValueError("A resolved NTLM credential requires a username")

        if len(self.lm_hash) != 16 or len(self.nt_hash) != 16:
            raise ValueError("NTLM LM and NT hashes must be exactly 16 bytes")


class NTLMCredentialRotationPolicy(enum.Enum):
    """How an acceptor reacts to a mid-handshake credential rotation."""

    pin = "pin"
    """Reject the handshake when the store revision captured from the
    ``NEGOTIATE`` message no longer matches the revision returned when the
    ``AUTHENTICATE`` message is resolved. Each completed handshake therefore
    uses a single, consistent credential version."""

    reload = "reload"
    """Resolve the ``AUTHENTICATE`` identity against the current store and
    validate the response against the freshly resolved credential even when the
    store was rotated while the handshake was in flight."""


class NTLMCredentialResolver(abc.ABC):
    """Resolves NTLM acceptor credentials for a specific instance.

    A resolver is bound to a single acceptor instance, for example one test
    tenant. Lookups use the exact domain and username from the peer's
    ``AUTHENTICATE`` message. A missing match raises
    :class:`spnego.exceptions.NoCredentialError` rather than falling back to
    another tenant or a process default.
    """

    @abc.abstractmethod
    def current_version(self) -> NTLMCredentialVersion:
        """The revision of the backing store at this point in time.

        The acceptor records this when it receives a ``NEGOTIATE`` message and
        compares it against the version attached to the credential resolved for
        the ``AUTHENTICATE`` message to enforce the configured
        :class:`NTLMCredentialRotationPolicy`.
        """

    @abc.abstractmethod
    def resolve(self, domain: str, username: str) -> ResolvedNTLMCredential:
        """Resolve the LM/NT hashes for an explicit identity.

        Args:
            domain: The domain advertised by the peer. An empty string means
                the peer did not advertise a domain and must only match entries
                that themselves have no domain.
            username: The username advertised by the peer.

        Raises:
            spnego.exceptions.NoCredentialError: No entry matched the exact
                domain and username pair.
        """

    def diagnostic_id(self, domain: str, username: str) -> str:
        """A safe identifier for diagnostics that contains no secret material."""
        return f"{domain}\\{username}" if domain else username


class FileNTLMCredentialResolver(NTLMCredentialResolver):
    """Resolves credentials from the NTLM flat file credential store.

    Each line in the store can be in the Heimdal format
    ``DOMAIN:USER:PASSWORD`` like::

        testdom:testuser:Password01
        :testuser@TESTDOM.COM:Password01

    Or it can use the `smbpasswd`_ file format
    ``USERNAME:UID:LM_HASH:NT_HASH:ACCT_FLAGS:TIMESTAMP`` like::

        testuser:1000:278623D830DABE161104594F8C2EF12B:C3C6F4FD8A02A6C1268F1A8074B6E7E0:[U]:LCT-1589398321
        TESTDOM\\testuser:1000:4588C64B89437893AAD3B435B51404EE:65202355FA01AEF26B89B19E00F52679:[U]:LCT-1589398321
        testuser@TESTDOM.COM:1000:00000000000000000000000000000000:8ADB9B997580D69E69CAA2BBB68F4697:[U]:LCT-1589398321

    While only the ``USERNAME``, ``LM_HASH``, and ``NT_HASH`` fields are used,
    the colons are still required to differentiate between the 2 formats.

    Domains and usernames are matched case insensitively, matching the NTLM
    wire protocol, but the domain state is significant: an identity without a
    domain only matches entries without a domain and an identity with a domain
    only matches entries that carry that same domain. Empty domains are never
    treated as wildcards.

    The same file format can also be read with gss-ntlmssp.

    .. _smbpasswd:
        https://www.samba.org/samba/docs/current/man-html/smbpasswd.5.html
    """

    def __init__(self, path: typing.Union[str, "os.PathLike[str]"]) -> None:
        self.path = os.fspath(to_text(path, encoding="utf-8"))
        if not os.path.isfile(self.path):
            raise NoCredentialError(context_msg=f"NTLM credential store does not exist or is not a file: {self.path}")

    def current_version(self) -> NTLMCredentialVersion:
        stat_result = os.stat(self.path)
        # mtime_ns detects an in-place rewrite/rotation; the size guards against
        # a same-nanosecond replacement with identical length content.
        return NTLMCredentialVersion(source=self.path, revision=f"{stat_result.st_mtime_ns}:{stat_result.st_size}")

    def resolve(self, domain: str, username: str) -> ResolvedNTLMCredential:
        version = self.current_version()

        with open(self.path, mode="rb") as fd:
            cred_text = fd.read().decode()

        for entry_domain, entry_user, password, lm_hash, nt_hash in _iter_file_entries(cred_text):
            if entry_user.upper() != username.upper() or entry_domain.upper() != domain.upper():
                continue

            if lm_hash is None:
                lm_hash = lmowfv1(password or "")
            if nt_hash is None:
                nt_hash = ntowfv1(password or "")

            return ResolvedNTLMCredential(
                domain=entry_domain,
                username=entry_user,
                lm_hash=lm_hash,
                nt_hash=nt_hash,
                version=version,
            )

        raise NoCredentialError(
            context_msg=(
                f"NTLM credential resolver found no match for {self.diagnostic_id(domain, username)} "
                f"in store {self.path} (version {version})"
            )
        )


def _iter_file_entries(
    text: str,
) -> typing.Iterator[typing.Tuple[str, str, typing.Optional[str], typing.Optional[bytes], typing.Optional[bytes]]]:
    for line in text.splitlines():
        line_split = line.split(":")

        if len(line_split) == 3:
            yield line_split[0], line_split[1], line_split[2], None, None

        elif len(line_split) == 6:
            domain_entry, user_entry = split_username(line_split[0])
            lm_entry = base64.b16decode(line_split[2].upper())
            nt_entry = base64.b16decode(line_split[3].upper())

            yield domain_entry or "", user_entry or "", None, lm_entry, nt_entry
