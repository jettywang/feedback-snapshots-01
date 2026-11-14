# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Restricted issuance of OpenSSH user certificates.

This module deliberately only *issues* certificates.  It does not authenticate
users or authorise logins: successfully parsing or loading a certificate says
nothing about whether a server should accept it.

The entry point is `.CertificateAuthority`, which is constructed with a
server-owned `.CertificatePolicy`.  Requests may only make the resulting
certificate narrower than that policy: they cannot add principals, extend the
validity window, or enable extensions / critical options the server did not
already approve.

Only Ed25519 user keys and Ed25519 CA keys are supported at present, as
required by the OpenSSH certificate format (``PROTOCOL.certkeys``).
"""

import os
import time
from base64 import encodebytes
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from ipaddress import ip_network
from typing import Optional

from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException
from paramiko.util import b

# OpenSSH certificate type values, from PROTOCOL.certkeys.
CERT_TYPE_USER = 1
CERT_TYPE_HOST = 2

USER_CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com"
CA_KEY_TYPE = "ssh-ed25519"


# The critical options we know how to encode safely.  Anything else in a
# request is rejected: an unknown critical option would either be silently
# ignored (dangerous) or rejected by every server (useless).
SUPPORTED_CRITICAL_OPTIONS = frozenset(("force-command", "source-address"))

_MAX_UINT64 = (1 << 64) - 1
_MAX_UINT32 = (1 << 32) - 1


class CertificateError(SSHException, ValueError):
    """
    Raised when a certificate policy or issuance request is invalid.

    It inherits from both `.SSHException` and `ValueError` so callers can use
    whichever idiom their surrounding code already uses.
    """


def _ssh_string(value):
    """
    Encode a single SSH ``string`` (uint32 length plus bytes).
    """
    value = b(value)
    if len(value) > _MAX_UINT32:
        raise CertificateError("SSH string is too long")
    return len(value).to_bytes(4, "big") + value


def _one_line_text(value, field_name):
    value = _text(value, field_name)
    if any(char in value for char in ("\x00", "\n", "\r")):
        raise CertificateError(
            "{} must not contain NUL or newline characters".format(field_name)
        )
    return value


def _text(value, field_name):
    if not isinstance(value, str):
        raise CertificateError("{} must be a string".format(field_name))
    if not value:
        raise CertificateError("{} must not be empty".format(field_name))
    return value


def _text_tuple(value, field_name):
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (bytes, bytearray)):
        raise CertificateError(
            "{} must be an iterable of strings".format(field_name)
        )
    try:
        values = tuple(value)
    except TypeError:
        raise CertificateError(
            "{} must be an iterable of strings".format(field_name)
        )
    return values


def _normalize_networks(value, field_name):
    if value is None:
        return ()
    if isinstance(value, str):
        # Convenience for the comma-separated wire form.
        parts = [part.strip() for part in value.split(",")]
    else:
        try:
            parts = list(value)
        except TypeError:
            raise CertificateError(
                "{} must be an IP network or an iterable of them".format(
                    field_name
                )
            )
    networks = []
    for part in parts:
        if not isinstance(part, str) or not part:
            raise CertificateError(
                "{} entries must be non-empty strings".format(field_name)
            )
        try:
            # strict=True rejects host bits in CIDR notation, which keeps the
            # certificate contents unambiguous.
            network = ip_network(part, strict=True)
        except ValueError as e:
            raise CertificateError(
                "invalid {} entry {!r}: {}".format(field_name, part, e)
            )
        networks.append(network)
    if len(set(networks)) != len(networks):
        raise CertificateError(
            "{} contains duplicate entries".format(field_name)
        )
    return tuple(networks)


def _network_strings(networks):
    return tuple(str(network) for network in networks)


def _is_inside_any(network, approved):
    for candidate in approved:
        # IPv4 and IPv6 networks cannot be compared with subnet_of(); they
        # are simply disjoint as far as policy is concerned.
        if network.version != candidate.version:
            continue
        if network.subnet_of(candidate):
            return True
    return False


def _fingerprint(blob):
    digest = sha256(blob).digest()
    return "SHA256:" + encodebytes(digest).decode().strip().rstrip("=")


@dataclass(frozen=True)
class CertificatePolicy:
    """
    Server-owned maximum authority for issued user certificates.

    :param principals:
        Non-empty collection of usernames the server is willing to certify.
        An empty collection is invalid: OpenSSH treats an empty ``valid
        principals`` field as "valid for every principal".
    :param int max_validity:
        Maximum certificate lifetime, in seconds, from the moment of issuance.
    :param extensions:
        Extensions the server is willing to enable.  A request may choose a
        subset of these, but cannot add anything else.  Omitting extensions
        from a request yields a certificate with no extensions at all.
    :param str force_command:
        If set, every issued certificate carries this forced command.  A
        request cannot remove or change it.
    :param source_addresses:
        If non-empty, restricts issued certificates to source networks inside
        this set.  A request may choose narrower subnets but cannot broaden
        the list or remove the restriction.
    """

    principals: tuple
    max_validity: int
    extensions: tuple = ()
    force_command: Optional[str] = None
    source_addresses: tuple = ()

    def __post_init__(self):
        object.__setattr__(
            self, "principals", _text_tuple(self.principals, "principals")
        )
        if not self.principals:
            raise CertificateError(
                "policy principals must not be empty (empty valid principals "
                "would mean every identity)"
            )
        seen = set()
        for principal in self.principals:
            _one_line_text(principal, "principal")
            if principal in seen:
                raise CertificateError(
                    "policy principals contains duplicate {!r}".format(
                        principal
                    )
                )
            seen.add(principal)

        if isinstance(self.max_validity, bool) or not isinstance(
            self.max_validity, int
        ):
            raise CertificateError("max_validity must be an integer")
        if self.max_validity <= 0 or self.max_validity > _MAX_UINT64:
            raise CertificateError(
                "max_validity must be a positive number of seconds"
            )

        object.__setattr__(
            self, "extensions", _text_tuple(self.extensions, "extensions")
        )
        seen = set()
        for extension in self.extensions:
            _one_line_text(extension, "extension")
            if extension in seen:
                raise CertificateError(
                    "policy extensions contains duplicate {!r}".format(
                        extension
                    )
                )
            seen.add(extension)

        if self.force_command is not None:
            _one_line_text(self.force_command, "force_command")

        object.__setattr__(
            self,
            "source_addresses",
            _normalize_networks(self.source_addresses, "source_addresses"),
        )


@dataclass(frozen=True)
class CertificateRequest:
    """
    A caller's (untrusted) request to narrow the server policy.

    ``principals`` must be explicitly supplied and non-empty.  ``None`` does
    not mean "all principals"; it means "reject", because an empty OpenSSH
    principal list has the dangerously broad "any principal" semantics.

    ``critical_options`` may be a mapping or an iterable of ``(name, value)``
    pairs.  Only ``force-command`` and ``source-address`` are understood, and
    supplying the same option twice (including via the convenience fields) is
    rejected rather than resolved silently.
    """

    principals: tuple = ()
    valid_after: Optional[int] = None
    valid_before: Optional[int] = None
    extensions: tuple = ()
    force_command: Optional[str] = None
    source_addresses: tuple = ()
    key_id: str = ""
    serial: int = 0
    critical_options: object = None

    def __post_init__(self):
        object.__setattr__(
            self, "principals", _text_tuple(self.principals, "principals")
        )
        object.__setattr__(
            self, "extensions", _text_tuple(self.extensions, "extensions")
        )
        if isinstance(self.source_addresses, str):
            parts = [
                part.strip()
                for part in self.source_addresses.split(",")
                if part.strip()
            ]
            object.__setattr__(self, "source_addresses", tuple(parts))
        else:
            object.__setattr__(
                self,
                "source_addresses",
                _text_tuple(self.source_addresses, "source_addresses"),
            )
        if self.force_command is not None:
            _one_line_text(self.force_command, "force_command")
        if not isinstance(self.key_id, str):
            raise CertificateError("key_id must be a string")
        if any(char in self.key_id for char in ("\x00", "\n", "\r")):
            raise CertificateError(
                "key_id must not contain NUL or newline characters"
            )


class CertificateAudit(dict):
    """
    Public audit fields for an issued certificate.

    Supports both mapping access (``audit["principals"]``) and attribute access
    (``audit.principals``).  It intentionally contains no private key data and
    no authentication/authorisation result.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


class SignedCertificate:
    """
    A signed public OpenSSH user certificate, plus public audit metadata.

    This object exposes only public material.  It does not hold, and never
    serialises, the CA private key.  Loading the returned certificate with
    `PKey.load_certificate <paramiko.pkey.PKey.load_certificate>` only attaches
    the certificate to a key; it is not an authentication or authorisation
    decision.
    """

    def __init__(self, blob, audit, comment=""):
        self._blob = blob
        self._audit = audit
        self._comment = comment

    @property
    def certificate(self):
        """
        The OpenSSH one-line public certificate, i.e.
        ``<type> <base64> [comment]``.
        """
        encoded = encodebytes(self._blob).decode().replace("\n", "")
        line = "{} {}".format(USER_CERT_TYPE, encoded)
        if self._comment:
            line += " {}".format(self._comment)
        return line

    @property
    def audit(self):
        """
        A `.CertificateAudit` mapping of public fields describing the issuance.
        """
        return self._audit

    @property
    def blob(self):
        """
        The raw certificate blob (public bytes only).
        """
        return self._blob

    def to_string(self):
        """
        Return the OpenSSH one-line public certificate, suitable for
        ``PKey.load_certificate`` or writing to a ``-cert.pub`` file.
        """
        return self.certificate

    def to_dict(self):
        """
        Return the issuance output as ``{"certificate": ..., "audit": ...}``.

        The certificate is public material only, and the audit mapping holds
        public descriptive fields only.
        """
        return {"certificate": self.certificate, "audit": dict(self._audit)}

    def asbytes(self):
        return self._blob

    def __bytes__(self):
        return self._blob

    def __str__(self):
        return self.certificate

    def __repr__(self):
        return (
            "SignedCertificate(key_id={!r}, serial={!r}, principals={!r}, "
            "valid_after={!r}, valid_before={!r})"
        ).format(
            self._audit.get("key_id"),
            self._audit.get("serial"),
            self._audit.get("principals"),
            self._audit.get("valid_after"),
            self._audit.get("valid_before"),
        )


class CertificateAuthority:
    """
    Issue restricted OpenSSH user certificates with a fixed Ed25519 CA key.

    :param ca_key:
        A private `.Ed25519Key` with signing capability.  Certificate CAs
        (chained certificates) are not supported and are rejected.
    :param CertificatePolicy policy:
        Server-owned maximum principal/validity/extension policy.
    :param clock:
        Optional callable returning the current Unix time; useful for tests.
    """

    def __init__(self, ca_key, policy, clock=None):
        if not isinstance(policy, CertificatePolicy):
            raise TypeError("policy must be a CertificatePolicy")
        if not isinstance(ca_key, PKey):
            raise TypeError("ca_key must be a PKey")
        if ca_key.get_name() != CA_KEY_TYPE:
            raise CertificateError(
                "CA key must be an Ed25519 key, not {}".format(
                    ca_key.get_name()
                )
            )
        if getattr(ca_key, "public_blob", None) is not None:
            raise CertificateError(
                "CA key must be a plain key, not a certificate"
            )
        if not ca_key.can_sign():
            raise CertificateError(
                "CA key must include private signing material"
            )
        self._ca_key = ca_key
        self._policy = policy
        self._clock = clock or time.time
        self._ca_public = self._public_key_bytes(ca_key)
        self._ca_fingerprint = ca_key.fingerprint

    @property
    def policy(self):
        return self._policy

    @property
    def ca_fingerprint(self):
        return self._ca_fingerprint

    def issue(self, user_key, request=None, **request_kwargs):
        """
        Issue a signed user certificate.

        ``request`` may be a `.CertificateRequest`; alternatively, pass
        ``CertificateRequest`` keyword arguments directly.  The result is a
        `.SignedCertificate` containing the public certificate and audit
        fields, never the CA private key.
        """
        if request is None:
            request = CertificateRequest(**request_kwargs)
        elif request_kwargs:
            raise TypeError(
                "pass either a CertificateRequest or request keyword "
                "arguments, not both"
            )
        elif isinstance(request, Mapping):
            request = CertificateRequest(**dict(request))
        elif not isinstance(request, CertificateRequest):
            raise TypeError("request must be a CertificateRequest")

        user_public = self._validate_user_key(user_key)
        now = self._now()
        principals = self._resolve_principals(request.principals)
        valid_after, valid_before = self._resolve_validity(request, now)
        extensions = self._resolve_extensions(request.extensions)
        force_command, source_addresses = self._resolve_critical_options(
            request
        )
        key_id = self._validate_key_id(request.key_id)
        serial = self._validate_serial(request.serial)

        cert = self._build_unsigned(
            user_public=user_public,
            serial=serial,
            key_id=key_id,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            extensions=extensions,
            force_command=force_command,
            source_addresses=source_addresses,
        )
        signature = self._ca_key.sign_ssh_data(cert).asbytes()
        # Defensive check: a CA object must produce the Ed25519 signature
        # algorithm we are about to place in the certificate.
        sig_msg = Message(signature)
        if sig_msg.get_text() != CA_KEY_TYPE:
            raise CertificateError(
                "CA key produced an unexpected signature algorithm"
            )
        blob = cert + _ssh_string(signature)

        signature_fields = self._critical_option_pairs(
            force_command, source_addresses
        )
        audit = CertificateAudit(
            certificate_type="user",
            certificate_type_id=CERT_TYPE_USER,
            key_id=key_id,
            serial=serial,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            validity_seconds=valid_before - valid_after,
            extensions=extensions,
            critical_options=tuple(name for name, _ in signature_fields),
            force_command=force_command,
            source_addresses=source_addresses,
            signature_algorithm=CA_KEY_TYPE,
            ca_fingerprint=self._ca_fingerprint,
            user_fingerprint=fingerprint_for_public_key(user_public),
            certificate_fingerprint=_fingerprint(blob),
        )
        return SignedCertificate(blob, audit, comment=key_id)

    def issue_user_certificate(self, user_key, request=None, **kwargs):
        """
        Alias for `.issue`, matching the name of the module-level helper.
        """
        return self.issue(user_key, request=request, **kwargs)

    # ... internals ...

    def _now(self):
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CertificateError("clock must return a Unix timestamp")
        value = int(value)
        if value < 0 or value > _MAX_UINT64:
            raise CertificateError("clock returned an out-of-range timestamp")
        return value

    def _public_key_bytes(self, key):
        blob = key.asbytes()
        msg = Message(blob)
        key_type = msg.get_text()
        if key_type != CA_KEY_TYPE:
            raise CertificateError(
                "CA key must be an Ed25519 key, not {}".format(key_type)
            )
        public = msg.get_binary()
        if len(public) != 32 or msg.get_remainder():
            raise CertificateError("invalid Ed25519 CA public key")
        return public

    def _validate_user_key(self, user_key):
        if not isinstance(user_key, PKey):
            raise TypeError("user_key must be a PKey")
        if user_key.get_name() != CA_KEY_TYPE:
            raise CertificateError(
                "user key must be an Ed25519 key, not {}".format(
                    user_key.get_name()
                )
            )
        if getattr(user_key, "public_blob", None) is not None:
            raise CertificateError(
                "user key must be a plain key, not a certificate"
            )
        blob = user_key.asbytes()
        msg = Message(blob)
        key_type = msg.get_text()
        public = msg.get_binary()
        if key_type != CA_KEY_TYPE or len(public) != 32:
            raise CertificateError("invalid Ed25519 user public key")
        if msg.get_remainder():
            raise CertificateError("invalid Ed25519 user public key")
        if public == self._ca_public:
            raise CertificateError(
                "CA key and user key must be different keys"
            )
        return public

    def _resolve_principals(self, requested):
        if not requested:
            raise CertificateError(
                "request must name at least one principal; an empty principal "
                "list would certify every identity"
            )
        approved = set(self._policy.principals)
        seen = set()
        result = []
        for principal in requested:
            _one_line_text(principal, "principal")
            if principal in seen:
                raise CertificateError(
                    "request principals contains duplicate {!r}".format(
                        principal
                    )
                )
            if principal not in approved:
                raise CertificateError(
                    "principal {!r} is not approved by policy".format(
                        principal
                    )
                )
            seen.add(principal)
            result.append(principal)
        return tuple(result)

    def _resolve_validity(self, request, now):
        max_validity = self._policy.max_validity
        valid_after = request.valid_after
        valid_before = request.valid_before
        if valid_after is None:
            valid_after = now
        if valid_before is None:
            valid_before = now + max_validity
        for name, value in (
            ("valid_after", valid_after),
            ("valid_before", valid_before),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise CertificateError("{} must be an integer".format(name))
            if value < 0 or value > _MAX_UINT64:
                raise CertificateError("{} is out of range".format(name))
        if valid_after < now:
            raise CertificateError(
                "requested validity starts before issuance time"
            )
        if valid_before > now + max_validity:
            raise CertificateError(
                "requested validity exceeds policy maximum of {} "
                "seconds".format(max_validity)
            )
        if valid_before <= valid_after:
            raise CertificateError(
                "valid_before must be later than valid_after"
            )
        return valid_after, valid_before

    def _resolve_extensions(self, requested):
        if not requested:
            # Narrowest safe interpretation: no extensions at all.
            return ()
        approved = set(self._policy.extensions)
        seen = set()
        result = []
        for extension in requested:
            _one_line_text(extension, "extension")
            if extension in seen:
                raise CertificateError(
                    "request extensions contains duplicate {!r}".format(
                        extension
                    )
                )
            if extension not in approved:
                raise CertificateError(
                    "extension {!r} is not approved by policy".format(
                        extension
                    )
                )
            seen.add(extension)
            result.append(extension)
        return tuple(sorted(result))

    def _resolve_critical_options(self, request):
        """
        Merge explicit request fields with a critical_options mapping,
        rejecting duplicate or unknown names rather than picking one silently.
        """
        raw = request.critical_options
        supplied = {}
        if raw is not None:
            if isinstance(raw, Mapping):
                items = list(raw.items())
            else:
                try:
                    items = list(raw)
                except TypeError:
                    raise CertificateError(
                        "critical_options must be a mapping or iterable of "
                        "(name, value) pairs"
                    )
            for item in items:
                # Accept any two-item sequence, so JSON-decoded lists work too.
                if isinstance(item, (str, bytes)) or len(item) != 2:
                    raise CertificateError(
                        "critical_options entries must be (name, value) pairs"
                    )
                name, value = item
                name = _one_line_text(name, "critical option name")
                if name in supplied:
                    raise CertificateError(
                        "critical option {!r} supplied more than once".format(
                            name
                        )
                    )
                if name not in SUPPORTED_CRITICAL_OPTIONS:
                    raise CertificateError(
                        "unsupported critical option {!r}".format(name)
                    )
                if value is None:
                    raise CertificateError(
                        "critical option {!r} must not be null".format(name)
                    )
                if isinstance(value, str) and not value:
                    raise CertificateError(
                        "critical option {!r} must not be empty".format(name)
                    )
                supplied[name] = value

        if request.force_command is not None:
            if "force-command" in supplied:
                raise CertificateError(
                    "critical option 'force-command' supplied more than once"
                )
            supplied["force-command"] = request.force_command
        if request.source_addresses:
            if "source-address" in supplied:
                raise CertificateError(
                    "critical option 'source-address' supplied more than once"
                )
            supplied["source-address"] = request.source_addresses

        force_command = self._resolve_force_command(
            supplied.get("force-command")
        )
        source_addresses = self._resolve_source_addresses(
            supplied.get("source-address")
        )
        return force_command, source_addresses

    def _resolve_force_command(self, requested):
        policy_command = self._policy.force_command
        if policy_command is None:
            if requested is not None:
                raise CertificateError(
                    "force-command is not approved by policy"
                )
            return None
        if requested is None:
            # The policy restriction applies even if the request omitted it.
            return policy_command
        requested = _one_line_text(requested, "force-command")
        if requested != policy_command:
            raise CertificateError(
                "force-command does not match the approved policy"
            )
        return policy_command

    def _resolve_source_addresses(self, requested):
        approved = self._policy.source_addresses
        if not approved:
            if requested not in (None, (), ""):
                raise CertificateError(
                    "source-address is not approved by policy"
                )
            return ()

        if requested in (None, (), ""):
            # Apply the policy restriction rather than silently dropping it.
            return _network_strings(approved)

        networks = _normalize_networks(requested, "source-address")
        if not networks:
            raise CertificateError("source-address must not be empty")
        for network in networks:
            if not _is_inside_any(network, approved):
                raise CertificateError(
                    "source-address {!r} is outside the approved "
                    "policy".format(str(network))
                )
        return _network_strings(networks)

    def _validate_key_id(self, key_id):
        if not isinstance(key_id, str):
            raise CertificateError("key_id must be a string")
        if any(char in key_id for char in ("\x00", "\n", "\r")):
            raise CertificateError(
                "key_id must not contain NUL or newline characters"
            )
        return key_id

    def _validate_serial(self, serial):
        if isinstance(serial, bool) or not isinstance(serial, int):
            raise CertificateError("serial must be an integer")
        if serial < 0 or serial > _MAX_UINT64:
            raise CertificateError("serial is out of range")
        return serial

    def _critical_option_pairs(self, force_command, source_addresses):
        # Per PROTOCOL.certkeys, each critical option's data field is itself an
        # SSH string wrapping the option-specific payload.  force-command and
        # source-address both wrap a single string.
        pairs = []
        if force_command is not None:
            pairs.append(("force-command", _ssh_string(b(force_command))))
        if source_addresses:
            addresses = ",".join(source_addresses)
            pairs.append(("source-address", _ssh_string(b(addresses))))
        return tuple(pairs)

    def _build_unsigned(
        self,
        *,
        user_public,
        serial,
        key_id,
        principals,
        valid_after,
        valid_before,
        extensions,
        force_command,
        source_addresses,
    ):
        principals_blob = Message()
        for principal in principals:
            principals_blob.add_string(principal)

        critical_options = Message()
        for name, encoded_value in self._critical_option_pairs(
            force_command, source_addresses
        ):
            critical_options.add_string(name)
            critical_options.add_string(encoded_value)

        extensions_blob = Message()
        for extension in sorted(extensions):
            extensions_blob.add_string(extension)
            # Extensions have an empty data value, encoded as a plain empty
            # SSH string (not a nested string).
            extensions_blob.add_string(b"")

        cert = Message()
        cert.add_string(USER_CERT_TYPE)
        cert.add_string(os.urandom(32))
        cert.add_string(user_public)
        cert.add_int64(serial)
        cert.add_int(CERT_TYPE_USER)
        cert.add_string(key_id)
        cert.add_string(principals_blob.asbytes())
        cert.add_int64(valid_after)
        cert.add_int64(valid_before)
        cert.add_string(critical_options.asbytes())
        cert.add_string(extensions_blob.asbytes())
        cert.add_string(b"")
        # The signature covers everything up to and including this field.
        cert.add_string(self._ca_key.asbytes())
        return cert.asbytes()


def fingerprint_for_public_key(public_key_bytes):
    """
    Return the OpenSSH-style SHA256 fingerprint of an Ed25519 public key.
    """
    return _fingerprint(
        _ssh_string(CA_KEY_TYPE) + _ssh_string(public_key_bytes)
    )


def issue_user_certificate(
    ca_key, user_key, policy, request=None, clock=None, **kwargs
):
    """
    Convenience wrapper around `.CertificateAuthority.issue`.

    ``request`` is a `.CertificateRequest`, or keyword arguments accepted by
    that class.  The return value contains only the public certificate and
    public audit fields.
    """
    ca = CertificateAuthority(ca_key, policy, clock=clock)
    return ca.issue(user_key, request=request, **kwargs)
