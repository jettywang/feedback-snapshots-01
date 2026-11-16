"""
This module is responsible for working with Cobalt Strike C2 traffic.
"""

# Python imports
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import logging
import random
import re

# Typing imports
from typing import Any, Dict, Iterable, Iterator, List, Mapping, NamedTuple, Optional, Tuple, Union, overload

# Pycryptodome imports
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
except ImportError:
    raise ImportError(
        "pycryptodome is required for Cobalt Strike C2 traffic parsing, install with `pip install pycryptodome`"
    )

# flow.record imports
try:
    from flow.record import Record, RecordDescriptor
except ImportError:
    raise ImportError("flow.record is required for logging C2 packet records, install with `pip install flow.record`")

# Local imports
from dissect.cobaltstrike.beacon import BeaconConfig  # noqa: TCH001
from dissect.cobaltstrike.c_c2 import (  # noqa: F401
    BeaconCallback,
    BeaconCommand,
    BeaconMetadata,
    CallbackPacket,
    TaskPacket,
    c2struct,
)
from dissect.cobaltstrike.utils import (
    namedtuple_reprlib_repr,
    netbios_decode,
    netbios_encode,
    p32be,
    xor,
)

TransformStep = Tuple[str, Union[str, bytes, bool, int]]
"""Type TransformStep."""
C2Packet = Union[BeaconMetadata, TaskPacket, CallbackPacket]
"""Type that is either a :class:`BeaconMetadata`, a :class:`TaskPacket` or a :class:`CallbackPacket`."""

logger = logging.getLogger(__name__)


class EncryptedPacket(NamedTuple):
    """Container to hold ciphertext and HMAC signature."""

    ciphertext: bytes
    signature: bytes

    def dumps(self):
        """Return the EncryptedPacket as a bytes object with a size frame header.

        ``| size | ciphertext | signature |``
        """
        payload = self.ciphertext + self.signature
        return p32be(len(payload)) + payload

    def raise_for_signature(self, hmac_key: bytes):
        """
        Args:
            hmac_key: HMAC key to use for signature verification
        Raises:
            ValueError: if signature of the ciphertext is incorrect.
        """
        signature = hmac.new(hmac_key, self.ciphertext, "sha256").digest()[:16]
        if signature != self.signature:
            raise ValueError(f"Invalid HMAC signature, expected {signature.hex()} got {self.signature.hex()}")


class CarrierSource(NamedTuple):
    """Description of the raw HTTP field a recovered value was read from.

    ``carrier`` is one of ``"header"``, ``"parameter"``, ``"uri"`` or ``"body"``. For headers
    and parameters, ``name`` is the original field name as it appeared on the wire (headers may
    differ in case from the configured name) and ``occurrence`` is the zero-based position
    among all fields with the same case-insensitive name. ``value`` holds the raw bytes that
    were fed into the first transform step, before any decoding.
    """

    carrier: str
    name: Optional[bytes]
    value: bytes
    occurrence: Optional[int] = None
    wire_index: Optional[int] = None
    normalized_name: bool = False

    def describe(self) -> str:
        """Return a human readable description of this source."""
        if self.carrier in ("header", "parameter"):
            where = f"{self.carrier} {self.name!r} occurrence {self.occurrence}"
            if self.wire_index is not None:
                where += f" (field #{self.wire_index} in the message)"
            if self.normalized_name:
                where += " (name lower-cased by transport)"
            return where
        if self.carrier == "uri":
            return f"request target path {self.value!r}"
        return f"message body ({len(self.value)} bytes)"


class C2Data(NamedTuple):
    """Container for holding C2 data that is used for transform and recover steps.

    ``sources`` maps a build name (``"output"``, ``"metadata"`` or ``"id"``) to the
    :class:`CarrierSource` that provided its raw bytes. It is ``None`` when the data was not
    recovered from an HTTP carrier (for example when constructing data for a transform).
    """

    output: Optional[bytes] = None
    metadata: Optional[bytes] = None
    id: Optional[bytes] = None
    sources: Optional[Dict[str, CarrierSource]] = None

    @property
    def source(self) -> Optional[CarrierSource]:
        """Return the carrier source if the data was built from exactly one source."""
        if self.sources and len(self.sources) == 1:
            return next(iter(self.sources.values()))
        return None

    def source_for(self, build: str) -> Optional[CarrierSource]:
        """Return the carrier source for the given `build`, or ``None`` if unavailable."""
        return (self.sources or {}).get(build)


class ServerC2Data(C2Data):
    """Container for holding recovered server-side C2Data."""

    def iter_encrypted_packets(self) -> Iterator[EncryptedPacket]:
        """Iterate over ``EncryptedPacket``, parsed from server-side `c2data.output` data.

        For server-side data this is always one packet.
        """
        data = self.output
        if not data:
            return
        fobj = io.BytesIO(data)
        ciphertext = fobj.read(len(data) - 16)
        signature = fobj.read(16)
        yield EncryptedPacket(ciphertext, signature)


class ClientC2Data(C2Data):
    """Container for holding recovered client-side C2Data."""

    def iter_encrypted_packets(self) -> Iterator[EncryptedPacket]:
        """Iterate over ``EncryptedPacket``, parsed from client-side `c2data.output` data.

        For client-side data this could be one or more packets.
        """
        data = self.output
        while data:
            fobj = io.BytesIO(data)
            size = c2struct.uint32(fobj)
            ciphertext = fobj.read(size - 16)
            signature = fobj.read(16)
            data = fobj.read()
            yield EncryptedPacket(ciphertext, signature)


class HttpFields:
    """Ordered, occurrence-preserving collection of HTTP header or query fields.

    HTTP field names are compared case-insensitively as mandated by the protocol, but the
    original spelling of every name is kept. Field values are kept as raw bytes and are never
    URL- or percent-decoded. Iteration yields ``(name, value)`` pairs in wire order.

    The container deliberately does not collapse repeated names. Callers that want a single
    value must ask for one explicitly through :meth:`unique`, which raises
    :class:`AmbiguousFieldError` when the name occurs more than once.
    """

    __slots__ = ("_pairs", "_normalized_transport", "_match_names", "_case_insensitive")

    def __init__(
        self,
        fields: Union[None, "HttpFields", Iterable[Tuple[bytes, bytes]], Mapping[bytes, bytes]] = None,
        normalized_transport: bool = False,
        case_insensitive: bool = True,
    ) -> None:
        if isinstance(fields, HttpFields):
            pairs = list(fields._pairs)
            normalized_transport = fields._normalized_transport or normalized_transport
            case_insensitive = fields._case_insensitive
        elif fields is None:
            pairs = []
        elif isinstance(fields, Mapping):
            pairs = list(fields.items())
        else:
            pairs = list(fields)

        # ``normalized_transport=True`` marks header names that were received from a transport
        # (e.g. httpx) that already lower-cased them. Such names can only be matched
        # case-insensitively; the original spelling is no longer available.
        self._normalized_transport = normalized_transport
        self._case_insensitive = case_insensitive
        self._pairs: List[Tuple[bytes, bytes]] = [(bytes(k), bytes(v)) for k, v in pairs]
        self._match_names = tuple(self._match_key(name) for name, _ in self._pairs)

    @property
    def normalized_transport(self) -> bool:
        """Whether the stored header names were normalized (lower-cased) by the transport."""
        return self._normalized_transport

    @property
    def case_insensitive(self) -> bool:
        """Whether names are compared case-insensitively (headers) or exactly (query parameters)."""
        return self._case_insensitive

    def _match_key(self, name: bytes) -> bytes:
        return name.lower() if self._case_insensitive else name

    def __iter__(self) -> Iterator[Tuple[bytes, bytes]]:
        return iter(self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, bytes):
            return False
        return self._match_key(name) in self._match_names

    def __getitem__(self, name: bytes) -> bytes:
        return self.unique(name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, HttpFields):
            return self._pairs == other._pairs
        if isinstance(other, Mapping):
            # Compare order-insensitively but keep occurrences, so repeated fields never
            # compare equal to a collapsed dict.
            return sorted(self._pairs) == sorted((bytes(k), bytes(v)) for k, v in other.items())
        return NotImplemented

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._pairs!r})"

    def items(self) -> Iterator[Tuple[bytes, bytes]]:
        """Iterate over all ``(name, value)`` pairs in wire order."""
        return iter(self._pairs)

    def keys(self) -> List[bytes]:
        """Return all field names in wire order, including duplicates."""
        return [name for name, _ in self._pairs]

    def values(self) -> List[bytes]:
        """Return all field values in wire order, including duplicates."""
        return [value for _, value in self._pairs]

    def get(self, name: bytes, default: Any = None) -> Any:
        """Return the unique value for `name`, or `default` if it is absent.

        Raises:
            AmbiguousFieldError: if `name` occurs more than once.
        """
        if name not in self:
            return default
        return self.unique(name)

    def get_all(self, name: bytes) -> List[bytes]:
        """Return every value for `name` in wire order.

        Names are matched case-insensitively for headers and exactly for query parameters.
        """
        needle = self._match_key(name)
        return [value for lname, (_n, value) in zip(self._match_names, self._pairs) if lname == needle]

    def names(self) -> List[bytes]:
        """Return all field names in wire order, including duplicates."""
        return [name for name, _ in self._pairs]

    def occurrences(self, name: bytes) -> List[int]:
        """Return the zero-based wire positions of every occurrence of `name`."""
        needle = self._match_key(name)
        return [idx for idx, lname in enumerate(self._match_names) if lname == needle]

    def unique(self, name: bytes) -> bytes:
        """Return the single value for `name`.

        Raises:
            MissingFieldError: if `name` does not occur.
            AmbiguousFieldError: if `name` occurs more than once, even when the repeated values
                happen to be identical, because the transport cannot attribute a recovered
                value to a unique source field.
        """
        matches = self.get_all(name)
        if not matches:
            raise MissingFieldError(name)
        if len(matches) > 1:
            raise AmbiguousFieldError(name, matches, self.occurrences(name))
        return matches[0]

    def set(self, name: bytes, value: bytes) -> None:
        """Append a `(name, value)` pair, preserving any existing occurrences."""
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            raise TypeError("HTTP field names and values must be bytes")
        self._pairs.append((name, value))
        self._match_names = self._match_names + (self._match_key(name),)

    def replace(self, name: bytes, value: bytes) -> None:
        """Set `name` to a single `value`, removing any existing occurrences.

        This is the outbound transform behaviour: a profile directive places one field on the
        wire. Inbound parsing never uses this, so repeated wire fields remain visible.
        """
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            raise TypeError("HTTP field names and values must be bytes")
        key = self._match_key(name)
        kept = [
            (existing_name, existing_value)
            for existing_name, existing_value in self._pairs
            if self._match_key(existing_name) != key
        ]
        kept.append((name, value))
        self._pairs = kept
        self._match_names = tuple(self._match_key(existing) for existing, _ in kept)


class HttpFieldError(ValueError):
    """Base class for errors that describe why an HTTP carrier field cannot be used."""


class MissingFieldError(HttpFieldError):
    """The configured carrier field is not present in the HTTP message."""

    def __init__(self, name: bytes) -> None:
        super().__init__(f"Missing HTTP field {name!r}")
        self.name = name


class AmbiguousFieldError(HttpFieldError):
    """The configured carrier field occurs more than once, so the source is not unique."""

    def __init__(self, name: bytes, values: List[bytes], positions: Optional[List[int]] = None) -> None:
        super().__init__(f"Ambiguous HTTP field {name!r}: {len(values)} occurrences with values {values!r}")
        self.name = name
        self.values = values
        self.positions = positions if positions is not None else list(range(len(values)))


class AmbiguousRequestError(ValueError):
    """The HTTP request target matches more than one configured URI, so it is not unique."""

    def __init__(self, uri: bytes, candidates: List[bytes]) -> None:
        super().__init__(f"Ambiguous request target {uri!r}: matches configured URIs {candidates!r}")
        self.uri = uri
        self.candidates = candidates


class UnrelatedRequestError(ValueError):
    """The HTTP request does not match any configured URI for the selected configuration."""

    def __init__(self, uri: bytes, method: bytes, candidates: Iterable[bytes]) -> None:
        candidates = list(candidates)
        super().__init__(
            f"Possible unrelated HTTP Request or Response, cannot find correct transform for "
            f"{method!r} {uri!r}: it does not match any configured URI {candidates!r}"
        )
        self.uri = uri
        self.method = method
        self.candidates = candidates


class FieldDecodeError(HttpFieldError):
    """A carrier field was found and unique, but a transformation failed to decode it."""

    def __init__(
        self,
        message: str,
        *,
        name: Optional[bytes] = None,
        value: Optional[bytes] = None,
        transform: Optional[str] = None,
        source: Optional["CarrierSource"] = None,
    ) -> None:
        super().__init__(message)
        self.name = name
        self.value = value
        self.transform = transform
        self.source = source


def _unique_field(fields: "HttpFields", name: bytes) -> Tuple[bytes, int]:
    """Return the single value for `name` and its occurrence index.

    Raises:
        MissingFieldError: if `name` does not occur.
        AmbiguousFieldError: if `name` occurs more than once.
    """
    matches = fields.get_all(name)
    if not matches:
        raise MissingFieldError(name)
    if len(matches) > 1:
        raise AmbiguousFieldError(name, matches, fields.occurrences(name))
    return matches[0], 0


def _field_source(carrier: str, fields: "HttpFields", name: bytes, value: bytes, occurrence: int) -> "CarrierSource":
    """Build a :class:`CarrierSource` for the selected occurrence of `name`."""
    wire_index = fields.occurrences(name)[occurrence]
    return CarrierSource(
        carrier=carrier,
        name=fields.names()[wire_index],
        value=value,
        occurrence=occurrence,
        wire_index=wire_index,
        normalized_name=fields.normalized_transport,
    )


def _decode_error(transform: str, data: bytes, source: Optional["CarrierSource"], detail: object) -> FieldDecodeError:
    """Build a :class:`FieldDecodeError` that carries the transform, source and raw input."""
    where = source.describe() if source is not None else "recovered data"
    return FieldDecodeError(
        f"Failed to decode {transform} data from {where}: {detail}",
        name=source.name if source is not None else None,
        value=data,
        transform=transform,
        source=source,
    )


class HttpRequest(NamedTuple):
    """HTTP Request container.

    The request target is kept byte-for-byte as it appeared on the wire, including any
    percent-encoded or otherwise encoded path characters. ``params`` only contains the query
    component; the path is not decoded or normalized when the message is parsed.
    """

    method: bytes
    uri: bytes
    params: HttpFields
    headers: HttpFields
    body: bytes


class HttpResponse(NamedTuple):
    """HTTP Response container."""

    status: int
    headers: HttpFields
    reason: bytes
    body: bytes
    request: Optional[HttpRequest] = None


class BeaconKeys(NamedTuple):
    """Helper container to hold beacon session keys (AES + HMAC)."""

    DEFAULT_AES_IV = b"abcdefghijklmnop"

    aes_key: Optional[bytes]
    hmac_key: Optional[bytes] = None
    iv: bytes = DEFAULT_AES_IV

    @classmethod
    def from_aes_rand(cls, aes_rand: bytes, iv: bytes = DEFAULT_AES_IV) -> "BeaconKeys":
        """Create a :class:`BeaconKeys` instance from AES random bytes."""
        aes_key, hmac_key = derive_aes_hmac_keys(aes_rand)
        return cls(aes_key=aes_key, hmac_key=hmac_key, iv=iv)

    @classmethod
    def from_beacon_metadata(cls, metadata: BeaconMetadata, iv: bytes = DEFAULT_AES_IV) -> "BeaconKeys":
        """Create a :class:`BeaconKeys` instance from :class:`BeaconMetadata`."""
        return cls.from_aes_rand(metadata.aes_rand, iv=iv)


def enable_reprlib_c2():
    """Enables reprlib __repr__ for most of the namedtuple classes in this module."""
    HttpRequest.__repr__ = namedtuple_reprlib_repr
    HttpResponse.__repr__ = namedtuple_reprlib_repr
    C2Data.__repr__ = namedtuple_reprlib_repr


def c2packet_to_record(c2packet: C2Packet) -> Record:
    """Convert `c2packet` to a flow.record."""
    fields = [("bytes", "raw_http")]
    kv = c2packet.__dict__
    for field in c2packet._type.fields:
        ftype = str(field.type)
        if ftype.startswith("char"):
            ftype = "bytes"
        elif ftype == "uint8":
            ftype = "varint"
        elif ftype in ("BeaconCommand", "BeaconCallback", "BeaconMetadata"):
            ftype = "string"
            kv[field.name] = kv[field.name].name
        elif field.name == "epoch":
            ftype = "datetime"
        elif field.name == "ip":
            ftype = "net.ipaddress"
        fields.append((ftype, field.name))
    PacketDescriptor = RecordDescriptor(f"Beacon/{c2packet._type.name}", fields)
    return PacketDescriptor(**kv)


def _parse_query(query: bytes) -> HttpFields:
    """Parse a raw query string into an occurrence-preserving :class:`HttpFields`.

    Parameter names and values are kept as raw bytes; percent escapes and ``+`` are *not*
    decoded here. Decoding is a transformation concern and must not happen before a carrier
    field has been selected.
    """
    fields = HttpFields(case_insensitive=False)
    for part in query.split(b"&"):
        if not part:
            continue
        name, sep, value = part.partition(b"=")
        fields.set(name, value if sep else b"")
    return fields


def _split_request_target(target: bytes) -> Tuple[bytes, HttpFields]:
    """Split a raw request target into a raw path and raw query fields.

    The path is returned byte-for-byte as it appeared on the wire; no percent-decoding,
    ``+`` replacement or normalization is performed.
    """
    if target.startswith((b"http://", b"https://")):
        # absolute-form request target: drop the authority without decoding the path
        scheme_end = target.index(b"://") + 3
        path_start = target.find(b"/", scheme_end)
        target = target[path_start:] if path_start != -1 else b"/"

    path, sep, query = target.partition(b"?")
    return path, _parse_query(query) if sep else HttpFields()


def parse_raw_http(data: bytes) -> Union[HttpRequest, HttpResponse]:
    """Parse a raw HTTP request/response bytes and returns a :class:`HttpRequest` or :class:`HttpResponse` accordingly.

    Header names are compared case-insensitively by consumers, but their original spelling is
    retained. Repeated headers and repeated query parameters are preserved in wire order
    instead of being collapsed into a ``dict``. Header and parameter values are kept as raw
    bytes; no percent- or URL-decoding is applied.

    Args:
        data: raw HTTP request or response data bytes.

    Returns:
        Either a :class:`HttpRequest` or a :class:`HttpResponse` object based on the data.

    Raises:
        ValueError: if it cannot be parsed as :class:`HttpRequest` or :class:`HttpResponse`.
    """

    # Accept both CRLF and bare LF line endings, and tolerate a doubled terminator.
    boundary = re.search(rb"(?:\r?\n){2,}", data)
    if boundary is None:
        head, body = data, b""
    else:
        head, body = data[: boundary.start()], data[boundary.end() :]

    first_line, sep, header_data = head.partition(b"\r\n")
    if not sep:
        first_line, sep, header_data = head.partition(b"\n")
    if not sep:
        first_line, header_data = head, b""

    headers = HttpFields()
    for header in re.split(rb"\r?\n", header_data):
        if not header:
            continue
        key, sep, value = header.partition(b":")
        if not sep:
            raise ValueError(f"Error in parsing header line: {header!r}")
        # Strip exactly the optional single space after the colon; the value is otherwise
        # preserved as raw bytes.
        if value.startswith(b" "):
            value = value[1:]
        headers.set(key, value)

    # HTTP/1.1 200 OK
    if first_line.upper().startswith(b"HTTP/"):
        parts = first_line.rstrip().split()
        if len(parts) != 3:
            raise ValueError(f"Error in parsing response status line: {first_line!r}")
        _version, status, reason = parts
        status_code = int(status.decode())
        return HttpResponse(body=body, headers=headers, status=status_code, reason=reason)

    # GET /uri HTTP/1.1
    parts = first_line.rstrip().split()
    if len(parts) != 3:
        raise ValueError(f"Error in parsing request status line: {first_line!r}")
    method, target, _version = parts

    uri, params = _split_request_target(target)
    return HttpRequest(method=method, body=body, headers=headers, uri=uri, params=params)


class HttpDataTransform:
    """Transform and recover Cobalt Strike HTTP C2 data using transformation steps."""

    def __init__(self, steps: List[TransformStep], reverse: bool = False, build: str = None) -> None:
        self.tsteps: List[TransformStep] = steps
        self.rsteps: List[TransformStep] = steps[::-1]

        if reverse:
            self.tsteps, self.rsteps = self.rsteps, self.tsteps

        if build is not None:
            build_step = ("BUILD", build)
            self.tsteps.insert(0, build_step)
            self.rsteps.append(build_step)

    @property
    def append_to_uri(self) -> bool:
        """Whether this transform appends recovered data to the request URI."""
        return any(step.lower() == "uri_append" for step, _ in self.tsteps)

    def transform(self, c2data: C2Data, request: Optional[HttpRequest] = None) -> HttpRequest:
        """Transform `c2data` information into a :class:`HttpRequest` namedtuple.

        Args:
            c2data: :class:`C2Data` named tuple that needs to be transformed
            request: Optional initial HTTP request data

        Returns:
            HttpRequest: Transformed HTTP request data
        """
        # logger.debug("transform steps: %r", self.tsteps)
        request = request or HttpRequest(
            method=b"",
            uri=b"",
            body=b"",
            params=HttpFields(case_insensitive=False),
            headers=HttpFields(),
        )
        uri = request.uri
        params = (
            request.params
            if isinstance(request.params, HttpFields)
            else HttpFields(request.params, case_insensitive=False)
        )
        headers = request.headers if isinstance(request.headers, HttpFields) else HttpFields(request.headers)
        body = request.body
        data: bytes = b""
        for step, step_val in self.tsteps:
            # logger.debug("transform step %r, %r", step, step_val)
            step = step.lower()
            if step == "append":
                if isinstance(step_val, int):
                    step_val = b"X" * step_val
                assert isinstance(step_val, bytes)
                data = data + step_val
            elif step == "prepend":
                if isinstance(step_val, int):
                    step_val = b"X" * step_val
                assert isinstance(step_val, bytes)
                data = step_val + data
            elif step == "base64":
                data = base64.b64encode(data)
            elif step == "base64url":
                data = base64.urlsafe_b64encode(data)
            elif step == "netbios":
                data = netbios_encode(data).lower()
            elif step == "netbiosu":
                data = netbios_encode(data).upper()
            elif step == "mask":
                mask = p32be(random.getrandbits(32))
                data = mask + xor(data, mask)
            elif step == "print":
                body = data
            elif step == "header":
                assert isinstance(step_val, bytes)
                headers.replace(step_val, data)
            elif step == "_header" or step == "_hostheader":
                assert isinstance(step_val, bytes)
                key, _, val = step_val.partition(b": ")
                headers.replace(key, val)
            elif step == "uri_append":
                uri += data
            elif step == "parameter" or step == "_parameter":
                assert isinstance(step_val, bytes)
                params.replace(step_val, data)
            elif step == "build":
                if step_val == "output":
                    data = c2data.output or b""
                elif step_val == "id":
                    data = c2data.id or b""
                elif step_val == "metadata":
                    data = c2data.metadata or b""
            else:
                raise ValueError("Unknown transform step with value: {}".format((step, step_val)))
        return request._replace(body=body, params=params, uri=uri, headers=headers)

    @overload
    def recover(self, http: HttpRequest) -> ClientC2Data: ...

    @overload
    def recover(self, http: HttpResponse) -> ServerC2Data: ...

    def recover(self, http: Union[HttpRequest, HttpResponse]) -> Union[ClientC2Data, ServerC2Data]:
        """Recovers the transformed data in `http` object and returns a C2Data namedtuple.

        Every carrier access is checked explicitly:

        * a missing configured header/parameter raises :class:`MissingFieldError`;
        * a configured header/parameter that occurs more than once raises
          :class:`AmbiguousFieldError`, even when the duplicate values are identical, because the
          raw source cannot be attributed uniquely;
        * data that cannot be decoded by a transformation raises :class:`FieldDecodeError`.

        On success, ``c2data.sources`` names the raw carrier (and occurrence) each built value
        was read from.

        Args:
            http: a :class:`HttpRequest` or :class:`HttpResponse` namedtuple
        Returns:
            Either a :class:`ClientC2Data` or a :class:`ServerC2Data` namedtuple based on the `http` data.

        Raises:
            HttpFieldError: if a configured carrier is missing, ambiguous or fails to decode.
        """
        assert isinstance(http, (HttpRequest, HttpResponse)), "argument should be a HttpRequest or HttpResponse"
        build_metadata = None
        build_output = None
        build_id = None
        sources: Dict[str, CarrierSource] = {}
        data = b""
        source: Optional[CarrierSource] = None
        # logger.debug("recover steps: %r", self.rsteps)
        for step, step_val in self.rsteps:
            step = step.lower()
            if step == "append":
                if isinstance(step_val, bytes):
                    step_val = len(step_val)
                assert isinstance(step_val, int)
                data = data[:-step_val]
            elif step == "prepend":
                if isinstance(step_val, bytes):
                    step_val = len(step_val)
                assert isinstance(step_val, int)
                data = data[step_val:]
            elif step == "base64":
                data = self._decode_base64(data, url=False, source=source)
            elif step == "base64url":
                data = self._decode_base64(data, url=True, source=source)
            elif step == "netbios":
                # lowercase NetBIOS encoding is recovered by upper-casing before decoding
                data = self._decode_netbios(data, upper=True, source=source)
            elif step == "netbiosu":
                data = self._decode_netbios(data, upper=False, source=source)
            elif step == "mask":
                data = xor(data[4:], data[:4])
            elif step == "print":
                data = http.body
                source = CarrierSource(carrier="body", name=None, value=data)
            elif step == "uri_append":
                assert isinstance(http, HttpRequest)
                data = http.uri
                source = CarrierSource(carrier="uri", name=None, value=data)
            elif step == "header":
                assert isinstance(http, (HttpRequest, HttpResponse))
                assert isinstance(step_val, bytes)
                data, occurrence = _unique_field(http.headers, step_val)
                source = _field_source("header", http.headers, step_val, data, occurrence)
            elif step == "parameter":
                assert isinstance(http, HttpRequest)
                assert isinstance(step_val, bytes)
                data, occurrence = _unique_field(http.params, step_val)
                source = _field_source("parameter", http.params, step_val, data, occurrence)
            elif step == "build":
                if step_val == "output":
                    build_output = data
                elif step_val == "id":
                    build_id = data
                elif step_val == "metadata":
                    build_metadata = data
                else:
                    raise ValueError(f"Unknown build step: {step_val!r}")
                if source is not None:
                    sources[step_val] = source
                source = None
            elif step in ("_header", "_hostheader"):
                pass
            else:
                raise ValueError("Unknown recover step with value: {}".format((step, step_val)))

        result = dict(output=build_output, id=build_id, metadata=build_metadata, sources=sources or None)
        if isinstance(http, HttpRequest):
            return ClientC2Data(**result)
        return ServerC2Data(**result)

    @staticmethod
    def _decode_base64(data: bytes, *, url: bool, source: Optional[CarrierSource]) -> bytes:
        # HTTP servers, proxies and header folding may introduce whitespace; the Beacon itself
        # does not, so strip only ASCII whitespace and then decode strictly.
        compact = b"".join(data.split())
        padded = compact + b"=" * (-len(compact) % 4)
        try:
            if url:
                return base64.b64decode(padded, altchars=b"-_", validate=True)
            return base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _decode_error("base64" if not url else "base64url", data, source, exc) from exc

    @staticmethod
    def _decode_netbios(data: bytes, *, upper: bool, source: Optional[CarrierSource]) -> bytes:
        encoded = data.upper() if upper else data
        if len(encoded) % 2:
            raise _decode_error("netbios", data, source, "odd number of bytes")

        for byte in encoded:
            if not (0x41 <= byte <= 0x50):
                raise _decode_error("netbios", data, source, f"invalid nibble byte {byte:#04x}")
        return netbios_decode(encoded)


def _uri_matches(configured: bytes, uri: bytes, transform: HttpDataTransform) -> bool:
    """Return whether a raw request `uri` belongs to the `configured` URI for `transform`.

    Without a ``uri-append`` transform the match must be exact, so a configured
    ``/submit.php`` never absorbs an unrelated ``/submit.php.bak`` and a configured ``/ptj``
    never absorbs ``/ptjX``. With ``uri-append`` the configured URI is the prefix the beacon
    extended on the wire.
    """
    if configured is None:
        return False
    if configured == uri:
        return True
    return transform.append_to_uri and uri.startswith(configured)


class C2Http:
    """Class for decrypting and encrypting Cobalt Strike HTTP C2 traffic.

    It requires to be initialized with a :class:`BeaconConfig` and one of the following *key* material:

        * `aes_key` and optionally `hmac_key`
        * `aes_rand`
        * `rsa_private_key` (most preferred when available)
    """

    def __init__(
        self,
        bconfig: BeaconConfig,
        aes_key: Optional[bytes] = None,
        hmac_key: Optional[bytes] = None,
        aes_rand: Optional[bytes] = None,
        rsa_private_key: Optional[RSA.RsaKey] = None,
        verify_hmac=True,
    ) -> None:
        self.bconfig = bconfig

        if aes_rand and aes_key:
            raise ValueError("Cannot specify both aes_rand and aes_key.")
        if not any([aes_key, aes_rand, rsa_private_key]):
            raise ValueError("One of the following arguments is required: aes_key, aes_rand, rsa_private_key")

        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.verify_hmac = verify_hmac

        if aes_rand:
            self.aes_key, self.hmac_key = derive_aes_hmac_keys(aes_rand)

        if self.aes_key is not None and len(self.aes_key) != 16:
            raise ValueError(f"AES key must be 16 bytes, got: {self.aes_key!r}")

        if self.hmac_key is not None and len(self.hmac_key) != 16:
            raise ValueError(f"HMAC key must be 16 bytes, got: {self.hmac_key!r}")

        self.pub = RSA.import_key(bconfig.public_key)
        self.priv = rsa_private_key
        if self.priv:
            logger.debug("RSA Private Key: %r", self.priv)
            logger.debug("RSA Public Key: %r", self.pub)
            assert self.priv.n == self.pub.n, ValueError(
                f"RSA PrivateKey does not match PublicKey pair, {self.priv.n:#x} != {self.pub.n:#x}"
            )

        if self.bconfig.is_trial:
            raise ValueError("Trial beacons are not yet supported, please submit an issue")

        # Get the different URIs used by the beacon for matching HTTP requests (note everything is in bytes)
        self.submit_uri: bytes = bconfig.settings["SETTING_SUBMITURI"].encode()
        self.submit_verb: bytes = bconfig.settings["SETTING_C2_VERB_POST"].encode()
        self.get_uris: Tuple[bytes, ...] = tuple(uri.encode() for uri in bconfig.uris)
        self.get_verb: bytes = bconfig.settings["SETTING_C2_VERB_GET"].encode()

        # Load transform/recover steps from beacon config
        self.transform_submit = HttpDataTransform(steps=bconfig.settings["SETTING_C2_POSTREQ"])
        self.transform_get = HttpDataTransform(steps=bconfig.settings["SETTING_C2_REQUEST"])
        self.transform_response = HttpDataTransform(
            steps=bconfig.settings["SETTING_C2_RECOVER"], reverse=True, build="output"
        )

        # Used to map unencrypted metadata to decrypted BeaconMetadata
        self.metadata_cache: Dict[bytes, BeaconMetadata] = {}

        # Default decryption keys
        self.beacon_keys = BeaconKeys(aes_key=self.aes_key, hmac_key=self.hmac_key)

    def get_transform_for_http(self, http: Union[HttpRequest, HttpResponse, bytes]) -> HttpDataTransform:
        """Return the correct :class:`HttpDataTransform` instance for given `http`.

        Request targets are compared against the configured URIs as raw bytes; no
        percent-decoding or path normalization is performed before selecting a transform. A
        configured URI only matches exactly, unless its transform appends data to the URI
        (``uri-append``), in which case the configured URI must be a prefix of the raw path.

        A request with a look-alike but non-configured target is rejected as unrelated. If more
        than one configured URI can explain the target, an :class:`AmbiguousRequestError` is
        raised instead of silently selecting one by dictionary or configuration order.

        Args:
            http: either a :class:`HttpRequest` or :class:`HttpResponse` object or raw HTTP bytes.

        Returns:
            HttpDataTransform: The correct :class:`HttpDataTransform` instance for given `http`.

        Raises:
            UnrelatedRequestError: if no correct transform can be found for given `http` object.
            AmbiguousRequestError: if the request target matches more than one configured URI.
        """
        http = parse_raw_http(http) if isinstance(http, bytes) else http

        if isinstance(http, HttpResponse):
            return self.transform_response

        if not isinstance(http, HttpRequest):
            raise ValueError(f"Possible unrelated HTTP Request or Response, cannot find correct transform for {http!r}")

        candidates: List[Tuple[bytes, HttpDataTransform]] = []
        if http.method == self.get_verb:
            candidates.extend(
                (uri, self.transform_get)
                for uri in self.get_uris
                if _uri_matches(uri, http.uri, self.transform_get)
            )
        if http.method == self.submit_verb:
            candidates.extend(
                (uri, self.transform_submit)
                for uri in (self.submit_uri,)
                if _uri_matches(uri, http.uri, self.transform_submit)
            )

        if not candidates:
            configured = self.get_uris if http.method == self.get_verb else (self.submit_uri,)
            raise UnrelatedRequestError(http.uri, http.method, configured)

        # An exact match is deterministic and wins over prefix matches from uri-append
        # transforms. More than one exact match or more than one prefix match is ambiguous.
        exact = [candidate for candidate in candidates if candidate[0] == http.uri]
        if exact:
            candidates = exact
        if len(candidates) > 1:
            raise AmbiguousRequestError(http.uri, [uri for uri, _ in candidates])
        return candidates[0][1]

    def iter_recover_http(
        self, http: Union[bytes, HttpRequest, HttpResponse], keys: Optional[BeaconKeys] = None
    ) -> Iterator[C2Packet]:
        """Yield decrypted :class:`C2Packet` objects from given `http` object.

        You can pass your own set of :class:`BeaconKeys` `keys` to use for decryption instead of the default
        initialized ones. This can be useful if you are processing multiple Beacon sessions and do some sort of session
        tracking outside this class.

        Args:
            http: A :class:`HttpRequest` or :class:`HttpResponse` object, or raw HTTP request or response bytes.
            keys: Optional :class:`BeaconKeys` to use for decryption instead of current default keys.

        Yields:
            C2Packet: A :class:`C2Packet` object for each decrypted packet found in the HTTP request or response.
        """
        http = parse_raw_http(http) if isinstance(http, bytes) else http
        keys = keys or self.beacon_keys

        transform = self.get_transform_for_http(http)
        c2data = transform.recover(http)

        # decrypt c2data.metadata, if available and we have a private key
        if c2data.metadata and self.priv:
            metadata_source = c2data.source_for("metadata")
            metadata = self.metadata_cache.get(c2data.metadata)
            if metadata is None:
                metadata = decrypt_metadata(c2data.metadata, self.priv)
                self.metadata_cache[c2data.metadata] = metadata
                # if we do not have an AES key or HMAC key yet, we derive it.
                if not all([self.beacon_keys.aes_key, self.beacon_keys.hmac_key]):
                    aes_key, hmac_key = derive_aes_hmac_keys(metadata.aes_rand)
                    self.beacon_keys = BeaconKeys(aes_key, hmac_key)
                    logging.info("Derived AES + HMAC keys from %r", metadata)
            _set_packet_source(metadata, metadata_source)
            yield metadata

        # decrypt c2data.output, if any
        output_source = c2data.source_for("output")
        for enc_packet in c2data.iter_encrypted_packets():
            plaintext = decrypt_packet(enc_packet, verify=self.verify_hmac, **keys._asdict())
            if isinstance(c2data, ClientC2Data):
                packet: C2Packet = CallbackPacket(plaintext)
            elif isinstance(c2data, ServerC2Data):
                packet = TaskPacket(plaintext)
            else:  # pragma: no cover - c2data is always one of the two above
                continue
            _set_packet_source(packet, output_source)
            yield packet


def _set_packet_source(packet: C2Packet, source: Optional[CarrierSource]) -> None:
    """Attach the raw carrier `source` to a recovered packet, if the packet allows it."""
    if source is not None:
        try:
            packet.source = source
        except (AttributeError, TypeError):  # pragma: no cover - defensive for cstruct versions
            logger.debug("Unable to attach carrier source to %r", packet)


# ------------------
# Crypto functions
# ------------------


def decrypt_metadata(encrypted_metadata: bytes, private_key: RSA.RsaKey) -> BeaconMetadata:
    """Decrypt `encrypted_metadata` using RSA `private_key`.

    Args:
        encrypted_metadata: the encrypted metadata bytes
        private_key: the RSA private key used for decryption

    Returns:
        BeaconMetadata: The decrypted metadata.

    Raises:
        ValueError: if RSA failed to decrypt or metadata magic is invalid
    """
    cipher = PKCS1_v1_5.new(private_key)
    pt = cipher.decrypt(encrypted_metadata, None)
    if pt is None:
        raise ValueError("Failed to RSA decrypt metadata")
    metadata = BeaconMetadata(pt)
    if metadata.magic != 0xBEEF:
        raise ValueError(f"Invalid metadata magic, got {metadata.magic:08x}, expected 0xbeef")
    return metadata


def encrypt_metadata(metadata: BeaconMetadata, public_key: RSA.RsaKey) -> bytes:
    """Encrypt `metadata` using RSA `public_key`.

    Args:
        metadata: :class:`BeaconMetadata` object to encrypt
        public_key: the RSA public key used for encryption

    Returns:
        The encrypted metadata as bytes
    """
    cipher = PKCS1_v1_5.new(public_key)
    metadata.size = len(metadata) - 8
    return cipher.encrypt(metadata.dumps())


def derive_aes_hmac_keys(aes_random: bytes) -> Tuple[bytes, bytes]:
    """Derive the AES and HMAC keys from the `aes_random` bytes.

    Args:
        aes_random: the bytes to derive the keys from

    Returns:
        Tuple of (aes_key, hmac_key)
    """
    digest = hashlib.sha256(aes_random).digest()
    return digest[:16], digest[16:]


def pad(data: bytes, block_size: int = AES.block_size) -> bytes:
    """Mimics the padding behaviour in Cobalt Strike (which is to fill it with b'A').

    Args:
        data: the data to pad
        block_size: the block size to use for padding

    Returns:
        The padded data
    """
    to_pad = block_size - len(data) % block_size
    return data + b"A" * to_pad


def encrypt_data(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """AES encrypt `data` with given `aes_key` and `iv`.

    Args:
        data: the data to encrypt
        aes_key: the AES key to use
        iv: the initialization vector to use

    Returns:
        The encrypted data as bytes
    """
    if aes_key is None:
        raise ValueError("Cannot encrypt without AES key")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(pad(data))


def decrypt_data(data: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """AES decrypt the `data` with given `aes_key` and `iv` and return the decrypted bytes.

    Args:
        data: the encrypted data
        aes_key: the AES key to use for decryption
        iv: the AES IV to use for decryption

    Returns:
        The decrypted data as bytes
    """
    if aes_key is None:
        raise ValueError("Cannot decrypt without AES key")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    # Beacon and Team Server does not unpad data
    return cipher.decrypt(data)


def decrypt_packet(
    packet: EncryptedPacket,
    aes_key: bytes,
    hmac_key: Optional[bytes] = None,
    iv: bytes = BeaconKeys.DEFAULT_AES_IV,
    verify: bool = True,
) -> bytes:
    """Decrypt :class:`EncryptedPacket` `packet` and return the decrypted plaintext bytes.

    If `hmac_key`  is defined, the signature of the ciphertext is verified first before decrypting.

    Args:
        packet: the :class:`EncryptedPacket` to decrypt
        aes_key: the AES key to use for decryption
        hmac_key: the HMAC key to use for signature verification
        iv: the AES IV to use for decryption
        verify: whether to verify the HMAC signature of the ciphertext

    Returns:
        The decrypted plaintext bytes
    """
    if verify:
        if not hmac_key:
            raise ValueError("Cannot verify signature without hmac_key.")
        packet.raise_for_signature(hmac_key)
    return decrypt_data(packet.ciphertext, aes_key, iv)


def encrypt_packet(
    plaintext: bytes, aes_key: bytes, hmac_key: bytes, iv: bytes = BeaconKeys.DEFAULT_AES_IV
) -> EncryptedPacket:
    """Encrypt `plaintext` bytes and return a :class:`EncryptedPacket`.

    Args:
        plaintext: the plaintext bytes to encrypt
        aes_key: the AES key to use for encryption
        hmac_key: the HMAC key to use for signature generation
        iv: the AES IV to use for encryption
    Returns:
        The :class:`EncryptedPacket` containing the ciphertext and HMAC signature
    """
    ciphertext = encrypt_data(plaintext, aes_key=aes_key, iv=iv)
    signature = hmac.new(hmac_key, ciphertext, "sha256").digest()[:16]
    return EncryptedPacket(ciphertext, signature)
