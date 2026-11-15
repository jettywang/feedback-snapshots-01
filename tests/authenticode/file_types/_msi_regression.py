"""Synthetic MSI fixtures and an independent MSI digest reference.

This module deliberately does not call the implementation under test while constructing
fixtures or calculating expected digests.  The OLE directory tree is represented
by small dataclasses, serialized by :func:`build_ole`, and hashed by the explicit
walking rules in :func:`reference_stream_content` and
:func:`reference_prehash_encoding`.

Traditional MSI digest
----------------------
At each storage (including the root), sort the children by the raw UTF-16LE
encoded name bytes (``name_utf16``; no NUL terminator).  Skip the two signature
streams by name.  Visit children in that order: recurse into a storage, or
append a stream's bytes.  After all children of a storage, append the 16-byte
little-endian CLSID of that storage.  The root is treated the same way.  Names,
timestamps, flags and stream sizes do not directly enter this digest.

Extended MSI prehash
--------------------
Pre-order walk, sorting children exactly as above and skipping the signature
streams.  Each entry contributes its metadata at the point it is visited.  A
non-root entry contributes its raw UTF-16LE name bytes; root and storage entries
contribute a CLSID; stream entries contribute a 4-byte little-endian size;
every entry contributes its 4-byte little-endian user flags; and every non-root
entry contributes its 8-byte little-endian create and modify FILETIMEs.  Children
of a storage are then visited in sorted order.  Stream contents are not part of
the prehash; the extended digest prepends the prehash digest to the traditional
content bytes before hashing.

Fields the digests do not cover
-------------------------------
* the root entry's name
* the root entry's create and modify timestamps
* a stream entry's CLSID
* a storage entry's size field (normally zero)
* directory-entry colour, left/right/child SID topology, physical directory order,
  sector allocation, ``isectStart`` and MiniFAT/FAT placement
* the two signature streams themselves (excluded by name from both walks)
* the exact ``DigitalSignature`` stream contents and the exact
  ``MsiDigitalSignatureEx`` stream contents (signature data, not file metadata)

Of these, the fixtures vary physical directory order, the root name, the root
timestamp and a stream CLSID.  Colour (always 1), SID topology (always a
right-chain), sector allocation (always contiguous), storage size (always zero)
and signature-stream placement are held constant by :func:`build_ole`, so this
regression does not exercise those variations end to end.

The extended digest additionally commits to stream contents only through the
traditional part that is prepended, so a content change is not an
extended-digest-only change.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import struct
import uuid
from dataclasses import dataclass, field
from functools import lru_cache

from asn1crypto import algos, cms, x509
from oscrypto import asymmetric

from signify.asn1 import spc
from signify.x509 import Certificate, CertificateStore
from tests._utils import data_path

MAGIC = bytes.fromhex("D0 CF 11 E0 A1 B1 1A E1")
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_ROOT = 5

DIGITAL_SIGNATURE = "\x05DigitalSignature"
EXTENDED_DIGITAL_SIGNATURE = "\x05MsiDigitalSignatureEx"
SIGNATURE_NAMES = frozenset({DIGITAL_SIGNATURE, EXTENDED_DIGITAL_SIGNATURE})

ROOT_CLSID = "000C1084-0000-0000-C000-000000000046"
EMPTY_CLSID = "00000000-0000-0000-0000-000000000000"

# Arbitrary but fixed FILETIME values (100 ns ticks since 1601-01-01).
CREATED = 0x01D9A00000000000
MODIFIED = CREATED + 10_000_000
ROOT_MODIFIED = 0x01D9B00000000000


@dataclass
class DirNode:
    """A small, writer-independent model of one OLE directory entry."""

    name: str
    entry_type: int
    clsid: str = EMPTY_CLSID
    create_time: int = 0
    modify_time: int = 0
    user_flags: int = 0
    content: bytes | None = None
    children: list[DirNode] = field(default_factory=list)

    sid: int = -1
    left_sid: int = NOSTREAM
    right_sid: int = NOSTREAM
    child_sid: int = NOSTREAM
    start_sector: int = ENDOFCHAIN
    size: int = 0
    is_minifat: bool = False


def storage_node(
    name: str,
    *,
    clsid: str,
    children=(),
    create=CREATED,
    modify=MODIFIED,
    flags=0,
) -> DirNode:
    return DirNode(
        name=name,
        entry_type=STGTY_STORAGE,
        clsid=clsid,
        create_time=create,
        modify_time=modify,
        user_flags=flags,
        children=list(children),
    )


def stream_node(
    name: str,
    content: bytes,
    *,
    create=CREATED,
    modify=MODIFIED,
    flags=0,
    clsid=EMPTY_CLSID,
) -> DirNode:
    return DirNode(
        name=name,
        entry_type=STGTY_STREAM,
        clsid=clsid,
        create_time=create,
        modify_time=modify,
        user_flags=flags,
        content=content,
    )


def root_node(children, *, clsid=ROOT_CLSID, modify=ROOT_MODIFIED) -> DirNode:
    return DirNode(
        name="Root Entry",
        entry_type=STGTY_ROOT,
        clsid=clsid,
        create_time=0,
        modify_time=modify,
        children=list(children),
    )


def canonical_model() -> DirNode:
    """Return the canonical sample.

    It contains a nested storage, a storage with its own children, a Unicode
    storage and stream name, an empty stream, and two names that are adjacent
    under the raw UTF-16LE byte ordering but reverse under Python's code-point
    ordering (``aĀ`` and ``aÿ``).
    """
    return root_node(
        [
            stream_node("\x05SummaryInformation", b"summary"),
            storage_node(
                "Data",
                clsid="11111111-2222-3333-4444-555555555555",
                children=[
                    storage_node(
                        "inner",
                        clsid="66666666-7777-8888-9999-AAAAAAAAAAAA",
                        children=[stream_node("leaf", b"leaf")],
                    ),
                    stream_node("m", b"M"),
                ],
            ),
            # Raw UTF-16LE sorts aĀ (00 01) before aÿ (ff 00); Python
            # code-point order sorts aÿ before aĀ.  The physical order here is
            # deliberately the opposite of the pinned traversal order.
            stream_node("aÿ", b"PAIR-SECOND"),
            stream_node("aĀ", b"PAIR-FIRST"),
            stream_node("empty", b""),
            stream_node("top", b"TOP"),
            storage_node(
                "z_storage",
                clsid="BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF",
                children=[stream_node("X", b"X"), stream_node("Y", b"Y")],
            ),
            storage_node(
                "目录",
                clsid="12345678-9ABC-DEF0-1234-56789ABCDEF0",
                children=[stream_node("流", b"unicode")],
            ),
        ]
    )


def find_node(model: DirNode, name: str) -> DirNode:
    if model.name == name:
        return model
    for child in model.children:
        found = _find_optional(child, name)
        if found is not None:
            return found
    raise KeyError(name)


def _find_optional(model: DirNode, name: str) -> DirNode | None:
    if model.name == name:
        return model
    for child in model.children:
        found = _find_optional(child, name)
        if found is not None:
            return found
    return None


def clone_model(model: DirNode) -> DirNode:
    return copy.deepcopy(model)


def _clsid_bytes(clsid: str) -> bytes:
    return uuid.UUID(clsid).bytes_le


def _sort_key(node: DirNode) -> bytes:
    return node.name.encode("utf-16le")


def _ordered_children(node: DirNode) -> list[DirNode]:
    return sorted(
        (child for child in node.children if child.name not in SIGNATURE_NAMES),
        key=_sort_key,
    )


def reference_metadata(node: DirNode, *, is_root: bool = False) -> bytes:
    """Encode one directory entry exactly as stated in the module docstring."""
    result = bytearray()
    if not is_root:
        result += node.name.encode("utf-16le")
    if node.entry_type in (STGTY_ROOT, STGTY_STORAGE):
        result += _clsid_bytes(node.clsid)
    if node.entry_type == STGTY_STREAM:
        result += struct.pack("<I", len(node.content or b""))
    result += struct.pack("<I", node.user_flags)
    if not is_root:
        result += struct.pack("<Q", node.create_time)
        result += struct.pack("<Q", node.modify_time)
    return bytes(result)


def reference_stream_order(model: DirNode) -> list[tuple[tuple[str, ...], bytes]]:
    """Return (path, content) in traditional traversal order.

    This pins the traversal order itself, independently of any digest.
    """
    result: list[tuple[tuple[str, ...], bytes]] = []

    def walk(node: DirNode, path: tuple[str, ...]) -> None:
        for child in _ordered_children(node):
            if child.entry_type == STGTY_STORAGE:
                walk(child, (*path, child.name))
            elif child.entry_type == STGTY_STREAM:
                result.append(((*path, child.name), child.content or b""))
            else:
                raise AssertionError(f"unexpected entry type {child.entry_type}")

    walk(model, ())
    return result


def reference_stream_content(model: DirNode) -> bytes:
    """Calculate the traditional digest input without calling Signify."""
    result = bytearray()

    def walk(node: DirNode) -> None:
        for child in _ordered_children(node):
            if child.entry_type == STGTY_STORAGE:
                walk(child)
            elif child.entry_type == STGTY_STREAM:
                result.extend(child.content or b"")
            else:
                raise AssertionError(f"unexpected entry type {child.entry_type}")
        if node.entry_type in (STGTY_ROOT, STGTY_STORAGE):
            result.extend(_clsid_bytes(node.clsid))

    walk(model)
    return bytes(result)


def reference_prehash_encoding(model: DirNode) -> bytes:
    """Calculate the extended prehash input without calling Signify."""
    result = bytearray()

    def walk(node: DirNode, *, is_root: bool) -> None:
        result.extend(reference_metadata(node, is_root=is_root))
        for child in _ordered_children(node):
            if child.entry_type == STGTY_STORAGE:
                walk(child, is_root=False)
            elif child.entry_type == STGTY_STREAM:
                result.extend(reference_metadata(child, is_root=False))
            else:
                raise AssertionError(f"unexpected entry type {child.entry_type}")

    walk(model, is_root=True)
    return bytes(result)


@dataclass(frozen=True)
class ReferenceDigests:
    stream_content: bytes
    prehash_encoding: bytes
    traditional: bytes
    prehash: bytes
    extended: bytes


def reference_digests(model: DirNode, algorithm=hashlib.sha256) -> ReferenceDigests:
    content = reference_stream_content(model)
    encoding = reference_prehash_encoding(model)
    traditional = algorithm(content).digest()
    prehash = algorithm(encoding).digest()
    # The extended digest prepends the prehash *digest* to content, not the
    # raw prehash encoding.
    extended = algorithm(prehash + content).digest()
    return ReferenceDigests(content, encoding, traditional, prehash, extended)


def build_ole(model: DirNode) -> bytes:
    """Serialize the model as a minimal 512-byte-sector CFB/MS-CFB file."""
    entries: list[DirNode] = []

    def assign_sids(node: DirNode) -> None:
        node.sid = len(entries)
        entries.append(node)
        for child in node.children:
            assign_sids(child)

    assign_sids(model)

    def link_siblings(node: DirNode) -> None:
        for index, child in enumerate(node.children):
            child.left_sid = NOSTREAM
            child.right_sid = (
                node.children[index + 1].sid
                if index + 1 < len(node.children)
                else NOSTREAM
            )
        if node.entry_type in (STGTY_ROOT, STGTY_STORAGE):
            node.child_sid = node.children[0].sid if node.children else NOSTREAM
        for child in node.children:
            link_siblings(child)

    link_siblings(model)

    mini_stream = bytearray()
    mini_fat: list[int] = []
    for node in entries:
        if node.entry_type != STGTY_STREAM:
            node.size = 0
            node.start_sector = ENDOFCHAIN
            continue
        node.size = len(node.content or b"")
        if 0 < node.size < 4096:
            node.is_minifat = True
            count = (node.size + 63) // 64
            first = len(mini_fat)
            node.start_sector = first
            mini_fat.extend(
                first + index + 1 if index + 1 < count else ENDOFCHAIN
                for index in range(count)
            )
            mini_stream.extend((node.content or b"").ljust(count * 64, b"\x00"))
        else:
            node.start_sector = ENDOFCHAIN

    sectors: list[bytes] = []
    fat_links: dict[int, int] = {}

    def allocate_chain(data: bytes) -> int:
        if not data:
            return ENDOFCHAIN
        count = (len(data) + 511) // 512
        start = len(sectors)
        sectors.extend(
            data[index * 512 : (index + 1) * 512].ljust(512, b"\x00")
            for index in range(count)
        )
        for index in range(count - 1):
            fat_links[start + index] = start + index + 1
        fat_links[start + count - 1] = ENDOFCHAIN
        return start

    if mini_stream:
        model.start_sector = allocate_chain(bytes(mini_stream))
        model.size = len(mini_stream)
    else:
        model.start_sector = ENDOFCHAIN
        model.size = 0

    for node in entries:
        if node.entry_type == STGTY_STREAM and node.size >= 4096:
            node.start_sector = allocate_chain(node.content or b"")

    directory_count = max(1, (len(entries) + 3) // 4)
    directory_start = allocate_chain(b"\x00" * (directory_count * 512))

    if mini_fat:
        packed = bytearray()
        for value in mini_fat:
            packed += struct.pack("<I", value)
        while len(packed) % 512:
            packed += struct.pack("<I", FREESECT)
        mini_fat_start = allocate_chain(bytes(packed))
        mini_fat_count = len(packed) // 512
    else:
        mini_fat_start = ENDOFCHAIN
        mini_fat_count = 0

    for node in entries:
        name_bytes = node.name.encode("utf-16le")
        if len(name_bytes) + 2 > 64:
            raise ValueError(f"OLE directory name too long: {node.name!r}")
        raw = struct.pack(
            "<64sHBBIII16sIQQIII",
            name_bytes,
            len(name_bytes) + 2,
            node.entry_type,
            1,
            node.left_sid,
            node.right_sid,
            node.child_sid,
            _clsid_bytes(node.clsid),
            node.user_flags,
            node.create_time,
            node.modify_time,
            node.start_sector,
            node.size & 0xFFFFFFFF,
            (node.size >> 32) & 0xFFFFFFFF,
        )
        sector = directory_start + node.sid // 4
        offset = (node.sid % 4) * 128
        block = bytearray(sectors[sector])
        block[offset : offset + 128] = raw
        sectors[sector] = bytes(block)

    fat_start = len(sectors)
    sectors.append(b"\x00" * 512)
    if len(sectors) > 128:
        raise ValueError("fixture needs more than one FAT sector")

    links = {index: FREESECT for index in range(len(sectors))}
    links.update(fat_links)
    links[fat_start] = FATSECT
    fat = bytearray()
    for index in range(len(sectors)):
        fat += struct.pack("<I", links[index])
    sectors[fat_start] = bytes(fat).ljust(512, b"\x00")

    header = struct.pack(
        "<8s16sHHHHHHLLLLLLLLLL",
        MAGIC,
        b"\x00" * 16,
        0x003E,
        3,
        0xFFFE,
        9,
        6,
        0,
        0,
        0,
        1,
        directory_start,
        0,
        0x1000,
        mini_fat_start,
        mini_fat_count,
        ENDOFCHAIN,
        0,
    )
    header += struct.pack("<109I", fat_start, *([FREESECT] * 108))
    if len(header) != 512:
        raise AssertionError("CFB header must be 512 bytes")
    return header + b"".join(sectors)


@lru_cache(maxsize=1)
def _signing_material() -> tuple[object, x509.Certificate, Certificate]:
    private_key = asymmetric.load_private_key(
        data_path("certs/msi_regression_key.pem").read_bytes()
    )
    name = x509.Name.build({"common_name": "Signify MSI regression test"})
    not_before = x509.Time(
        {"utc_time": datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)}
    )
    not_after = x509.Time(
        {"utc_time": datetime.datetime(2034, 1, 1, tzinfo=datetime.timezone.utc)}
    )
    signature_algorithm = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    extensions = x509.Extensions(
        [
            x509.Extension(
                {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": x509.BasicConstraints({"ca": True}),
                }
            ),
            x509.Extension(
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": x509.KeyUsage(
                        {"digital_signature", "key_cert_sign"}
                    ),
                }
            ),
            x509.Extension(
                {
                    "extn_id": "extended_key_usage",
                    "extn_value": x509.ExtKeyUsageSyntax(["code_signing"]),
                }
            ),
        ]
    )
    tbs = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": 1,
            "signature": signature_algorithm,
            "issuer": name,
            "validity": {"not_before": not_before, "not_after": not_after},
            "subject": name,
            "subject_public_key_info": private_key.public_key.asn1,
            "extensions": extensions,
        }
    )
    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": signature_algorithm,
            "signature_value": asymmetric.rsa_pkcs1v15_sign(
                private_key, tbs.dump(), "sha256"
            ),
        }
    )
    return private_key, certificate, Certificate.from_der(certificate.dump())


def signing_certificate() -> x509.Certificate:
    return _signing_material()[1]


def trusted_store() -> CertificateStore:
    return CertificateStore([_signing_material()[2]], trusted=True)


def make_cms(digest: bytes) -> bytes:
    """Create a self-signed Authenticode CMS signature over the given digest."""
    private_key, certificate, _ = _signing_material()
    digest_algorithm = algos.DigestAlgorithm({"algorithm": "sha256"})
    signature_algorithm = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})

    sig_info = spc.SpcSigInfo(
        {
            "sip_version": 2,
            "sip_guid": "f1100c00-0000-0000-c000-000000000046",
            "reserved1": 0,
            "reserved2": 0,
            "reserved3": 0,
            "reserved4": 0,
            "reserved5": 0,
        }
    )
    indirect_data = spc.SpcIndirectDataContent(
        {
            "data": {"type": "microsoft_spc_siginfo", "value": sig_info},
            "message_digest": {
                "digest_algorithm": {"algorithm": "sha256"},
                "digest": digest,
            },
        }
    )
    attributes = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {
                    "type": "content_type",
                    "values": ["microsoft_spc_indirect_data_content"],
                }
            ),
            cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [hashlib.sha256(indirect_data.contents).digest()],
                }
            ),
        ]
    )
    # SignerInfo.signedAttrs is [0] IMPLICIT in the CMS encoding, but its
    # signature input is a SET OF (tag 0x31), as RFC 5652 section 5.2 says.
    signature_input = cms.CMSAttributes(contents=attributes.contents).dump()
    signature = asymmetric.rsa_pkcs1v15_sign(private_key, signature_input, "sha256")

    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": certificate["tbs_certificate"]["subject"],
                            "serial_number": certificate["tbs_certificate"][
                                "serial_number"
                            ],
                        }
                    )
                }
            ),
            "digest_algorithm": digest_algorithm,
            "signed_attrs": attributes,
            "signature_algorithm": signature_algorithm,
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [digest_algorithm],
            "encap_content_info": {
                "content_type": "microsoft_spc_indirect_data_content",
                "content": indirect_data,
            },
            "certificates": [certificate],
            "signer_infos": [signer_info],
        }
    )
    return cms.ContentInfo(
        {"content_type": "signed_data", "content": signed_data}
    ).dump()


def build_signed_msi(
    model: DirNode,
    *,
    extended: bool,
    signed_digest: bytes,
    prehash_digest: bytes = b"",
) -> bytes:
    """Attach a signature to an arbitrary model and serialize it.

    The digests are supplied by the caller, allowing a mutated tree to carry the
    canonical signature.  This is how verification tests prove which layer
    observes a change.
    """
    signed_model = clone_model(model)
    signed_model.children.append(
        stream_node(DIGITAL_SIGNATURE, make_cms(signed_digest))
    )
    if extended:
        signed_model.children.append(
            stream_node(EXTENDED_DIGITAL_SIGNATURE, prehash_digest)
        )
    return build_ole(signed_model)


def signed_canonical_msi(*, extended: bool) -> tuple[bytes, ReferenceDigests]:
    model = canonical_model()
    digests = reference_digests(model)
    data = build_signed_msi(
        model,
        extended=extended,
        signed_digest=digests.extended if extended else digests.traditional,
        prehash_digest=digests.prehash,
    )
    return data, digests


def with_renamed_storage(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "Data").name = "DataX"
    return mutated


def with_empty_stream_moved_into_storage(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    empty = next(child for child in mutated.children if child.name == "empty")
    mutated.children.remove(empty)
    find_node(mutated, "Data").children.append(empty)
    return mutated


def with_leaf_moved_to_parent_storage(model: DirNode) -> DirNode:
    """Move a non-empty stream one storage level up without changing its bytes."""
    mutated = clone_model(model)
    leaf = find_node(mutated, "leaf")
    find_node(mutated, "inner").children.remove(leaf)
    find_node(mutated, "Data").children.append(leaf)
    return mutated


def with_stream_timestamp(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "top").create_time += 1
    return mutated


def with_storage_timestamp(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "Data").modify_time += 1
    return mutated


def with_storage_flags(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "Data").user_flags = 1
    return mutated


def with_root_timestamp(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    mutated.modify_time += 1
    return mutated


def with_stream_clsid(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "top").clsid = "99999999-9999-9999-9999-999999999999"
    return mutated


def with_reversed_physical_order(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    mutated.children.reverse()
    return mutated


def with_changed_storage_clsid(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "Data").clsid = "99999999-9999-9999-9999-999999999999"
    return mutated


def with_changed_stream_content(model: DirNode) -> DirNode:
    mutated = clone_model(model)
    find_node(mutated, "top").content = b"TOX"
    return mutated
