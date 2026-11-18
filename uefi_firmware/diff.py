'''Read-only comparison of two parsed firmware object trees.

A firmware image can hold several components with the same GUID, so a dict
keyed by GUID loses instances and can pair the wrong ones. This module keeps
each component's container path, its original bytes and a digest of its
logical payload, and reports what can and cannot be paired uniquely.

The comparison never modifies either tree. It reports:

  - components whose payload is the same but whose stored bytes differ (a
    recompressed, repadded or re-signed wrapper),
  - components whose payload changed,
  - components that moved to another container path,
  - pairs the parser could not decode, whose content therefore cannot be
    judged equal,
  - components with no unique partner, together with the candidates that
    need a manual look, and
  - padding that was added or removed.

A GUID or a UI section name is only a hint for finding candidates. Matching
uses content first, then container path, and only then those hints.
'''

import contextlib
import hashlib
import io
import struct

from . import efi_compressor
from .base import AutoRawObject, PaddingObject, RawObject
from .structs.uefi_structs import FIRMWARE_GUIDED_GUIDS
from .uefi import (
    CompressedSection, FirmwareCapsule, FirmwareFile, FirmwareFileSystem,
    FirmwareFileSystemSection, FirmwareVolume, GuidDefinedSection,
    MultiVolumeContainer, NVARVariable, NVARVariableStore)
from .utils import MAX_DECOMPRESSED_BYTES, sguid


# Outcomes for one component.
IDENTICAL = "identical"
WRAPPER_ONLY = "wrapper_only"
CONTENT_CHANGED = "content_changed"
MOVED = "moved"
UNVERIFIED = "unverified"
AMBIGUOUS = "ambiguous"
REMOVED = "removed"
ADDED = "added"

# How far a component's payload could be decoded. Only a status in
# TRUSTED_DECODE may support a claim that two payloads are equal.
DECODE_OK = "decoded"
DECODE_NOT_COMPRESSED = "not_compressed"
DECODE_FAILED = "decode_failed"
DECODE_UNSUPPORTED = "decode_unsupported"
DECODE_NO_PAYLOAD = "no_payload"

TRUSTED_DECODE = (DECODE_OK, DECODE_NOT_COMPRESSED)

# Where a content digest came from.
SOURCE_DECODED = "decoded"
SOURCE_PARSED = "parsed"
SOURCE_NONE = "none"

# How a pair was found.
BASIS_CONTENT = "content"
BASIS_PATH = "path"
BASIS_IDENTITY = "identity"
BASIS_RAW = "raw"

_STATUS_RANK = {
    DECODE_NO_PAYLOAD: -1,
    DECODE_NOT_COMPRESSED: 0,
    DECODE_OK: 1,
    DECODE_UNSUPPORTED: 2,
    DECODE_FAILED: 3,
}

# A component with no content of its own, such as a UI-name section, carries
# no payload to compare. It is not a decode failure.
_NO_CONTENT = frozenset(["ui-name-excluded"])

# GUID-defined sections that this parser can decompress.
_COMPRESSED_GUIDS = frozenset([
    FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED"],
    FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED_HP"],
    FIRMWARE_GUIDED_GUIDS["TIANO_COMPRESSED"],
    FIRMWARE_GUIDED_GUIDS["ZLIB_COMPRESSED_AMD"],
    FIRMWARE_GUIDED_GUIDS["GZIP_COMPRESSED_QC"],
])

# A single decode is refused above the limit the C extension enforces, and
# a comparison uses the same total budget the parser allows one image.
_MAX_DECODE_OUTPUT = 100000000
_MAX_COMPARE_DECODE = MAX_DECOMPRESSED_BYTES


def _claimed_output(algorithm, buffer):
    '''The output size a stream's header claims, within the hard limit.'''
    if algorithm is efi_compressor.LzmaDecompress:
        header = buffer[5:13]
        size = struct.unpack("<Q", header)[0] if len(header) == 8 else 0
    else:
        header = buffer[4:8]
        size = struct.unpack("<I", header)[0] if len(header) == 4 else 0
    if size > _MAX_DECODE_OUTPUT:
        return None
    return size


def _decode(algorithm, buffer, cache):
    '''Decode one candidate stream within a per-comparison budget.

    The comparison runs after parsing, outside the parser's own budget. A
    crafted image can hold many streams, so the total decoded bytes are
    bounded here as well; a stream that would exceed the budget is left
    undecoded and therefore unverified rather than trusted.
    '''
    key = ("decode-bytes", id(algorithm), hashlib.sha256(buffer).digest())
    if key in cache:
        return cache[key]
    claimed = _claimed_output(algorithm, buffer)
    budget = cache.setdefault("decode-budget", [_MAX_COMPARE_DECODE])[0]
    decoded = None
    if claimed is not None and claimed <= budget:
        try:
            output = algorithm(buffer, len(buffer))
        except Exception:
            output = None
        if output:
            decoded = bytes(output)
            if len(decoded) > budget:
                decoded = None
            else:
                cache["decode-budget"][0] = budget - len(decoded)
    cache[key] = decoded
    return decoded


def _worst(statuses):
    '''Return the status that most restricts what may be claimed.'''
    statuses = [status for status in statuses if status is not None]
    if not statuses:
        return DECODE_NO_PAYLOAD
    return max(statuses, key=lambda status: _STATUS_RANK.get(status, 0))


def _digest(data):
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def _as_bytes(data):
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    try:
        return bytes(data)
    except Exception:
        return b""


def _guid_of(obj):
    guid = getattr(obj, "guid", None)
    if not isinstance(guid, (bytes, bytearray)) or len(guid) != 16:
        return None
    return sguid(bytes(guid))


def _decode_name(name):
    if isinstance(name, bytes):
        try:
            name = name.decode("utf-8", "replace")
        except Exception:
            return None
    if not isinstance(name, str):
        return None
    name = name.strip()
    return name or None


def _ui_name_of(obj):
    '''A display name, never an identity.

    A UI section (type 0x15) names the file it precedes, and is the closest
    thing to a component name an image carries. It is read from the file's
    first UI section so the file itself carries the hint. Vendors can give
    several files the same name, and a name can change without the payload
    changing, so it is only shown as a clue.
    '''
    name = _decode_name(getattr(obj, "name", None))
    if name is not None:
        return name
    for section in getattr(obj, "sections", None) or []:
        if getattr(section, "type", None) != 0x15:
            continue
        name = _decode_name(getattr(section, "name", None))
        if name is not None:
            return name
    return None


def _mix(hasher, value):
    '''Feed a tagged, length-prefixed value to a hash.'''
    if value is None:
        hasher.update(b"n;")
    elif isinstance(value, bytes):
        hasher.update(b"b%d:" % len(value))
        hasher.update(value)
    elif isinstance(value, str):
        data = value.encode("utf-8", "replace")
        hasher.update(b"s%d:" % len(data))
        hasher.update(data)
    elif isinstance(value, bool):
        hasher.update(b"t;" if value else b"f;")
    elif isinstance(value, int):
        hasher.update(b"i%d;" % value)
    elif isinstance(value, (list, tuple)):
        hasher.update(b"l%d;" % len(value))
        for item in value:
            _mix(hasher, item)
    else:
        _mix(hasher, str(value))


def _hash(parts):
    hasher = hashlib.sha256()
    _mix(hasher, list(parts))
    return hasher.hexdigest()


def _raw_bytes(obj):
    '''The original bytes an object was parsed from, when it kept them.'''
    for attribute in ("_data", "_body"):
        data = getattr(obj, attribute, None)
        if isinstance(data, (bytes, bytearray, memoryview)) and data:
            return bytes(data)

    # A PFS section drops its parsed copy and keeps the pieces instead.
    if hasattr(obj, "header") and hasattr(obj, "section_data"):
        pieces = [getattr(obj, "header", b""),
                  getattr(obj, "section_data", b"")]
        for name in ("rsa1", "pmim", "rsa2"):
            chunk = getattr(obj, name, None)
            pieces.append(_as_bytes(getattr(chunk, "data", b"")))
        return b"".join(pieces)

    return _as_bytes(getattr(obj, "data", None))


def _is_padding(obj):
    if isinstance(obj, PaddingObject):
        return True
    return isinstance(obj, FirmwareFile) and getattr(obj, "type", None) == 0xf0


def _pad_bytes(obj):
    if isinstance(obj, FirmwareFile) and getattr(obj, "type", None) == 0xf0:
        # An FFS pad file's header carries its type and size; the fill is its
        # body.
        return _as_bytes(getattr(obj, "data", b""))
    return _raw_bytes(obj)


def _is_erased(data):
    return data.strip(b"\xff") == b"" or data.strip(b"\x00") == b""


def _is_erased_padding(obj, data=None):
    data = _pad_bytes(obj) if data is None else data
    erased = getattr(obj, "erased", None)
    if erased is None:
        erased = _is_erased(data)
    return bool(erased)


def _payload_children(children):
    '''Drop erased padding from the children a payload digest covers.

    Erased fill is not component content; a gap that grows or shrinks belongs
    in the padding part of the report. Padding that holds other bytes may be
    vendor data, so those bytes stay in the digest.
    '''
    return [child for child in children
            if child is not None and not (
                _is_padding(child) and _is_erased_padding(child))]


def _parse_sections(payload):
    '''Parse a decoded stream as FFS sections, or return None.

    Only the common headers and sizes are validated here; the nested parse
    needed by a compressed subsection is done for those types alone. A
    stream that is not a sequence of in-bounds sections is not a valid
    payload for a compressed section, which lets a decoder that silently
    accepted another codec's stream be rejected.
    '''
    sections = []
    offset = 0
    length = len(payload)
    while offset < length:
        if offset % 4:
            offset += 4 - (offset % 4)
        remaining = length - offset
        if remaining < 4:
            if payload[offset:].strip(b"\xff\x00") == b"":
                break
            return None
        section = FirmwareFileSystemSection(payload[offset:], None)
        if not section.valid_header or section.size <= 0:
            return None
        if section.size > remaining:
            return None
        sections.append(section)
        offset += section.size

    if not sections:
        return None

    for section in sections:
        if section.type in (0x01, 0x02):
            # A nested wrapper needs its parsed object to be digested as
            # content instead of compressed bytes. Parsing these fresh
            # objects touches neither input tree.
            with contextlib.ExitStack() as stack:
                stack.enter_context(contextlib.redirect_stdout(
                    io.StringIO()))
                stack.enter_context(contextlib.redirect_stderr(
                    io.StringIO()))
                section.process()
    return sections


def _decode_candidates(section, cache):
    '''Return the distinct payloads the supported decoders produce.

    The parser tries one decoder first and keeps its output even when another
    supported decoder describes the stream better; EFI and Tiano streams are
    told apart only by trying both. Decoding here with every supported
    decoder lets a recompressed payload be recognised as unchanged.
    '''
    key = ("candidates", id(section))
    if key in cache:
        return cache[key]

    compressed = _as_bytes(getattr(section, "compressed_data", b""))
    buffers = [compressed]
    if len(compressed) > 4:
        buffers.append(compressed[4:])
    if getattr(section, "type", 0) == 0x01:
        algorithms = [efi_compressor.EfiDecompress,
                      efi_compressor.TianoDecompress]
    else:
        algorithms = [efi_compressor.LzmaDecompress,
                      efi_compressor.TianoDecompress,
                      efi_compressor.EfiDecompress]

    payloads = []
    for buffer in buffers:
        for algorithm in algorithms:
            decoded = _decode(algorithm, buffer, cache)
            if decoded:
                payloads.append(decoded)
        if payloads:
            break

    distinct = []
    for payload in payloads:
        if payload not in distinct:
            distinct.append(payload)
    cache[key] = distinct
    return distinct


def _payload_digest(payload, cache):
    '''Digest a decoded payload once per distinct byte string.'''
    key = ("payload", hashlib.sha256(payload).digest())
    if key in cache:
        return cache[key]
    sections = _parse_sections(payload)
    if sections is None:
        result = None
    else:
        result = _join_children(sections, 0, cache)
    cache[key] = result
    return result


def _best_decode(section, cache):
    '''Return (canonical digest, decode status, source) for a wrapper.

    Decoders can accept each other's streams and produce plausible but wrong
    bytes, so a payload is trusted only when it parses as sections. A stream
    no decoder can turn into sections, and a stream two decoders describe
    differently, are both reported as undecodable rather than as a payload
    change.
    '''
    key = ("decode", id(section))
    if key in cache:
        return cache[key]

    parser_data = getattr(section, "data", None)
    candidates = _decode_candidates(section, cache)
    if parser_data is not None and bytes(parser_data) not in candidates:
        candidates = [bytes(parser_data)] + candidates

    parsed = {}
    for payload in candidates:
        result = _payload_digest(payload, cache)
        if result is None:
            continue
        digest, status, _ = result
        if digest is not None:
            parsed.setdefault(digest, status)

    if len(parsed) == 1:
        digest, status = next(iter(parsed.items()))
        if status in TRUSTED_DECODE:
            result = (digest, DECODE_OK, SOURCE_DECODED)
        else:
            result = (digest, status, SOURCE_DECODED)
    elif len(parsed) > 1:
        # Two decoders describe the stream differently and both look valid;
        # neither can be called the payload.
        result = (None, DECODE_FAILED, SOURCE_NONE)
    else:
        # A compressed section holds sections. When no decoder produced a
        # stream that parses as sections, the payload is not established,
        # even if a decoder happened to emit bytes. Calling it decoded would
        # risk reporting two different streams as the same content.
        result = (None, DECODE_FAILED, SOURCE_NONE)
    cache[key] = result
    return result


def _join_children(children, depth, cache):
    '''Digest a list of children, failing if any of them is unverifiable.'''
    digests = []
    statuses = []
    sources = []
    for child in children:
        digest, status, source = _canonical(child, depth + 1, cache)
        statuses.append(status)
        sources.append(source)
        if digest is None:
            return None, _worst(statuses), SOURCE_NONE
        digests.append(digest)
    if SOURCE_DECODED in sources:
        source = SOURCE_DECODED
    elif SOURCE_PARSED in sources:
        source = SOURCE_PARSED
    else:
        source = SOURCE_NONE
    return _hash(digests), _worst(statuses), source


def _canonical_section(section, depth, cache):
    '''Digest a section by its logical payload, not its wrapper.

    A compressed, GUID-defined or raw section that holds the same logical
    bytes gets the same digest, so recompression or a changed wrapper does
    not look like a payload change. A UI section is a display hint and does
    not take part in the payload digest.
    '''
    section_type = getattr(section, "type", None)
    if section_type == 0x15:
        digest = _hash(["ui-name-excluded"])
        return digest, DECODE_OK, SOURCE_PARSED

    if section_type in (0x01, 0x02):
        parsed = getattr(section, "parsed_object", None)
        if parsed is None:
            if section_type == 0x01:
                return None, DECODE_FAILED, SOURCE_NONE
            body = _as_bytes(getattr(section, "data", b""))
            guid = sguid(body[:16]) if len(body) >= 16 else ""
            if guid in _COMPRESSED_GUIDS:
                return None, DECODE_FAILED, SOURCE_NONE
            # An unknown GUID-defined section with no parser is opaque
            # payload; its bytes are the content.
            return _hash(["opaque", body]), DECODE_NOT_COMPRESSED, \
                SOURCE_PARSED
        return _canonical(parsed, depth + 1, cache)

    if section_type == 0x17:
        parsed = getattr(section, "parsed_object", None)
        if parsed is not None:
            return _canonical(parsed, depth + 1, cache)
        return _hash(["volume-section", _as_bytes(section.data)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED

    if section_type == 0x19:
        parsed = getattr(section, "parsed_object", None)
        if parsed is not None and not isinstance(parsed, RawObject):
            return _canonical(parsed, depth + 1, cache)
        return _hash(["raw-section", _as_bytes(section.data)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED

    return _hash(["section", section_type, _as_bytes(section.data)]), \
        DECODE_NOT_COMPRESSED, SOURCE_PARSED


def _canonical_compressed(section, depth, cache):
    if getattr(section, "type", 0) == 0x00:
        subsections = _payload_children(
            list(getattr(section, "subsections", [])))
        if subsections:
            return _join_children(subsections, depth, cache)
        return _hash(["uncompressed", _as_bytes(section.data)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED

    if getattr(section, "data", None) is None:
        # The stream could not be decoded. Its stored bytes say nothing about
        # the payload, so they must not be compared as content.
        return None, DECODE_FAILED, SOURCE_NONE

    return _best_decode(section, cache)


def _canonical_guid_defined(section, depth, cache):
    guid = _guid_of(section)
    subsections = _payload_children(
        list(getattr(section, "subsections", [])))

    if guid in _COMPRESSED_GUIDS:
        if not hasattr(section, "subtype"):
            return None, DECODE_FAILED, SOURCE_NONE
        if subsections:
            digest, status, _ = _join_children(subsections, depth, cache)
            if digest is None:
                return None, status, SOURCE_NONE
            # A nested plain section is still content that came out of a
            # decoder, so the component reports a decoded payload.
            return digest, DECODE_OK, SOURCE_DECODED
        return _hash(["decoded", _as_bytes(section.data)]), DECODE_OK, \
            SOURCE_DECODED

    if subsections:
        return _join_children(subsections, depth, cache)
    return _hash(["guid-defined", _as_bytes(section.data)]), \
        DECODE_NOT_COMPRESSED, SOURCE_PARSED


def _canonical_me(obj, depth, cache):
    '''Digest an ME module or CPD entry by its decompressed data.'''
    compression = getattr(obj, "compression", None)
    if compression is None or compression == 0:
        return _hash(["me", _as_bytes(obj.data)]), DECODE_NOT_COMPRESSED, \
            SOURCE_PARSED
    if compression == 1:
        # Huffman modules are parsed but this parser has no decoder for them.
        return None, DECODE_UNSUPPORTED, SOURCE_NONE
    decoded = getattr(obj, "decompressed", None)
    if decoded is None:
        return None, DECODE_FAILED, SOURCE_NONE
    return _hash(["me-decoded", _as_bytes(decoded)]), DECODE_OK, \
        SOURCE_DECODED


def _container_or_raw(obj, children, depth, cache):
    '''Digest a container's children, or its bytes when it has none.'''
    if not children:
        return _hash(["raw-container", _raw_bytes(obj)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED
    return _join_children(children, depth, cache)


def _canonical_object(obj, depth, cache):
    if obj is None:
        return None, DECODE_NO_PAYLOAD, SOURCE_NONE
    if depth > 64:
        return None, DECODE_FAILED, SOURCE_NONE

    if isinstance(obj, AutoRawObject):
        inner = getattr(obj, "object", None)
        if inner is None:
            # Nothing was parsed from these bytes, so they are the payload.
            return _hash(["raw-auto", _as_bytes(obj.data)]), \
                DECODE_NOT_COMPRESSED, SOURCE_PARSED
        return _canonical(inner, depth, cache)
    if isinstance(obj, FirmwareFileSystemSection):
        return _canonical_section(obj, depth, cache)
    if isinstance(obj, CompressedSection):
        return _canonical_compressed(obj, depth, cache)
    if isinstance(obj, GuidDefinedSection):
        return _canonical_guid_defined(obj, depth, cache)

    if isinstance(obj, FirmwareFile):
        sections = list(getattr(obj, "sections", []))
        blobs = _payload_children(list(getattr(obj, "raw_blobs", [])))
        parts = ["file", getattr(obj, "type", None)]
        digests = []
        statuses = []
        sources = []
        for child in sections + blobs:
            digest, status, source = _canonical(child, depth + 1, cache)
            statuses.append(status)
            sources.append(source)
            if digest is None:
                return None, _worst(statuses), SOURCE_NONE
            digests.append(digest)
        parts.append(digests)
        source = SOURCE_DECODED if SOURCE_DECODED in sources else \
            SOURCE_PARSED
        return _hash(parts), _worst(statuses), source

    if isinstance(obj, FirmwareVolume):
        children = _payload_children(
            list(getattr(obj, "firmware_filesystems", [])) +
            [raw for raw in getattr(obj, "raw_objects", [])
             if not isinstance(raw, (bytes, bytearray, memoryview))])
        if not children:
            return _hash(["empty-volume", _raw_bytes(obj)]), \
                DECODE_NOT_COMPRESSED, SOURCE_PARSED
        return _join_children(children, depth, cache)

    if isinstance(obj, FirmwareFileSystem):
        files = _payload_children(list(getattr(obj, "files", [])))
        if not files:
            # An unparsed file system keeps its bytes as opaque content, so
            # two different ones are not called equal.
            return _hash(["raw-filesystem", _raw_bytes(obj)]), \
                DECODE_NOT_COMPRESSED, SOURCE_PARSED
        return _join_children(files, depth, cache)

    if isinstance(obj, MultiVolumeContainer):
        children = _payload_children(list(getattr(obj, "objs", [])))
        if not children:
            return _hash(["empty-volumes"]), DECODE_NOT_COMPRESSED, \
                SOURCE_PARSED
        return _join_children(children, depth, cache)

    if isinstance(obj, FirmwareCapsule):
        body = getattr(obj, "capsule_body", None)
        if body is None:
            return _hash(["capsule", _as_bytes(obj.data)]), \
                DECODE_NOT_COMPRESSED, SOURCE_PARSED
        return _canonical(body, depth + 1, cache)

    if isinstance(obj, NVARVariableStore):
        return _join_children(list(obj.variables), depth, cache)
    if isinstance(obj, NVARVariable):
        return _hash(["nvar", _as_bytes(obj.data)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED

    # PFS, ME and other containers keep their children in a few different
    # list attributes rather than one 'objects' property. A container whose
    # children did not parse keeps its bytes as opaque content, so two
    # different unparsed bodies are not called equal.
    if hasattr(obj, "section_objects"):
        return _container_or_raw(
            obj, _payload_children(list(obj.section_objects)), depth, cache)
    if hasattr(obj, "sections") and not isinstance(obj, FirmwareFile):
        return _container_or_raw(
            obj, _payload_children(list(obj.sections)), depth, cache)
    if hasattr(obj, "modules"):
        return _container_or_raw(
            obj, _payload_children(
                list(obj.modules) +
                list(getattr(obj, "variable_modules", []))), depth, cache)
    if hasattr(obj, "partitions"):
        return _container_or_raw(
            obj, _payload_children(list(obj.partitions)), depth, cache)
    if isinstance(obj, RawObject):
        return _hash(["raw", _as_bytes(obj.data)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED

    if getattr(obj, "compression", None) is not None:
        return _canonical_me(obj, depth, cache)

    children = _payload_children(list(getattr(obj, "objects", None) or []))
    if children:
        return _join_children(children, depth, cache)

    data = getattr(obj, "data", None)
    if data is not None:
        return _hash(["opaque", _as_bytes(data)]), \
            DECODE_NOT_COMPRESSED, SOURCE_PARSED

    return _hash(["empty"]), DECODE_NO_PAYLOAD, SOURCE_NONE


def _canonical(obj, depth=0, cache=None):
    '''Return (content digest, decode status, source) for an object.

    A None digest means the logical payload is unavailable, so the object's
    content must not be called equal to anything. Results are cached per
    object for one comparison, so a nested payload is decoded once.
    '''
    if cache is None:
        cache = {}
    key = ("canonical", id(obj))
    if key in cache:
        return cache[key]
    # Guard against a tree that points back at itself while digesting.
    cache[key] = (None, DECODE_FAILED, SOURCE_NONE)
    result = _canonical_object(obj, depth, cache)
    cache[key] = result
    # Section objects built from decoded payloads are not part of either
    # tree. Keep them alive for the comparison so their ids cannot be reused
    # by a later object and return a stale digest.
    cache.setdefault("keepalive", []).append(obj)
    return result


def _children_of(obj):
    '''Return the child objects to walk, in a stable order.'''
    if isinstance(obj, FirmwareVolume):
        return list(getattr(obj, "firmware_filesystems", [])) + \
            [raw for raw in getattr(obj, "raw_objects", [])
             if not isinstance(raw, (bytes, bytearray, memoryview))]
    if isinstance(obj, FirmwareFileSystem):
        return list(getattr(obj, "files", []))
    if isinstance(obj, FirmwareFile):
        return list(getattr(obj, "sections", [])) + \
            list(getattr(obj, "raw_blobs", []))
    if isinstance(obj, FirmwareCapsule):
        body = getattr(obj, "capsule_body", None)
        return [body] if body is not None else []
    if isinstance(obj, MultiVolumeContainer):
        return list(getattr(obj, "objs", []))
    if isinstance(obj, NVARVariableStore):
        return list(getattr(obj, "variables", []))
    name = obj.__class__.__name__
    if name in ("PFSSection", "PFSPartitionedSection"):
        return list(getattr(obj, "section_objects", []))
    if name == "PFSFile":
        return list(getattr(obj, "sections", []))
    if name == "MeContainer":
        return list(getattr(obj, "partitions", []))
    if name == "PartitionEntry":
        manifest = getattr(obj, "manifest", None)
        return [manifest] if manifest is not None else []
    if name in ("MeManifestHeader", "CPDManifestHeader"):
        children = list(getattr(obj, "modules", []))
        children += list(getattr(obj, "variable_modules", []))
        if getattr(obj, "huffman_llut", None) is not None:
            children.append(obj.huffman_llut)
        return children
    if isinstance(obj, AutoRawObject):
        return list(obj.objects)
    return [child for child in (getattr(obj, "objects", None) or [])
            if child is not None]


def _is_component(obj):
    if isinstance(obj, (FirmwareFile, NVARVariable)):
        return True
    # ME and PFS entries are components. Their class names are checked to
    # keep this module free of circular imports.
    return obj.__class__.__name__ in (
        "MeModule", "CPDEntry", "PFSSection", "PFSPartitionedSection")


def _base_label(obj):
    '''A stable, readable name for one object in a path.'''
    name = obj.__class__.__name__
    if isinstance(obj, FirmwareVolume):
        fvname = getattr(obj, "fvname", None)
        if fvname:
            label = sguid(fvname)
        else:
            volume_name = getattr(obj, "name", None)
            if volume_name not in (None, "", "0"):
                label = str(volume_name)
            else:
                label = _guid_of(obj)
        return "volume:%s" % (label or "?")
    if isinstance(obj, FirmwareFileSystem):
        return "ffs"
    if isinstance(obj, FirmwareFile):
        if _is_padding(obj):
            return "padding"
        guid = _guid_of(obj)
        if guid:
            return "file:%s" % guid
        return "file:type%02x" % (getattr(obj, "type", 0) or 0)
    if isinstance(obj, FirmwareFileSystemSection):
        return "section:%02x" % (getattr(obj, "type", 0) or 0)
    if isinstance(obj, NVARVariable):
        return "nvar:%s" % (_ui_name_of(obj) or "?")
    if isinstance(obj, FirmwareCapsule):
        return "capsule:%s" % (_guid_of(obj) or "?")
    if name in ("PFSSection", "PFSPartitionedSection"):
        return "pfs-section:%s" % (sguid(getattr(obj, "uuid", b"")) or "?")
    if name == "MeModule":
        label = _ui_name_of(obj)
        if label is None:
            tag = getattr(obj, "tag", b"?")
            label = tag.decode("ascii", "replace") if isinstance(
                tag, bytes) else str(tag)
        return "me-module:%s" % (label or "?")
    if name == "CPDEntry":
        return "cpd-entry:%s" % (_ui_name_of(obj) or "?")
    if name == "MeVariableModule":
        tag = getattr(obj, "tag", b"?")
        return "me-vmodule:%s" % (
            tag.decode("ascii", "replace") if isinstance(tag, bytes)
            else str(tag))
    if isinstance(obj, PaddingObject):
        return "padding"
    return name.lower()


class _Walk(object):
    '''Collect components and padding from a tree without changing it.'''

    def __init__(self):
        self.components = []
        self.padding = []
        self.cache = {}

    def _record_padding(self, path, data):
        data = _as_bytes(data)
        self.padding.append({
            "path": "/".join(path),
            "containerPath": "/".join(path[:-1]),
            "size": len(data),
            "erased": _is_erased(data),
            "sha256": _digest(data),
        })

    def _record_raw_data(self, obj, path, data):
        '''Record non-erased padding, which can be vendor data.'''
        data = _as_bytes(data)
        self.components.append(ComponentSnapshot(
            path=path,
            container_path=path[:-1],
            kind=obj.__class__.__name__,
            guid=None,
            ui_name=None,
            raw=data,
            content_digest=_hash(["raw", data]),
            decode_status=DECODE_NOT_COMPRESSED,
            content_source=SOURCE_PARSED))

    def _add(self, obj, parent_path, label):
        if obj is None:
            return
        path = parent_path + (label,)
        if _is_padding(obj):
            data = _pad_bytes(obj)
            if _is_erased_padding(obj, data):
                self._record_padding(path, data)
            else:
                # A pad file holding other bytes may be vendor data; compare
                # it as content rather than dismissing it as fill.
                self._record_raw_data(obj, path, data)
            return

        if _is_component(obj):
            digest, status, source = _canonical(obj, 0, self.cache)
            self.components.append(ComponentSnapshot(
                path=path,
                container_path=parent_path,
                kind=obj.__class__.__name__,
                guid=_guid_of(obj),
                ui_name=_ui_name_of(obj),
                raw=_raw_bytes(obj),
                content_digest=digest,
                decode_status=status,
                content_source=source))

        if isinstance(obj, FirmwareFileSystem):
            overflow = _as_bytes(getattr(obj, "overflow_data", b""))
            if overflow:
                # Overflow is usually erased free space whose length follows
                # the files, so it is padding even when a few stale bytes
                # survive in it.
                self._record_padding(path + ("free",), overflow)

        counters = {}
        for child in _children_of(obj):
            if child is None:
                continue
            base = _base_label(child)
            occurrence = counters.get(base, 0)
            counters[base] = occurrence + 1
            child_label = base if occurrence == 0 else \
                "%s[%d]" % (base, occurrence)
            self._add(child, path, child_label)

    def run(self, obj):
        self._add(obj, (), _base_label(obj))
        parsed_container = isinstance(obj, (
            FirmwareVolume, FirmwareFileSystem, MultiVolumeContainer,
            FirmwareCapsule))
        if not self.components and obj is not None and not parsed_container:
            # Nothing parseable was found and the root is not a known
            # container, so compare it by its stored bytes. A change in an
            # unparsed image cannot then pass as identical.
            data = _raw_bytes(obj)
            if data:
                digest, status, source = _canonical(obj, 0, self.cache)
                self.components.append(ComponentSnapshot(
                    path=(_base_label(obj),),
                    container_path=(),
                    kind=obj.__class__.__name__,
                    guid=_guid_of(obj),
                    ui_name=_ui_name_of(obj),
                    raw=data,
                    content_digest=digest,
                    decode_status=status,
                    content_source=source))
        return self


class ComponentSnapshot(object):
    '''One component, with the evidence needed to compare and locate it.

    Attributes:
        path (tuple): The component's path of readable labels, such as
            ``('volume:ffs2', 'ffs', 'file:...')``.
        container_path (tuple): path without the component's own label.
        kind (str): The parsed object's class name.
        guid (str): The component's GUID, when it has one.
        ui_name (str): A display name, used only as a candidate hint.
        raw (bytes): The exact bytes the component was parsed from.
        size (int): The length of raw.
        raw_sha256 (str): Digest of raw, or None when it is empty.
        content_sha256 (str): Digest of the logical, parsed-or-decoded
            payload. None when the payload could not be decoded.
        content_source (str): 'decoded', 'parsed' or 'none'.
        decoded_sha256 (str): The content digest when it came from a decoder,
            otherwise None.
        decode_status (str): One of the DECODE_* values. A failure or an
            unsupported algorithm leaves content_sha256 as None and must not
            be reported as an unchanged payload.
        content_trusted (bool): False when the payload could not be decoded,
            so the stored bytes cannot establish payload equality.
    '''

    def __init__(self, path, container_path, kind, guid, ui_name, raw,
                 content_digest=None, decode_status=DECODE_NO_PAYLOAD,
                 content_source=SOURCE_NONE):
        self.path = tuple(path)
        self.container_path = tuple(container_path)
        self.kind = kind
        self.guid = guid
        self.ui_name = ui_name
        self.raw = _as_bytes(raw)
        self.size = len(self.raw)
        self.raw_sha256 = _digest(self.raw) if self.raw else None
        self.decode_status = decode_status
        self.content_sha256 = content_digest
        self.content_source = content_source
        self.content_trusted = (
            decode_status in TRUSTED_DECODE and content_digest is not None)
        if self.content_source == SOURCE_DECODED and \
                decode_status == DECODE_OK:
            self.decoded_sha256 = content_digest
        else:
            self.decoded_sha256 = None

    @property
    def path_label(self):
        return "/".join(self.path)

    @property
    def container_label(self):
        return "/".join(self.container_path)

    def to_dict(self):
        return {
            "path": self.path_label,
            "containerPath": self.container_label,
            "kind": self.kind,
            "guid": self.guid,
            "uiName": self.ui_name,
            "size": self.size,
            "rawSha256": self.raw_sha256,
            "rawPreview": self.raw[:64].hex(),
            "contentSha256": self.content_sha256,
            "contentSource": self.content_source,
            "decodedSha256": self.decoded_sha256,
            "decodeStatus": self.decode_status,
            "contentTrusted": self.content_trusted,
        }


class ComponentDiff(object):
    '''One component and its outcome.

    Attributes:
        left (ComponentSnapshot): The left component, or None for a component
            that exists only in the right tree.
        right (ComponentSnapshot): Its partner, or None.
        status (str): IDENTICAL, WRAPPER_ONLY, CONTENT_CHANGED, MOVED,
            UNVERIFIED, AMBIGUOUS, REMOVED or ADDED.
        basis (str): How the pair was found: content, path, identity or raw.
        evidence (list): Human-readable reasons for the pair and status.
        candidates (list): Right components that could not be chosen between,
            and so need a manual look.
    '''

    def __init__(self, left, right=None, status=IDENTICAL, evidence=None,
                 candidates=None, basis=None):
        self.left = left
        self.right = right
        self.status = status
        self.basis = basis
        self.evidence = list(evidence or [])
        self.candidates = list(candidates or [])

    @property
    def raw_changed(self):
        if self.left is None or self.right is None:
            return True
        return self.left.raw_sha256 != self.right.raw_sha256

    @property
    def content_changed(self):
        if self.left is None or self.right is None:
            return True
        if not (self.left.content_trusted and self.right.content_trusted):
            return None
        return self.left.content_sha256 != self.right.content_sha256

    @property
    def path_changed(self):
        if self.left is None or self.right is None:
            return True
        return self.left.path != self.right.path

    def to_dict(self):
        return {
            "left": self.left.to_dict() if self.left is not None else None,
            "right": self.right.to_dict() if self.right is not None else None,
            "status": self.status,
            "basis": self.basis,
            "rawChanged": self.raw_changed,
            "contentChanged": self.content_changed,
            "pathChanged": self.path_changed,
            "evidence": self.evidence,
            "candidates": [candidate.to_dict()
                           for candidate in self.candidates],
        }


def _status_for(left, right):
    '''Classify a pair, and return (status, evidence).'''
    evidence = []
    if not (left.content_trusted and right.content_trusted):
        evidence.append(
            "payload equality is unproven: decode status left=%s, right=%s" % (
                left.decode_status, right.decode_status))
        return UNVERIFIED, evidence

    if left.content_sha256 != right.content_sha256:
        evidence.append("payload digest differs: left %s, right %s" % (
            left.content_sha256[:12], right.content_sha256[:12]))
        if left.container_path != right.container_path:
            evidence.append("also moved from %s to %s" % (
                left.container_label, right.container_label))
        return CONTENT_CHANGED, evidence

    # A move is a change of container. The component label can also change,
    # for example when the file GUID changed in place, which is not a move.
    if left.container_path != right.container_path:
        evidence.append("payload matches; moved from %s to %s" % (
            left.container_label, right.container_label))
        return MOVED, evidence

    if left.raw_sha256 != right.raw_sha256:
        evidence.append(
            "stored bytes differ while the payload matches: compression, "
            "wrapper, metadata or padding changed")
        if left.ui_name != right.ui_name:
            evidence.append("display name changed from %r to %r (a name is "
                            "a clue, not content)" % (
                                left.ui_name, right.ui_name))
        if left.guid != right.guid:
            evidence.append("GUID changed from %s to %s while the payload "
                            "matched" % (left.guid, right.guid))
        if left.path != right.path:
            evidence.append("its path changed from %s to %s" % (
                left.path_label, right.path_label))
        return WRAPPER_ONLY, evidence

    evidence.append("payload and stored bytes match")
    return IDENTICAL, evidence


class FirmwareDiff(object):
    '''The read-only result of comparing two parsed firmware trees.

    Attributes:
        left_root: The left tree root.
        right_root: The right tree root.
        components (list): ComponentDiff in left tree order, then ADDED
            components found only in the right tree.
        padding (list): Padding entries present on only one side.
        summary (dict): Counts by status, plus 'padding'.
        verdict (str): The strongest overall outcome.
    '''

    def __init__(self, left_root, right_root):
        self.left_root = left_root
        self.right_root = right_root
        left_walk = _Walk().run(left_root)
        right_walk = _Walk().run(right_root)
        self.components = []
        self._match(left_walk.components, right_walk.components)
        self.padding = self._padding_changes(
            left_walk.padding, right_walk.padding)
        self.summary = {}
        for diff in self.components:
            self.summary[diff.status] = self.summary.get(diff.status, 0) + 1
        self.summary["padding"] = len(self.padding)
        self._set_verdict()

    # -- matching ---------------------------------------------------------

    @staticmethod
    def _key(snapshot):
        '''The identity hint that narrows the candidate search.

        GUIDs repeat, so this never decides a pair by itself. A UI name is
        not used, because it is display text and not an identity.
        '''
        if snapshot.guid:
            return (snapshot.kind, snapshot.guid)
        return (snapshot.kind, None)

    def _match(self, left, right):
        left_by_key = {}
        right_by_key = {}
        left_by_kind = {}
        right_by_kind = {}
        for item in left:
            left_by_key.setdefault(self._key(item), []).append(item)
            left_by_kind.setdefault(item.kind, []).append(item)
        for item in right:
            right_by_key.setdefault(self._key(item), []).append(item)
            right_by_kind.setdefault(item.kind, []).append(item)

        pairs = {}
        taken = set()

        def available(items):
            return [item for item in items if id(item) not in taken]

        def take(left_item, right_item, basis, evidence=None):
            pairs[id(left_item)] = (right_item, basis, list(evidence or []))
            taken.add(id(right_item))

        # 1. Trusted payload content, which is the strongest evidence and
        # does not depend on the GUID. A shared path separates duplicate
        # instances that hold identical payloads.
        for kind, left_items in left_by_kind.items():
            groups = {}
            for item in left_items:
                if item.content_trusted:
                    groups.setdefault(item.content_sha256, ([], []))[0].append(
                        item)
            for item in right_by_kind.get(kind, []):
                if item.content_trusted:
                    groups.setdefault(item.content_sha256, ([], []))[1].append(
                        item)
            for digest, (left_group, right_group) in groups.items():
                for left_item in list(left_group):
                    if id(left_item) in pairs:
                        continue
                    same_path = [candidate for candidate in available(
                        right_group) if candidate.path == left_item.path]
                    if len(same_path) == 1:
                        take(left_item, same_path[0], BASIS_CONTENT, [
                            "payload %s matches" % digest[:12],
                            "same component path"])
                remaining_left = [item for item in left_group
                                  if id(item) not in pairs]
                remaining_right = available(right_group)
                if len(remaining_left) == 1 and len(remaining_right) == 1:
                    take(remaining_left[0], remaining_right[0],
                         BASIS_CONTENT,
                         ["payload %s is the only match" % digest[:12]])
                elif len(remaining_left) == len(remaining_right):
                    # Pair the rest of the identical payloads by position.
                    # Their content is equal either way, and a shared order
                    # keeps a duplicate that did not move reported as such.
                    remaining_left.sort(key=lambda item: item.path)
                    remaining_right.sort(key=lambda item: item.path)
                    for left_item, right_item in zip(remaining_left,
                                                     remaining_right):
                        take(left_item, right_item, BASIS_CONTENT, [
                            "payload %s matches" % digest[:12],
                            "duplicate instance paired by order"])

        # 2. Remaining components under the same identity hint. When the
        # counts are equal the pair is by position; otherwise a lone
        # component on each side is the only safe pair. Anything else is
        # left for the ambiguous part of the report, because a GUID repeats.
        for key, left_items in left_by_key.items():
            remaining_left = [item for item in left_items
                              if id(item) not in pairs]
            remaining_right = available(right_by_key.get(key, []))
            evidence_hint = "only remaining component with %s" % (
                "GUID %s" % remaining_left[0].guid if remaining_left and
                remaining_left[0].guid else "kind %s" % key[0])
            if len(remaining_left) == 1 and len(remaining_right) == 1:
                take(remaining_left[0], remaining_right[0], BASIS_IDENTITY,
                     [evidence_hint])
            elif remaining_left and \
                    len(remaining_left) == len(remaining_right):
                remaining_left.sort(key=lambda item: item.path)
                remaining_right.sort(key=lambda item: item.path)
                for left_item, right_item in zip(remaining_left,
                                                 remaining_right):
                    take(left_item, right_item, BASIS_IDENTITY, [
                        "same GUID and position among %d instances" % (
                            len(remaining_left))])

        # 3. The same path, when duplicates leave phase 2 undecided. This
        # also pairs a component whose GUID changed in place. It only
        # applies when the counts match: with an extra or missing instance,
        # position cannot say which one changed, so the left instance is
        # reported as ambiguous instead of guessed.
        left_counts = {}
        right_counts = {}
        for item in left:
            left_counts[item.kind] = left_counts.get(item.kind, 0) + 1
        for item in right:
            right_counts[item.kind] = right_counts.get(item.kind, 0) + 1
        for left_item in left:
            if id(left_item) in pairs:
                continue
            if left_counts[left_item.kind] != right_counts.get(
                    left_item.kind, 0):
                continue
            same_path = [candidate for candidate in available(right)
                         if candidate.path == left_item.path and
                         candidate.kind == left_item.kind]
            if len(same_path) == 1:
                take(left_item, same_path[0], BASIS_PATH,
                     ["same component path"])

        # 4. Identical stored bytes for unverifiable payloads. This pairs
        # them for review but never proves their content equal.
        for kind, left_items in left_by_kind.items():
            remaining_left = [item for item in left_items
                              if id(item) not in pairs and
                              not item.content_trusted and
                              item.raw_sha256 is not None]
            remaining_right = [candidate for candidate in
                               available(right_by_kind.get(kind, []))
                               if not candidate.content_trusted and
                               candidate.raw_sha256 is not None]
            groups = {}
            for item in remaining_left:
                groups.setdefault(item.raw_sha256, ([], []))[0].append(item)
            for item in remaining_right:
                groups.setdefault(item.raw_sha256, ([], []))[1].append(item)
            for digest, (left_group, right_group) in groups.items():
                if len(left_group) != 1 or len(right_group) != 1:
                    continue
                take(left_group[0], right_group[0], BASIS_RAW, [
                    "stored bytes are identical, but the payload could not "
                    "be decoded; equality is unproven"])

        # 5. Report pairs and everything left over.
        added_right = set(id(item) for item in right)
        for left_item in left:
            if id(left_item) in pairs:
                right_item, basis, evidence = pairs[id(left_item)]
                status, status_evidence = _status_for(left_item, right_item)
                self.components.append(ComponentDiff(
                    left_item, right_item, status,
                    evidence + status_evidence, basis=basis))
                added_right.discard(id(right_item))
                continue

            candidates = available(right_by_key.get(self._key(left_item), []))
            if not candidates:
                candidates = [candidate for candidate in available(right)
                              if candidate.path == left_item.path and
                              candidate.kind == left_item.kind]
            if candidates:
                self.components.append(ComponentDiff(
                    left_item, None, AMBIGUOUS,
                    ["%d candidates share %s; payload and path do not choose "
                     "one" % (len(candidates),
                              "GUID %s" % left_item.guid if left_item.guid
                              else "kind %s" % left_item.kind)],
                    candidates=candidates))
                for candidate in candidates:
                    added_right.discard(id(candidate))
            else:
                self.components.append(ComponentDiff(
                    left_item, None, REMOVED,
                    ["no partner in the right tree"]))

        for right_item in right:
            if id(right_item) in added_right:
                self.components.append(ComponentDiff(
                    None, right_item, ADDED,
                    ["no partner in the left tree"]))

    # -- padding ----------------------------------------------------------

    @staticmethod
    def _padding_changes(left, right):
        '''Report padding that is present on only one side.

        Erased fill is sized by the files around it, so its length changes
        with every edit. Two erased entries at the same position are the
        same padding, and a shrunk or grown one is reported with both sizes.
        '''
        def key(entry):
            return (entry["erased"], entry["containerPath"])

        remaining = {}
        for entry in left:
            remaining.setdefault(key(entry), []).append(entry)

        changes = []
        for entry in right:
            entry_key = key(entry)
            candidates = remaining.get(entry_key, [])
            if entry["erased"]:
                # Erased fill is sized by the files around it. The same
                # position with another length is one padding that resized,
                # not one removed and one added.
                match = next((other for other in candidates
                              if other["size"] == entry["size"]), None)
                if match is None and candidates:
                    match = candidates[0]
                    changes.append(dict(entry, change="resized",
                                        previousSize=match["size"]))
                if match is not None:
                    candidates.remove(match)
                    continue
            else:
                match = candidates[0] if candidates else None
                if match is not None:
                    candidates.remove(match)
                    continue
            changes.append(dict(entry, change="added"))

        for entry_key, candidates in remaining.items():
            for entry in candidates:
                changes.append(dict(entry, change="removed"))
        return changes

    # -- report -----------------------------------------------------------

    def _set_verdict(self):
        statuses = [diff.status for diff in self.components]
        self.has_content_changes = CONTENT_CHANGED in statuses
        self.needs_manual_review = any(
            status in (AMBIGUOUS, UNVERIFIED) for status in statuses)
        self.has_structural_changes = any(
            status in (REMOVED, ADDED) for status in statuses)
        self.only_wrapper_or_padding = (
            not self.has_content_changes and
            not self.has_structural_changes and
            not any(status in (MOVED, AMBIGUOUS, UNVERIFIED)
                    for status in statuses) and
            (WRAPPER_ONLY in statuses or bool(self.padding)))

        if self.has_content_changes:
            self.verdict = CONTENT_CHANGED
        elif self.needs_manual_review:
            # An unverified or ambiguous pair is reported before structure:
            # a component that could not be judged is the reason to look.
            self.verdict = "needs_review"
        elif self.has_structural_changes:
            self.verdict = "structure_changed"
        elif MOVED in statuses:
            self.verdict = MOVED
        elif WRAPPER_ONLY in statuses:
            self.verdict = WRAPPER_ONLY
        elif self.padding:
            self.verdict = "padding_only"
        else:
            self.verdict = IDENTICAL

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "summary": dict(self.summary),
            "hasContentChanges": self.has_content_changes,
            "needsManualReview": self.needs_manual_review,
            "onlyWrapperOrPadding": self.only_wrapper_or_padding,
            "components": [diff.to_dict() for diff in self.components],
            "padding": list(self.padding),
        }

    def report(self):
        '''Return a human-readable report of the comparison.'''
        lines = [
            "verdict: %s" % self.verdict,
            "components: %d, changed payloads: %d, need review: %d" % (
                len(self.components),
                self.summary.get(CONTENT_CHANGED, 0),
                self.summary.get(AMBIGUOUS, 0) +
                self.summary.get(UNVERIFIED, 0)),
        ]
        for status in sorted(self.summary):
            if status == "padding":
                continue
            lines.append("  %-16s %d" % (status, self.summary[status]))
        if self.padding:
            lines.append("  %-16s %d" % ("padding", len(self.padding)))

        for diff in self.components:
            if diff.status == IDENTICAL:
                continue
            source = diff.left or diff.right
            lines.append("")
            lines.append("[%s] %s" % (diff.status, source.path_label))
            if diff.basis:
                lines.append("  basis: %s" % diff.basis)
            if diff.left is not None:
                left = diff.left
                lines.append(
                    "  left:  guid %s name %r size %d raw %s payload %s (%s)"
                    % (left.guid, left.ui_name, left.size,
                       left.raw_sha256, left.content_sha256,
                       left.content_source))
            if diff.right is not None:
                right = diff.right
                lines.append(
                    "  right: guid %s name %r size %d raw %s payload %s (%s)"
                    % (right.guid, right.ui_name, right.size,
                       right.raw_sha256, right.content_sha256,
                       right.content_source))
            for evidence in diff.evidence:
                lines.append("  evidence: %s" % evidence)
            for candidate in diff.candidates:
                lines.append(
                    "  candidate: %s raw %s payload %s (%s)" % (
                        candidate.path_label, candidate.raw_sha256,
                        candidate.content_sha256, candidate.decode_status))
        for entry in self.padding:
            lines.append("")
            lines.append("[padding %s] %s size %d erased %s" % (
                entry["change"], entry["path"], entry["size"],
                entry["erased"]))
        return "\n".join(lines)

    def showinfo(self):
        print(self.report())


def diff_firmware_trees(left, right):
    '''Compare two parsed firmware trees, returning a FirmwareDiff.

    Both arguments must already be parsed objects, such as the value returned
    by AutoParser.parse(). The trees are only read: nothing is rebuilt,
    modified or written.
    '''
    return FirmwareDiff(left, right)


def diff_firmware_files(left_path, right_path):
    '''Parse two firmware files and compare their trees.

    Returns:
        FirmwareDiff: The comparison. Either input that cannot be parsed
        raises ValueError rather than being treated as an empty tree.
    '''
    from . import AutoParser

    def parse(path):
        with open(path, "rb") as fh:
            data = fh.read()
        parser = AutoParser(data, search=True)
        if parser.type() == "unknown":
            raise ValueError("cannot detect the firmware type of %s" % path)
        firmware = parser.parse()
        if firmware is None:
            raise ValueError("cannot parse %s as %s" % (
                path, parser.type()))
        return firmware

    return FirmwareDiff(parse(left_path), parse(right_path))
