"""MS-OVBA 2.4.1 CompressedContainer builder and dir-record helpers.

The compressor emits literal-only CompressedChunks (flag bit 0x1, no copy
tokens). That is fully conformant and is enough to carry arbitrary VBA source;
round-tripping through :func:`oletools.olevba.decompress_stream` recovers the
exact original bytes. Helpers also build the records of an MS-OVBA dir stream
and let a test rewrite a MODULEOFFSET value in place.
"""

import struct

CHUNK_DATA_MAX = 4096
# A literal-only chunk stores one flag byte per 8 data bytes plus one flag byte
# per group. The reference decompressor rejects a chunk whose total size exceeds
# 4095, and the 12-bit header field encodes (total_size - 3). For n data bytes
# the total size is 2 + ceil(n/8) + (n rounded up to a multiple of 8), so the
# largest safe whole-group source length is 3584 bytes
# (2 + 448 + 3584 = 4034 <= 4095).
LITERAL_CHUNK_MAX = 3584
SIGNATURE = 0x01


def compress_stream(data):
    """Compress bytes into an MS-OVBA CompressedContainer (literal chunks)."""
    if isinstance(data, str):
        data = data.encode('latin-1')
    out = bytearray([SIGNATURE])
    pos = 0
    while pos < len(data):
        chunk_data = data[pos:pos + LITERAL_CHUNK_MAX]
        pos += len(chunk_data)
        compressed = _compress_chunk(chunk_data)
        out.extend(compressed)
    return bytes(out)


def _compress_chunk(chunk_data):
    # literal tokens: one flag byte per group of up to 8 literal bytes.
    # The reference decompressor walks all 8 token slots per flag byte, so the
    # final (partial) group is padded with zero bytes to keep chunk alignment.
    body = bytearray()
    for start in range(0, len(chunk_data), 8):
        group = bytearray(chunk_data[start:start + 8])
        if len(group) < 8:
            group.extend(b'\x00' * (8 - len(group)))
        body.append(0x00)          # all eight flags 0 -> literals
        body.extend(group)
    chunk_size = len(body) + 2     # header counts itself
    header = (0b011 << 12) | (1 << 15) | (chunk_size - 3)
    return struct.pack('<H', header) + bytes(body)


def raw_chunk(chunk_data, declared_size=None):
    """Build an uncompressed (RawChunk, flag 0) chunk with 4096 data bytes."""
    if len(chunk_data) != CHUNK_DATA_MAX:
        raise ValueError('raw chunk must carry exactly 4096 bytes')
    chunk_size = declared_size if declared_size is not None else CHUNK_DATA_MAX + 2
    header = (0b011 << 12) | (0 << 15) | (chunk_size - 3)
    return struct.pack('<H', header) + chunk_data


def bad_signature_chunk():
    """A chunk header whose 3-bit signature is not 0b011 (decompress must fail)."""
    header = (0b000 << 12) | (1 << 15) | 0
    return struct.pack('<H', header) + b'\x00'


# --------------------------------------------------------------------------- #
# dir stream record builders (MS-OVBA 2.3.4.2)
# --------------------------------------------------------------------------- #

def _rec(rid, body):
    return struct.pack('<H', rid) + struct.pack('<L', len(body)) + body


def build_dir(modules, project_name=b'TestProj', codepage=1252, cookie=0xFFFF):
    """Build a decompressed dir stream for the given module descriptors.

    :param modules: list of dicts with keys name, streamname, textoffset,
                    module_type (0x21 procedural / 0x22 document).
    """
    out = bytearray()
    out += _rec(0x0001, struct.pack('<I', 0x01))                 # PROJECTSYSKIND
    out += _rec(0x0002, struct.pack('<I', 0x00000409))           # PROJECTLCID
    out += _rec(0x0014, struct.pack('<I', 0x00000409))           # PROJECTLCIDINVOKE
    out += _rec(0x0003, struct.pack('<H', codepage))             # PROJECTCODEPAGE
    out += _rec(0x0004, project_name)                            # PROJECTNAME
    out += _rec(0x0005, b'')                                     # PROJECTDOCSTRING
    out += struct.pack('<H', 0x0040)
    out += struct.pack('<L', 0)
    out += _rec(0x0006, b'')                                     # PROJECTHELPFILEPATH
    out += struct.pack('<H', 0x003D) + struct.pack('<L', 0)
    out += _rec(0x0007, struct.pack('<I', 0))                    # PROJECTHELPCONTEXT
    out += _rec(0x0008, struct.pack('<I', 0))                    # PROJECTLIBFLAGS
    # PROJECTVERSION (2.3.4.2.1.10) is Id + Reserved(4)=4 + Major(4) + Minor(2)
    out += struct.pack('<H', 0x0009) + struct.pack('<I', 4) \
        + struct.pack('<I', 1) + struct.pack('<H', 0)
    out += _rec(0x000C, b'')                                     # PROJECTCONSTANTS
    out += struct.pack('<H', 0x003C) + struct.pack('<L', 0)
    # no REFERENCE records: jump straight to PROJECTMODULES (0x000F)
    out += _rec(0x000F, struct.pack('<H', len(modules)))         # PROJECTMODULES
    out += _rec(0x0013, struct.pack('<H', cookie))               # ProjectCookie
    for mod in modules:
        out += _module_records(mod)
    return bytes(out)


def _module_records(mod):
    out = bytearray()
    name = mod['name']
    stream = mod['streamname']
    out += _rec(0x0019, name)                                    # MODULENAME
    # MODULESTREAMNAME (2.3.4.2.3.2.3): Id+Size+ANSI name, then Reserved(2)=0x32,
    # SizeOfStreamNameUnicode(4) and the UTF-16 stream name.
    out += struct.pack('<H', 0x001A) + struct.pack('<L', len(stream)) + stream
    stream_unicode = stream.decode('latin-1').encode('utf-16-le')
    out += struct.pack('<H', 0x0032) + struct.pack('<L', len(stream_unicode))
    out += stream_unicode
    # MODULEDOCSTRING (2.3.4.2.3.2.4): empty ANSI docstring + empty unicode part
    out += struct.pack('<H', 0x001C) + struct.pack('<L', 0)
    out += struct.pack('<H', 0x0048) + struct.pack('<L', 0)
    # The parser walks fixed record ids in this order after the docstring:
    # MODULEOFFSET (0x31), MODULEHELPCONTEXT (0x1E), MODULETYPE (0x21/0x22),
    # then the TERMINATOR (0x2B).
    out += _rec(0x0031, struct.pack('<I', mod['textoffset']))    # MODULEOFFSET
    out += _rec(0x001E, struct.pack('<I', 0))                    # MODULEHELPCONTEXT
    # MODULETYPE (2.3.4.2.3.2.8) is a fixed Id(2)+Reserved(4) record, no Size.
    out += struct.pack('<H', mod.get('module_type', 0x21)) + struct.pack('<I', 0)
    # TERMINATOR (2.3.4.2.3.2.10) is a fixed Id(2)+Reserved(4) record, with no
    # intervening Size field.
    out += struct.pack('<H', 0x002B) + struct.pack('<I', 0)
    return bytes(out)


def replace_module_offset(dir_decompressed, module_index, new_offset):
    """Rewrite one MODULEOFFSET (record id 0x0031, fixed size 4) in a dir stream.

    Returns the (same length) mutated bytes. The dir stream mixes Id/Size records
    with fixed (Id-only) records such as PROJECTVERSION, MODULETYPE and the
    TERMINATOR, so a generic length-walk cannot stay aligned; instead locate each
    ``31 00 04 00 00 00`` needle, which uniquely identifies a MODULEOFFSET record.
    """
    needle = struct.pack('<H', 0x0031) + struct.pack('<L', 4)
    data = bytearray(dir_decompressed)
    occurrences = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        occurrences.append(idx)
        start = idx + len(needle)
    if module_index >= len(occurrences):
        raise IndexError('MODULEOFFSET record %d not found (found %d)'
                         % (module_index, len(occurrences)))
    pos = occurrences[module_index]
    struct.pack_into('<I', data, pos + 6, new_offset)
    return bytes(data)
