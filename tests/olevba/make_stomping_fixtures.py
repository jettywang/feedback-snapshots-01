"""
Build real OLE VBA fixtures for the VBA stomping detection tests.

The fixtures are derived from tests/test-data/olevba/sample_with_vba.ppt by
extracting its embedded VBA OLE subfile and rewriting the *compressed source
code* region of a module stream only. The P-code performance cache (including
its 0xCAFE magic) is left byte-for-byte untouched, so pcodedmp still
disassembles the original P-code while olevba decompresses different source
code. No macro is ever executed and no pcodedmp output is fabricated: the
fixtures are genuine OLE files processed end-to-end by both libraries.

Run with the project virtualenv:
    .venv/bin/python tests/olevba/make_stomping_fixtures.py
"""

import math
import os
import shutil
import struct

import olefile

from oletools.olevba import decompress_stream
from oletools import ppt_parser

# ---------------------------------------------------------------------------
# MS-OVBA 2.4.1.3.6 compressor (literal + CopyToken), the write-side counterpart
# of olevba.decompress_stream. Only needed to build the fixtures below.
# ---------------------------------------------------------------------------

def _bit_count(decompressed_current):
    if decompressed_current <= 0:
        return 4
    return max(int(math.ceil(math.log(decompressed_current, 2))), 4)


def _pack_copy_token(offset, length, decompressed_current):
    bit_count = _bit_count(decompressed_current)
    length_mask = 0xFFFF >> bit_count
    return ((offset - 1) << (16 - bit_count)) | ((length - 3) & length_mask)


def _compress_chunk(chunk):
    body = bytearray()
    pos = 0
    size = len(chunk)
    while pos < size:
        flag_index = len(body)
        body.append(0)
        flags = 0
        for bit in range(8):
            if pos >= size:
                break
            bit_count = _bit_count(pos)
            max_length = (0xFFFF >> bit_count) + 3
            best_length = 0
            best_offset = 0
            for offset in range(1, pos + 1):
                match_length = 0
                while (match_length < max_length
                       and pos + match_length < size
                       and chunk[pos - offset + (match_length % offset)]
                       == chunk[pos + match_length]):
                    match_length += 1
                if match_length > best_length:
                    best_length = match_length
                    best_offset = offset
                    if match_length >= max_length:
                        break
            if best_length >= 3:
                token = _pack_copy_token(best_offset, best_length, pos)
                body += struct.pack('<H', token)
                flags |= 1 << bit
                pos += best_length
            else:
                body.append(chunk[pos])
                pos += 1
        body[flag_index] = flags
    return bytes(body)


def compress_stream(data):
    """Compress bytes into an MS-OVBA CompressedContainer."""
    out = bytearray(b'\x01')
    for start in range(0, len(data), 4096):
        chunk = data[start:start + 4096]
        if len(chunk) == 4096:
            out += struct.pack('<H', 0x3000 | 4095) + chunk
            continue
        body = _compress_chunk(chunk)
        # 4098 = 2 header bytes + 4096 max chunk body
        if len(body) + 2 > 4098:  # pragma: no cover - defensive, chunks are small
            out += struct.pack('<H', 0x3000 | 4095) + chunk
        else:
            out += struct.pack('<H', 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def pad_container(container, target_size):
    """
    Grow a compressed container to exactly target_size by appending literal
    space tokens to the last compressed chunk. A free slot in the current
    8-token group costs one byte; a new flag group costs two bytes (flag +
    token). The chunk size header is adjusted by the number of bytes appended,
    and decompression only yields extra trailing spaces, which do not affect
    the stomping comparison.
    """
    container = bytearray(container)
    if len(container) > target_size:
        raise ValueError('container already larger than target size')
    # locate the last chunk header
    index = 1
    last_header = 1
    while index < len(container):
        header = struct.unpack('<H', bytes(container[index:index + 2]))[0]
        last_header = index
        index += (header & 0x0FFF) + 3
    header = struct.unpack('<H', bytes(container[last_header:last_header + 2]))[0]
    if not (header >> 15):
        raise ValueError('cannot pad a raw chunk')
    # count the token slots used by the last flag group of the chunk body
    position = last_header + 2
    body_end = len(container)
    used_slots = 0
    while position < body_end:
        flag_byte = container[position]
        position += 1
        for slot in range(8):
            if position >= body_end:
                break
            position += 2 if (flag_byte >> slot) & 1 else 1
            used_slots = slot + 1
    while len(container) < target_size:
        if used_slots < 8:
            container.append(0x20)          # one literal space token
            used_slots += 1
            header += 1
        else:
            container.append(0x00)          # new all-literal flag group
            container.append(0x20)
            used_slots = 1
            header += 2
        container[last_header:last_header + 2] = struct.pack('<H', header)
    if len(container) != target_size:
        raise ValueError('cannot pad container to target size')
    # validate the padded container round-trips through the real decompressor
    decompress_stream(bytearray(container))
    return bytes(container)


def _literal_compress(data):
    """Compress using only literal tokens; useful when no repeats are expected."""
    out = bytearray(b'\x01')
    for start in range(0, len(data), 4096):
        chunk = data[start:start + 4096]
        if len(chunk) == 4096:
            out += struct.pack('<H', 0x3000 | 4095) + chunk
            continue
        body = bytearray()
        for index in range(0, len(chunk), 8):
            body.append(0x00)
            body += chunk[index:index + 8]
        out += struct.pack('<H', 0xB000 | (len(body) + 2 - 3)) + body
    return bytes(out)


def find_source_offset(module_stream):
    """Return the offset of the compressed source container in a module stream."""
    for index, byte in enumerate(module_stream):
        if byte != 0x01:
            continue
        try:
            decompressed = decompress_stream(bytearray(module_stream[index:]))
        except Exception:
            continue
        if decompressed and b'Attribute VB_Name' in decompressed:
            return index
    raise RuntimeError('compressed source container not found in module stream')


def replace_module_source(ole_path, stream_path, new_source, target_container_size):
    """Rewrite the compressed source region of one module, keeping P-code intact."""
    if isinstance(new_source, str):
        new_source = new_source.encode('latin-1')
    container = pad_container(compress_stream(new_source), target_container_size)
    # sanity check: our container is valid and decompresses back to the new source
    decompressed = decompress_stream(bytearray(container))
    if not decompressed.startswith(new_source):
        raise RuntimeError('container roundtrip failed')
    ole = olefile.OleFileIO(ole_path, write_mode=True)
    raw = bytearray(ole.openstream(stream_path).read())
    offset = find_source_offset(raw)
    if len(raw) - offset != target_container_size:
        ole.close()
        raise RuntimeError('unexpected source container size')
    raw[offset:] = container
    ole.write_stream(stream_path, bytes(raw))
    ole.close()


def extract_base_project(destination):
    source_ppt = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'test-data', 'olevba', 'sample_with_vba.ppt')
    ole = olefile.OleFileIO(source_ppt)
    vba_data = list(ppt_parser.PptParser(ole, fast_fail=True).iter_vba_data())[0]
    ole.close()
    with open(destination, 'wb') as handle:
        handle.write(vba_data)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(here, os.pardir, 'test-data', 'olevba', 'stomping')
    data_dir = os.path.abspath(data_dir)
    if not os.path.isdir(data_dir):
        os.makedirs(data_dir)
    base = os.path.join(data_dir, '_base_project.bin')
    extract_base_project(base)

    ole = olefile.OleFileIO(base)
    module_stream = ole.openstream('VBA/Module1').read()
    ole.close()
    source_offset = find_source_offset(module_stream)
    container_size = len(module_stream) - source_offset
    original_source = decompress_stream(bytearray(module_stream[source_offset:]))
    print('base module stream: %d bytes, source container: %d bytes, '
          'source: %d bytes' % (len(module_stream), container_size,
                                len(original_source)))

    # Fixture 1: real stomping. The visible source is benign and contains none
    # of the P-code string "The action button clicked!"; its length is matched
    # with trailing spaces. (MsgBox is present in both, the LitStr is not.)
    stomped_source = (
        'Attribute VB_Name = "Module1"\r\n'
        'Sub BenignProc()\r\n'
        '  MsgBox "Document ready."\r\n'
        'End Sub\r\n'
    )
    if len(stomped_source) > len(original_source):
        raise RuntimeError('stomped source longer than original')
    stomped_source += ' ' * (len(original_source) - len(stomped_source))
    stomped = os.path.join(data_dir, 'stomped_module.bin')
    shutil.copy(base, stomped)
    replace_module_source(stomped, 'VBA/Module1', stomped_source, container_size)
    print('written', stomped)

    # Fixture 2: not stomped, source re-serialized with the same content. The
    # P-code keywords must still match after the source container is rebuilt.
    clean = os.path.join(data_dir, 'clean_recompressed.bin')
    shutil.copy(base, clean)
    replace_module_source(clean, 'VBA/Module1',
                          original_source.decode('latin-1'), container_size)
    print('written', clean)

    # Fixture 3: unanalysable input. The module stream is truncated inside the
    # P-code performance cache, so pcodedmp cannot produce a disassembly while
    # the OLE structure itself stays openable. Source is still present.
    unanalysable = os.path.join(data_dir, 'pcode_unparseable.bin')
    shutil.copy(base, unanalysable)
    ole = olefile.OleFileIO(unanalysable, write_mode=True)
    raw = bytearray(ole.openstream('VBA/Module1').read())
    # keep the compressed source region, zero the P-code magic region so no
    # disassembly can be produced (pcodedmp bails out before the 0xCAFE check)
    cafe = raw.find(b'\xfe\xca')
    raw[:source_offset] = b'\x00' * source_offset
    assert cafe < source_offset
    ole.write_stream('VBA/Module1', bytes(raw))
    ole.close()
    print('written', unanalysable)

    os.remove(base)
    print('done')


if __name__ == '__main__':
    main()
