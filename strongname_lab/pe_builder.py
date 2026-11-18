"""Assemble minimal but structurally valid managed PE images.

The builder writes only file bytes: DOS/PE headers, one .text section holding
the CLI header, metadata, an IL method body and the strong-name signature
slot.  No assembly is ever loaded or executed.
"""

from __future__ import annotations

import struct

from . import crypto, metadata

IMAGE_BASE = 0x400000
SECTION_RVA = 0x2000
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x2000
HEADERS_SIZE = 0x200
CHECKSUM_OFFSET_IN_OPTIONAL = 64
DATA_DIRECTORY_OFFSET_IN_OPTIONAL = 96  # PE32
NUMBER_OF_RVA_AND_SIZES = 16
CLI_HEADER_SIZE = 72
ENTRY_STUB_RVA = 0x2000 + 0x400  # after CLI header + metadata, before IL body


class BuilderError(ValueError):
    pass


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_dos_header() -> bytes:
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos = bytearray(0x80)
    struct.pack_into("<H", dos, 0x00, 0x5A4D)
    struct.pack_into("<H", dos, 0x02, 0x90)      # e_cblp
    struct.pack_into("<H", dos, 0x04, 0x03)      # e_cp
    struct.pack_into("<H", dos, 0x06, 0x00)      # e_crlc
    struct.pack_into("<H", dos, 0x08, 0x04)      # e_cparhdr
    struct.pack_into("<H", dos, 0x0A, 0x00)      # e_minalloc
    struct.pack_into("<H", dos, 0x0C, 0xFFFF)    # e_maxalloc
    struct.pack_into("<H", dos, 0x0E, 0x00)      # e_ss
    struct.pack_into("<H", dos, 0x10, 0x00B8)    # e_sp
    struct.pack_into("<H", dos, 0x12, 0x00)      # e_csum
    struct.pack_into("<H", dos, 0x14, 0x00)      # e_ip
    struct.pack_into("<H", dos, 0x16, 0x00)      # e_cs
    struct.pack_into("<H", dos, 0x18, 0x40)      # e_lfarlc
    struct.pack_into("<I", dos, 0x3C, 0x80)      # e_lfanew
    dos[0x40:0x40 + len(stub)] = stub
    return bytes(dos)


def build_optional_header(
    *,
    text_raw_size: int,
    text_virtual_size: int,
    entry_point_rva: int,
    checksum: int,
    com_rva: int,
    com_size: int,
    cert_offset: int,
    cert_size: int,
    import_rva: int = 0,
    import_size: int = 0,
) -> bytes:
    header = bytearray()
    header += struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,          # Magic PE32
        0x30, 0x00,     # linker
        text_raw_size,  # SizeOfCode
        text_raw_size,  # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        entry_point_rva,
        SECTION_RVA,    # BaseOfCode
        SECTION_RVA,    # BaseOfData
        IMAGE_BASE,
        SECTION_ALIGN,
        FILE_ALIGN,
        4, 0,           # OS version
        0, 0,           # Image version
        4, 0,           # Subsystem version
        0,              # Win32VersionValue
        _align(SECTION_RVA + text_virtual_size, SECTION_ALIGN),  # SizeOfImage
        HEADERS_SIZE,
        checksum,
        3,              # IMAGE_SUBSYSTEM_WINDOWS_CUI
        0x0100,         # NX_COMPAT
        0x100000, 0x1000, 0x100000, 0x1000,
        0,              # LoaderFlags
        NUMBER_OF_RVA_AND_SIZES,
    )
    if len(header) != DATA_DIRECTORY_OFFSET_IN_OPTIONAL:
        raise BuilderError(f"optional header prefix is {len(header)} bytes, expected 96")
    directories = [(0, 0)] * NUMBER_OF_RVA_AND_SIZES
    directories[1] = (import_rva, import_size)
    directories[12] = (import_rva + 16, 8)  # IAT
    directories[14] = (com_rva, com_size)
    directories[4] = (cert_offset, cert_size)
    for rva, size in directories:
        header += struct.pack("<II", rva, size)
    return bytes(header)


def build_section_header(name: bytes, virtual_size: int, raw_size: int) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name, virtual_size, SECTION_RVA, raw_size, HEADERS_SIZE, 0, 0, 0, 0,
        0x60000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
    )


def build_cli_header(
    *,
    metadata_rva: int,
    metadata_size: int,
    flags: int,
    entry_point_token: int,
    strong_name_rva: int,
    strong_name_size: int,
) -> bytes:
    fields = [
        CLI_HEADER_SIZE, 2, 0,
        metadata_rva, metadata_size,
        flags, entry_point_token,
        0, 0,                                   # Resources
        strong_name_rva, strong_name_size,      # StrongNameSignature
        0, 0,                                   # CodeManagerTable
        0, 0,                                   # VTableFixups
        0, 0,                                   # ExportAddressTableJumps
        0, 0,                                   # ManagedNativeHeader
    ]
    header = struct.pack("<IHH" + "I" * (len(fields) - 3), *fields)
    if len(header) != CLI_HEADER_SIZE:
        raise BuilderError(f"CLI header is {len(header)} bytes, expected {CLI_HEADER_SIZE}")
    return header


def file_checksum(data: bytes, checksum_field_offset: int) -> int:
    """Standard PE image checksum (the field is treated as zero)."""
    total = 0
    length = len(data)
    # Sum 16-bit words with end-around carry.
    limit = length - (length % 2)
    for offset in range(0, limit, 2):
        value = data[offset] | (data[offset + 1] << 8)
        total += value
        total = (total & 0xFFFF) + (total >> 16)
    if length % 2:
        total += data[-1]
        total = (total & 0xFFFF) + (total >> 16)
    # Subtract the current checksum field content, then add the file length.
    current = struct.unpack_from("<I", data, checksum_field_offset)[0]
    total -= current & 0xFFFF
    total -= current >> 16
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    total += length
    return total & 0xFFFFFFFF


def build_import_stub(dll_name: str, symbol: str) -> tuple[bytes, int, int]:
    """Import directory + one hint/name entry + a 12-byte x86 jump thunk.

    Real managed PEs route AddressOfEntryPoint through mscoree.dll's
    _CorDllMain (or _CorExeMain).  The thunk is data only; it is never run.
    """
    rva_import = ENTRY_STUB_RVA
    descriptor_size = 20 * 2
    ilt_rva = rva_import + descriptor_size
    name_table_rva = ilt_rva + 8             # ILT (1 entry + null machine-word)
    hint_name_rva = name_table_rva + len(dll_name) + 1
    hint_name = struct.pack("<H", 0) + symbol.encode("ascii") + b"\x00"
    thunk_rva = hint_name_rva + len(hint_name)
    thunk = b"\xff\x25" + struct.pack("<I", IMAGE_BASE + thunk_rva + 6)
    blob = bytearray()
    blob += struct.pack("<IIIII", ilt_rva, 0, 0, name_table_rva, thunk_rva)
    blob += b"\x00" * 20
    blob += struct.pack("<I", hint_name_rva) + b"\x00" * 4
    blob += dll_name.encode("ascii") + b"\x00"
    blob += hint_name
    blob += thunk
    return bytes(blob), rva_import, len(blob)


def build_managed_pe(
    *,
    assembly_name: str,
    version: str,
    key: crypto.RSA.RsaKey,
    strong_name_signed: bool,
    public_key_blob: bytes,
    strong_name_slot: bool | None = None,
    strong_name_flag: bool | None = None,
    assembly_flags: int | None = None,
    assembly_refs: tuple[tuple[str, str, bytes], ...] = (),
    hash_name: str = "sha1",
    method_body: bytes = b"\x00\x2a",
    cert_table: bytes = b"",
) -> bytes:
    """Build the image with the strong-name slot reserved.

    The caller signs after this returns, using the reported slot offset.
    """
    if strong_name_slot is None:
        strong_name_slot = strong_name_signed
    if strong_name_flag is None:
        strong_name_flag = strong_name_signed
    if len(method_body) > 0x3F:
        raise BuilderError("tiny IL method body limited to 63 bytes")
    if assembly_flags is None:
        assembly_flags = 0x0001  # AssemblyFlags.PublicKey
    hash_alg_id = {"sha1": crypto.CALG_SHA1, "sha256": crypto.CALG_SHA256}[hash_name]
    builder = metadata.MetadataBuilder(
        assembly_name, version=version, flags=assembly_flags, hash_alg_id=hash_alg_id,
    )
    builder.public_key = public_key_blob
    for name, ref_version, token_or_key in assembly_refs:
        builder.add_assembly_ref(name, ref_version, token_or_key)
    builder.rows[metadata.TABLE_METHODDEF] = [{
        "RVA": 0, "ImplFlags": 0, "Flags": 0x0006,
        "Name": builder.string("Main"), "Signature": builder.blob(b"\x00\x00\x01"),
        "ParamList": 1,
    }]
    builder.rows[metadata.TABLE_PARAM] = [{
        "Flags": 0, "Sequence": 1, "Name": builder.string("args"),
    }]
    strong_name_size = (key.n.bit_length() + 7) // 8
    metadata_rva = SECTION_RVA + CLI_HEADER_SIZE
    metadata_placeholder = builder.build()
    body_rva = _align(ENTRY_STUB_RVA + 0x200, 4)
    builder.rows[metadata.TABLE_METHODDEF][0]["RVA"] = body_rva
    metadata_bytes = builder.build()
    if len(metadata_bytes) != len(metadata_placeholder):
        raise BuilderError("metadata size changed between layout passes")
    body_offset = body_rva - SECTION_RVA
    import_blob, import_rva, import_size = build_import_stub("mscoree.dll", "_CorDllMain")
    if SECTION_RVA + CLI_HEADER_SIZE + len(metadata_bytes) > ENTRY_STUB_RVA:
        raise BuilderError("metadata overlaps the entry stub region")

    strong_name_offset = _align(body_offset + len(method_body), 4)
    strong_name_rva = SECTION_RVA + strong_name_offset
    text_virtual_size = strong_name_offset + strong_name_size
    text_raw_size = _align(text_virtual_size, FILE_ALIGN)

    cli_flags = 0x1  # COMIMAGE_FLAGS_ILONLY
    if strong_name_flag:
        cli_flags |= 0x8  # COMIMAGE_FLAGS_STRONGNAMESIGNED

    text = bytearray(text_raw_size)
    cli = build_cli_header(
        metadata_rva=metadata_rva,
        metadata_size=len(metadata_bytes),
        flags=cli_flags,
        entry_point_token=0,
        strong_name_rva=strong_name_rva if strong_name_slot else 0,
        strong_name_size=strong_name_size if strong_name_slot else 0,
    )
    text[:len(cli)] = cli
    text[CLI_HEADER_SIZE:CLI_HEADER_SIZE + len(metadata_bytes)] = metadata_bytes
    text[ENTRY_STUB_RVA - SECTION_RVA:ENTRY_STUB_RVA - SECTION_RVA + len(import_blob)] = import_blob
    text[body_offset:body_offset + len(method_body)] = method_body
    headers = bytearray()
    headers += build_dos_header()
    headers += b"PE\x00\x00"
    headers += struct.pack(
        "<HHIIIHH",
        0x14C,           # Machine I386
        1,               # NumberOfSections
        0x5F5E1000,      # TimeDateStamp (fixed for reproducibility)
        0, 0,
        224,             # SizeOfOptionalHeader
        0x2102,          # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL
    )
    optional = build_optional_header(
        text_raw_size=text_raw_size,
        text_virtual_size=text_virtual_size,
        entry_point_rva=ENTRY_STUB_RVA,
        checksum=0,
        com_rva=SECTION_RVA,
        com_size=CLI_HEADER_SIZE,
        cert_offset=0,
        cert_size=0,
        import_rva=import_rva,
        import_size=import_size,
    )
    if len(optional) != 224:
        raise BuilderError(f"optional header is {len(optional)} bytes, expected 224")
    headers += optional
    headers += build_section_header(b".text", text_virtual_size, text_raw_size)
    if len(headers) > HEADERS_SIZE:
        raise BuilderError("headers exceed reserved header size")
    headers += b"\x00" * (HEADERS_SIZE - len(headers))

    image = bytearray(headers) + text
    checksum_offset = 0x80 + 24 + CHECKSUM_OFFSET_IN_OPTIONAL
    struct.pack_into("<I", image, checksum_offset, file_checksum(bytes(image), checksum_offset))
    return bytes(image)


def attach_certificate_table(image: bytes, certificate: bytes) -> tuple[bytes, int, int]:
    """Append a single WIN_CERTIFICATE entry; return (image, offset, size)."""
    if len(image) % 8:
        image += b"\x00" * (8 - len(image) % 8)
    entry_length = 8 + len(certificate)
    padded_length = _align(entry_length, 8)
    blob = struct.pack("<IHH", entry_length, 0x0200, 0x0002) + certificate
    blob += b"\x00" * (padded_length - len(blob))
    table_offset = len(image)
    image = image + blob
    # Fill the Certificate Table directory entry (index 4).
    entry_offset = 0x80 + 24 + DATA_DIRECTORY_OFFSET_IN_OPTIONAL + 4 * 8
    image = bytearray(image)
    struct.pack_into("<II", image, entry_offset, table_offset, padded_length)
    checksum_offset = 0x80 + 24 + CHECKSUM_OFFSET_IN_OPTIONAL
    struct.pack_into("<I", image, checksum_offset, file_checksum(bytes(image), checksum_offset))
    return bytes(image), table_offset, padded_length


def sign_strong_name(image: bytes, key: crypto.RSA.RsaKey, slot_offset: int, slot_size: int, hash_name: str = "sha1") -> bytes:
    import hashlib

    covered = strong_name_covered_bytes(image, slot_offset, slot_size)
    digest = hashlib.new(hash_name, covered).digest()
    signature = crypto.pkcs1_v15_sign(key, crypto.digest_info(hash_name, digest))
    signature_le = crypto.big_endian_signature_for_strong_name(signature)
    if len(signature_le) != slot_size:
        raise BuilderError("signature size does not match slot")
    out = bytearray(image)
    out[slot_offset:slot_offset + slot_size] = signature_le
    # The checksum field is excluded from the strong-name hash, so it can be
    # refreshed after signing without invalidating the signature.
    optional = _optional_header_offset(bytes(out))
    checksum_offset = optional + CHECKSUM_OFFSET_IN_OPTIONAL
    struct.pack_into("<I", out, checksum_offset, file_checksum(bytes(out), checksum_offset))
    return bytes(out)


def _optional_header_offset(image: bytes) -> int:
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    return e_lfanew + 24


def strong_name_excluded_ranges(image: bytes) -> tuple[tuple[int, int], tuple[int, int], int]:
    """Return (checksum_field, certificate_directory_entry, headers_end)."""
    e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
    optional = e_lfanew + 24
    checksum = (optional + CHECKSUM_OFFSET_IN_OPTIONAL, optional + CHECKSUM_OFFSET_IN_OPTIONAL + 4)
    cert_entry = (
        optional + DATA_DIRECTORY_OFFSET_IN_OPTIONAL + 4 * 8,
        optional + DATA_DIRECTORY_OFFSET_IN_OPTIONAL + 4 * 8 + 8,
    )
    size_of_headers = struct.unpack_from("<I", image, optional + 60)[0]
    if size_of_headers > len(image):
        raise BuilderError("SizeOfHeaders exceeds file size")
    return checksum, cert_entry, size_of_headers


def strong_name_covered_bytes(image: bytes, slot_offset: int, slot_size: int) -> bytes:
    """Headers plus raw section bytes, minus checksum, cert entry and signature slot."""
    import pefile

    pe = pefile.PE(data=image, fast_load=True)
    checksum_range, cert_range, _ = strong_name_excluded_ranges(image)
    segments = [(0, checksum_range[0]), (checksum_range[1], cert_range[0]), (cert_range[1], pe.OPTIONAL_HEADER.SizeOfHeaders)]
    for section in sorted(pe.sections, key=lambda s: s.PointerToRawData):
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if start == 0 or end == 0:
            continue
        if slot_offset >= start and slot_offset + slot_size <= end:
            segments.append((start, slot_offset))
            segments.append((slot_offset + slot_size, end))
        else:
            segments.append((start, end))
    covered = bytearray()
    for start, end in segments:
        if end > len(image):
            raise BuilderError(f"section range {start:#x}-{end:#x} exceeds file size")
        covered += image[start:end]
    return bytes(covered)
