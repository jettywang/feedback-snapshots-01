#-------------------------------------------------------------------------------
# elftools tests: synthetic ELF fixtures for static binding analysis
#
# Builds minimal ELF64 little-endian ET_DYN files containing only what the
# binding analyzer reads: .dynsym, .dynstr, .dynamic and the GNU version
# sections. No compiler, linker or host library is involved.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import struct

SHT_DYNSYM = 11
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_GNU_VERDEF = 0x6ffffffd
SHT_GNU_VERNEED = 0x6ffffffe
SHT_GNU_VERSYM = 0x6fffffff

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11
DT_SONAME = 14
DT_FLAGS = 30
DT_FLAGS_1 = 0x6ffffffb
DT_VERSYM = 0x6ffffff0
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd
DT_VERNEED = 0x6ffffffe
DT_VERNEEDNUM = 0x6fffffff

DF_SYMBOLIC = 0x2

BIND = {'LOCAL': 0, 'GLOBAL': 1, 'WEAK': 2}
VIS = {'DEFAULT': 0, 'INTERNAL': 1, 'HIDDEN': 2, 'PROTECTED': 3}
SHN_UNDEF = 0
SHN_ABS = 0xfff1

VER_FLG_BASE = 0x1
VER_NDX_GLOBAL = 1
VERSYM_HIDDEN = 0x8000


def sym(name, bind='GLOBAL', vis='DEFAULT', defined=False, version=None,
        version_hidden=False):
    """Convenience constructor for one symbol spec dict."""
    return dict(name=name, bind=bind, vis=vis, defined=defined,
                version=version, version_hidden=version_hidden)


class _StringTable:
    def __init__(self):
        self._blob = bytearray(b'\0')
        self._offsets = {'': 0}

    def add(self, s):
        if s not in self._offsets:
            self._offsets[s] = len(self._blob)
            self._blob += s.encode('utf-8') + b'\0'
        return self._offsets[s]

    def bytes(self):
        return bytes(self._blob)


def build_elf(path, *, soname=None, needed=(), flags=0, flags1=0,
              symbols=(), verdefs=(), verneeds=()):
    """Write a minimal ELF64 ET_DYN file to `path`.

    symbols:  iterable of sym() dicts, in .dynsym order (index 0 is the
              reserved null symbol).
    verdefs:  version names this file defines (VERDEF); indices start at 2.
    verneeds: (filename, [version names]) pairs recording version
              requirements (VERNEED) on needed libraries.
    """
    verdefs = list(verdefs)
    verneeds = [(fname, list(names)) for fname, names in verneeds]

    # Allocate version indices: verdef ndx and verneed vna_other share the
    # versym index space starting at 2.
    next_ndx = 2
    verdef_ndx = {}
    for name in verdefs:
        verdef_ndx[name] = next_ndx
        next_ndx += 1
    verneed_ndx = {}
    for _fname, names in verneeds:
        for name in names:
            verneed_ndx[name] = next_ndx
            next_ndx += 1

    dynstr = _StringTable()
    if soname is not None:
        dynstr.add(soname)
    for dep in needed:
        dynstr.add(dep)
    for spec in symbols:
        dynstr.add(spec['name'])
    for name in verdefs:
        dynstr.add(name)
    for fname, names in verneeds:
        dynstr.add(fname)
        for name in names:
            dynstr.add(name)

    # .dynsym
    dynsym = bytearray(24)  # reserved null symbol
    for i, spec in enumerate(symbols, start=1):
        info = (BIND[spec['bind']] << 4) | (2 if spec['defined'] else 0)
        dynsym += struct.pack(
            '<IBBHQQ',
            dynstr.add(spec['name']), info, VIS[spec['vis']],
            SHN_ABS if spec['defined'] else SHN_UNDEF,
            0x1000 * i if spec['defined'] else 0,
            0x10 if spec['defined'] else 0)

    # .gnu.version
    versioned = bool(verdefs or verneeds)
    versym = bytearray()
    if versioned:
        versym += struct.pack('<H', 0)
        for spec in symbols:
            if spec['version'] is None:
                ndx = VER_NDX_GLOBAL
            elif spec['defined']:
                ndx = verdef_ndx[spec['version']]
            else:
                ndx = verneed_ndx[spec['version']]
            if spec['version_hidden']:
                ndx |= VERSYM_HIDDEN
            versym += struct.pack('<H', ndx)

    # .gnu.version_d
    verdef_data = bytearray()
    if verdefs:
        for i, name in enumerate(verdefs):
            verdef_data += struct.pack(
                '<HHHHIII', 1, 0, verdef_ndx[name], 1, 0, 20,
                28 if i + 1 < len(verdefs) else 0)
            verdef_data += struct.pack('<II', dynstr.add(name), 0)

    # .gnu.version_r
    verneed_data = bytearray()
    if verneeds:
        for i, (fname, names) in enumerate(verneeds):
            aux_size = 16 * len(names)
            verneed_data += struct.pack(
                '<HHIII', 1, len(names), dynstr.add(fname), 16,
                16 + aux_size if i + 1 < len(verneeds) else 0)
            for j, name in enumerate(names):
                verneed_data += struct.pack(
                    '<IHHII', 0, 0, verneed_ndx[name], dynstr.add(name),
                    16 if j + 1 < len(names) else 0)

    # .dynamic (addresses are file offsets; nothing is ever loaded)
    dynstr_bytes = dynstr.bytes()
    sections = []  # (name, type, flags, align, link, info, entsize, data)
    sections.append(('.dynsym', SHT_DYNSYM, 0x2, 8, 2, 1, 24, bytes(dynsym)))
    sections.append(('.dynstr', SHT_STRTAB, 0x2, 1, 0, 0, 0, dynstr_bytes))

    # Lay out to know offsets for DT_* values.
    offset = 64
    placed = []
    for name, sht, shflags, align, link, info, entsize, data in sections:
        offset = _align(offset, align)
        placed.append((name, sht, shflags, align, link, info, entsize, data,
                       offset))
        offset += len(data)

    dynsec_off = _align(offset, 8)
    # .dynamic size depends on the tag count; version section offsets are
    # patched into the tags once the layout below is final.
    tags = []
    for dep in needed:
        tags.append((DT_NEEDED, dynstr.add(dep)))
    if flags:
        tags.append((DT_FLAGS, flags))
    if flags1:
        tags.append((DT_FLAGS_1, flags1))
    if soname is not None:
        tags.append((DT_SONAME, dynstr.add(soname)))
    dynsym_off = placed[0][8]
    dynstr_off = placed[1][8]
    tags += [
        (DT_STRTAB, dynstr_off), (DT_SYMTAB, dynsym_off),
        (DT_STRSZ, len(dynstr_bytes)), (DT_SYMENT, 24),
    ]
    if versioned:
        tags.append((DT_VERSYM, 'versym'))
        if verdefs:
            tags.append((DT_VERDEF, 'verdef'))
            tags.append((DT_VERDEFNUM, len(verdefs)))
        if verneeds:
            tags.append((DT_VERNEED, 'verneed'))
            tags.append((DT_VERNEEDNUM, len(verneeds)))
    tags.append((DT_NULL, 0))

    cur = dynsec_off + 16 * len(tags)
    extra_sections = []
    versym_off = verdef_off = verneed_off = 0
    if versioned:
        versym_off = _align(cur, 2)
        cur = versym_off + len(versym)
        extra_sections.append(('.gnu.version', SHT_GNU_VERSYM, 0x2, 2, 1, 0,
                               2, bytes(versym), versym_off))
        if verdefs:
            verdef_off = _align(cur, 4)
            cur = verdef_off + len(verdef_data)
            extra_sections.append(('.gnu.version_d', SHT_GNU_VERDEF, 0x2, 4,
                                   2, len(verdefs), 0, bytes(verdef_data),
                                   verdef_off))
        if verneeds:
            verneed_off = _align(cur, 4)
            cur = verneed_off + len(verneed_data)
            extra_sections.append(('.gnu.version_r', SHT_GNU_VERNEED, 0x2, 4,
                                   2, len(verneeds), 0, bytes(verneed_data),
                                   verneed_off))
    offsets = {'versym': versym_off, 'verdef': verdef_off,
               'verneed': verneed_off}
    tags = [(t, offsets[v] if isinstance(v, str) else v) for t, v in tags]
    dynamic = b''.join(struct.pack('<qQ', t, v) for t, v in tags)
    placed.append(('.dynamic', SHT_DYNAMIC, 0x3, 8, 2, 0, 16, dynamic,
                   dynsec_off))
    placed.extend(extra_sections)

    # .shstrtab
    shstrtab = _StringTable()
    for name, *_rest in placed:
        shstrtab.add(name)
    shstrtab.add('.shstrtab')
    shstr_off = _align(cur, 1)
    cur = shstr_off + len(shstrtab.bytes())
    placed.append(('.shstrtab', SHT_STRTAB, 0, 1, 0, 0, 0, shstrtab.bytes(),
                   shstr_off))

    shoff = _align(cur, 8)
    shnum = len(placed) + 1
    shstrndx = len(placed)

    blob = bytearray()
    blob += struct.pack(
        '<16sHHIQQQIHHHHHH',
        b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8),  # e_ident
        3,        # ET_DYN
        62,       # EM_X86_64
        1, 0, 0, shoff, 0, 64, 56, 0, 64, shnum, shstrndx)
    for name, sht, shflags, align, link, info, entsize, data, off in placed:
        blob += bytes(off - len(blob))
        blob += data
    blob += bytes(shoff - len(blob))
    blob += bytes(64)  # null section header
    for name, sht, shflags, align, link, info, entsize, data, off in placed:
        blob += struct.pack(
            '<IIQQQQIIQQ',
            shstrtab.add(name), sht, shflags, 0, off, len(data),
            link, info, align, entsize)
    with open(path, 'wb') as stream:
        stream.write(bytes(blob))
    return path


def _align(value, align):
    return (value + align - 1) & ~(align - 1) if align > 1 else value
