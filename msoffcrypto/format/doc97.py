import io
import logging
import shutil
import tempfile
from collections import namedtuple
from struct import pack, unpack, unpack_from

import olefile

from msoffcrypto import exceptions
from msoffcrypto.format import base
from msoffcrypto.format.common import _parse_header_RC4CryptoAPI
from msoffcrypto.method.rc4 import DocumentRC4
from msoffcrypto.method.rc4_cryptoapi import DocumentRC4CryptoAPI

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

FibBase = namedtuple(
    "FibBase",
    [
        "wIdent",
        "nFib",
        "unused",
        "lid",
        "pnNext",
        "fDot",
        "fGlsy",
        "fComplex",
        "fHasPic",
        "cQuickSaves",
        "fEncrypted",
        "fWhichTblStm",
        "fReadOnlyRecommended",
        "fWriteReservation",
        "fExtChar",
        "fLoadOverride",
        "fFarEast",
        "nFibBack",
        "fObfuscation",
        "IKey",
        "envr",
        "fMac",
        "fEmptySpecial",
        "fLoadOverridePage",
        "reserved1",
        "reserved2",
        "fSpare0",
        "reserved3",
        "reserved4",
        "reserved5",
        "reserved6",
    ],
)


def _parseFibBase(blob):
    r"""
    Pasrse FibBase binary blob.

        >>> blob = io.BytesIO(b'\xec\xa5\xc1\x00G\x00\t\x04\x00\x00\x00\x13\xbf\x004\x00\
        ... \x00\x00\x00\x10\x00\x00\x00\x00\x00\x04\x00\x00\x16\x04\x00\x00')
        >>> fibbase = _parseFibBase(blob)
        >>> hex(fibbase.wIdent)
        '0xa5ec'
        >>> hex(fibbase.nFib)
        '0xc1'
        >>> hex(fibbase.fExtChar)
        '0x1'
    """
    getBit = lambda bits, i: (bits & (1 << i)) >> i
    getBitSlice = lambda bits, i, w: (bits & (2**w - 1 << i)) >> i

    # https://msdn.microsoft.com/en-us/library/dd944620(v=office.12).aspx
    (buf,) = unpack_from("<H", blob.read(2))
    wIdent = buf

    (buf,) = unpack_from("<H", blob.read(2))
    nFib = buf

    (buf,) = unpack_from("<H", blob.read(2))
    unused = buf

    (buf,) = unpack_from("<H", blob.read(2))
    lid = buf

    (buf,) = unpack_from("<H", blob.read(2))
    pnNext = buf

    (buf,) = unpack_from("<H", blob.read(2))
    fDot = getBit(buf, 0)
    fGlsy = getBit(buf, 1)
    fComplex = getBit(buf, 2)
    fHasPic = getBit(buf, 3)
    cQuickSaves = getBitSlice(buf, 4, 4)
    fEncrypted = getBit(buf, 8)
    fWhichTblStm = getBit(buf, 9)
    fReadOnlyRecommended = getBit(buf, 10)
    fWriteReservation = getBit(buf, 11)
    fExtChar = getBit(buf, 12)
    fLoadOverride = getBit(buf, 13)
    fFarEast = getBit(buf, 14)
    fObfuscation = getBit(buf, 15)

    (buf,) = unpack_from("<H", blob.read(2))
    nFibBack = buf

    (buf,) = unpack_from("<I", blob.read(4))
    IKey = buf

    (buf,) = unpack_from("<B", blob.read(1))
    envr = buf

    (buf,) = unpack_from("<B", blob.read(1))
    fMac = getBit(buf, 0)
    fEmptySpecial = getBit(buf, 1)
    fLoadOverridePage = getBit(buf, 2)
    reserved1 = getBit(buf, 3)
    reserved2 = getBit(buf, 4)
    fSpare0 = getBitSlice(buf, 5, 3)

    (buf,) = unpack_from("<H", blob.read(2))
    reserved3 = buf

    (buf,) = unpack_from("<H", blob.read(2))
    reserved4 = buf

    (buf,) = unpack_from("<I", blob.read(4))
    reserved5 = buf

    (buf,) = unpack_from("<I", blob.read(4))
    reserved6 = buf

    fibbase = FibBase(
        wIdent=wIdent,
        nFib=nFib,
        unused=unused,
        lid=lid,
        pnNext=pnNext,
        fDot=fDot,
        fGlsy=fGlsy,
        fComplex=fComplex,
        fHasPic=fHasPic,
        cQuickSaves=cQuickSaves,
        fEncrypted=fEncrypted,
        fWhichTblStm=fWhichTblStm,
        fReadOnlyRecommended=fReadOnlyRecommended,
        fWriteReservation=fWriteReservation,
        fExtChar=fExtChar,
        fLoadOverride=fLoadOverride,
        fFarEast=fFarEast,
        nFibBack=nFibBack,
        fObfuscation=fObfuscation,
        IKey=IKey,
        envr=envr,
        fMac=fMac,
        fEmptySpecial=fEmptySpecial,
        fLoadOverridePage=fLoadOverridePage,
        reserved1=reserved1,
        reserved2=reserved2,
        fSpare0=fSpare0,
        reserved3=reserved3,
        reserved4=reserved4,
        reserved5=reserved5,
        reserved6=reserved6,
    )
    return fibbase


def _packFibBase(fibbase):
    setBit = lambda bits, i, v: (bits & ~(1 << i)) | (v << i)
    setBitSlice = lambda bits, i, w, v: (bits & ~((2**w - 1) << i)) | (
        (v & (2**w - 1)) << i
    )

    blob = io.BytesIO()
    buf = pack("<H", fibbase.wIdent)
    blob.write(buf)

    buf = pack("<H", fibbase.nFib)
    blob.write(buf)

    buf = pack("<H", fibbase.unused)
    blob.write(buf)

    buf = pack("<H", fibbase.lid)
    blob.write(buf)

    buf = pack("<H", fibbase.pnNext)
    blob.write(buf)

    _buf = 0xFFFF
    _buf = setBit(_buf, 0, fibbase.fDot)
    _buf = setBit(_buf, 1, fibbase.fGlsy)
    _buf = setBit(_buf, 2, fibbase.fComplex)
    _buf = setBit(_buf, 3, fibbase.fHasPic)
    _buf = setBitSlice(_buf, 4, 4, fibbase.cQuickSaves)
    _buf = setBit(_buf, 8, fibbase.fEncrypted)
    _buf = setBit(_buf, 9, fibbase.fWhichTblStm)
    _buf = setBit(_buf, 10, fibbase.fReadOnlyRecommended)
    _buf = setBit(_buf, 11, fibbase.fWriteReservation)
    _buf = setBit(_buf, 12, fibbase.fExtChar)
    _buf = setBit(_buf, 13, fibbase.fLoadOverride)
    _buf = setBit(_buf, 14, fibbase.fFarEast)
    _buf = setBit(_buf, 15, fibbase.fObfuscation)
    buf = pack("<H", _buf)
    blob.write(buf)

    buf = pack("<H", fibbase.nFibBack)
    blob.write(buf)

    buf = pack("<I", fibbase.IKey)
    blob.write(buf)

    buf = pack("<B", fibbase.envr)
    blob.write(buf)

    _buf = 0xFF
    _buf = setBit(_buf, 0, fibbase.fMac)
    _buf = setBit(_buf, 1, fibbase.fEmptySpecial)
    _buf = setBit(_buf, 2, fibbase.fLoadOverridePage)
    _buf = setBit(_buf, 3, fibbase.reserved1)
    _buf = setBit(_buf, 4, fibbase.reserved2)
    _buf = setBitSlice(_buf, 5, 3, fibbase.fSpare0)
    buf = pack("<B", _buf)
    blob.write(buf)

    buf = pack("<H", fibbase.reserved3)
    blob.write(buf)

    buf = pack("<H", fibbase.reserved4)
    blob.write(buf)

    buf = pack("<I", fibbase.reserved5)
    blob.write(buf)

    buf = pack("<I", fibbase.reserved6)
    blob.write(buf)

    blob.seek(0)
    return blob


def _parseFib(blob):
    Fib = namedtuple("Fib", ["base"])
    fib = Fib(base=_parseFibBase(blob))
    return fib


FIB_BASE_LENGTH = 0x20

#: MS-DOC 2.1: FibBase and the beginning of the FIB (0x44 bytes) are stored
#: unencrypted in the WordDocument stream.
FIB_LENGTH_UNENCRYPTED = 0x44


def _parseFibRgFcLcb(blob):
    r"""Return ``(pairs, end_offset)`` for the FIB hub following FibBase.

    The pairs are offsets and sizes into the table stream
    (MS-DOC 2.1.2 FibRgFcLcb97). Truncation anywhere inside the FIB hub is
    reported as a ParseError instead of a struct.error.
    """

    def read_exact(offset, size, label):
        blob.seek(offset)
        raw = blob.read(size)
        if len(raw) != size:
            raise exceptions.ParseError(
                "WordDocument stream is truncated in the FIB {} at offset "
                "{:#x}: needed {} bytes, found {}".format(
                    label, offset, size, len(raw)
                )
            )
        return raw

    (csw,) = unpack("<H", read_exact(FIB_BASE_LENGTH, 2, "csw"))
    offset = FIB_BASE_LENGTH + 2 + csw * 2
    (cslw,) = unpack("<H", read_exact(offset, 2, "cslw"))
    offset += 2 + cslw * 4
    (cb,) = unpack("<H", read_exact(offset, 2, "cbRgFcLcb"))
    offset += 2
    pairs = []
    for _ in range(cb):
        pairs.append(unpack("<II", read_exact(offset, 8, "fc/lcb pairs")))
        offset += 8
    return pairs, offset


#: Index 87 of FibRgFcLcb97 is ftModified (an 8-byte FILETIME), not an
#: fc/lcb pair. It must not be interpreted as an offset/size pair.
_FIB_FTMODIFIED_INDEX = 87

#: Index of fcClx in FibRgFcLcb97: the CLX holding the piece table.
_FIB_FC_CLX_INDEX = 33


def _validate_table_extents(pairs, table_size, table_name):
    """Reject a table stream that is shorter than the FIB says it is."""
    for index, (fc, lcb) in enumerate(pairs):
        if index == _FIB_FTMODIFIED_INDEX or lcb == 0:
            continue
        if fc == 0xFFFFFFFF:
            continue
        if lcb > table_size or fc + lcb > table_size:
            raise exceptions.ParseError(
                "FIB fc/lcb pair {} (fc={:#x}, lcb={:#x}, end={:#x}) lies outside "
                "the {}-byte {} stream; the table stream is truncated".format(
                    index, fc, lcb, fc + lcb, table_size, table_name
                )
            )


def _text_extents_from_clx(clx):
    r"""Return the highest byte offset referenced by a CLX piece table.

    MS-DOC 2.8.35 PlcPcd: each piece stores a file offset (``fc``). The two
    low flag bits of a compressed piece's fc are used as a compression marker,
    so ``fc & 0x3FFFFFFF`` is the real offset; a compressed piece stores two
    characters per byte, so one byte per character position is a safe outer
    bound for the stream range the piece table references.
    """
    highest = 0
    pos = 0
    while pos < len(clx):
        kind = clx[pos]
        if kind == 0x01:  # Prc: 2-byte cbGrpprl then the grpprl
            (cb,) = unpack("<H", clx[pos + 1:pos + 3])
            pos += 3 + cb
        elif kind == 0x02:  # Pcdt: 4-byte lcb then a PlcPcd
            (lcb,) = unpack("<I", clx[pos + 1:pos + 5])
            plc = clx[pos + 5:pos + 5 + lcb]
            if len(plc) != lcb or lcb < 4:
                raise exceptions.ParseError(
                    "CLX piece table is truncated (needs {} bytes, found {})".format(
                        lcb, len(plc)
                    )
                )
            # PlcPcd = (n+1) CPs then n 8-byte PCDs; n = (lcb - 4) / 12.
            if (lcb - 4) % 12:
                raise exceptions.ParseError(
                    "CLX piece table has an invalid length {}".format(lcb)
                )
            count = (lcb - 4) // 12
            pcd_base = (count + 1) * 4
            for index in range(count):
                start = pcd_base + index * 8
                (fc,) = unpack("<I", plc[start + 2:start + 6])
                highest = max(highest, fc & 0x3FFFFFFF)
            pos += 5 + lcb
        else:
            raise exceptions.ParseError(
                "CLX starts with unsupported record type {:#x}".format(kind)
            )
    return highest


def _validate_worddocument_text(pairs, table_plain, worddocument_size):
    """Reject a WordDocument stream shorter than its piece table addresses."""
    if not pairs:
        return
    fc, lcb = pairs[_FIB_FC_CLX_INDEX]
    if lcb == 0:
        return
    clx = table_plain[fc:fc + lcb]
    highest = _text_extents_from_clx(clx)
    if highest > worddocument_size:
        raise exceptions.ParseError(
            "piece table addresses WordDocument byte {:#x} but the stream is "
            "only {} bytes; the WordDocument stream is truncated".format(
                highest, worddocument_size
            )
        )


EncryptionHeaderProbe = namedtuple(
    "EncryptionHeaderProbe",
    ["valid", "stream", "version", "header_size", "size", "reason"],
)


def _probe_encryption_header(ole, stream_name, declared_size):
    r"""Check whether a table stream could carry this file's key header.

    This is structural validation only; nothing is decrypted and the password
    is not involved. Three independent facts are checked:

    * the stream starts with a known EncryptionVersionInfo (MS-OFFCRYPTO
      2.3.2 / 2.3.3);
    * the header plus verifier fit inside the stream;
    * FibBase.lKey, defined as the size of the EncryptionHeader at the start
      of the table stream (MS-DOC 2.1), covers the EncryptionHeader and does
      not exceed the stream.

    The exact byte consumption of ``load_key`` is mirrored, because the
    CryptoAPI CSP name is decoded from the remainder of the stream: a stream
    that merely looks like it starts with a header but has no room for the
    verifier is rejected.
    """
    if not ole.exists(stream_name):
        return EncryptionHeaderProbe(
            False, stream_name, None, 0, 0, "stream is missing"
        )
    stream_size = ole.get_size(stream_name)
    if stream_size < 4:
        return EncryptionHeaderProbe(
            False, stream_name, None, 0, 0,
            "stream is only {} bytes long".format(stream_size),
        )
    with ole.openstream(stream_name) as stream:
        head = stream.read(min(stream_size, 12))
    vMajor, vMinor = unpack("<HH", head[:4])
    version = (vMajor, vMinor)
    if version not in (
        (0x0001, 0x0001),
        (0x0002, 0x0002),
        (0x0003, 0x0002),
        (0x0004, 0x0002),
    ):
        return EncryptionHeaderProbe(
            False, stream_name, version, 0, 0,
            "no known encryption version info (found {}.{})".format(vMajor, vMinor),
        )
    if version == (0x0001, 0x0001):
        # Version (4) + salt (16) + verifier (16) + verifier hash (16).
        required = 4 + 16 + 16 + 16
        header_size = 0
    else:
        if len(head) < 12:
            return EncryptionHeaderProbe(
                False, stream_name, version, 0, 0,
                "RC4 CryptoAPI header needs 12 bytes but the stream has {}".format(
                    stream_size
                ),
            )
        (header_size,) = unpack("<I", head[8:12])
        # flags(4) + headerSize field(4) + EncryptionHeader(header_size)
        # + saltSize(4) + salt(16) + verifier(16) + verifierHashSize(4)
        # + verifierHash(20, RC4).
        required = 12 + header_size + 4 + 16 + 16 + 4 + 20
    if required > stream_size:
        return EncryptionHeaderProbe(
            False, stream_name, version, header_size, required,
            "key header needs {} bytes but the stream has only {}".format(
                required, stream_size
            ),
        )
    if declared_size:
        # FibBase.lKey is the size of the encryption header at the start of
        # the table stream. It must at least cover the EncryptionHeader
        # itself, and it cannot exceed the stream.
        header_region = 12 + header_size
        if declared_size < header_region:
            return EncryptionHeaderProbe(
                False, stream_name, version, header_size, required,
                "FibBase.lKey is {} but the EncryptionHeader alone needs {} "
                "bytes".format(declared_size, header_region),
            )
        if declared_size > stream_size:
            return EncryptionHeaderProbe(
                False, stream_name, version, header_size, required,
                "FibBase.lKey is {} but the stream has only {} bytes".format(
                    declared_size, stream_size
                ),
            )
    try:
        with ole.openstream(stream_name) as stream:
            body = io.BytesIO(stream.read())
        if version == (0x0001, 0x0001):
            _parse_header_RC4(body)
        else:
            body.read(4)
            _parse_header_RC4CryptoAPI(body)
    except Exception as exc:  # struct.error, UnicodeDecodeError, ...
        return EncryptionHeaderProbe(
            False, stream_name, version, header_size, required,
            "malformed key header ({})".format(exc),
        )
    return EncryptionHeaderProbe(
        True, stream_name, version, header_size, required, None
    )


def _parse_header_RC4(encryptionHeader):
    # RC4: https://msdn.microsoft.com/en-us/library/dd908560(v=office.12).aspx
    salt = encryptionHeader.read(16)
    encryptedVerifier = encryptionHeader.read(16)
    encryptedVerifierHash = encryptionHeader.read(16)
    info = {
        "salt": salt,
        "encryptedVerifier": encryptedVerifier,
        "encryptedVerifierHash": encryptedVerifierHash,
    }
    return info


class Doc97File(base.BaseOfficeFile):
    """Return a MS-DOC file object.

    Examples:
        >>> with open("tests/inputs/rc4cryptoapi_password.doc", "rb") as f:
        ...     officefile = Doc97File(f)
        ...     officefile.load_key(password="Password1234_")

        >>> with open("tests/inputs/rc4cryptoapi_password.doc", "rb") as f:
        ...     officefile = Doc97File(f)
        ...     officefile.load_key(password="0000")
        Traceback (most recent call last):
            ...
        msoffcrypto.exceptions.InvalidKeyError: ...
    """

    def __init__(self, file):
        self.file = file
        ole = olefile.OleFileIO(file)  # do not close this, would close file
        self.ole = ole
        self.format = "doc97"
        self.keyTypes = ["password"]
        self.key = None
        self.salt = None

        # https://msdn.microsoft.com/en-us/library/dd944620(v=office.12).aspx
        if not ole.exists("wordDocument"):
            raise exceptions.FileFormatError(
                "MS-DOC file has no WordDocument stream"
            )
        with ole.openstream("wordDocument") as stream:
            fib = _parseFib(stream)
        if fib.base.wIdent != 0xA5EC:
            raise exceptions.FileFormatError(
                "Not a MS-DOC WordDocument stream (wIdent={:#x})".format(
                    fib.base.wIdent
                )
            )

        # https://msdn.microsoft.com/en-us/library/dd923367(v=office.12).aspx
        declared = "1Table" if fib.base.fWhichTblStm == 1 else "0Table"
        tablename, table_stream_notes = self._resolve_table_stream(fib, declared)

        Info = namedtuple("Info", ["fib", "tablename"])
        self.info = Info(
            fib=fib,
            tablename=tablename,
        )
        self.table_stream = table_stream_notes

    def _resolve_table_stream(self, fib, declared):
        r"""Return the table stream selected by FibBase.fWhichTblStm.

        MS-DOC 2.1.1 defines fWhichTblStm as the authority: 1 means 1Table,
        0 means 0Table. That stream is used for both the encryption header and
        the table data. The other stream is never substituted, because doing
        so would silently reinterpret the document as a different one; if the
        declared stream cannot hold the key header, that is reported instead.

        The returned notes record the structural evidence so callers and tests
        can state exactly which stream was used and why.
        """
        if fib.base.fEncrypted == 0:
            # Unencrypted documents have no key header; only the declared
            # stream must exist because its fc/lcb offsets point into it.
            if not self.ole.exists(declared):
                raise exceptions.ParseError(
                    "FibBase.fWhichTblStm selects {} but the file has no {} "
                    "stream (present: {})".format(
                        declared, declared, self._table_stream_names()
                    )
                )
            return declared, {"declared": declared, "probes": {}}

        probes = {
            name: _probe_encryption_header(self.ole, name, fib.base.IKey)
            for name in ("0Table", "1Table")
        }
        notes = {
            "declared": declared,
            "probes": {name: probe._asdict() for name, probe in probes.items()},
        }
        if not probes[declared].valid:
            raise exceptions.ParseError(
                "FibBase.fWhichTblStm={} selects {}, which cannot hold this "
                "file's encryption header ({}). Refusing to substitute the "
                "other stream; {}={}, {}={}".format(
                    fib.base.fWhichTblStm,
                    declared,
                    probes[declared].reason,
                    "0Table",
                    probes["0Table"].reason,
                    "1Table",
                    probes["1Table"].reason,
                )
            )
        alternate = "0Table" if declared == "1Table" else "1Table"
        if probes[alternate].valid:
            notes["warning"] = (
                "both 0Table and 1Table start with a key header; "
                "FibBase.fWhichTblStm={} selects {}".format(
                    fib.base.fWhichTblStm, declared
                )
            )
        return declared, notes

    def _table_stream_names(self):
        return sorted(
            "/".join(entry)
            for entry in self.ole.listdir(streams=True, storages=False)
            if entry[-1] in ("0Table", "1Table", "Data")
        )

    def load_key(self, password=None):
        fib = self.info.fib
        logger.debug(
            "fEncrypted: {}, fObfuscation: {}".format(
                fib.base.fEncrypted, fib.base.fObfuscation
            )
        )
        logger.debug(
            "table stream: declared={}, probes={}".format(
                self.table_stream["declared"],
                {
                    name: probe["reason"]
                    for name, probe in self.table_stream["probes"].items()
                },
            )
        )

        if fib.base.fEncrypted == 1:
            if fib.base.fObfuscation == 1:  # Using XOR obfuscation
                raise exceptions.DecryptionError(
                    "XOR-obfuscated MS-DOC is not supported"
                )
            else:  # elif fib.base.fObfuscation == 0:
                encryptionHeader_size = fib.base.IKey
                logger.debug(
                    "encryptionHeader_size: {}".format(hex(encryptionHeader_size))
                )
                with self.ole.openstream(self.info.tablename) as table:
                    encryptionVersionInfo = table.read(4)
                    vMajor, vMinor = unpack("<HH", encryptionVersionInfo)
                    logger.debug("Version: {} {}".format(vMajor, vMinor))
                    if vMajor == 0x0001 and vMinor == 0x0001:  # RC4
                        info = _parse_header_RC4(table)
                        if DocumentRC4.verifypw(
                            password,
                            info["salt"],
                            info["encryptedVerifier"],
                            info["encryptedVerifierHash"],
                        ):
                            self.type = "rc4"
                            self.key = password
                            self.salt = info["salt"]
                        else:
                            raise exceptions.InvalidKeyError(
                                "Failed to verify password"
                            )
                    elif (
                        vMajor in [0x0002, 0x0003, 0x0004] and vMinor == 0x0002
                    ):  # RC4 CryptoAPI
                        info = _parse_header_RC4CryptoAPI(table)
                        if DocumentRC4CryptoAPI.verifypw(
                            password,
                            info["salt"],
                            info["keySize"],
                            info["encryptedVerifier"],
                            info["encryptedVerifierHash"],
                        ):
                            self.type = "rc4_cryptoapi"
                            self.key = password
                            self.salt = info["salt"]
                            self.keySize = info["keySize"]
                        else:
                            raise exceptions.InvalidKeyError(
                                "Failed to verify password"
                            )
                    else:
                        raise exceptions.DecryptionError(
                            "Unsupported encryption method"
                        )
        else:
            raise exceptions.DecryptionError("File is not encrypted")

    def _decrypt_stream(self, data):
        if self.type == "rc4":
            return DocumentRC4.decrypt(self.key, self.salt, io.BytesIO(data)).read()
        elif self.type == "rc4_cryptoapi":
            return DocumentRC4CryptoAPI.decrypt(
                self.key, self.salt, self.keySize, io.BytesIO(data)
            ).read()
        raise exceptions.DecryptionError(
            "Unsupported encryption method: {}".format(self.type)
        )

    def _decrypted_worddocument(self):
        """Return (raw, plaintext) for the WordDocument stream.

        MS-DOC 2.1: the first 0x44 bytes of the stream (FibBase plus the start
        of the FIB) are not encrypted. RC4 in MS-DOC is keyed and re-keyed by
        absolute stream offset, so the ciphertext must be decrypted from
        offset 0; only then are the leading 0x44 plaintext bytes spliced back.
        Decrypting from 0x44 instead would shift every RC4 block index.
        """
        with self.ole.openstream("wordDocument") as stream:
            raw = stream.read()
        if len(raw) < FIB_BASE_LENGTH:
            raise exceptions.ParseError(
                "WordDocument stream is only {} bytes; at least {} are needed "
                "for FibBase".format(len(raw), FIB_BASE_LENGTH)
            )
        plain = bytearray(self._decrypt_stream(raw))
        keep = min(FIB_LENGTH_UNENCRYPTED, len(raw))
        plain[:keep] = raw[:keep]
        return raw, bytes(plain)

    def _decrypted_table_stream(self, name):
        """Return (raw, plaintext) for the whole table stream.

        The stream starts with the key header (lKey bytes), which is plaintext
        in the input; the payload after it is ciphertext keyed to absolute
        stream offsets. Decryption therefore starts at offset 0, exactly as
        MS-OFFCRYPTO describes: the header bytes are written over the
        encrypted stream after encryption, they are not a separate keystream
        segment. Decrypting from lKey instead shifts every RC4 block index and
        corrupts the payload.
        """
        with self.ole.openstream(name) as stream:
            raw = stream.read()
        return raw, self._decrypt_stream(raw)

    def decrypt(self, outfile):
        # fd, _outfile_path = tempfile.mkstemp()

        # shutil.copyfile(os.path.realpath(self.file.name), _outfile_path)
        # outole = olefile.OleFileIO(_outfile_path, write_mode=True)

        obuf1 = io.BytesIO()
        fibbase = FibBase(
            wIdent=self.info.fib.base.wIdent,
            nFib=self.info.fib.base.nFib,
            unused=self.info.fib.base.unused,
            lid=self.info.fib.base.lid,
            pnNext=self.info.fib.base.pnNext,
            fDot=self.info.fib.base.fDot,
            fGlsy=self.info.fib.base.fGlsy,
            fComplex=self.info.fib.base.fComplex,
            fHasPic=self.info.fib.base.fHasPic,
            cQuickSaves=self.info.fib.base.cQuickSaves,
            fEncrypted=0,
            fWhichTblStm=self.info.fib.base.fWhichTblStm,
            fReadOnlyRecommended=self.info.fib.base.fReadOnlyRecommended,
            fWriteReservation=self.info.fib.base.fWriteReservation,
            fExtChar=self.info.fib.base.fExtChar,
            fLoadOverride=self.info.fib.base.fLoadOverride,
            fFarEast=self.info.fib.base.fFarEast,
            nFibBack=self.info.fib.base.nFibBack,
            fObfuscation=0,
            IKey=0,
            envr=self.info.fib.base.envr,
            fMac=self.info.fib.base.fMac,
            fEmptySpecial=self.info.fib.base.fEmptySpecial,
            fLoadOverridePage=self.info.fib.base.fLoadOverridePage,
            reserved1=self.info.fib.base.reserved1,
            reserved2=self.info.fib.base.reserved2,
            fSpare0=self.info.fib.base.fSpare0,
            reserved3=self.info.fib.base.reserved3,
            reserved4=self.info.fib.base.reserved4,
            reserved5=self.info.fib.base.reserved5,
            reserved6=self.info.fib.base.reserved6,
        )
        FIB_LENGTH = 0x44

        raw_wd, plain_wd = self._decrypted_worddocument()
        if len(raw_wd) < FIB_LENGTH:
            raise exceptions.ParseError(
                "WordDocument stream is only {} bytes but the FIB is {} bytes; "
                "the stream is truncated".format(len(raw_wd), FIB_LENGTH)
            )
        # The first 0x44 bytes of the FIB are rewritten as plaintext, but every
        # other byte of the stream keeps its original laid-out contents.
        header = _packFibBase(fibbase).read()
        obuf1.write(header)
        obuf1.write(plain_wd[len(header):])
        obuf1.seek(0)

        # TODO: Preserve header
        raw_table, plain_table = self._decrypted_table_stream(self.info.tablename)
        obuf2 = io.BytesIO(plain_table)

        obuf3 = None
        if self.ole.exists("Data"):
            raw_data, plain_data = self._decrypted_table_stream("Data")
            obuf3 = io.BytesIO(plain_data)

        # Verify the FIB's fc/lcb ranges against the decrypted streams before
        # writing an output that only looks structurally plausible.
        pairs, fib_end = _parseFibRgFcLcb(io.BytesIO(plain_wd))
        if fib_end > len(plain_wd):
            raise exceptions.ParseError(
                "FIB ends at {:#x} but the WordDocument stream is only {} "
                "bytes; the stream is truncated".format(fib_end, len(plain_wd))
            )
        _validate_table_extents(pairs, len(plain_table), self.info.tablename)
        _validate_worddocument_text(pairs, plain_table, len(plain_wd))

        with tempfile.TemporaryFile() as _outfile:
            self.file.seek(0)
            shutil.copyfileobj(self.file, _outfile)
            outole = olefile.OleFileIO(_outfile, write_mode=True)

            outole.write_stream("wordDocument", obuf1.read())
            outole.write_stream(self.info.tablename, obuf2.read())
            if obuf3:
                outole.write_stream("Data", obuf3.read())

            # _outfile = open(_outfile_path, 'rb')

            _outfile.seek(0)

            shutil.copyfileobj(_outfile, outfile)

    def is_encrypted(self):
        r"""
        Test if the file is encrypted.

            >>> f = open("tests/inputs/plain.doc", "rb")
            >>> file = Doc97File(f)
            >>> file.is_encrypted()
            False
            >>> f = open("tests/inputs/rc4cryptoapi_password.doc", "rb")
            >>> file = Doc97File(f)
            >>> file.is_encrypted()
            True
        """
        return True if self.info.fib.base.fEncrypted == 1 else False
