"""Test independent I/O state of per-object virtual streams (IterStream).

Embedded objects of a ppt file are accessed through virtual streams:
``PptRecordExOleVbaActiveXAtom.get_data_as_olefile`` wraps an
``IterStream`` (oletools.ppt_record_parser) around the object's byte range.
Every object must behave like an independent file: own cursor, own length
(offset origin at the object's first byte) and own release state.

These tests obtain several objects from a short ppt record stream (plus one
object from a real ppt test file) and verify that interleaved read, readinto,
relative seek and seek-back on two or more objects never mix up position,
length or close state. Expected values come from an independent model that is
computed from each object's actual byte range -- objects are never just
hash-compared against some final exported file.

The tests are designed to catch implementations that share one cursor between
objects, use a wrong offset origin (e.g. file-absolute instead of
object-relative) or read beyond an object's tail into the next object.
Everything is verified in chunks, so no large object has to be loaded into
memory at once.
"""

import io
import unittest
import zlib
from os.path import join
from struct import pack

# Directory with test data, independent of current working directory
from tests.test_utils import DATA_BASE_DIR

from oletools import record_base
from oletools.ppt_record_parser import (
    IterStream,
    PptFile,
    PptRecordExOleVbaActiveXAtom,
    PptStream,
)


# real ppt file with one embedded object (compressed ExOleObjStg record)
REAL_PPT = join(DATA_BASE_DIR, 'oleobj', 'embedded-simple-2007.ppt')

OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

# record type of ExOleObjStg / VbaProjectStg / ExControlStg
EX_OLE_VBA_ACTIVEX_ATOM = 0x1011


def make_payload(seed, size):
    """ deterministic pseudo-random bytes, distinct for every seed """
    return bytes(bytearray((seed + 31 * i + (i >> 3)) % 256
                           for i in range(size)))


def make_compressible_payload(seed, size):
    """ deterministic, distinct and well compressible bytes """
    block = bytes(bytearray((seed + 7 * i) % 256 for i in range(256)))
    repeats, rest = divmod(size, len(block))
    return block * repeats + block[:rest]


def ole_object_record(payload, compress):
    """ build bytes of an ExOleObjStg record holding given payload """
    if compress:
        data = pack('<L', len(payload)) + zlib.compress(payload)
        instance = 1     # compressed atom
    else:
        data = payload
        instance = 0     # uncompressed atom
    ver_inst = (instance << 4) | 0x0      # version 0
    return pack('<HHL', ver_inst, EX_OLE_VBA_ACTIVEX_ATOM, len(data)) + data


def filler_record(payload):
    """ build bytes of a non-object record (unknown type, skipped by parser) """
    return pack('<HHL', 0, 0x1234, len(payload)) + payload


def build_short_ppt(payloads):
    """ build a short ppt "PowerPoint Document" stream with several objects

    payloads: list of (payload, compress) tuples. Filler records are placed
    between objects so every object lives at a different, non-zero offset.
    Returns the stream bytes.
    """
    parts = [filler_record(b'header-filler')]
    for payload, compress in payloads:
        parts.append(ole_object_record(payload, compress))
        parts.append(filler_record(b'filler-after-object'))
    return b''.join(parts)


def iter_object_records(ppt_stream_bytes):
    """ parse a ppt record stream, yield PptRecordExOleVbaActiveXAtom-s """
    stream = PptStream(io.BytesIO(ppt_stream_bytes), len(ppt_stream_bytes),
                       'PowerPoint Document', record_base.STGTY_STREAM)
    for record in stream.iter_records():
        if isinstance(record, PptRecordExOleVbaActiveXAtom):
            yield record


def real_ppt_object_records(filename):
    """ extract embedded object records from a real ppt file """
    ppt_file = PptFile(filename)
    try:
        records = []
        for stream in ppt_file.iter_streams():
            if stream.name != 'PowerPoint Document':
                continue
            for record in stream.iter_records():
                if isinstance(record, PptRecordExOleVbaActiveXAtom):
                    records.append(record)
        return records
    finally:
        ppt_file.close()


def open_virtual_stream(record, chunk_size=None):
    """ create the virtual stream for one object, like get_data_as_olefile """
    if chunk_size is None:
        creator = record.iter_uncompressed
    else:
        creator = lambda: record.iter_uncompressed(chunk_size=chunk_size)
    return IterStream(creator, record.get_uncompressed_size())


class StreamChecker(object):
    """ check one virtual stream against an independent per-object model

    The model is just the object's own expected bytes plus a position
    counter; it shares no state with the stream under test. All file
    semantics are object-relative: offset 0 is the object's first byte and
    SEEK_END is relative to the object's own length.
    """

    def __init__(self, test_case, stream, expected_data, name):
        self.test = test_case
        self.stream = stream
        self.data = expected_data
        self.pos = 0
        self.name = name

    def _msg(self, what):
        return '{0} [object {1}]'.format(what, self.name)

    def check_pos(self):
        """ cursor must be exactly where this object's own operations put it """
        self.test.assertEqual(self.stream.tell(), self.pos,
                              self._msg('cursor position'))

    def read(self, size):
        got = self.stream.read(size)
        if size == 0:
            self.test.assertEqual(got, b'', self._msg('read(0) result'))
        elif size is None or size < 0:
            self.test.assertEqual(got, self.data[self.pos:],
                                  self._msg('read() to end'))
            self.pos = len(self.data)
        else:
            max_len = max(0, min(size, len(self.data) - self.pos))
            self.test.assertLessEqual(len(got), max_len,
                                      self._msg('read past object tail'))
            if max_len > 0:
                # raw streams may return short reads but never 0 before EOF
                self.test.assertGreaterEqual(
                    len(got), 1, self._msg('read returned 0 before EOF'))
            self.test.assertEqual(got, self.data[self.pos:self.pos+len(got)],
                                  self._msg('read data from wrong origin'))
            self.pos += len(got)
        self.check_pos()
        return got

    def readinto(self, buf_size):
        target = bytearray(b'\xaa' * buf_size)
        count = self.stream.readinto(target)
        max_len = max(0, min(buf_size, len(self.data) - self.pos))
        self.test.assertLessEqual(count, max_len,
                                  self._msg('readinto past object tail'))
        if max_len > 0:
            self.test.assertGreaterEqual(
                count, 1, self._msg('readinto returned 0 before EOF'))
        self.test.assertEqual(bytes(target[:count]),
                              self.data[self.pos:self.pos+count],
                              self._msg('readinto data from wrong origin'))
        self.test.assertEqual(bytes(target[count:]),
                              b'\xaa' * (buf_size - count),
                              self._msg('readinto wrote beyond returned count'))
        self.pos += count
        self.check_pos()
        return count

    def seek(self, offset, whence):
        if whence == io.SEEK_SET:
            new_pos = offset
        elif whence == io.SEEK_CUR:
            new_pos = self.pos + offset
        elif whence == io.SEEK_END:
            new_pos = len(self.data) + offset
        else:
            raise ValueError('bad whence in test')
        result = self.stream.seek(offset, whence)
        self.test.assertEqual(result, new_pos, self._msg('seek return value'))
        self.pos = new_pos
        self.check_pos()

    def seek_invalid(self, offset, whence):
        """ seeks before the object's start must fail and not move cursor """
        self.test.assertRaises(IOError, self.stream.seek, offset, whence)
        self.check_pos()

    def check_at_eof(self):
        """ at/after object tail: empty results, cursor pinned, repeatable """
        self.test.assertEqual(self.stream.read(7), b'',
                              self._msg('read past EOF'))
        self.test.assertEqual(self.stream.readinto(bytearray(7)), 0,
                              self._msg('readinto past EOF'))
        self.test.assertEqual(self.stream.read(7), b'',
                              self._msg('repeated read past EOF'))
        self.check_pos()

    def drain(self, buf_size=8192):
        """ read rest of object in chunks; return total byte count """
        total = 0
        while True:
            target = bytearray(buf_size)
            count = self.stream.readinto(target)
            if count == 0:
                break
            self.test.assertEqual(
                bytes(target[:count]), self.data[self.pos:self.pos+count],
                self._msg('chunk data'))
            self.pos += count
            total += count
        self.check_pos()
        return total


class TestIterStreamIndependence(unittest.TestCase):
    """ independent I/O criteria for virtual streams of embedded objects """

    # sizes chosen so objects span several chunks but stay fast to test
    PAYLOAD_A = make_payload(11, 1000)                    # uncompressed
    PAYLOAD_B = make_payload(23, 5000)                    # compressed
    PAYLOAD_C = make_compressible_payload(5, 300000)      # compressed, big

    @classmethod
    def setUpClass(cls):
        super(TestIterStreamIndependence, cls).setUpClass()
        ppt_bytes = build_short_ppt([
            (cls.PAYLOAD_A, False),
            (cls.PAYLOAD_B, True),
            (cls.PAYLOAD_C, True),
        ])
        cls.records = list(iter_object_records(ppt_bytes))
        # model per object: expected bytes from the object's own byte range
        cls.models = [b''.join(rec.iter_uncompressed())
                      for rec in cls.records]

    def make_checker(self, index, name, chunk_size=None):
        stream = open_virtual_stream(self.records[index], chunk_size)
        return StreamChecker(self, stream, self.models[index], name)

    def test_objects_found_with_own_byte_ranges(self):
        """ sanity: short ppt yields 3 objects, models match their ranges """
        self.assertEqual(len(self.records), 3)
        self.assertEqual(self.models[0], self.PAYLOAD_A)
        self.assertEqual(self.models[1], self.PAYLOAD_B)
        self.assertEqual(self.models[2], self.PAYLOAD_C)
        # records sit at increasing offsets: origins must not be confused
        positions = [rec.pos for rec in self.records]
        self.assertEqual(positions, sorted(positions))
        self.assertGreater(positions[1], positions[0])
        # declared sizes agree with the actual byte ranges
        for rec, model in zip(self.records, self.models):
            self.assertEqual(rec.get_uncompressed_size(), len(model))
        # objects are really distinct (no accidental shared content)
        self.assertNotEqual(self.models[0][:256], self.models[1][:256])
        self.assertNotEqual(self.models[1][:256], self.models[2][:256])

    def test_interleaved_read_readinto_seek_two_objects(self):
        """ interleaved ops on two objects must not share cursor/length """
        obj_a = self.make_checker(0, 'A')
        obj_b = self.make_checker(1, 'B')

        obj_a.read(100)
        obj_b.check_pos()                     # B cursor untouched by A
        obj_b.read(250)
        obj_a.check_pos()                     # and vice versa
        obj_a.readinto(64)
        obj_b.readinto(333)
        obj_a.seek(10, io.SEEK_CUR)           # relative seek forward
        obj_b.check_pos()
        obj_b.seek(-100, io.SEEK_CUR)         # relative seek back
        obj_a.check_pos()
        obj_b.read(120)
        obj_a.seek(512, io.SEEK_SET)          # absolute, object-relative
        obj_a.read(50)
        obj_b.check_pos()
        obj_b.seek(0, io.SEEK_SET)            # rewind B while A stays put
        obj_b.read(40)
        obj_a.check_pos()
        obj_a.seek(-50, io.SEEK_CUR)          # seek back within A
        obj_a.read(25)
        obj_b.seek(-40, io.SEEK_END)          # END relative to B's own size
        obj_b.read(20)
        obj_a.check_pos()
        obj_a.seek(0, io.SEEK_END)            # jump to A's own tail
        obj_a.check_at_eof()
        obj_b.check_pos()                     # B still mid-stream
        obj_b.read(-1)                        # drain B to its end
        obj_b.check_at_eof()

    def test_interleaved_with_real_ppt_object(self):
        """ object from a real ppt file interleaved with a synthetic one """
        real_records = real_ppt_object_records(REAL_PPT)
        self.assertEqual(len(real_records), 1)
        real_model = b''.join(real_records[0].iter_uncompressed())
        # sanity: model really is the embedded ole file's own byte range
        self.assertEqual(real_model[:len(OLE_MAGIC)], OLE_MAGIC)
        self.assertEqual(real_records[0].get_uncompressed_size(),
                         len(real_model))

        obj_real = StreamChecker(
            self, open_virtual_stream(real_records[0]), real_model, 'real')
        obj_b = self.make_checker(1, 'B')

        obj_real.read(512)                    # ole header sector
        obj_b.read(1000)
        obj_real.check_pos()
        obj_b.seek(0, io.SEEK_SET)
        obj_real.readinto(100)
        obj_b.check_pos()
        obj_real.seek(0, io.SEEK_SET)         # back to known magic bytes
        self.assertEqual(obj_real.stream.read(len(OLE_MAGIC)), OLE_MAGIC)
        obj_real.pos = len(OLE_MAGIC)
        obj_b.readinto(77)
        obj_real.seek(-8, io.SEEK_CUR)
        obj_real.read(16)
        obj_b.seek(0, io.SEEK_END)
        obj_b.check_at_eof()
        obj_real.check_pos()                  # real object unaffected
        obj_real.read(-1)
        obj_real.check_at_eof()

    def test_zero_length_reads_do_not_move_cursor(self):
        """ read(0)/readinto(empty) return empty and never advance cursor """
        obj_a = self.make_checker(0, 'A')
        obj_b = self.make_checker(1, 'B')
        for obj in (obj_a, obj_b):
            obj.read(0)                       # at start
            obj.readinto(0)
            obj.read(100)
            obj.read(0)                       # mid-stream
            obj.readinto(0)
            obj.seek(0, io.SEEK_END)
            obj.read(0)                       # at EOF
            obj.readinto(0)
            obj.check_at_eof()
        # and the two cursors never interfered
        obj_a.check_pos()
        obj_b.check_pos()

    def test_eof_stops_exactly_at_object_tail(self):
        """ total readable bytes == object size; nothing leaks past tail """
        obj_a = self.make_checker(0, 'A')
        obj_b = self.make_checker(1, 'B')
        total_a = obj_a.drain(buf_size=111)   # odd size: unaligned chunks
        self.assertEqual(total_a, len(self.models[0]))
        obj_a.check_at_eof()
        # B has not even started; its full content must still be available
        total_b = obj_b.drain(buf_size=4096)
        self.assertEqual(total_b, len(self.models[1]))
        obj_b.check_at_eof()
        # seeking past the tail is allowed but yields no data either
        obj_b.seek(100, io.SEEK_END)
        obj_b.check_at_eof()
        obj_b.seek(0, io.SEEK_SET)            # rewind still works
        obj_b.read(10)

    def test_short_underlying_reads(self):
        """ tiny underlying chunks: position and content stay consistent """
        obj_a = self.make_checker(0, 'A', chunk_size=3)
        obj_b = self.make_checker(1, 'B', chunk_size=5)
        # interleave many short reads; every readinto may return very few
        # bytes, but always the right ones for each object
        for _ in range(40):
            obj_a.readinto(17)
            obj_b.readinto(9)
        obj_a.read(1)
        obj_b.read(2)
        obj_a.seek(-30, io.SEEK_CUR)          # seek back with short chunks
        obj_a.read(30)
        obj_b.seek(0, io.SEEK_SET)
        total_b = obj_b.drain(buf_size=13)
        self.assertEqual(total_b, len(self.models[1]))
        remaining_a = len(self.models[0]) - obj_a.pos
        self.assertEqual(obj_a.drain(buf_size=100), remaining_a)
        obj_a.check_at_eof()
        obj_b.check_at_eof()

    def test_large_object_streamed_in_chunks(self):
        """ big object verified chunk-wise; other objects usable mid-drain """
        obj_c = self.make_checker(2, 'C')
        obj_a = self.make_checker(0, 'A')
        self.assertEqual(obj_c.stream.size, len(self.models[2]))
        total = 0
        rounds = 0
        while True:
            target = bytearray(8192)
            count = obj_c.stream.readinto(target)
            if count == 0:
                break
            self.assertEqual(
                bytes(target[:count]),
                self.models[2][obj_c.pos:obj_c.pos+count],
                'chunk of large object C')
            obj_c.pos += count
            total += count
            rounds += 1
            if rounds == 3:
                # interleave some I/O on another object mid-drain
                obj_a.read(200)
                obj_a.seek(-50, io.SEEK_CUR)
                obj_a.read(50)
                obj_c.check_pos()
        self.assertEqual(total, len(self.models[2]))
        self.assertGreater(rounds, 1)         # really streamed, not one read
        obj_c.check_at_eof()
        obj_a.read(-1)                        # A still consistent afterwards
        obj_a.check_at_eof()

    def test_close_leaves_other_streams_usable(self):
        """ closing one object's stream must not affect any other object """
        obj_a = self.make_checker(0, 'A')
        obj_b = self.make_checker(1, 'B')
        obj_c = self.make_checker(2, 'C')
        obj_a.read(100)
        obj_b.read(200)
        obj_c.read(300)
        obj_b.stream.close()                  # release B
        obj_b.stream.close()                  # close is idempotent
        # A and C keep their cursors and content
        obj_a.check_pos()
        obj_c.check_pos()
        obj_a.read(50)
        obj_c.readinto(1000)
        obj_a.seek(-30, io.SEEK_CUR)
        obj_a.read(30)
        remaining_a = len(self.models[0]) - obj_a.pos
        self.assertEqual(obj_a.drain(), remaining_a)
        obj_a.check_at_eof()
        remaining_c = len(self.models[2]) - obj_c.pos
        self.assertEqual(obj_c.drain(), remaining_c)
        obj_c.check_at_eof()
        # B itself is in a defined state: reset to its start, still readable
        self.assertEqual(obj_b.stream.tell(), 0)
        obj_b.pos = 0
        obj_b.read(10)

    def test_underlying_exception_aborts_safely(self):
        """ failing underlying iterable: clean error, no state corruption """
        healthy = self.models[0]
        state = {'fail': True}

        def flaky_creator():
            pos = 0
            while pos < len(healthy):
                if state['fail'] and pos >= 128:
                    raise RuntimeError('simulated underlying read failure')
                yield healthy[pos:pos+64]
                pos += 64

        victim = IterStream(flaky_creator, len(healthy))
        sibling = self.make_checker(1, 'B')

        victim_model = StreamChecker(self, victim, healthy, 'victim')
        victim_model.readinto(64)
        victim_model.readinto(64)
        # third chunk triggers the simulated failure
        self.assertRaises(RuntimeError, victim.readinto, bytearray(64))
        # failed read did not advance the cursor nor fake a length
        self.assertEqual(victim.tell(), 128)
        # sibling object is completely unaffected by the abort
        sibling.read(500)
        sibling.seek(-100, io.SEEK_CUR)
        sibling.read(100)
        self.assertEqual(victim.tell(), 128)
        # after the cause is gone, a rewind fully recovers the victim
        state['fail'] = False
        victim_model.seek(0, io.SEEK_SET)
        self.assertEqual(victim_model.drain(buf_size=64), len(healthy))
        victim_model.check_at_eof()
        sibling.check_pos()

    def test_get_data_as_olefile_still_works(self):
        """ integration: virtual stream can back an OleFileIO as before """
        real_records = real_ppt_object_records(REAL_PPT)
        ole = real_records[0].get_data_as_olefile()
        try:
            self.assertTrue(ole.listdir())
        finally:
            ole.close()


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
