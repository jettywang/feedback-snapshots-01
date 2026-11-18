'''An optional index of a firmware tree defers compressed branches.

The full parser still decodes every branch as it builds the tree. The index
lists the wrappers it can see without running their decoders, and expands a
branch only when a caller reaches into it.
'''

import contextlib
import io
import struct
import unittest
import uuid
from unittest import mock

from uefi_firmware import AutoParser, MultiObject, efi_compressor
from uefi_firmware import uefi
from uefi_firmware.base import (
    PARSE_FAILED, PARSE_OPAQUE, PARSE_PARSED, PARSE_UNEXPANDED)
from uefi_firmware.structs.uefi_structs import (
    FIRMWARE_GUIDED_GUIDS, FIRMWARE_VOLUME_GUIDS)
from uefi_firmware.uefi import FirmwareVolume

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
UNKNOWN_GUID = uuid.UUID("01234567-89ab-4def-8123-456789abcdef").bytes_le
DRIVERS = ("alpha", "beta", "gamma")


def make_section(section_type, body):
    size = 4 + len(body)
    data = struct.pack("<I", size)[:3] + bytes([section_type]) + body
    return data + b"\x00" * (-len(data) % 4)


def make_file(body, guid=FILE_GUID):
    size = 24 + len(body)
    header = guid + struct.pack(
        "<HBB3sB", 0, 0x07, 0x00, struct.pack("<I", size)[:3], 0xf8)
    data = header + body
    return data + b"\xff" * (-len(data) % 8)


def make_volume(body=b"", size=0x1000):
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = FirmwareVolume._HEADER_SIZE + len(block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le,
        size, b"_FVH", 0, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + body.ljust(size - hdrlen, b"\xff")


def compressed_branch(payload):
    '''A file holding one type 0x01 compression section around payload.'''
    inner = make_section(0x19, payload)
    stream = efi_compressor.EfiCompress(inner, len(inner))
    body = struct.pack("<IB", len(inner), 0x01) + stream
    return make_file(make_section(0x01, body), uuid.uuid4().bytes_le)


def three_drivers():
    payloads = [("%s-driver" % name).encode() * 8 for name in DRIVERS]
    return make_volume(b"".join(compressed_branch(p) for p in payloads))


def quietly(function, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        return function(*args, **kwargs)


def flat_shape(obj):
    '''A comparable description of an object tree.'''
    data = getattr(obj, "data", None)
    result = [(
        type(obj).__name__,
        obj.label,
        getattr(obj, "guid_label", ""),
        len(data) if isinstance(data, bytes) else None,
    )]
    for child in obj.objects:
        if child is not None:
            result.extend(flat_shape(child))
    return result


def all_objects(obj):
    yield obj
    for child in obj.index_children():
        for item in all_objects(child):
            yield item


def branches(tree):
    return [obj for obj in all_objects(tree) if obj.unexpanded]


class DecodeCounter(object):
    '''Count the payloads handed to the decompression helper.'''

    def __init__(self):
        self.sizes = []
        self._real = uefi.decompress
        self._patch = mock.patch.object(uefi, "decompress", self.count)

    def count(self, algorithms, data):
        self.sizes.append(len(data))
        return self._real(algorithms, data)

    def start(self):
        self._patch.start()
        return self

    def stop(self):
        self._patch.stop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc_info):
        self.stop()


class IndexTest(unittest.TestCase):

    def build(self):
        data = three_drivers()
        counter = DecodeCounter().start()
        self.addCleanup(counter.stop)
        tree = quietly(AutoParser(data).index)
        return data, tree, counter

    def test_index_decodes_no_branch(self):
        data, tree, counter = self.build()
        self.assertIsInstance(tree, FirmwareVolume)
        # The volume, its file system and every file are visible.
        files = tree.firmware_filesystems[0].files
        self.assertEqual(len(files), len(DRIVERS))
        self.assertEqual(counter.sizes, [])
        # The three wrapped drivers are listed, not decoded.
        self.assertEqual([branch.wrapper for branch in branches(tree)],
                         ["compression"] * len(DRIVERS))
        for branch in branches(tree):
            self.assertEqual(branch.parse_state, PARSE_UNEXPANDED)
            self.assertGreater(len(branch.raw_data), 0)
            self.assertEqual(branch.index_children(), [])

    def test_index_matches_the_tree_shape(self):
        data, tree, counter = self.build()
        files = tree.firmware_filesystems[0].files
        self.assertEqual([type(obj).__name__ for obj in tree.objects],
                         ["FirmwareFileSystem"])
        self.assertEqual([len(obj.sections) for obj in files], [1] * 3)

    def test_one_branch_expands_only_itself(self):
        data, tree, counter = self.build()
        target = branches(tree)[1]

        target.expand()

        self.assertEqual(len(counter.sizes), 1)
        # An expanded branch reports the same state the full parse assigns.
        self.assertEqual(target.parse_state, PARSE_PARSED)
        decoded = target.subsections[0]
        self.assertEqual(decoded.data, b"beta-driver" * 8)
        # Its sibling drivers remain deferred.
        still_closed = [branch for branch in branches(tree)]
        self.assertEqual(len(still_closed), len(DRIVERS) - 1)

    def test_repeated_expansion_does_not_decode_again(self):
        data, tree, counter = self.build()
        target = branches(tree)[0]
        target.expand()
        target.expand()
        # Reading children or showing the branch is also already cached.
        list(target.objects)
        target.to_dict()
        self.assertEqual(len(counter.sizes), 1)
        self.assertEqual(len(target.subsections), 1)

    def test_expand_all_matches_the_full_parser(self):
        data, tree, counter = self.build()
        legacy = quietly(AutoParser(data).parse)

        tree.expand_all()

        self.assertEqual(flat_shape(tree), flat_shape(legacy))
        self.assertEqual(tree.to_dict(), legacy.to_dict())
        self.assertEqual(branches(tree), [])

    def test_full_parser_still_decodes_every_branch(self):
        data = three_drivers()
        counter = DecodeCounter().start()
        self.addCleanup(counter.stop)
        legacy = quietly(AutoParser(data).parse)
        self.assertEqual(len(counter.sizes), len(DRIVERS))
        # Each decoded branch holds the payload it was built with.
        payloads = [file.sections[0].parsed_object.subsections[0].data
                    for file in legacy.firmware_filesystems[0].files]
        self.assertEqual(payloads, [
            ("%s-driver" % name).encode() * 8 for name in DRIVERS])

    def test_input_bytes_are_not_modified(self):
        data = bytearray(three_drivers())
        original = bytes(data)
        tree = quietly(AutoParser(data).index)
        branches(tree)[0].expand()
        tree.expand_all()
        self.assertEqual(bytes(data), original)

    def test_index_does_not_decode_during_traversal(self):
        data, tree, counter = self.build()
        # Walking the index, including its JSON entries, leaves it closed.
        list(tree.iterate_objects())
        tree.to_index()
        self.assertEqual(counter.sizes, [])


class FailureStateTest(unittest.TestCase):

    def failed_branch(self):
        body = struct.pack("<IB", 0x100, 0x01) + b"not a stream"
        return make_section(0x01, body)

    def test_failed_expansion_is_not_an_empty_subtree(self):
        data = make_volume(make_file(self.failed_branch()))
        tree = quietly(AutoParser(data).index)
        branch = branches(tree)[0]
        raw = branch.raw_data

        branch.expand()

        self.assertEqual(branch.parse_state, PARSE_FAILED)
        self.assertTrue(branch.failed)
        self.assertIsNotNone(branch.parse_error)
        # The material is kept, and the entry reports the failure.
        self.assertEqual(branch.raw_data, raw)
        self.assertGreater(len(raw), 0)
        entry = branch.to_index()
        self.assertEqual(entry["state"], PARSE_FAILED)
        self.assertIn("error", entry)

    def test_failed_expansion_is_not_retried(self):
        data = make_volume(make_file(self.failed_branch()))
        tree = quietly(AutoParser(data).index)
        branch = branches(tree)[0]
        counter = DecodeCounter().start()
        self.addCleanup(counter.stop)
        branch.expand()
        branch.expand()
        self.assertEqual(len(counter.sizes), 1)
        self.assertEqual(branch.parse_state, PARSE_FAILED)

    def test_failed_guided_section_keeps_its_state(self):
        guid = uuid.UUID(
            FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED"]).bytes_le
        body = guid + struct.pack("<HH", 24, 0) + b"not lzma" * 4
        data = make_volume(make_file(make_section(0x02, body)))
        tree = quietly(AutoParser(data).index)
        section = tree.firmware_filesystems[0].files[0].sections[0]
        branch = branches(tree)[0]

        section.expand()

        self.assertEqual(branch.parse_state, PARSE_FAILED)
        self.assertTrue(branch.failed)
        self.assertGreater(len(branch.raw_data), 0)
        # The section that held it says why it has no decoded child.
        self.assertIsNone(section.parsed_object)
        self.assertEqual(section.parse_state, PARSE_FAILED)

    def test_unknown_guid_keeps_raw_material(self):
        body = UNKNOWN_GUID + struct.pack("<HH", 24, 0) + b"signed payload"
        data = make_volume(make_file(make_section(0x02, body)))
        tree = quietly(AutoParser(data).index)
        branch = branches(tree)[0]

        self.assertFalse(branch.wrapper_known)
        self.assertEqual(branch.parse_state, PARSE_UNEXPANDED)
        self.assertEqual(branch.raw_data, body)

        branch.expand()
        # No rule applies, so the material is kept and the state says so
        # instead of presenting an empty subtree.
        self.assertEqual(branch.parse_state, PARSE_OPAQUE)
        self.assertTrue(branch.opaque)
        self.assertEqual(branch.raw_data, body)
        self.assertEqual(branch.index_children(), [])
        self.assertEqual(branch.to_index()["rawSize"], len(body))


class LegacyEntryTest(unittest.TestCase):

    def test_parse_entry_is_unchanged(self):
        inner = make_section(0x19, b"plain data")
        body = struct.pack("<IB", len(inner), 0x00) + inner
        data = make_volume(make_file(make_section(0x01, body)))
        tree = AutoParser(data).parse()
        section = tree.firmware_filesystems[0].files[0].sections[0]
        self.assertEqual(section.parsed_object.data, inner)
        # Objects that were never deferred report the ordinary state.
        self.assertEqual(section.parsed_object.parse_state, PARSE_PARSED)
        self.assertFalse(section.parsed_object.unexpanded)

    def test_index_entry_alias(self):
        data = three_drivers()
        self.assertEqual(
            flat_shape(quietly(AutoParser(data).build_index)),
            flat_shape(quietly(AutoParser(data).index)))

    def test_lazy_parser_option(self):
        data = three_drivers()
        with DecodeCounter() as counter:
            tree = quietly(AutoParser(data, lazy=True).parse)
            self.assertEqual(counter.sizes, [])
            self.assertEqual(len(branches(tree)), len(DRIVERS))

        # Without the option, parse is still the full parser.
        with DecodeCounter() as counter:
            quietly(AutoParser(data).parse)
            self.assertEqual(len(counter.sizes), len(DRIVERS))


class DirectEntryTest(unittest.TestCase):

    def test_volume_process_accepts_lazy(self):
        # A caller that holds a volume can build an index without AutoParser.
        data = make_volume(
            compressed_branch(b"a" * 8) + compressed_branch(b"b" * 8))
        with DecodeCounter() as counter:
            volume = FirmwareVolume(data)
            self.assertTrue(quietly(volume.process, lazy=True))
            self.assertEqual(counter.sizes, [])
            self.assertEqual(
                [branch.parse_state for branch in branches(volume)],
                [PARSE_UNEXPANDED] * 2)

            branches(volume)[0].expand()
            self.assertEqual(len(counter.sizes), 1)

        full = FirmwareVolume(data)
        self.assertTrue(quietly(full.process))
        self.assertEqual(volume.to_dict(), full.to_dict())


class GuidedIndexTest(unittest.TestCase):

    def test_lzma_wrapper_expands_on_demand(self):
        inner = make_section(0x19, b"lzma payload")
        stream = efi_compressor.LzmaCompress(inner, len(inner))
        guid = uuid.UUID(FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED"]).bytes_le
        body = guid + struct.pack("<HH", 24, 0) + stream
        data = make_volume(make_file(make_section(0x02, body)))

        with DecodeCounter() as counter:
            tree = quietly(AutoParser(data).index)
            self.assertEqual(counter.sizes, [])
            branch = branches(tree)[0]
            self.assertEqual(branch.compression_kind, "lzma")
            self.assertEqual(branch.raw_data, body)

            branch.expand()
            self.assertEqual(len(counter.sizes), 1)
            self.assertEqual(branch.subsections[0].data, b"lzma payload")
            self.assertEqual(branch.parse_state, PARSE_PARSED)

        self.assertEqual(flat_shape(tree),
                         flat_shape(quietly(AutoParser(data).parse)))


class MultiVolumeIndexTest(unittest.TestCase):

    def test_stacked_volumes_list_in_index_mode(self):
        data = make_volume(size=0x200) + make_volume(size=0x200)
        with DecodeCounter() as counter:
            tree = quietly(AutoParser(data).index)
        self.assertIsInstance(tree, MultiObject)
        self.assertEqual(counter.sizes, [])
        self.assertEqual(flat_shape(tree), flat_shape(
            quietly(AutoParser(data).parse)))


class NestedIndexTest(unittest.TestCase):

    def test_nested_raw_section_stays_closed(self):
        # A raw file whose body is a volume holding a compressed driver.
        inner = make_volume(compressed_branch(b"nested-driver" * 8))
        data = make_volume(make_file(make_section(0x19, inner), uuid.uuid4().bytes_le))
        counter = DecodeCounter().start()
        self.addCleanup(counter.stop)
        tree = quietly(AutoParser(data).index)
        self.assertEqual(counter.sizes, [])
        self.assertEqual(len(branches(tree)), 1)

        branches(tree)[0].expand()
        self.assertEqual(len(counter.sizes), 1)
        tree.expand_all()
        self.assertEqual(flat_shape(tree),
                         flat_shape(quietly(AutoParser(data).parse)))


if __name__ == '__main__':
    unittest.main()
