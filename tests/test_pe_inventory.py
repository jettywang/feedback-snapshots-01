import struct
import unittest
import uuid

from uefi_firmware import efi_compressor
from uefi_firmware.pe_inventory import collect_images, parse_image
from uefi_firmware.structs.uefi_structs import FIRMWARE_VOLUME_GUIDS
from uefi_firmware.uefi import FirmwareVolume, find_volumes

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le


def make_section(section_type, body):
    size = 4 + len(body)
    return struct.pack("<I", size)[:3] + bytes([section_type]) + body


def make_file(body, file_type=0x07):
    '''An FFS file with an 8-byte aligned size.'''
    size = 24 + len(body)
    header = FILE_GUID + struct.pack(
        "<HBB3sB", 0, file_type, 0x00, struct.pack("<I", size)[:3], 0xf8)
    data = header + body
    return data + b"\xff" * (-len(data) % 8)


def make_volume(body, size=0x1000):
    '''An FFS2 volume made of a single block.'''
    block_map = struct.pack("<II", 1, size) + b"\x00" * 8
    hdrlen = FirmwareVolume._HEADER_SIZE + len(block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le,
        size, b"_FVH", 0, hdrlen, 0, 0, b"\x00", 2)
    return header + block_map + body.ljust(size - hdrlen, b"\xff")


def parse_volume(body):
    volume = FirmwareVolume(make_volume(make_file(body)))
    volume.process()
    return volume


# PE32+ layout used by the tests: headers of 0x200 bytes, one .text
# section mapping RVA 0x1000-0x11ff to file offset 0x200.
PE_ENTRY_RVA = 0x1010
PE_IMAGE_BASE = 0x100000000
PE_ENTRY_OFFSET = 0x200 + (PE_ENTRY_RVA - 0x1000)


def make_pe32plus(entry_rva=PE_ENTRY_RVA, image_base=PE_IMAGE_BASE):
    e_lfanew = 0x80
    data = bytearray(b"MZ" + b"\x00" * 0x3a + struct.pack("<I", e_lfanew))
    data += b"\x00" * (e_lfanew - len(data))
    data += b"PE\x00\x00"
    data += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, entry_rva)
    struct.pack_into("<Q", optional, 24, image_base)
    struct.pack_into("<I", optional, 56, 0x2000)
    struct.pack_into("<I", optional, 60, 0x200)
    struct.pack_into("<I", optional, 108, 16)
    data += optional
    data += struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x100, 0x1000,
                        0x200, 0x200, 0, 0, 0, 0, 0)
    data += b"\x00" * (0x200 - len(data))
    data += b"\xcc" * 0x200
    return bytes(data)


# TE layout: StrippedSize 0x140, so the stripped delta is 0x118 and the
# entry RVA 0x178 lands at file offset 0x60 (right after the 0x50 bytes of
# TE header plus section header). A PE-style mapping would instead treat
# 0x178 as a header-relative RVA and report 0x178.
TE_STRIPPED_SIZE = 0x140
TE_ENTRY_RVA = 0x178
TE_IMAGE_BASE = 0xFFE00000
TE_ENTRY_OFFSET = TE_ENTRY_RVA - (TE_STRIPPED_SIZE - 40)


def make_te(entry_rva=TE_ENTRY_RVA, stripped_size=TE_STRIPPED_SIZE,
            image_base=TE_IMAGE_BASE):
    header = struct.pack(
        "<HHBBHIIQ", 0x5A56, 0x8664, 1, 0, stripped_size, entry_rva,
        entry_rva, image_base)
    header += b"\x00" * 16  # base relocation and debug data directories
    header += struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 0x100,
                          0x1000, 0x100, 0x50, 0, 0, 0, 0, 0)
    return header + b"\xcc" * 0x100


def only_image(parsed_object):
    inventory = collect_images(parsed_object)
    assert len(inventory.images) == 1, inventory.to_dict()
    return inventory.images[0]


class PeHeaderTest(unittest.TestCase):

    def test_pe32plus_entry_is_mapped_through_sections(self):
        info = parse_image(make_pe32plus())
        self.assertEqual(info["kind"], "PE32+")
        self.assertEqual(info["arch"], "x86_64")
        self.assertEqual(info["entry_rva"], PE_ENTRY_RVA)
        self.assertEqual(info["entry_image_offset"], PE_ENTRY_OFFSET)
        self.assertEqual(info["entry_va"], PE_IMAGE_BASE + PE_ENTRY_RVA)
        self.assertEqual(info["limits"], [])

    def test_te_entry_uses_stripped_delta_not_pe_rva(self):
        info = parse_image(make_te())
        self.assertEqual(info["kind"], "TE")
        self.assertEqual(info["arch"], "x86_64")
        self.assertEqual(info["entry_rva"], TE_ENTRY_RVA)
        # The stripped-header correction: RVA - (StrippedSize - 40).
        self.assertEqual(info["entry_image_offset"], TE_ENTRY_OFFSET)
        self.assertNotEqual(info["entry_image_offset"], TE_ENTRY_RVA)
        self.assertEqual(info["entry_va"], TE_IMAGE_BASE + TE_ENTRY_RVA)
        self.assertEqual(info["limits"], [])

    def test_truncated_pe_keeps_evidence(self):
        # Only part of the optional header is present.
        info = parse_image(make_pe32plus()[:0x98 + 0x40])
        self.assertEqual(info["kind"], "PE32+")
        self.assertEqual(info["entry_rva"], PE_ENTRY_RVA)
        self.assertIsNone(info["entry_image_offset"])
        self.assertTrue(any("truncated" in limit for limit in info["limits"]))

    def test_truncated_te_keeps_evidence(self):
        info = parse_image(make_te()[:20])
        self.assertEqual(info["kind"], "TE")
        self.assertEqual(info["arch"], "x86_64")
        self.assertIsNone(info["entry_rva"])
        self.assertTrue(any("truncated" in limit for limit in info["limits"]))

    def test_non_image_is_not_an_image(self):
        self.assertIsNone(parse_image(b"\xff" * 64))


class InventoryTest(unittest.TestCase):

    def test_plain_pe_position_is_recomputed_layer_by_layer(self):
        volume = parse_volume(make_section(0x10, make_pe32plus()))
        image = only_image(volume)

        self.assertEqual(image["kind"], "PE32+")
        layers = [node["layer"] for node in image["location"]]
        self.assertEqual(layers, ["firmware_volume", "ffs_file", "section"])
        # FV header + FFS file header (24) + section header (4).
        image_offset = volume.hdrlen + 24 + 4
        self.assertEqual(image["image_offset_in_fv"], image_offset)
        self.assertEqual(
            image["entry_offset_in_fv"], image_offset + PE_ENTRY_OFFSET)
        self.assertIsNone(image["decoded_offset"])
        self.assertEqual(image["transforms"], [])

    def test_te_position_in_fv(self):
        volume = parse_volume(make_section(0x12, make_te()))
        image = only_image(volume)

        self.assertEqual(image["kind"], "TE")
        image_offset = volume.hdrlen + 24 + 4
        self.assertEqual(image["image_offset_in_fv"], image_offset)
        self.assertEqual(
            image["entry_offset_in_fv"], image_offset + TE_ENTRY_OFFSET)

    def test_compressed_wrapper_keeps_transform_chain(self):
        decompressed = make_section(0x10, make_pe32plus())
        body = struct.pack("<IB", len(decompressed), 0x01) + \
            efi_compressor.EfiCompress(decompressed, len(decompressed))
        volume = parse_volume(make_section(0x01, body))
        image = only_image(volume)

        self.assertEqual(image["kind"], "PE32+")
        self.assertEqual(len(image["transforms"]), 1)
        layers = [node["layer"] for node in image["location"]]
        self.assertIn("compressed_section", layers)
        # The image only exists in the decoded stream: no FV offset.
        self.assertIsNone(image["image_offset_in_fv"])
        self.assertIsNone(image["entry_offset_in_fv"])
        # Decoded stream: PE32 section header (4) then the image.
        self.assertEqual(image["decoded_offset"], 4)
        self.assertEqual(image["entry_decoded_offset"], 4 + PE_ENTRY_OFFSET)
        # Image-relative semantics are unchanged by the wrapping.
        self.assertEqual(image["entry_rva"], PE_ENTRY_RVA)
        self.assertEqual(image["entry_image_offset"], PE_ENTRY_OFFSET)

    def test_unknown_section_type_is_an_evidence_limit(self):
        volume = parse_volume(
            make_section(0x70, b"mystery!") + make_section(0x10,
                                                           make_pe32plus()))
        inventory = collect_images(volume)
        self.assertEqual(len(inventory.images), 1)
        self.assertEqual(len(inventory.limits), 1)
        self.assertIn("0x70", inventory.limits[0]["reason"])

    def test_parent_padding_shifts_container_not_image(self):
        fv_bytes = make_volume(make_file(make_section(0x10, make_pe32plus())))

        def image_at(padding):
            objects = find_volumes(padding + fv_bytes)
            image = only_image(objects)
            volume_node = image["location"][0]
            return volume_node["offset"], image

        offset_a, image_a = image_at(b"\xff" * 0x800)
        offset_b, image_b = image_at(b"\xff" * 0x1200)

        # The container moved with the padding...
        self.assertEqual(offset_a, 0x800)
        self.assertEqual(offset_b, 0x1200)
        # ...but every image-relative and volume-relative address stayed.
        for key in ("entry_rva", "entry_va", "entry_image_offset",
                    "image_offset_in_fv", "entry_offset_in_fv"):
            self.assertEqual(image_a[key], image_b[key], key)
            self.assertIsNotNone(image_a[key], key)


if __name__ == "__main__":
    unittest.main()


class FailedTransformTest(unittest.TestCase):

    def test_failed_decompression_is_an_evidence_limit(self):
        # A compressed section whose payload is not decompressable.
        body = struct.pack("<IB", 0x100, 0x01) + b"not compressed data"
        volume = parse_volume(make_section(0x01, body))
        inventory = collect_images(volume)
        self.assertEqual(len(inventory.images), 0)
        self.assertTrue(any("decompress" in limit["reason"]
                            for limit in inventory.limits))
