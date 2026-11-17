# -*- coding: utf-8 -*-

'''Reviewable permission report for Intel flash descriptors.

The report decodes the in-image descriptor map, region section and master
section, and derives which master may read/write each declared region. Every
line cites the raw register values and the image offsets they came from so a
reviewer can recompute each entry by hand.

The report only reflects declarations inside the image. It cannot prove that
the host's runtime write protection (SMM_BWP, BLE, PRx, ...) is in effect.
'''

import struct

from .structs.flash_structs import FLASH_HEADER

DISCLAIMER = (
    "This report only reflects declarations inside the image; it does not "
    "prove the host's runtime write protection is in effect.")

# Region indices match the bit positions in the master access masks.
REGION_NAMES = ["descriptor", "bios", "me", "gbe", "pdr"]
MASTER_NAMES = ["bios", "me", "gbe"]

MAP_OFFSET = 0x14
MAP_SIZE = 16
REGION_SECTION_SIZE = 20
MASTER_SECTION_SIZE = 12

# (name, offset of base register within the region section) for regions 1-4.
# Region 0 (the descriptor itself) is implicit and has no registers.
_REGION_REGISTER_OFFSETS = {
    "bios": 4,
    "me": 8,
    "gbe": 12,
    "pdr": 16,
}

# (name, offset of the id register within the master section).
_MASTER_REGISTER_OFFSETS = {
    "bios": 0,
    "me": 4,
    "gbe": 8,
}

STATUS_DECLARED = "declared"
STATUS_DISABLED = "disabled"
STATUS_ZERO_ENCODED = "zero-encoded"
STATUS_OUT_OF_BOUNDS = "out-of-bounds"
STATUS_UNAVAILABLE = "unavailable"


def _section_status(offset, size, image_size):
    '''Describe how a structure at offset/size relates to the image.'''
    if offset >= image_size:
        return "out-of-bounds"
    if offset + size > image_size:
        return "truncated"
    return "ok"


def _decode_region(name, index, base, limit, base_offset, limit_offset,
                   image_size):
    region = {
        "index": index,
        "name": name,
        "base": base,
        "limit": limit,
        "base_offset": base_offset,
        "limit_offset": limit_offset,
        "start": None,
        "end": None,
        "size": None,
        "status": None,
        "notes": [],
    }
    if limit < base:
        region["status"] = STATUS_DISABLED
        if base == 0x7FFF and limit == 0x0000:
            region["notes"].append(
                "canonical disabled encoding (base=0x7fff, limit=0x0000)")
        else:
            region["notes"].append("limit < base: region is not used")
        return region

    start = base * 0x1000
    end = (limit + 1) * 0x1000
    region["start"] = start
    region["end"] = end
    region["size"] = end - start

    if base == 0 and limit == 0:
        # Zero registers decode to 0x0000-0x0fff, which is the descriptor
        # itself; vendors commonly leave these registers zero instead of
        # using the canonical disabled encoding. Report it distinctly.
        region["status"] = STATUS_ZERO_ENCODED
        region["notes"].append(
            "zero registers decode to 0x00000000-0x00000fff (the descriptor "
            "region); ambiguous vendor encoding, not a usable declaration")
        return region

    if end > image_size:
        region["status"] = STATUS_OUT_OF_BOUNDS
        region["notes"].append(
            "declared end 0x%x exceeds image size 0x%x" % (end, image_size))
        return region

    region["status"] = STATUS_DECLARED
    return region


def analyze_descriptor(data):
    '''Decode a flash descriptor image into a reviewable report dict.'''
    image_size = len(data)
    report = {
        "image_size": image_size,
        "valid_header": False,
        "disclaimer": DISCLAIMER,
        "map": None,
        "regions": [],
        "masters": [],
        "conflicts": [],
        "warnings": [],
    }

    if image_size < MAP_OFFSET + 4:
        report["warnings"].append(
            "image is %d bytes, too small for the descriptor header at "
            "0x10-0x13" % image_size)
        return report

    header = data[0x10:0x14]
    if header != FLASH_HEADER:
        report["warnings"].append(
            "missing flash descriptor signature 5aa5f00f at 0x10-0x13 "
            "(found %s)" % header.hex())
        return report
    report["valid_header"] = True

    map_status = _section_status(MAP_OFFSET, MAP_SIZE, image_size)
    if map_status != "ok":
        report["warnings"].append(
            "descriptor map @ 0x%x needs %d bytes, image has %d (%s)" % (
                MAP_OFFSET, MAP_SIZE, image_size, map_status))
        return report

    fields = struct.unpack("<14BH", data[MAP_OFFSET:MAP_OFFSET + MAP_SIZE])
    (component_base, num_chips, region_base, num_regions, master_base,
     num_masters, pch_straps_base, num_pch_straps, proc_straps_base,
     num_proc_straps, icc_base, num_icc, dmi_base, num_dmi, reserved) = fields

    region_section_offset = region_base * 0x10
    master_section_offset = master_base * 0x10
    report["map"] = {
        "offset": MAP_OFFSET,
        "component_base": component_base,
        "number_of_flash_chips": num_chips,
        "region_base": region_base,
        "number_of_regions": num_regions,
        "master_base": master_base,
        "number_of_masters": num_masters,
        "pch_straps_base": pch_straps_base,
        "number_of_pch_straps": num_pch_straps,
        "proc_straps_base": proc_straps_base,
        "number_of_proc_straps": num_proc_straps,
        "icc_table_base": icc_base,
        "number_of_icc_table_entries": num_icc,
        "dmi_table_base": dmi_base,
        "number_of_dmi_table_entries": num_dmi,
        "region_section_offset": region_section_offset,
        "master_section_offset": master_section_offset,
        "region_section_status": _section_status(
            region_section_offset, REGION_SECTION_SIZE, image_size),
        "master_section_status": _section_status(
            master_section_offset, MASTER_SECTION_SIZE, image_size),
    }

    if num_regions < len(REGION_NAMES):
        report["warnings"].append(
            "map declares %d region(s), fewer than the %d decoded here" % (
                num_regions, len(REGION_NAMES)))
    if num_masters < len(MASTER_NAMES):
        report["warnings"].append(
            "map declares %d master(s), fewer than the %d decoded here" % (
                num_masters, len(MASTER_NAMES)))
    if (region_section_offset < master_section_offset + MASTER_SECTION_SIZE
            and master_section_offset
            < region_section_offset + REGION_SECTION_SIZE):
        report["warnings"].append(
            "region section @ 0x%x and master section @ 0x%x overlap; the "
            "map pointers are inconsistent" % (
                region_section_offset, master_section_offset))

    # Region 0 is the descriptor itself; it has no base/limit registers.
    report["regions"].append({
        "index": 0,
        "name": "descriptor",
        "base": None,
        "limit": None,
        "base_offset": None,
        "limit_offset": None,
        "start": 0,
        "end": 0x1000,
        "size": 0x1000,
        "status": STATUS_DECLARED,
        "notes": ["implicit: region 0 is the flash descriptor itself"],
    })

    if report["map"]["region_section_status"] == "ok":
        section = data[region_section_offset:
                       region_section_offset + REGION_SECTION_SIZE]
        values = struct.unpack("<10H", section)
        for index, name in enumerate(REGION_NAMES):
            if name not in _REGION_REGISTER_OFFSETS:
                continue
            register = _REGION_REGISTER_OFFSETS[name] // 2
            base, limit = values[register], values[register + 1]
            base_offset = region_section_offset + register * 2
            report["regions"].append(_decode_region(
                name, index, base, limit, base_offset, base_offset + 2,
                image_size))
    else:
        report["warnings"].append(
            "region section @ 0x%x (RegionBase=0x%02x * 0x10) is %s: "
            "needs %d bytes, image has %d" % (
                region_section_offset, region_base,
                report["map"]["region_section_status"],
                REGION_SECTION_SIZE, image_size))
        for index, name in enumerate(REGION_NAMES):
            if name == "descriptor":
                continue
            report["regions"].append({
                "index": index,
                "name": name,
                "base": None,
                "limit": None,
                "base_offset": None,
                "limit_offset": None,
                "start": None,
                "end": None,
                "size": None,
                "status": STATUS_UNAVAILABLE,
                "notes": ["region section is %s" %
                          report["map"]["region_section_status"]],
            })

    if report["map"]["master_section_status"] == "ok":
        section = data[master_section_offset:
                       master_section_offset + MASTER_SECTION_SIZE]
        for name in MASTER_NAMES:
            register = _MASTER_REGISTER_OFFSETS[name]
            master_id, read, write = struct.unpack(
                "<HBB", section[register:register + 4])
            base_offset = master_section_offset + register
            access = {}
            for index, region_name in enumerate(REGION_NAMES):
                access[region_name] = {
                    "read": bool(read & (1 << index)),
                    "write": bool(write & (1 << index)),
                }
            report["masters"].append({
                "name": name,
                "id": master_id,
                "read": read,
                "write": write,
                "id_offset": base_offset,
                "read_offset": base_offset + 2,
                "write_offset": base_offset + 3,
                "access": access,
            })
    else:
        report["warnings"].append(
            "master section @ 0x%x (MasterBase=0x%02x * 0x10) is %s: "
            "needs %d bytes, image has %d" % (
                master_section_offset, master_base,
                report["map"]["master_section_status"],
                MASTER_SECTION_SIZE, image_size))

    # Overlaps between regions that decode to a usable byte range.
    ranged = [r for r in report["regions"]
              if r["status"] in (STATUS_DECLARED, STATUS_OUT_OF_BOUNDS)
              and r["start"] is not None]
    for i, first in enumerate(ranged):
        for second in ranged[i + 1:]:
            start = max(first["start"], second["start"])
            end = min(first["end"], second["end"])
            if start < end:
                report["conflicts"].append({
                    "regions": [first["name"], second["name"]],
                    "start": start,
                    "end": end,
                    "sources": [
                        "%s base/limit @ 0x%x/0x%x" % (
                            first["name"], first["base_offset"],
                            first["limit_offset"]),
                        "%s base/limit @ 0x%x/0x%x" % (
                            second["name"], second["base_offset"],
                            second["limit_offset"]),
                    ],
                })
    return report


def _format_range(region):
    if region["start"] is None:
        return "-"
    return "0x%08x-0x%08x" % (region["start"], region["end"] - 1)


def format_report(report):
    '''Render the report dict as reviewer-friendly text.'''
    lines = []
    lines.append("Intel Flash Descriptor region permission report")
    lines.append("Image size: 0x%x (%d bytes)" % (
        report["image_size"], report["image_size"]))
    lines.append("Note: %s" % report["disclaimer"])
    lines.append("")

    if not report["valid_header"]:
        lines.append("No valid flash descriptor found:")
        for warning in report["warnings"]:
            lines.append("  ! %s" % warning)
        return "\n".join(lines)

    if report["map"] is None:
        lines.append("Descriptor map is not fully present:")
        for warning in report["warnings"]:
            lines.append("  ! %s" % warning)
        return "\n".join(lines)

    descriptor_map = report["map"]
    lines.append("Descriptor map @ 0x%x:" % descriptor_map["offset"])
    lines.append(
        "  RegionBase=0x%02x -> region section @ 0x%x (%d bytes, %s)" % (
            descriptor_map["region_base"],
            descriptor_map["region_section_offset"],
            REGION_SECTION_SIZE,
            descriptor_map["region_section_status"]))
    lines.append(
        "  MasterBase=0x%02x -> master section @ 0x%x (%d bytes, %s)" % (
            descriptor_map["master_base"],
            descriptor_map["master_section_offset"],
            MASTER_SECTION_SIZE,
            descriptor_map["master_section_status"]))
    lines.append(
        "  Declared counts: regions=%d masters=%d chips=%d "
        "pch-straps=%d proc-straps=%d" % (
            descriptor_map["number_of_regions"],
            descriptor_map["number_of_masters"],
            descriptor_map["number_of_flash_chips"],
            descriptor_map["number_of_pch_straps"],
            descriptor_map["number_of_proc_straps"]))
    lines.append("")

    lines.append("Regions (base/limit registers are 4 KiB units):")
    for region in report["regions"]:
        if region["base"] is None:
            source = "no registers"
        else:
            source = "base=0x%04x@0x%x limit=0x%04x@0x%x" % (
                region["base"], region["base_offset"],
                region["limit"], region["limit_offset"])
        lines.append("  [%d] %-10s %-21s %-13s %s" % (
            region["index"], region["name"], _format_range(region),
            region["status"], source))
        for note in region["notes"]:
            lines.append("      note: %s" % note)
    lines.append("")

    if report["masters"]:
        lines.append(
            "Access matrix (bit N of each master mask covers region N; "
            "R=read W=write .=no access):")
        header = "  %-12s" % "region"
        for master in report["masters"]:
            header += " %-10s" % ("%s-master" % master["name"])
        lines.append(header)
        for region in report["regions"]:
            row = "  %-12s" % region["name"]
            for master in report["masters"]:
                access = master["access"][region["name"]]
                cell = "%s%s" % (
                    "R" if access["read"] else ".",
                    "W" if access["write"] else ".")
                row += " %-10s" % cell
            lines.append(row)
        lines.append("")
        lines.append("Master register sources:")
        for master in report["masters"]:
            lines.append(
                "  %-10s id=0x%04x@0x%x read=0x%02x@0x%x "
                "write=0x%02x@0x%x" % (
                    master["name"], master["id"], master["id_offset"],
                    master["read"], master["read_offset"],
                    master["write"], master["write_offset"]))
        lines.append("")

    if report["conflicts"]:
        lines.append("Conflicting ranges:")
        for conflict in report["conflicts"]:
            lines.append("  ! %s and %s overlap at 0x%08x-0x%08x (%s)" % (
                conflict["regions"][0], conflict["regions"][1],
                conflict["start"], conflict["end"] - 1,
                "; ".join(conflict["sources"])))
        lines.append("")

    if report["warnings"]:
        lines.append("Warnings:")
        for warning in report["warnings"]:
            lines.append("  ! %s" % warning)
        lines.append("")

    return "\n".join(lines)
