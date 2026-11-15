from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dissect.shellitem.lnk import Lnk
from dissect.util import ts

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def _string_evidence(link_string) -> tuple[str | None, str | None, bool]:
    """Return ``(ansi_text, unicode_text, conflict)`` for a LinkInfo string field."""
    if link_string is None:
        return None, None, False
    ansi_text = link_string.ansi.decode() if link_string.ansi is not None and not link_string.ansi.absent else None
    unicode_text = (
        link_string.unicode.decode() if link_string.unicode is not None and not link_string.unicode.absent else None
    )
    return ansi_text, unicode_text, link_string.conflict


def parse(path: Path) -> None:
    lnk_file = Lnk(path.open("rb"))
    lnk_net_name = lnk_device_name = None

    if lnk_file.link_header:
        lnk_path = path
        lnk_name = lnk_file.stringdata.name_string.string if lnk_file.flag("has_name") else None

        lnk_mtime = ts.from_unix(path.stat().st_mtime)
        lnk_atime = ts.from_unix(path.stat().st_atime)
        lnk_ctime = ts.from_unix(path.stat().st_ctime)

        lnk_relativepath = lnk_file.stringdata.relative_path.string if lnk_file.flag("has_relative_path") else None
        lnk_workdir = lnk_file.stringdata.working_dir.string if lnk_file.flag("has_working_dir") else None
        lnk_iconlocation = lnk_file.stringdata.icon_location.string if lnk_file.flag("has_icon_location") else None
        lnk_arguments = lnk_file.stringdata.command_line_arguments.string if lnk_file.flag("has_arguments") else None

        local_ansi = local_unicode = None
        suffix_ansi = suffix_unicode = None
        if lnk_file.flag("has_link_info"):
            info = lnk_file.linkinfo
            local_ansi, local_unicode, _ = _string_evidence(info.local_base_path_string)
            suffix_ansi, suffix_unicode, _ = _string_evidence(info.common_path_suffix_string)

        local_base_path = local_unicode if local_unicode is not None else local_ansi
        common_path_suffix = suffix_unicode if suffix_unicode is not None else suffix_ansi

        if local_base_path and common_path_suffix:
            lnk_full_path = local_base_path + common_path_suffix
        elif local_base_path and not common_path_suffix:
            lnk_full_path = local_base_path
        else:
            lnk_full_path = None

        if lnk_file.flag("has_link_info") and lnk_file.linkinfo.flag("common_network_relative_link_and_pathsuffix"):
            net_ansi, net_unicode, _ = _string_evidence(lnk_file.linkinfo.net_name_string)
            device_ansi, device_unicode, _ = _string_evidence(lnk_file.linkinfo.device_name_string)
            lnk_net_name = net_unicode if net_unicode is not None else net_ansi
            lnk_device_name = device_unicode if device_unicode is not None else device_ansi

        conflicts = lnk_file.linkinfo.conflicts if lnk_file.flag("has_link_info") else []

        try:
            machine_id = lnk_file.extradata.TRACKER_PROPS.machine_id.decode()
        except AttributeError:
            machine_id = None

        target_mtime = ts.wintimestamp(lnk_file.link_header.write_time)
        target_atime = ts.wintimestamp(lnk_file.link_header.access_time)
        target_ctime = ts.wintimestamp(lnk_file.link_header.creation_time)

        conflict_line = ", ".join(conflicts) if conflicts else "none"
        print(
            f"Link Path\t\t\t: {lnk_path}\n"
            f"Link Name / description\t\t: {lnk_name}\n"
            f"Link modification time\t\t: {lnk_mtime}\n"
            f"Link access time\t\t: {lnk_atime}\n"
            f"Link changed time\t\t: {lnk_ctime}\n"
            f"Link relative path\t\t: {lnk_relativepath}\n"
            f"Link working directory\t\t: {lnk_workdir}\n"
            f"Link icon location\t\t: {lnk_iconlocation}\n"
            f"Link arguments\t\t\t: {lnk_arguments}\n"
            f"Link local base path (ANSI)\t: {local_ansi}\n"
            f"Link local base path (Unicode)\t: {local_unicode}\n"
            f"Link common path suffix (ANSI)\t: {suffix_ansi}\n"
            f"Link common path suffix (Unicode): {suffix_unicode}\n"
            f"Link full path\t\t\t: {lnk_full_path}\n"
            f"Link encoding conflicts\t\t: {conflict_line}\n"
            f"Net name link\t\t\t: {lnk_net_name}\n"
            f"Device name link\t\t: {lnk_device_name}\n"
            f"Machine id link\t\t\t: {machine_id}\n"
            f"Target file modification time\t: {target_mtime}\n"
            f"Target file access time\t\t: {target_atime}\n"
            f"Target file changed time\t: {target_ctime}\n"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse a .lnk file from your local disk.",
    )

    parser.add_argument("paths", metavar="paths", type=str, nargs="+", help="Path to .lnk file(s).")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")

    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    for path in args.paths:
        path = Path(path)

        if path.is_dir():
            continue

        parse(Path(path))


if __name__ == "__main__":
    main()
