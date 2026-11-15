from __future__ import annotations

import argparse
import logging
from pathlib import Path

from dissect.util import ts

from dissect.shellitem.lnk import Lnk
from dissect.shellitem.lnk.itemid import FileEntryShellItem, ShellItem

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def format_shell_item(index: int, item: ShellItem) -> str:
    """Format a single shell item of a target IDList for display."""
    status = item.name if item.name is not None else "<unresolved>"
    line = f"[{index}] {item.type_name} (0x{item.type:02x}): {status}"

    if isinstance(item, FileEntryShellItem):
        line += f" (short name: {item.primary_name}, long name: {item.long_name})"
    elif item.name is None:
        # Unknown entries are shown as raw data, no name is guessed from it.
        line += f" raw: {item.data.hex()}"

    if item.error:
        line += f" [error: {item.error}]"
    return line


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
        local_base_path = (
            lnk_file.linkinfo.local_base_path.decode(errors="backslashreplace")
            if lnk_file.flag("has_link_info") and lnk_file.linkinfo.flag("volumeid_and_local_basepath")
            else None
        )
        common_path_suffix = (
            lnk_file.linkinfo.common_path_suffix.decode(errors="backslashreplace")
            if lnk_file.flag("has_link_info")
            else None
        )

        if local_base_path and common_path_suffix:
            lnk_full_path = local_base_path + common_path_suffix
        elif local_base_path and not common_path_suffix:
            lnk_full_path = local_base_path
        else:
            lnk_full_path = None

        if lnk_file.flag("has_link_info") and lnk_file.linkinfo.flag("common_network_relative_link_and_pathsuffix"):
            lnk_net_name = (
                # TODO add codepage CLI flag to decode for supplied codepage
                lnk_file.linkinfo.common_network_relative_link.net_name.decode(errors="backslashreplace")
                if lnk_file.linkinfo.common_network_relative_link.net_name
                else None
            )
            lnk_device_name = (
                # TODO add codepage CLI flag to decode for supplied codepage
                lnk_file.linkinfo.common_network_relative_link.device_name.decode(errors="backslashreplace")
                if lnk_file.linkinfo.common_network_relative_link.device_name
                else None
            )

        try:
            machine_id = lnk_file.extradata.TRACKER_PROPS.machine_id.decode()
        except AttributeError:
            machine_id = None

        lnk_target_idlist_path = None
        lnk_target_idlist_components = "None"
        if lnk_file.flag("has_link_target_idlist"):
            target_idlist = lnk_file.target_idlist
            lnk_target_idlist_path = target_idlist.get_path()
            components = [format_shell_item(index, item) for index, item in enumerate(target_idlist.items)]
            if target_idlist.truncated:
                components.append("<truncated target idlist>")
            if components:
                lnk_target_idlist_components = "\n\t\t\t\t  ".join(components)

        target_mtime = ts.wintimestamp(lnk_file.link_header.write_time)
        target_atime = ts.wintimestamp(lnk_file.link_header.access_time)
        target_ctime = ts.wintimestamp(lnk_file.link_header.creation_time)

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
            f"Link local base path\t\t: {local_base_path}\n"
            f"Link common path suffix\t\t: {common_path_suffix}\n"
            f"Link full path\t\t\t: {lnk_full_path}\n"
            f"Net name link\t\t\t: {lnk_net_name}\n"
            f"Device name link\t\t: {lnk_device_name}\n"
            f"Machine id link\t\t\t: {machine_id}\n"
            f"Target IDList path\t\t: {lnk_target_idlist_path}\n"
            f"Target IDList components\t: {lnk_target_idlist_components}\n"
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
