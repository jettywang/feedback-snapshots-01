from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from auditwheel import options

if TYPE_CHECKING:
    import argparse

logger = logging.getLogger(__name__)


def configure_subparser(sub_parsers: Any) -> None:  # noqa: ANN401
    help_ = "Analyze a single ELF file (similar to ``ldd``)."
    p = sub_parsers.add_parser("lddtree", help=help_, description=help_)
    p.add_argument("file", type=Path, help="Path to .so file")
    options.ldpaths(p)
    options.sysroot(p)
    p.set_defaults(func=execute)


def execute(args: argparse.Namespace, p: argparse.ArgumentParser) -> int:  # noqa: ARG001
    from auditwheel import json
    from auditwheel.error import MissingLibraryError, SearchPathError
    from auditwheel.lddtree import build_search_paths, ldd

    try:
        search = build_search_paths(args.LDPATHS, sysroot=args.SYSROOT)
        result = ldd(args.file, ldpaths=search)
    except (MissingLibraryError, SearchPathError) as e:
        logger.error("%s", e.message)
        return 1
    logger.info(json.dumps(result))
    return 0