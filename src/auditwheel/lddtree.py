# Copyright 2016 Robert McGibbon
# Copyright 2012-2014 Gentoo Foundation
# Copyright 2012-2014 Mike Frysinger <vapier@gentoo.org>
# Copyright 2012-2014 The Chromium OS Authors
# Use of this source code is governed by a BSD-style license (BSD-3)
# Original version available from:
#   https://sources.gentoo.org/cgi-bin/viewvc.cgi/gentoo-projects/pax-utils/lddtree.py
"""Read the ELF dependency tree

This does not work like `ldd` in that we do not execute/load code (only read
files on disk).
"""

from __future__ import annotations

import errno
import functools
import glob
import logging
import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

from elftools.elf.constants import E_FLAGS
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection
from elftools.elf.segments import InterpSegment

from auditwheel.architecture import Architecture
from auditwheel.error import InvalidLibcError, MissingLibraryError, SearchPathError
from auditwheel.libc import Libc

if TYPE_CHECKING:
    from collections.abc import Mapping

log = logging.getLogger(__name__)
__all__ = ["LIBPYTHON_RE", "DynamicExecutable", "DynamicLibrary", "SearchPaths", "ldd"]

# Regex to match libpython shared library names
LIBPYTHON_RE = re.compile(r"^libpython\d+\.\d+m?.so(\.\d)*$")

# Regex to match ORIGIN references in rpaths.
ORIGIN_RE = re.compile(r"\$(ORIGIN|\{ORIGIN\})")


@dataclass(frozen=True)
class Platform:
    _elf_osabi: str
    _elf_class: int
    _elf_little_endian: bool
    _elf_machine: str
    _base_arch: Architecture | None
    _ext_arch: Architecture | None
    _error_msg: str | None

    def is_compatible(self, other: Platform) -> bool:
        os_abis = frozenset((self._elf_osabi, other._elf_osabi))
        compat_sets = (frozenset(f"ELFOSABI_{x}" for x in ("NONE", "SYSV", "GNU", "LINUX")),)
        return (
            (len(os_abis) == 1 or any(os_abis.issubset(x) for x in compat_sets))
            and self._elf_class == other._elf_class
            and self._elf_little_endian == other._elf_little_endian
            and self._elf_machine == other._elf_machine
        )

    @property
    def baseline_architecture(self) -> Architecture:
        if self._base_arch is not None:
            return self._base_arch
        raise ValueError(self._error_msg)

    @property
    def extended_architecture(self) -> Architecture | None:
        if self._error_msg is not None:
            raise ValueError(self._error_msg)
        return self._ext_arch


@dataclass(frozen=True)
class DynamicLibrary:
    soname: str
    path: str | None
    realpath: Path | None
    platform: Platform | None = None
    needed: tuple[str, ...] = ()
    search_source: str | None = None
    search_dir: str | None = None


@dataclass(frozen=True)
class DynamicExecutable:
    interpreter: str | None
    libc: Libc | None
    path: str
    realpath: Path
    platform: Platform
    needed: tuple[str, ...]
    rpath: tuple[str, ...]
    runpath: tuple[str, ...]
    libraries: dict[str, DynamicLibrary]
    search_paths: tuple[str, ...] = ()


_SEARCH_KINDS = ("rpath", "runpath", "env", "conf", "interp")


def _resolved_under(path: str | Path, root: str | Path) -> bool:
    candidate = Path(path).resolve()
    base = Path(root).resolve()
    return candidate == base or base in candidate.parents


@dataclass(eq=False)
class SearchPaths:
    """Ordered library search directories with their provenance.

    ``strict`` makes every approved source mandatory and records unresolved
    dependencies so callers can fail with a locatable report.
    """

    paths: dict[str, list[str]] = field(
        default_factory=lambda: {"conf": [], "env": [], "interp": []},
    )
    source_of: dict[tuple[str, str], str] = field(default_factory=dict)
    root: str = "/"
    internal_root: str | None = None
    strict: bool = False
    extra_conf: tuple[str, ...] = ()
    missing: dict[str, set[str]] = field(default_factory=dict)
    unavailable: list[str] = field(default_factory=list)
    _conf_loaded: bool = field(default=False, repr=False)

    @classmethod
    def from_dict(cls, paths: Mapping[str, list[str]]) -> SearchPaths:
        search = cls()
        for kind, entries in paths.items():
            search.add(kind, list(entries), kind)
        for kind in _SEARCH_KINDS:
            search.paths.setdefault(kind, [])
        return search

    def __eq__(self, other: object) -> bool:
        # Keep ``ld_paths_from_arg`` comparable to plain path dictionaries.
        if isinstance(other, dict):
            return self.paths == other
        if isinstance(other, SearchPaths):
            return self.paths == other.paths
        return NotImplemented

    def add(self, kind: str, paths: list[str], source: str) -> None:
        bucket = self.paths.setdefault(kind, [])
        for path in paths:
            if path in bucket:
                continue
            bucket.append(path)
            self.source_of[(kind, path)] = source

    def ordered(self) -> list[tuple[str, str]]:
        return [(kind, path) for kind in _SEARCH_KINDS for path in self.paths.get(kind, [])]

    def describe(self, kind: str, path: str) -> str:
        source = self.source_of.get((kind, path), kind)
        return f"{source}:{path}"

    def record_missing(self, soname: str, needed_by: str) -> None:
        self.missing.setdefault(soname, set()).add(needed_by)

    def missing_error(self, search_paths: tuple[str, ...] | None = None) -> MissingLibraryError:
        return MissingLibraryError(
            self.missing,
            self.all_display_paths() if search_paths is None else search_paths,
            tuple(dedupe(self.unavailable)),
        )

    def approved_dir(self, kind: str, path: str) -> str | None:
        """Return the effective directory for ``path`` or ``None`` if unapproved.

        A strict sysroot behaves like a chroot: an absolute RPATH/RUNPATH or
        interpreter path from a library in the sysroot is remapped below the
        sysroot as long as that remapped directory exists. Wheel-internal
        references remain valid through ``internal_root``.
        """
        if not self.strict or kind not in {"rpath", "runpath", "interp"}:
            return path
        for candidate in (self.root, self.internal_root):
            if candidate is not None and _resolved_under(path, candidate):
                return path
        if path.startswith("/") and self.root not in {"", "/"}:
            remapped = normpath(self.root + path)
            if Path(remapped).is_dir():
                log.debug("remapping %s entry %s below sysroot as %s", kind, path, remapped)
                return remapped
        log.debug("ignoring %s entry %s outside the approved sysroot", kind, path)
        return None

    def all_display_paths(self) -> tuple[str, ...]:
        return tuple(path for _, path in self.ordered())

    def fork(self) -> SearchPaths:
        """A per-ELF view sharing the approved configuration and missing set."""
        fork = SearchPaths(
            root=self.root,
            internal_root=self.internal_root,
            strict=self.strict,
            extra_conf=self.extra_conf,
            missing=self.missing,
            unavailable=self.unavailable,
            _conf_loaded=self._conf_loaded,
        )
        for kind in _SEARCH_KINDS:
            fork.paths[kind] = list(self.paths.get(kind, []))
        fork.source_of = dict(self.source_of)
        return fork


def _parse_approved_paths(str_ldpaths: str, root: str) -> list[str]:
    """Parse ``--ldpaths`` entries that must live inside the approved root."""
    approved: list[str] = []
    for entry in str_ldpaths.split(":"):
        if not entry:
            continue
        path = Path(entry)
        if not path.is_absolute():
            msg = f"approved library directory must be absolute: {entry}"
            raise SearchPathError(msg)
        if not path.is_dir():
            msg = f"approved library directory does not exist: {entry}"
            raise SearchPathError(msg)
        if not _resolved_under(path, root):
            msg = f"approved library directory is outside the sysroot {root}: {entry}"
            raise SearchPathError(msg)
        approved.append(normpath(str(path)))
    return list(dedupe(approved))


def load_conf_for(search: SearchPaths, libc: Libc | None) -> None:
    """Resolve the sysroot's approved ld.so configuration exactly once."""
    if search._conf_loaded:
        return
    search._conf_loaded = True
    if search.root == "/" and not search.strict and not search.extra_conf:
        return
    loaded = load_ld_paths(
        libc,
        root=search.root,
        strict=search.strict,
    )
    if search.strict:
        missing_conf = [
            path
            for path in loaded["conf"]
            if not Path(path).is_dir() and path not in search.unavailable
        ]
        search.unavailable.extend(missing_conf)
    search.add("conf", loaded["conf"], "sysroot ld.so.conf")
    search.add("interp", loaded["interp"], "sysroot interpreter")
    search.add("conf", list(search.extra_conf), "--ldpaths")


def build_search_paths(
    args_ldpaths: str | None = None,
    *,
    sysroot: str | None = None,
    internal_root: str | None = None,
) -> SearchPaths | None:
    """Build the effective search paths for an analysis.

    Without ``sysroot`` this is the historical environment-based behaviour.
    With ``sysroot``, host environment variables and host configuration are
    ignored; only the sysroot configuration and approved ``--ldpaths``
    directories below it are searched.
    """
    if sysroot is None:
        return ld_paths_from_arg(args_ldpaths)

    root = os.path.abspath(sysroot)
    if not Path(root).is_dir():
        msg = f"sysroot does not exist: {sysroot}"
        raise SearchPathError(msg)

    extra: list[str] = []
    if args_ldpaths:
        extra = _parse_approved_paths(args_ldpaths, root)

    for variable in ("LD_LIBRARY_PATH", "AUDITWHEEL_LD_LIBRARY_PATH"):
        if os.environ.get(variable):
            log.warning("ignoring %s: strict sysroot search is in effect", variable)

    search = SearchPaths(
        root=root,
        internal_root=internal_root,
        strict=True,
        extra_conf=tuple(extra),
    )
    # ``ldd`` expands the approved configuration once the libc is known.
    return search


def _get_platform(elf: ELFFile) -> Platform:
    elf_osabi = elf.header["e_ident"]["EI_OSABI"]
    elf_class = elf.elfclass
    elf_little_endian = elf.little_endian
    elf_machine = elf["e_machine"]
    base_arch = {
        ("EM_386", 32, True): Architecture.i686,
        ("EM_X86_64", 64, True): Architecture.x86_64,
        ("EM_PPC64", 64, True): Architecture.ppc64le,
        ("EM_PPC64", 64, False): Architecture.ppc64,
        ("EM_RISCV", 64, True): Architecture.riscv64,
        ("EM_AARCH64", 64, True): Architecture.aarch64,
        ("EM_S390", 64, False): Architecture.s390x,
        ("EM_ARM", 32, True): Architecture.armv7l,
        ("EM_LOONGARCH", 64, True): Architecture.loongarch64,
    }.get((elf_machine, elf_class, elf_little_endian))
    ext_arch: Architecture | None = None
    error_msg: str | None = None
    flags = elf["e_flags"]
    assert base_arch is None or base_arch.baseline == base_arch  # noqa: S101
    if base_arch is None:
        error_msg = "Unknown architecture"
    elif base_arch == Architecture.x86_64:
        for section in elf.iter_sections():
            if not isinstance(section, NoteSection):
                continue
            for note in section.iter_notes():
                if note["n_type"] != "NT_GNU_PROPERTY_TYPE_0":
                    continue
                if note["n_name"] != "GNU":
                    continue
                for prop in note["n_desc"]:
                    if prop.pr_type != "GNU_PROPERTY_X86_ISA_1_NEEDED":
                        continue
                    if prop.pr_datasz != 4:
                        continue
                    data = prop.pr_data
                    data -= data & 1  # clear baseline
                    if data & 8 == 8:
                        ext_arch = Architecture.x86_64_v4
                        break
                    if data & 4 == 4:
                        ext_arch = Architecture.x86_64_v3
                        break
                    if data & 2 == 2:
                        ext_arch = Architecture.x86_64_v2
                        break
                    if data != 0:
                        error_msg = "unknown x86_64 ISA"
                break
    elif base_arch == Architecture.armv7l:
        if (flags & E_FLAGS.EF_ARM_EABIMASK) != E_FLAGS.EF_ARM_EABI_VER5:
            error_msg = "Invalid ARM EABI version for armv7l"
        elif (flags & E_FLAGS.EF_ARM_ABI_FLOAT_HARD) != E_FLAGS.EF_ARM_ABI_FLOAT_HARD:
            error_msg = "armv7l shall use hard-float"
        if error_msg is not None:
            base_arch = None

    return Platform(
        elf_osabi,
        elf_class,
        elf_little_endian,
        elf_machine,
        base_arch,
        ext_arch,
        error_msg,
    )


def normpath(path: str) -> str:
    """Normalize a path

    Python's os.path.normpath() doesn't handle some cases:
    // -> //
    //..// -> //
    //..//..// -> ///
    """
    return os.path.normpath(path).replace("//", "/")


def readlink(path: str, root: str, *, prefixed: bool = False) -> str:
    """Like os.readlink(), but relative to a ``root``

    This does not currently handle the pathological case:
    /lib/foo.so -> ../../../../../../../foo.so
    This relies on the .. entries in / to point to itself.

    Parameters
    ----------
    path
        The symlink to read
    root
        The path to use for resolving absolute symlinks
    prefixed
        When False, the ``path`` must not have ``root`` prefixed to it, nor
        will the return value have ``root`` prefixed.  When True, ``path``
        must have ``root`` prefixed, and the return value will have ``root``
        added.

    Returns
    -------
    A fully resolved symlink path

    """
    root = root.rstrip("/")
    if prefixed:
        path = path[len(root) :]

    while os.path.islink(root + path):
        path = os.path.join(os.path.dirname(path), os.readlink(root + path))

    return normpath((root + path) if prefixed else path)


def dedupe(items: list[str]) -> list[str]:
    """Remove all duplicates from ``items`` (keeping order)"""
    seen: dict[str, str] = {}
    return [seen.setdefault(x, x) for x in items if x not in seen]


def parse_ld_paths(
    str_ldpaths: str,
    path: str = "",
    root: str = "",
    *,
    keep_missing: bool = False,
) -> list[str]:
    """Parse the colon-delimited list of paths and apply ldso rules to each

    Note the special handling as dictated by the ldso:
    - Empty paths are equivalent to $PWD
    - $ORIGIN is expanded to the directory containing the given file
    - (TODO) $LIB and friends

    Parameters
    ----------
    str_ldpaths
        A colon-delimited string of paths
    root
        The path to prepend to all paths found
    path
        The object actively being parsed (used for $ORIGIN)
    keep_missing
        Keep entries that do not exist on the host. Strict sysroot analysis
        uses this so absolute RPATHs can be remapped below the sysroot later.

    Returns
    -------
        list of processed paths

    """
    if not str_ldpaths:
        return []

    ldpaths: list[str] = []
    for ldpath in str_ldpaths.split(":"):
        if ldpath == "":
            # The ldso treats "" paths as $PWD.
            ldpath_ = os.getcwd()
        elif re.search(ORIGIN_RE, ldpath):
            if not path:
                msg = "can't expand $ORIGIN without a path"
                raise ValueError(msg)
            ldpath_ = re.sub(ORIGIN_RE, os.path.dirname(os.path.abspath(path)), ldpath)
        else:
            ldpath_ = root + ldpath
        ldpaths.append(normpath(ldpath_))
    if keep_missing:
        return list(dedupe(ldpaths))
    return [p for p in dedupe(ldpaths) if os.path.isdir(p)]


@functools.lru_cache
def parse_ld_so_conf(
    ldso_conf: str,
    *,
    root: str = "/",
    _first: bool = True,
    keep_missing: bool = False,
) -> list[str]:
    """Load all the paths from a given ldso config file

    This should handle comments, whitespace, and "include" statements.

    Parameters
    ----------
    ldso_conf
        The file to scan
    root
        The path to prepend to all paths found
    _first
        Recursive use only; is this the first ELF?
    keep_missing
        Keep configured directories that do not exist (strict sysroot audit).

    Returns
    -------
    list of paths found

    """
    paths: list[str] = []

    dbg_pfx = "" if _first else "  "
    try:
        log.debug("%sparse_ld_so_conf(%s)", dbg_pfx, ldso_conf)
        with open(ldso_conf) as f:
            for input_line in f:
                line = input_line.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("include "):
                    line = line[8:]
                    if line[0] == "/":
                        line = root + line.lstrip("/")
                    else:
                        line = os.path.dirname(ldso_conf) + "/" + line
                    log.debug("%s  glob: %s", dbg_pfx, line)
                    for path in glob.glob(line):
                        paths += parse_ld_so_conf(
                            path,
                            root=root,
                            _first=False,
                            keep_missing=keep_missing,
                        )
                else:
                    paths += [normpath(root + line)]
    except OSError as e:
        if e.errno != errno.ENOENT:
            log.warning(e)

    if _first:
        # TODO: Load paths from ldso itself.
        # Remove duplicate entries to speed things up.
        paths = list(dedupe(paths))
        if not keep_missing:
            paths = [p for p in paths if os.path.isdir(p)]

    return paths


def _system_conf_dirs(root: str, *, keep_missing: bool = False) -> list[str]:
    """The trusted directories the dynamic linker searches below ``root``."""
    dirs = ["/lib", "/lib64/", "/usr/lib", "/usr/lib64"]
    if root not in {"", "/"}:
        rooted = [normpath(root + dir_.rstrip("/")) for dir_ in dirs]
        rooted.append(normpath(root + "/usr/local/lib"))
        dirs = rooted
    if keep_missing:
        return dirs
    return [dir_ for dir_ in dirs if Path(dir_).is_dir()]


@functools.lru_cache
def load_ld_paths(
    libc: Libc | None,
    root: str = "/",
    prefix: str = "",
    strict: bool = False,
) -> dict[str, list[str]]:
    """Load linker paths from common locations

    This parses the ld.so.conf and AUDITWHEEL_LD_LIBRARY_PATH / LD_LIBRARY_PATH env vars.

    Parameters
    ----------
    root
        The root tree to prepend to paths
    prefix
        The path under ``root`` to search
    strict
        Fail if the given ``root`` or its ld.so configuration is missing
        instead of silently falling back to default directories.

    Returns
    -------
    dict containing library paths to search

    """
    ldpaths: dict[str, list[str]] = {"conf": [], "env": [], "interp": []}
    rooted = root not in {"", "/"}

    if strict and rooted and not Path(root).is_dir():
        msg = f"sysroot does not exist: {root}"
        raise SearchPathError(msg)

    ld_library_path = os.environ.get("LD_LIBRARY_PATH")
    if root != "/" and ld_library_path is not None:
        log.warning("ignoring LD_LIBRARY_PATH due to ROOT usage")
        ld_library_path = None

    # Load up $AUDITWHEEL_LD_LIBRARY_PATH and $LD_LIBRARY_PATH
    env_ldpath = ":".join(
        filter(None, (os.environ.get("AUDITWHEEL_LD_LIBRARY_PATH"), ld_library_path)),
    )

    if env_ldpath:
        # TODO: If this contains $ORIGIN, we probably have to parse this
        # on a per-ELF basis so it can get turned into the right thing.
        # don't pass root: in case root != "/", only AUDITWHEEL_LD_LIBRARY_PATH is checked
        # it shall already contain fully resolved paths
        ldpaths["env"] = parse_ld_paths(env_ldpath, path="")

    if libc == Libc.MUSL:
        # from https://git.musl-libc.org/cgit/musl/tree/ldso
        # /dynlink.c?id=3f701faace7addc75d16dea8a6cd769fa5b3f260#n1063
        root_prefix = Path(root) / prefix
        ld_musl = list((root_prefix / "etc").glob("ld-musl-*.path"))
        assert len(ld_musl) <= 1  # noqa: S101
        if len(ld_musl) == 0:
            if strict and rooted:
                msg = f"sysroot has no musl ld-musl-*.path configuration: {root_prefix / 'etc'}"
                raise SearchPathError(msg)
            ldpaths["conf"] = _system_conf_dirs(root, keep_missing=strict)
        else:
            ldpaths["conf"] = []
            for ldpath in ld_musl[0].read_text().split(":"):
                ldpath_stripped = ldpath.strip()
                if ldpath_stripped == "":
                    continue
                ldpaths["conf"].append(normpath(root + ldpath_stripped))
    else:
        # Load up /etc/ld.so.conf.
        conf = root + prefix + "/etc/ld.so.conf"
        if strict and not Path(conf).is_file():
            msg = f"approved sysroot has no linker configuration: {conf}"
            raise SearchPathError(msg)
        ldpaths["conf"] = parse_ld_so_conf(conf, root=root, keep_missing=strict)
        # the trusted directories are not necessarily in ld.so.conf
        ldpaths["conf"].extend(_system_conf_dirs(root, keep_missing=strict))
    log.debug("linker ldpaths: %s", ldpaths)
    return ldpaths


def ld_paths_from_arg(args_ldpaths: str | None) -> SearchPaths | None:
    """Load linker paths from the --ldpaths option and the environment."""
    if args_ldpaths is None:
        # The option was not provided, so fall back on load_ld_paths.
        return None

    search = SearchPaths()
    search.add(
        "env",
        parse_ld_paths(os.environ.get("AUDITWHEEL_LD_LIBRARY_PATH", "")),
        "AUDITWHEEL_LD_LIBRARY_PATH",
    )
    search.add("conf", parse_ld_paths(args_ldpaths), "--ldpaths")
    return search


def find_lib(
    platform: Platform,
    lib: str,
    ldpaths: list[str],
    root: str = "/",
) -> tuple[Path | None, str | None]:
    """Try to locate a ``lib`` that is compatible to ``elf`` in the given
    ``ldpaths``

    Parameters
    ----------
    platform : Platform
        The platform which the library should be compatible with (ELF wise)
    lib : str
        The library (basename) to search for
    ldpaths : list[str]
        A list of paths to search
    root : str
       The root path to resolve symlinks

    Returns
    -------
    Tuple of the full path to the desired library and the real path to it

    """
    match = find_lib_with_source(platform, lib, ldpaths, root)
    return match[0], match[1]


def find_lib_with_source(
    platform: Platform,
    lib: str,
    ldpaths: list[str],
    root: str = "/",
) -> tuple[Path | None, str | None, str | None]:
    """Like :func:`find_lib` but also return the directory that matched."""
    for ldpath in ldpaths:
        path = os.path.join(ldpath, lib)
        target = Path(readlink(path, root, prefixed=True))

        if target.exists():
            with open(target, "rb") as f:
                libelf = ELFFile(f)
                if platform.is_compatible(_get_platform(libelf)):
                    return target, path, ldpath

    return None, None, None


def ldd(
    path: Path,
    root: str = "/",
    prefix: str = "",
    ldpaths: dict[str, list[str]] | SearchPaths | None = None,
    display: str | None = None,
    exclude: frozenset[str] = frozenset(),
    _all_libs: dict[str, DynamicLibrary] | None = None,
) -> DynamicExecutable:
    """Parse the ELF dependency tree of the specified file

    Parameters
    ----------
    path
        The ELF to scan
    root
        The root tree to prepend to paths; this applies to interp and rpaths
        only as ``path`` and ``ldpaths`` are expected to be prefixed already
    prefix
        The path under ``root`` to search
    ldpaths
        dict containing library paths to search; should have the keys:
        conf, env, interp. If not supplied, the function ``load_ld_paths``
        will be called.
    display
        The path to show rather than ``path``
    exclude
        List of soname (DT_NEEDED) to exclude from the tree
    _all_libs
        Recursive use only; dict of all libs we've seen

    Returns
    -------
    a dict containing information about all the ELFs; e.g.
    {
      'interp': '/lib64/ld-linux.so.2',
      'needed': ['libc.so.6', 'libcurl.so.4',],
      'libs': {
        'libc.so.6': {
          'path': '/lib64/libc.so.6',
          'needed': [],
        },
        'libcurl.so.4': {
          'path': '/usr/lib64/libcurl.so.4',
          'needed': ['libc.so.6', 'librt.so.1',],
        },
      },
    }

    """
    _first = _all_libs is None
    if _all_libs is None:
        _all_libs = {}

    if isinstance(ldpaths, dict):
        ldpaths = SearchPaths.from_dict(ldpaths)
    # The top-level call owns a private view so per-ELF interpreters do not
    # leak into sibling analyses sharing the same approved boundary.
    search = ldpaths
    if _first and search is not None and search.strict:
        search = search.fork()

    log.debug("ldd(%s)", path)

    interpreter: str | None = None
    libc: Libc | None = None
    needed: list[str] = []
    rpaths: list[str] = []
    runpaths: list[str] = []

    with open(path, "rb") as f:
        elf = ELFFile(f)

        # get the platform
        platform = _get_platform(elf)

        # If this is the first ELF, extract the interpreter.
        if _first:
            for segment in elf.iter_segments():
                if not isinstance(segment, InterpSegment):
                    continue
                interp = segment.get_interp_name()
                log.debug("  interp           = %s", interp)
                interpreter = normpath(root + interp)
                soname = os.path.basename(interpreter)
                _all_libs[soname] = DynamicLibrary(
                    soname,
                    interpreter,
                    Path(readlink(interpreter, root, prefixed=True)),
                    platform,
                    search_source="interp",
                    search_dir=os.path.dirname(interpreter),
                )
                # if we have an interpreter and it's not MUSL, assume GLIBC
                libc = Libc.MUSL if soname.startswith("ld-musl-") else Libc.GLIBC
                # TODO: Should read it and scan for /lib paths.
                interp_dirs = [
                    normpath(root + os.path.dirname(interp)),
                    normpath(
                        root + prefix + "/usr" + os.path.dirname(interp).lstrip(prefix),
                    ),
                ]
                if search is not None:
                    search.paths["interp"] = list(interp_dirs)
                log.debug("  ldpaths[interp]  = %s", interp_dirs)
                break

        # Parse the ELF's dynamic tags.
        for segment in elf.iter_segments():
            if not isinstance(segment, DynamicSegment):
                continue
            for t in segment.iter_tags():
                if t.entry.d_tag == "DT_RPATH":
                    rpaths = parse_ld_paths(
                        t.rpath,  # type: ignore[attr-defined]
                        path=str(path),
                        root=root,
                        keep_missing=search is not None and search.strict,
                    )
                elif t.entry.d_tag == "DT_RUNPATH":
                    runpaths = parse_ld_paths(
                        t.runpath,  # type: ignore[attr-defined]
                        path=str(path),
                        root=root,
                        keep_missing=search is not None and search.strict,
                    )
                elif t.entry.d_tag == "DT_NEEDED":
                    needed.append(t.needed)  # type: ignore[attr-defined]
            if runpaths:
                # If both RPATH and RUNPATH are set, only the latter is used.
                rpaths = []

            # We assume there is only one PT_DYNAMIC.  This is
            # probably fine since the runtime ldso does the same.
            break

        del elf

    if _first:
        # get the libc based on dependencies
        for soname in needed:
            if soname.startswith(("libc.musl-", "ld-musl-")):
                if libc is None:
                    libc = Libc.MUSL
                if libc != Libc.MUSL:
                    msg = f"found a dependency on MUSL but the libc is already set to {libc}"
                    raise InvalidLibcError(msg)
            elif soname == "libc.so.6" or soname.startswith(("ld-linux-", "ld64.so.")):
                if libc is None:
                    libc = Libc.GLIBC
                if libc != Libc.GLIBC:
                    msg = f"found a dependency on GLIBC but the libc is already set to {libc}"
                    raise InvalidLibcError(msg)
        if libc is None:
            # try the filename as a last resort
            if path.name.endswith(("-arm-linux-musleabihf.so", "-linux-musl.so")):
                libc = Libc.MUSL
            elif path.name.endswith(("-arm-linux-gnueabihf.so", "-linux-gnu.so")):
                # before python 3.11, musl was also using gnu
                soabi = path.stem.split(".")[-1].split("-")
                valid_python = tuple(f"3{minor}" for minor in range(11, 100))
                if soabi[0] == "cpython" and soabi[1].startswith(valid_python):
                    libc = Libc.GLIBC

        if search is None:
            search = SearchPaths.from_dict(load_ld_paths(libc).copy())
        load_conf_for(search, libc)
        # Propagate the rpaths used by the main ELF since those will be
        # used at runtime to locate things.
        search.paths["rpath"] = list(rpaths)
        search.paths["runpath"] = list(runpaths)
        for entry in rpaths:
            search.source_of[("rpath", entry)] = "DT_RPATH"
        for entry in runpaths:
            search.source_of[("runpath", entry)] = "DT_RUNPATH"
        log.debug("  ldpaths[rpath]   = %s", rpaths)
        log.debug("  ldpaths[runpath] = %s", runpaths)

    assert search is not None  # noqa: S101

    # Preserve the linker search order and the provenance of every directory.
    candidates: list[tuple[str, str, str]] = [
        (search.describe("rpath", p), "rpath", p) for p in search.paths.get("rpath", [])
    ]
    candidates.extend((f"DT_RPATH of {path.name}", "rpath", p) for p in rpaths)
    candidates.extend((f"DT_RUNPATH of {path.name}", "runpath", p) for p in runpaths)
    candidates.extend(
        (search.describe("env", p), "env", p) for p in search.paths.get("env", [])
    )
    candidates.extend(
        (search.describe("runpath", p), "runpath", p) for p in search.paths.get("runpath", [])
    )
    candidates.extend(
        (search.describe("conf", p), "conf", p) for p in search.paths.get("conf", [])
    )
    candidates.extend(
        (search.describe("interp", p), "interp", p) for p in search.paths.get("interp", [])
    )
    all_ldpaths = [
        (label, effective)
        for label, kind, dir_ in candidates
        if (effective := search.approved_dir(kind, dir_)) is not None
    ]

    _excluded_libs: set[str] = set()
    for soname in needed:
        if soname in _all_libs:
            continue
        if soname in _excluded_libs:
            continue
        if any(fnmatch(soname, e) for e in exclude):
            log.info("Excluding %s", soname)
            _excluded_libs.add(soname)
            continue

        # special case for libpython, see https://github.com/pypa/auditwheel/issues/589
        # we want to return the dependency to be able to remove it later on but
        # we don't want to analyze it for symbol versions nor do we want to analyze its
        # dependencies as it will be removed.
        if LIBPYTHON_RE.match(soname):
            log.info("Skip %s resolution", soname)
            _all_libs[soname] = DynamicLibrary(soname, None, None)
            continue

        realpath, fullpath, search_dir = find_lib_with_source(
            platform,
            soname,
            [dir_ for _, dir_ in all_ldpaths],
            root,
        )
        search_source = next(
            (label for label, dir_ in all_ldpaths if dir_ == search_dir),
            None,
        )
        if realpath is not None and any(fnmatch(str(realpath), e) for e in exclude):
            log.info("Excluding %s", realpath)
            _excluded_libs.add(soname)
            continue
        _all_libs[soname] = DynamicLibrary(
            soname,
            fullpath,
            realpath,
            search_source=search_source,
            search_dir=search_dir,
        )
        if realpath is None or fullpath is None:
            if search.strict:
                log.warning(
                    "%s (needed by %s) was not found in the approved search paths",
                    soname,
                    path.name,
                )
                search.record_missing(soname, str(path))
            continue
        dependency = ldd(realpath, root, prefix, search, fullpath, exclude, _all_libs)
        _all_libs[soname] = DynamicLibrary(
            soname,
            fullpath,
            realpath,
            dependency.platform,
            dependency.needed,
            search_source,
            search_dir,
        )

    if _first and search.strict and search.missing:
        raise search.missing_error()

    return DynamicExecutable(
        interpreter,
        libc,
        str(path) if display is None else display,
        path,
        platform,
        tuple(soname for soname in needed if soname not in _excluded_libs),
        tuple(rpaths),
        tuple(runpaths),
        _all_libs,
        search.all_display_paths(),
    )
