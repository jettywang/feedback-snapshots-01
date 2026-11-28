"""Generative regressions for the ELF dependency analyzer (:func:`lddtree.ldd`).

These tests build small, valid ELF shared objects from in-memory metadata (no
compiler and no execution of the analyzed code, only ``pyelftools`` parsing) and
check that :func:`auditwheel.lddtree.ldd` reconstructs the *exact* dependency
graph that was generated.

The point is to protect two properties that a real wheel repair depends on:

* the located edges must not depend on the temporary directory a wheel is
  unpacked into, nor on the order in which the members were written;
* two graphs that contain the same number of nodes are only equivalent when
  they share the same edges -- a stand-in that merely counts libraries (or
  matches node names) must not be accepted.

A stable seed keeps the generated cases reproducible, and
``test_minimal_missing_edge_failure_example`` is a hand-written, independently
runnable minimal case whose assertion report names the single approved edge
that a node-counting substitute would drop.
"""

from __future__ import annotations

import os
import random
import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from auditwheel.lddtree import ldd

# A fixed seed so generated cases are reproducible across machines and runs.
# It can be overridden through the environment when debugging a failure:
#   AUDITWHEEL_GEN_SEED=12345 pytest tests/unit/test_lddtree_generative.py
DEFAULT_SEED = 20261129

# ELF constants needed to emit a minimal, well-formed ET_DYN object.
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_EV_CURRENT = 1
_ET_DYN = 3
_EM_X86_64 = 62
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PF_R = 4
_PF_W = 2
_PF_X = 1
_SHT_NULL = 0
_SHT_STRTAB = 3
_SHT_DYNAMIC = 6
_SHF_ALLOC = 2
_SHF_WRITE = 1
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_STRSZ = 10
_DT_SONAME = 14
_DT_RUNPATH = 29
_ELF_MIN_ALIGN = 8

# An edge is a (dependent, dependency) pair of sonames.
Edge = tuple[str, str]
# A dependency graph maps each soname to the ordered sonames it DT_NEEDEDs.
Graph = dict[str, list[str]]


def build_elf(
    needed: tuple[str, ...] = (),
    *,
    soname: str | None = None,
    runpath: str | None = None,
) -> bytes:
    """Build a minimal 64-bit little-endian x86_64 ELF shared object.

    The emitted object contains a ``PT_LOAD`` and a ``PT_DYNAMIC`` segment plus
    the matching ``.dynamic``/``.dynstr`` sections that ``pyelftools`` uses to
    resolve dynamic strings.  Only metadata is produced; the file is never
    loaded or executed.
    """

    dynstr = bytearray(b"\x00")
    string_offsets: dict[str, int] = {}

    def intern(value: str) -> int:
        if value not in string_offsets:
            string_offsets[value] = len(dynstr)
            dynstr.extend(value.encode("utf-8"))
            dynstr.append(0)
        return string_offsets[value]

    dynamic: list[tuple[int, int]] = [(dt, intern(name)) for dt, name in
                                      ((_DT_NEEDED, n) for n in needed)]
    if soname is not None:
        dynamic.append((_DT_SONAME, intern(soname)))
    if runpath is not None:
        dynamic.append((_DT_RUNPATH, intern(runpath)))
    # DT_STRTAB is patched with the virtual address once the layout is known.
    dynamic.append((_DT_STRTAB, 0))
    dynamic.append((_DT_STRSZ, len(dynstr)))
    dynamic.append((_DT_NULL, 0))
    dynamic_bytes = b"".join(struct.pack("<QQ", tag, value) for tag, value in dynamic)

    section_names = ("", ".dynstr", ".dynamic", ".shstrtab")
    shstrtab = bytearray()
    section_name_offsets: dict[str, int] = {}
    for name in section_names:
        section_name_offsets[name] = len(shstrtab)
        shstrtab.extend(name.encode("utf-8"))
        shstrtab.append(0)

    ehsize = 64
    phentsize = 56
    phnum = 2
    shentsize = 64
    shnum = 4
    phoff = ehsize
    section_header_table_offset = ehsize + phentsize * phnum

    dynstr_offset = section_header_table_offset
    dynamic_offset = dynstr_offset + len(dynstr)
    shstrtab_offset = dynamic_offset + len(dynamic_bytes)
    section_header_offset = shstrtab_offset + len(shstrtab)
    # The single PT_LOAD is identity mapped, so virtual address == file offset.
    dynstr_vaddr = dynstr_offset
    dynamic_vaddr = dynamic_offset
    file_size = section_header_offset + shentsize * shnum

    patched_dynamic = dynamic_bytes.replace(
        struct.pack("<QQ", _DT_STRTAB, 0),
        struct.pack("<QQ", _DT_STRTAB, dynstr_vaddr),
        1,
    )

    e_ident = (
        b"\x7fELF"
        + bytes((_ELFCLASS64, _ELFDATA2LSB, _EV_CURRENT, 0))
        + b"\x00" * 8
    )
    elf_header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        _ET_DYN,
        _EM_X86_64,
        _EV_CURRENT,
        0,  # e_entry
        phoff,
        section_header_offset,
        0,  # e_flags
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        3,  # e_shstrndx -> .shstrtab
    )

    load_segment = struct.pack(
        "<IIQQQQQQ",
        _PT_LOAD,
        _PF_R | _PF_X,
        0,
        0,
        0,
        file_size,
        file_size,
        _ELF_MIN_ALIGN,
    )
    dynamic_segment = struct.pack(
        "<IIQQQQQQ",
        _PT_DYNAMIC,
        _PF_R | _PF_W,
        dynamic_offset,
        dynamic_vaddr,
        dynamic_offset,
        len(patched_dynamic),
        len(patched_dynamic),
        _ELF_MIN_ALIGN,
    )

    null_section = b"\x00" * shentsize
    dynstr_section = struct.pack(
        "<IIQQQQIIQQ",
        section_name_offsets[".dynstr"],
        _SHT_STRTAB,
        _SHF_ALLOC,
        dynstr_vaddr,
        dynstr_offset,
        len(dynstr),
        0,
        0,
        1,
        0,
    )
    # sh_link points at the .dynstr section (index 1) used to decode tags.
    dynamic_section = struct.pack(
        "<IIQQQQIIQQ",
        section_name_offsets[".dynamic"],
        _SHT_DYNAMIC,
        _SHF_ALLOC | _SHF_WRITE,
        dynamic_vaddr,
        dynamic_offset,
        len(patched_dynamic),
        1,
        0,
        _ELF_MIN_ALIGN,
        0,
    )
    shstrtab_section = struct.pack(
        "<IIQQQQIIQQ",
        section_name_offsets[".shstrtab"],
        _SHT_STRTAB,
        0,
        0,
        shstrtab_offset,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )

    return b"".join(
        (
            elf_header,
            load_segment,
            dynamic_segment,
            bytes(dynstr),
            patched_dynamic,
            bytes(shstrtab),
            null_section,
            dynstr_section,
            dynamic_section,
            shstrtab_section,
        )
    )


@dataclass(frozen=True)
class GeneratedCase:
    """A generated dependency graph plus where its members were written."""

    graph: Graph
    directory: Path
    root_node: str


def generate_dag(rng: random.Random, node_count: int) -> Graph:
    """Generate a small, connected acyclic dependency graph.

    Nodes are numbered ``libN.so`` with edges only from lower to higher indices,
    which guarantees acyclicity.  A backbone chain keeps every node reachable
    from the root; extra forward edges are then added at random so that the
    generated graph is richer than a plain chain.
    """

    names = [f"lib{index}.so" for index in range(node_count)]
    graph: Graph = {name: [] for name in names}

    # Backbone chain so the root transitively reaches every node.
    for dependent, dependency in zip(names, names[1:]):
        graph[dependent].append(dependency)

    # Random additional forward edges, never duplicating the backbone edges.
    for i, dependent in enumerate(names):
        for dependency in names[i + 2 :]:
            if rng.random() < 0.4:
                graph[dependent].append(dependency)
    return graph


def write_case(graph: Graph, directory: Path, *, order: list[str] | None = None) -> GeneratedCase:
    """Write one ELF per graph node into ``directory`` and return the case."""

    members = list(graph) if order is None else order
    for soname in members:
        elf_path = directory / soname
        elf_path.write_bytes(build_elf(tuple(graph[soname]), soname=soname))
    root_node = next(iter(graph))
    return GeneratedCase(graph=graph, directory=directory, root_node=root_node)


def analyze_edges(case: GeneratedCase) -> set[Edge]:
    """Run the real analyzer on a case and return its reconstructed edge set."""

    ldpaths = {
        "conf": [str(case.directory)],
        "env": [],
        "interp": [],
        "rpath": [],
        "runpath": [],
    }
    result = ldd(case.directory / case.root_node, ldpaths=ldpaths)

    edges: set[Edge] = set()
    for soname, library in result.libraries.items():
        if library.realpath is None:
            # Every node is provided in the case, so an unresolved node means
            # the analyzer failed to locate an approved dependency.
            continue
        for dependency in library.needed:
            edges.add((soname, dependency))
    # The root's direct DT_NEEDED edges are reported on the executable itself.
    for dependency in result.needed:
        edges.add((case.root_node, dependency))
    return edges


def expected_edges(graph: Graph) -> set[Edge]:
    """Flatten a generated graph into its approved edge set."""

    return {(dependent, dependency) for dependent, deps in graph.items()
            for dependency in deps}


def format_edge_table(edges: set[Edge]) -> str:
    """Render an edge set as a stable dependency table for failure reports."""

    lines = ["dependent -> dependency"]
    lines.extend(f"{dependent} -> {dependency}"
                 for dependent, dependency in sorted(edges))
    return "\n".join(lines)


def assert_matches_graph(case: GeneratedCase) -> None:
    """Assert the analyzer reconstructs exactly the approved graph."""

    expected = expected_edges(case.graph)
    observed = analyze_edges(case)
    missing = expected - observed
    extra = observed - expected
    assert not missing, (
        "Analyzer dropped approved edge(s):\n"
        f"{format_edge_table(missing)}"
    )
    assert not extra, (
        "Analyzer invented edge(s) not present in the generated graph:\n"
        f"{format_edge_table(extra)}"
    )
    assert observed == expected


def test_generated_graphs_stable_seed() -> None:
    """The generator itself is deterministic for the fixed seed."""

    seed = int(os.environ.get("AUDITWHEEL_GEN_SEED", DEFAULT_SEED))
    first = [generate_dag(random.Random(seed), n) for n in range(3, 7)]
    second = [generate_dag(random.Random(seed), n) for n in range(3, 7)]
    assert first == second


@pytest.mark.parametrize("node_count", [3, 4, 5, 6])
def test_ldd_reconstructs_generated_graph(tmp_path: Path, node_count: int) -> None:
    """Each approved edge of a generated graph is located accurately."""

    seed = int(os.environ.get("AUDITWHEEL_GEN_SEED", DEFAULT_SEED)) + node_count
    graph = generate_dag(random.Random(seed), node_count)
    case = write_case(graph, tmp_path)
    assert_matches_graph(case)


def test_ldd_independent_of_temp_directory(tmp_path: Path) -> None:
    """Moving the wheel contents to another directory keeps the same edges."""

    seed = int(os.environ.get("AUDITWHEEL_GEN_SEED", DEFAULT_SEED))
    graph = generate_dag(random.Random(seed), 5)

    first_dir = tmp_path / "unpack-a" / "wheel"
    second_dir = tmp_path / "unpack-b" / "wheel"
    first_dir.mkdir(parents=True)
    second_dir.mkdir(parents=True)

    first_edges = analyze_edges(write_case(graph, first_dir))
    second_edges = analyze_edges(write_case(graph, second_dir))

    assert first_edges == second_edges == expected_edges(graph)


def test_ldd_independent_of_member_order(tmp_path: Path) -> None:
    """Writing wheel members in different orders yields the same edges."""

    seed = int(os.environ.get("AUDITWHEEL_GEN_SEED", DEFAULT_SEED))
    graph = generate_dag(random.Random(seed + 99), 6)
    members = list(graph)

    forward_dir = tmp_path / "forward"
    reversed_dir = tmp_path / "reversed"
    forward_dir.mkdir()
    reversed_dir.mkdir()

    forward_edges = analyze_edges(write_case(graph, forward_dir, order=members))
    reversed_edges = analyze_edges(
        write_case(graph, reversed_dir, order=list(reversed(members)))
    )

    assert forward_edges == reversed_edges == expected_edges(graph)


def test_distinguishes_graphs_with_same_node_count(tmp_path: Path) -> None:
    """Same node count but different real references must not compare equal.

    Both graphs have four nodes and three edges, but the middle node points at
    different leaves, so a node-counting or name-only substitute would wrongly
    treat them as equivalent while the edge sets differ.
    """

    # Both graphs share the same four nodes and four edges, and every node stays
    # reachable from the root; only two references are rewired.  A node-counting
    # or name-only substitute would wrongly treat them as equivalent.
    approved: Graph = {
        "app.so": ["core.so", "libx.so"],
        "core.so": ["libx.so"],
        "libx.so": ["liby.so"],
        "liby.so": [],
    }
    substitute: Graph = {
        "app.so": ["core.so", "libx.so"],
        "core.so": ["liby.so"],  # rewired: core now reaches liby, not libx
        "libx.so": ["liby.so"],
        "liby.so": [],
    }

    approved_dir = tmp_path / "approved"
    substitute_dir = tmp_path / "substitute"
    approved_dir.mkdir()
    substitute_dir.mkdir()

    approved_edges = analyze_edges(write_case(approved, approved_dir))
    substitute_edges = analyze_edges(write_case(substitute, substitute_dir))

    assert len(approved) == len(substitute)
    assert len(approved_edges) == len(substitute_edges)
    assert approved_edges != substitute_edges

    dropped = approved_edges - substitute_edges
    assert dropped == {("core.so", "libx.so")}
    added = substitute_edges - approved_edges
    assert added == {("core.so", "liby.so")}


def test_ldd_follows_runpath_into_subdirectory(tmp_path: Path) -> None:
    """A DT_RUNPATH entry lets the analyzer locate a dependency in a subdir."""

    lib_dir = tmp_path / "mylibs"
    lib_dir.mkdir()
    (lib_dir / "helper.so").write_bytes(build_elf((), soname="helper.so"))
    (tmp_path / "app.so").write_bytes(
        build_elf(("helper.so",), soname="app.so", runpath="$ORIGIN/mylibs")
    )

    # No conf/env/interp path contains the library: only DT_RUNPATH can find it.
    ldpaths = {"conf": [], "env": [], "interp": [], "rpath": [], "runpath": []}
    result = ldd(tmp_path / "app.so", ldpaths=ldpaths)

    assert result.libraries["helper.so"].realpath == (lib_dir / "helper.so").resolve()
    assert result.needed == ("helper.so",)


def test_minimal_missing_edge_failure_example(tmp_path: Path) -> None:
    """Independently runnable minimal case naming the single dropped edge.

    Run it on its own with::

        pytest tests/unit/test_lddtree_generative.py\\
            ::test_minimal_missing_edge_failure_example

    A stand-in that only counts nodes would accept ``substitute`` (it has the
    same three nodes), but the edge-table comparison reports exactly which
    approved edge is missing.
    """

    approved: Graph = {
        "app.so": ["core.so"],
        "core.so": ["helper.so"],
        "helper.so": [],
    }
    # Same node set, but the stand-in graph loses the core -> helper edge.
    substitute: Graph = {
        "app.so": ["core.so"],
        "core.so": [],
        "helper.so": [],
    }

    approved_dir = tmp_path / "approved"
    substitute_dir = tmp_path / "substitute"
    approved_dir.mkdir()
    substitute_dir.mkdir()

    approved_edges = analyze_edges(write_case(approved, approved_dir))
    substitute_edges = analyze_edges(write_case(substitute, substitute_dir))

    assert len(approved) == len(substitute)
    missing = approved_edges - substitute_edges
    assert missing == {("core.so", "helper.so")}, (
        "Expected the stand-in to miss exactly one approved edge, got:\n"
        f"{format_edge_table(missing)}"
    )
