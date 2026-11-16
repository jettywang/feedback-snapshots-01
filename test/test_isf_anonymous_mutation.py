# Volatility 3 tests
#
# Directed graph mutation tests for anonymous structure/union expansion in the
# Intermediate Symbol Format (ISF). Each case starts from a small ISF document
# that successfully instantiates an object, then mutates exactly one graph
# feature (anonymous struct/union, member offset or type reference). The outer
# JSON envelope always stays schema-valid so every input really passes template
# parsing and object reading instead of being rejected up front.
#
# The cases distinguish two fundamentally different graphs:
#   * a pointer self-reference is a legal edge that must terminate and read;
#   * an anonymous by-value nesting that revisits an expanding type is an
#     illegal infinite expansion that must be rejected with a bounded error.
#
# Every visible flattened member is recorded individually with its origin and
# accumulated offset. Field name conflicts must surface as errors rather than
# being silently dropped by dictionary overwrite.

import copy
import json
import os
import struct
import tempfile

import pytest

from volatility3.framework import constants, contexts, exceptions
from volatility3.framework.layers import physical
from volatility3.framework.symbols import intermed

# Keep the recursion limit low enough that a missing expansion guard fails the
# test quickly instead of hanging on an effectively unbounded recursion.
MUTATION_RECURSION_LIMIT = 250

LAYER_NAME = "memory"
TABLE_NAME = "mutations"
MEMORY_SIZE = 256


#
# ISF graph construction helpers
#


def base_type(name):
    return {"kind": "base", "name": name}


def pointer_to(subtype):
    return {"kind": "pointer", "base": "pointer", "subtype": subtype}


def reference_to(name, kind="struct"):
    return {"kind": kind, "name": name}


def array_of(subtype, count):
    return {"kind": "array", "count": count, "subtype": subtype}


def bitfield_of(base, position, length):
    return {
        "kind": "bitfield",
        "bit_position": position,
        "bit_length": length,
        "type": base,
    }


def field(type_descriptor, offset, anonymous=False):
    descriptor = {"type": type_descriptor, "offset": offset}
    if anonymous:
        descriptor["anonymous"] = True
    return descriptor


BASE_TYPES = {
    "void": {"kind": "void", "size": 0, "signed": False, "endian": "little"},
    "char": {"kind": "char", "size": 1, "signed": True, "endian": "little"},
    "int": {"kind": "int", "size": 4, "signed": True, "endian": "little"},
    "long": {"kind": "int", "size": 8, "signed": True, "endian": "little"},
    "pointer": {"kind": "void", "size": 8, "signed": False, "endian": "little"},
}


def isf_document(user_types, fmt="6.2.0"):
    metadata = {"format": fmt}
    # Schema 6.3.0 makes the producer mandatory.
    if tuple(int(part) for part in fmt.split(".")) >= (6, 3, 0):
        metadata["producer"] = {"name": "mutation-tests", "version": "0.0.0"}
    return {
        "metadata": metadata,
        "base_types": BASE_TYPES,
        "user_types": user_types,
        "symbols": {},
        "enums": {},
    }


def baseline_user_types():
    """A legal graph mixing ordinary members, nested anonymous structs and a
    nested anonymous union. All flattened leaves have unique names so the same
    document also acts as the seed for every mutation below."""
    return {
        "leaf_struct": {
            "kind": "struct",
            "size": 8,
            "fields": {
                "leaf_a": field(base_type("int"), 0),
                "leaf_b": field(base_type("int"), 4),
            },
        },
        "leaf_union": {
            "kind": "union",
            "size": 8,
            "fields": {
                "union_u32": field(base_type("int"), 0),
                "union_u64": field(base_type("long"), 0),
            },
        },
        "middle": {
            "kind": "struct",
            "size": 24,
            "fields": {
                "middle_marker": field(base_type("int"), 0),
                "nested_struct": field(reference_to("leaf_struct"), 8, anonymous=True),
                "nested_union": field(reference_to("leaf_union"), 16, anonymous=True),
            },
        },
        "root": {
            "kind": "struct",
            "size": 40,
            "fields": {
                "root_head": field(base_type("int"), 0),
                "root_ptr": field(pointer_to(base_type("char")), 8),
                "middle_anon": field(reference_to("middle"), 16, anonymous=True),
                "root_tail": field(base_type("int"), 32),
            },
        },
    }


#
# Loading and observation helpers
#


class MutableBufferLayer(physical.BufferDataLayer):
    """A BufferDataLayer backed by a mutable bytearray so write() updates the
    same bytes subsequent reads return."""

    def __init__(self, context, config_path, name, buffer):
        super().__init__(context, config_path, name, buffer)
        self._buffer = bytearray(buffer)

    def write(self, address, data):
        self._buffer[address : address + len(data)] = data


class LoadedGraph:
    """A parsed ISF together with a writable in-memory layer."""

    def __init__(self, user_types, fmt="6.2.0", validate=True):
        self.context = contexts.Context()
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as handle:
            json.dump(isf_document(user_types, fmt=fmt), handle)
        self.url = pathlib_url(path)
        self.table = intermed.IntermediateSymbolTable(
            context=self.context,
            config_path="temporary.symbols." + TABLE_NAME,
            name=TABLE_NAME,
            isf_url=self.url,
            validate=validate,
        )
        self.context.symbol_space.append(self.table)
        self.buffer = bytearray(MEMORY_SIZE)
        self.context.add_layer(
            MutableBufferLayer(
                context=self.context,
                config_path="temporary.layers." + LAYER_NAME,
                name=LAYER_NAME,
                buffer=bytes(self.buffer),
            )
        )

    def template(self, type_name):
        return self.table.get_type(type_name)

    def object(self, type_name, offset=0):
        return self.context.object(
            TABLE_NAME + constants.BANG + type_name, LAYER_NAME, offset
        )

    def write_u32(self, offset, value):
        self.context.layers[LAYER_NAME].write(offset, struct.pack("<I", value))

    def write_u64(self, offset, value):
        self.context.layers[LAYER_NAME].write(offset, struct.pack("<Q", value))


def pathlib_url(path):
    from pathlib import Path

    return Path(path).as_uri()


def flattened_members(template):
    """Return member name -> (offset, type name) for independent inspection."""
    return {
        name: (offset, member_template.vol.type_name)
        for name, (offset, member_template) in template.vol.members.items()
    }


def load_graph(user_types, fmt="6.2.0", validate=True):
    return LoadedGraph(user_types, fmt=fmt, validate=validate)


def mutate(seed, mutation):
    """Deep-copy the seed graph before applying a single directed mutation."""
    user_types = copy.deepcopy(seed)
    mutation(user_types)
    return user_types


#
# Baseline: legal anonymous flattening and offset accumulation
#


def test_baseline_graph_loads_and_flattens_all_leaves():
    graph = load_graph(baseline_user_types())
    template = graph.template("root")
    members = flattened_members(template)

    # Every leaf of every anonymous struct/union is visible on the root.
    expected = {
        "root_head": (0, "int"),
        "root_ptr": (8, "pointer"),
        "middle_marker": (16, "int"),
        "leaf_a": (24, "int"),
        "leaf_b": (28, "int"),
        "union_u32": (32, "int"),
        "union_u64": (32, "long"),
        "root_tail": (32, "int"),
    }
    assert set(members) == set(expected)
    for name, (offset, kind) in expected.items():
        assert members[name][0] == offset, name
        assert members[name][1].endswith(kind), name

    # The anonymous containers themselves must not survive as visible members.
    assert "middle_anon" not in members
    assert "nested_struct" not in members
    assert "nested_union" not in members


def test_baseline_member_offsets_match_actual_reads():
    graph = load_graph(baseline_user_types())
    root = graph.object("root")

    pattern = {
        "root_head": (0, 0x11111111),
        "middle_marker": (16, 0x22222222),
        "leaf_a": (24, 0x33333333),
        "leaf_b": (28, 0x44444444),
        "union_u32": (32, 0x55555555),
        "root_tail": (32, 0x55555555),
    }
    for offset, value in {(off, val) for off, val in pattern.values()}:
        graph.write_u32(offset, value)

    root = graph.object("root")
    for name, (_, value) in pattern.items():
        assert (
            root.member(name) == struct.unpack("<i", struct.pack("<I", value))[0]
        ), name

    # Overwrite the shared union slot and read through a fresh object because
    # aggregate objects cache the concrete members they have already handed out.
    graph.write_u64(32, 0x6666666677777777)
    union_root = graph.object("root")
    assert (
        union_root.union_u64
        == struct.unpack("<q", struct.pack("<Q", 0x6666666677777777))[0]
    )
    # The 32-bit view reads only the low word of the shared backing bytes.
    assert (
        union_root.union_u32
        == struct.unpack("<i", struct.pack("<I", 0x6666666677777777 & 0xFFFFFFFF))[0]
    )
    assert (
        union_root.union_u32
        == struct.unpack("<i", struct.pack("<Q", 0x6666666677777777)[:4])[0]
    )


def test_baseline_offsets_accumulate_parent_chain():
    graph = load_graph(baseline_user_types())
    members = flattened_members(graph.template("root"))
    # leaf_a sits at root+16 (middle) + 8 (leaf_struct) + 0
    assert members["leaf_a"][0] == 16 + 8
    assert members["leaf_b"][0] == 16 + 8 + 4


#
# Legal self references: pointer edges must terminate
#


def test_pointer_self_reference_is_legal_and_reads():
    user_types = {
        "node": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "value": field(base_type("int"), 0),
                "next": field(pointer_to(reference_to("node")), 8),
            },
        }
    }
    graph = load_graph(user_types)
    members = flattened_members(graph.template("node"))
    assert set(members) == {"value", "next"}
    assert members["value"] == (0, TABLE_NAME + constants.BANG + "int")
    assert members["next"][0] == 8
    assert members["next"][1] == TABLE_NAME + constants.BANG + "pointer"

    graph.write_u32(0, 0x0BADF00D & 0xFFFFFFFF)
    graph.write_u64(8, 0x40)
    node = graph.object("node")
    assert node.value == struct.unpack("<i", struct.pack("<I", 0x0BADF00D))[0]
    # The pointer member itself sits at the struct base plus its relative offset;
    # dereferencing follows the stored value and lands on address 0x40.
    assert node.next.vol.offset == 8
    assert node.next.dereference().vol.offset == 0x40
    # Following the pointer yields another object of the same recursive type.
    assert node.next.dereference().vol.type_name == TABLE_NAME + "!node"


def test_pointer_mutual_reference_between_two_types_terminates():
    user_types = {
        "a": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "a_id": field(base_type("int"), 0),
                "to_b": field(pointer_to(reference_to("b")), 8),
            },
        },
        "b": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "b_id": field(base_type("int"), 0),
                "to_a": field(pointer_to(reference_to("a")), 8),
            },
        },
    }
    graph = load_graph(user_types)
    assert set(flattened_members(graph.template("a"))) == {"a_id", "to_b"}
    assert set(flattened_members(graph.template("b"))) == {"b_id", "to_a"}
    graph.write_u64(8, 0x20)
    # vol.offset is absolute: object base 0 plus the member's relative offset 8;
    # the stored pointer value is read when the pointer is dereferenced.
    assert graph.object("a").to_b.vol.offset == 8
    assert graph.object("a", offset=0x10).to_b.vol.offset == 0x18


def test_pointer_chain_of_anonymous_containers_stays_bounded():
    # A legal, deeply nested but finite anonymous nesting chain whose deepest
    # member is a self pointer: expansion must reach the leaves without error.
    depth = 24
    user_types = {}
    for level in range(depth + 1):
        child = f"level_{level + 1}"
        if level == depth:
            fields = {
                "deep_value": field(base_type("int"), 0),
                "deep_self": field(pointer_to(reference_to("level_0")), 8),
            }
        else:
            fields = {
                f"marker_{level}": field(base_type("int"), 0),
                f"child_{level}": field(reference_to(child), 8, anonymous=True),
            }
        user_types[f"level_{level}"] = {
            "kind": "struct",
            "size": 16,
            "fields": fields,
        }
    graph = load_graph(user_types)
    members = flattened_members(graph.template("level_0"))
    assert "deep_value" in members
    assert "deep_self" in members
    # level_0's child sits at 8; each of the depth anonymous hops adds another 8.
    assert members["deep_value"][0] == 8 * depth
    assert members["deep_self"][0] == 8 * depth + 8
    # Every intermediate marker is preserved as an independently sourced member.
    for level in range(depth):
        assert f"marker_{level}" in members
        assert members[f"marker_{level}"][0] == 8 * level


#
# Illegal graphs: anonymous by-value infinite expansion
#


def test_anonymous_by_value_self_cycle_is_rejected_bounded():
    user_types = {
        "loop": {
            "kind": "struct",
            "size": 8,
            "fields": {"myself": field(reference_to("loop"), 0, anonymous=True)},
        }
    }
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError, match="Recursive anonymous"):
        graph.template("loop")


def test_anonymous_mutual_cycle_is_rejected_bounded():
    user_types = {
        "alpha": {
            "kind": "struct",
            "size": 16,
            "fields": {"into_beta": field(reference_to("beta"), 0, anonymous=True)},
        },
        "beta": {
            "kind": "struct",
            "size": 16,
            "fields": {"into_alpha": field(reference_to("alpha"), 0, anonymous=True)},
        },
    }
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError, match="Recursive anonymous"):
        graph.template("alpha")


def test_anonymous_cycle_does_not_recurse_even_under_low_limit():
    # If the cycle guard were removed, this would blow the stack instead of
    # raising the framework's own SymbolSpaceError.
    user_types = {
        "loop": {
            "kind": "struct",
            "size": 8,
            "fields": {"myself": field(reference_to("loop"), 0, anonymous=True)},
        }
    }
    graph = load_graph(user_types)
    previous_limit = __import__("sys").getrecursionlimit()
    __import__("sys").setrecursionlimit(MUTATION_RECURSION_LIMIT)
    try:
        with pytest.raises(exceptions.SymbolSpaceError):
            graph.template("loop")
    finally:
        __import__("sys").setrecursionlimit(previous_limit)


def test_mutation_pointer_self_reference_into_anonymous_cycle_is_caught():
    # Directed mutation of the legal linked list: flip the self pointer to an
    # anonymous by-value reference. The legal case must flip into rejection.
    user_types = {
        "node": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "value": field(base_type("int"), 0),
                "next": field(reference_to("node"), 8, anonymous=True),
            },
        }
    }
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError):
        graph.template("node")


def test_unknown_anonymous_target_raises_symbol_error_not_keyerror():
    user_types = {
        "root": {
            "kind": "struct",
            "size": 8,
            "fields": {
                "ghost": field(reference_to("does_not_exist"), 0, anonymous=True)
            },
        }
    }
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError, match="unknown type"):
        graph.template("root")


#
# Field conflicts must not be silently overwritten
#


def test_flattened_name_collision_raises_instead_of_overwriting():
    user_types = {
        "inner": {
            "kind": "struct",
            "size": 4,
            "fields": {"dup": field(base_type("int"), 0)},
        },
        "outer": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "dup": field(base_type("int"), 0),
                "anon": field(reference_to("inner"), 8, anonymous=True),
            },
        },
    }
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError, match="Conflicting field name"):
        graph.template("outer")


def test_collision_between_two_anonymous_siblings_is_reported():
    user_types = {
        "one": {
            "kind": "struct",
            "size": 4,
            "fields": {"shared": field(base_type("int"), 0)},
        },
        "two": {
            "kind": "struct",
            "size": 4,
            "fields": {"shared": field(base_type("int"), 0)},
        },
        "outer": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "first": field(reference_to("one"), 0, anonymous=True),
                "second": field(reference_to("two"), 8, anonymous=True),
            },
        },
    }
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError, match="Conflicting field name"):
        graph.template("outer")


def test_legal_non_conflicting_fields_remain_all_visible():
    # Guard against an over-eager conflict check: distinct names survive.
    seed = baseline_user_types()
    graph = load_graph(seed)
    members = flattened_members(graph.template("root"))
    assert len(members) == 8
    # Every member name is unique and independently addressable.
    offsets = [offset for offset, _ in members.values()]
    names = list(members)
    assert len(names) == len(set(names))
    assert offsets.count(32) == 3  # union leaves + root_tail legitimately share it


#
# Offset mutations: parent accumulation must stay exact
#


def test_offset_mutation_propagates_through_anonymous_parent():
    seed = baseline_user_types()

    def shift(types):
        types["middle"]["fields"]["nested_struct"]["offset"] = 4

    user_types = mutate(seed, shift)
    graph = load_graph(user_types)
    members = flattened_members(graph.template("root"))
    # leaf offsets move with their anonymous parent's offset.
    assert members["leaf_a"][0] == 16 + 4
    assert members["leaf_b"][0] == 16 + 4 + 4
    assert members["union_u32"][0] == 32


def test_negative_member_offset_is_honoured_not_dropped():
    user_types = {
        "inner": {
            "kind": "struct",
            "size": 8,
            "fields": {
                "back": field(base_type("int"), -4),
                "forward": field(base_type("int"), 0),
            },
        },
        "outer": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "anon": field(reference_to("inner"), 8, anonymous=True),
            },
        },
    }
    graph = load_graph(user_types)
    members = flattened_members(graph.template("outer"))
    assert members["back"][0] == 8 - 4
    assert members["forward"][0] == 8


def test_zero_offset_anonymous_union_overlays_correctly():
    user_types = {
        "u": {
            "kind": "union",
            "size": 8,
            "fields": {
                "lo": field(base_type("int"), 0),
                "hi": field(base_type("int"), 4),
            },
        },
        "outer": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "head": field(base_type("int"), 0),
                "anon_union": field(reference_to("u", kind="union"), 4, anonymous=True),
            },
        },
    }
    graph = load_graph(user_types)
    members = flattened_members(graph.template("outer"))
    assert members["lo"][0] == 4
    assert members["hi"][0] == 8
    graph.write_u32(4, 0xAAAAAAAA)
    graph.write_u32(8, 0xBBBBBBBB)
    outer = graph.object("outer")
    assert outer.lo == struct.unpack("<i", struct.pack("<I", 0xAAAAAAAA))[0]
    assert outer.hi == struct.unpack("<i", struct.pack("<I", 0xBBBBBBBB))[0]


#
# Type reference mutations
#


def test_repointing_anonymous_reference_flattens_new_target():
    seed = baseline_user_types()

    def repoint(types):
        # Point the union slot at the leaf struct and drop the struct slot so the
        # flattened graph stays conflict-free, isolating the reference mutation.
        types["middle"]["fields"]["nested_union"]["type"] = reference_to("leaf_struct")
        del types["middle"]["fields"]["nested_struct"]

    user_types = mutate(seed, repoint)
    graph = load_graph(user_types)
    members = flattened_members(graph.template("root"))
    assert "leaf_a" in members and "leaf_b" in members
    assert "union_u32" not in members and "union_u64" not in members


def test_making_ordinary_member_anonymous_inlines_its_leaves():
    seed = baseline_user_types()

    def anonymize(types):
        types["root"]["fields"]["root_ptr"]["anonymous"] = True

    # A pointer cannot be inlined (it has no user_type fields), expect a clean
    # framework error rather than a KeyError or infinite loop.
    user_types = mutate(seed, anonymize)
    graph = load_graph(user_types)
    with pytest.raises(exceptions.SymbolSpaceError):
        graph.template("root")


def test_array_and_bitfield_leaves_inside_anonymous_struct():
    user_types = {
        "inner": {
            "kind": "struct",
            "size": 16,
            "fields": {
                "words": field(array_of(base_type("int"), 2), 0),
                "flag": field(bitfield_of(base_type("int"), 0, 4), 8),
            },
        },
        "outer": {
            "kind": "struct",
            "size": 24,
            "fields": {
                "anon": field(reference_to("inner"), 4, anonymous=True),
            },
        },
    }
    graph = load_graph(user_types)
    members = flattened_members(graph.template("outer"))
    assert members["words"][0] == 4
    assert members["flag"][0] == 12


@pytest.mark.parametrize("fmt", ["6.2.0"])
def test_anonymous_expansion_works_across_supported_formats(fmt):
    # 6.2.0 is the first format carrying the anonymous field-reduction path;
    # later 6.x documents resolve to the same handler.
    graph = load_graph(baseline_user_types(), fmt=fmt)
    members = flattened_members(graph.template("root"))
    assert members["leaf_a"][0] == 24
    assert members["leaf_b"][0] == 28
    # Object reading works end to end on each supported format.
    graph.write_u32(24, 0x01020304)
    root = graph.object("root")
    assert root.leaf_a == struct.unpack("<i", struct.pack("<I", 0x01020304))[0]


#
# Schema envelope integrity: mutated documents still validate as ISF
#


@pytest.mark.parametrize(
    "mutation_name",
    [
        "pointer_self_cycle",
        "mutual_cycle",
        "collision",
        "offset_shift",
        "repoint",
    ],
)
def test_mutated_documents_remain_schema_valid(mutation_name):
    from volatility3 import schemas

    seed = baseline_user_types()

    def pointer_self_cycle(types):
        types["node"] = {
            "kind": "struct",
            "size": 8,
            "fields": {"myself": field(reference_to("node"), 0, anonymous=True)},
        }

    def mutual_cycle(types):
        types["alpha"] = {
            "kind": "struct",
            "size": 8,
            "fields": {"into_beta": field(reference_to("beta"), 0, anonymous=True)},
        }
        types["beta"] = {
            "kind": "struct",
            "size": 8,
            "fields": {"into_alpha": field(reference_to("alpha"), 0, anonymous=True)},
        }

    def collision(types):
        types["inner"] = {
            "kind": "struct",
            "size": 4,
            "fields": {"dup": field(base_type("int"), 0)},
        }
        types["root"]["fields"]["dup"] = field(base_type("int"), 0)
        types["root"]["fields"]["anon"] = field(
            reference_to("inner"), 8, anonymous=True
        )

    def offset_shift(types):
        types["middle"]["fields"]["nested_struct"]["offset"] = 4

    def repoint(types):
        types["middle"]["fields"]["nested_struct"]["type"] = reference_to("leaf_union")

    mutations = {
        "pointer_self_cycle": pointer_self_cycle,
        "mutual_cycle": mutual_cycle,
        "collision": collision,
        "offset_shift": offset_shift,
        "repoint": repoint,
    }
    document = isf_document(mutate(seed, mutations[mutation_name]))
    assert schemas.validate(document, use_cache=False), mutation_name
