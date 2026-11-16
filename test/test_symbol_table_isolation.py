"""Isolation guarantees when several symbol tables coexist in one context.

A single forensic process may interpret memory images from different kernel
versions at once.  Their Intermediate Symbol Format files routinely define
same-named structures with incompatible layouts.  The framework must keep
each table's templates, native types and class overrides scoped to that
table, while still honouring legitimate cross-table references, native
types and explicit class extensions.
"""

import json
import struct

import pytest

from volatility3.framework import contexts, objects
from volatility3.framework.layers import physical
from volatility3.framework.symbols import intermed, native


def _base_types():
    return {
        "pointer": {
            "endian": "little",
            "kind": "int",
            "signed": False,
            "size": 8,
        },
        "unsigned char": {
            "endian": "little",
            "kind": "int",
            "signed": False,
            "size": 1,
        },
        "unsigned int": {
            "endian": "little",
            "kind": "int",
            "signed": False,
            "size": 4,
        },
        "void": {"endian": "little", "kind": "void", "signed": False, "size": 0},
    }


def _kernel_a():
    # _task { unsigned int pid @0; pointer comm @8 }, 16 bytes
    return {
        "base_types": _base_types(),
        "enums": {},
        "metadata": {
            "format": "6.2.0",
            "producer": {"name": "isolation-test", "version": "1.0.0"},
        },
        "symbols": {
            "init_task": {
                "address": 0x1000,
                "type": {"kind": "struct", "name": "_task"},
            }
        },
        "user_types": {
            "_task": {
                "kind": "struct",
                "size": 16,
                "fields": {
                    "pid": {
                        "offset": 0,
                        "type": {"kind": "base", "name": "unsigned int"},
                    },
                    "comm": {
                        "offset": 8,
                        "type": {
                            "kind": "pointer",
                            "subtype": {"kind": "base", "name": "unsigned char"},
                        },
                    },
                },
            }
        },
    }


def _kernel_b():
    # Same name, incompatible layout:
    # _task { pointer comm @0; unsigned int pid @16; state @20 }, 24 bytes
    return {
        "base_types": _base_types(),
        "enums": {},
        "metadata": {
            "format": "6.2.0",
            "producer": {"name": "isolation-test", "version": "2.0.0"},
        },
        "symbols": {
            "init_task": {
                "address": 0x1000,
                "type": {"kind": "struct", "name": "_task"},
            }
        },
        "user_types": {
            "_task": {
                "kind": "struct",
                "size": 24,
                "fields": {
                    "comm": {
                        "offset": 0,
                        "type": {
                            "kind": "pointer",
                            "subtype": {"kind": "base", "name": "unsigned char"},
                        },
                    },
                    "pid": {
                        "offset": 16,
                        "type": {"kind": "base", "name": "unsigned int"},
                    },
                    "state": {
                        "offset": 20,
                        "type": {"kind": "base", "name": "unsigned int"},
                    },
                },
            }
        },
    }


def _cross_reference_table():
    # Holds a legitimate reference to a foreign table name.
    return {
        "base_types": _base_types(),
        "enums": {},
        "metadata": {
            "format": "6.2.0",
            "producer": {"name": "isolation-test", "version": "1.0.0"},
        },
        "symbols": {},
        "user_types": {
            "_holder": {
                "kind": "struct",
                "size": 8,
                "fields": {
                    "task": {
                        "offset": 0,
                        "type": {
                            "kind": "pointer",
                            "subtype": {
                                "kind": "struct",
                                "name": "nt_symbols!_task",
                            },
                        },
                    }
                },
            }
        },
    }


def _write_isf(tmp_path, filename, isf):
    path = tmp_path / filename
    with path.open("w") as handle:
        json.dump(isf, handle)
    return path.as_uri()


def _load(context, tmp_path, table_name, filename, isf, **kwargs):
    url = _write_isf(tmp_path, filename, isf)
    table = intermed.IntermediateSymbolTable(
        context=context,
        config_path="temporary/" + table_name,
        name=table_name,
        isf_url=url,
        **kwargs,
    )
    context.symbol_space.append(table)
    return table


@pytest.fixture
def two_kernel_context(tmp_path):
    context = contexts.Context()
    # Interleaved loading: A first, then B, sharing one symbol space.
    _load(context, tmp_path, "ka", "kernel_a.json", _kernel_a())
    _load(context, tmp_path, "kb", "kernel_b.json", _kernel_b())
    return context


def test_same_named_types_keep_their_own_layout(two_kernel_context):
    context = two_kernel_context
    template_a = context.symbol_space.get_type("ka!_task")
    template_b = context.symbol_space.get_type("kb!_task")

    assert template_a.size == 16
    assert template_b.size == 24
    assert template_a.relative_child_offset("pid") == 0
    assert template_a.relative_child_offset("comm") == 8
    assert template_b.relative_child_offset("comm") == 0
    assert template_b.relative_child_offset("pid") == 16
    assert template_b.relative_child_offset("state") == 20
    assert not template_a.has_member("state")


def test_same_address_reads_different_structures(two_kernel_context):
    context = two_kernel_context
    # The first qword is B's comm pointer; its low dword is A's pid.
    blob = (
        struct.pack("<Q", 0x10110)
        + struct.pack("<Q", 0x0BEEF)
        + struct.pack("<I", 0x0220)
        + struct.pack("<I", 0x0007)
    )
    # Padding widens the layer's address mask so pointer values survive.
    context.layers.add_layer(
        physical.BufferDataLayer(
            context, "memory", "memory", blob + b"\x00" * 65536
        )
    )

    object_a = context.object("ka!_task", "memory", 0)
    object_b = context.object("kb!_task", "memory", 0)

    assert object_a.vol.size == 16
    assert object_b.vol.size == 24
    assert int(object_a.pid) == 0x10110
    assert int(object_a.comm) == 0x0BEEF
    assert int(object_b.comm) == 0x10110
    assert int(object_b.pid) == 0x0220
    assert int(object_b.state) == 7
    assert not object_a.has_valid_member("state")


def test_reverse_lookup_is_scoped_per_table(two_kernel_context):
    context = two_kernel_context
    matches = list(context.symbol_space.get_symbols_by_location(0x1000))
    assert "ka!init_task" in matches
    assert "kb!init_task" in matches

    assert list(
        context.symbol_space.get_symbols_by_location(0x1000, table_name="ka")
    ) == ["ka!init_task"]
    assert context.symbol_space.has_type("ka!_task")
    assert context.symbol_space.has_type("kb!_task")


def test_native_tables_are_not_shared_state(two_kernel_context):
    context = two_kernel_context
    natives_a = context.symbol_space["ka"].natives
    natives_b = context.symbol_space["kb"].natives

    assert natives_a is not natives_b
    assert natives_a is not native.x64NativeTable
    assert natives_b is not native.x64NativeTable
    assert natives_a.name == "ka_natives"
    assert natives_b.name == "kb_natives"
    # The process-wide templates stay usable and must never be renamed.
    assert native.x64NativeTable.name == "native"
    assert native.x86NativeTable.name == "native"

    pointer_a = context.symbol_space.get_type("ka!pointer")
    pointer_b = context.symbol_space.get_type("kb!pointer")
    assert pointer_a.vol.type_name == "ka!pointer"
    assert pointer_b.vol.type_name == "kb!pointer"
    assert pointer_a.size == pointer_b.size == 8


def test_legacy_isf_gets_an_independent_native_table(tmp_path):
    # Format 2.0.0 readers historically returned the shared module singletons.
    legacy = _kernel_a()
    legacy["metadata"]["format"] = "2.0.0"
    context = contexts.Context()
    table = intermed.IntermediateSymbolTable(
        context=context,
        config_path="temporary/legacy",
        name="legacy",
        isf_url=_write_isf(tmp_path, "legacy.json", legacy),
        validate=False,
    )
    context.symbol_space.append(table)

    assert table.natives is not native.x64NativeTable
    assert table.natives is not native.x86NativeTable
    assert table.natives.name == "legacy_natives"
    assert native.x64NativeTable.name == "native"


def test_reused_native_types_remain_independent_and_renamed(tmp_path):
    # Plugins build secondary tables by reusing a primary table's natives.
    context = contexts.Context()
    primary = _load(context, tmp_path, "ka", "kernel_a.json", _kernel_a())
    secondary = _load(
        context,
        tmp_path,
        "kb",
        "kernel_b.json",
        _kernel_b(),
        native_types=primary.natives,
        table_mapping={"nt_symbols": "ka"},
    )

    assert secondary.natives is not primary.natives
    assert secondary.natives.name == "kb_natives"
    assert primary.natives.name == "ka_natives"
    assert (
        context.symbol_space.get_type("kb!pointer").vol.type_name == "kb!pointer"
    )
    assert (
        context.symbol_space.get_type("ka!pointer").vol.type_name == "ka!pointer"
    )


def test_class_override_is_scoped_and_rebuilds_templates(two_kernel_context):
    context = two_kernel_context

    class KernelATask(objects.StructType):
        pass

    context.symbol_space["ka"].set_type_class("_task", KernelATask)

    template_a = context.symbol_space.get_type("ka!_task")
    template_b = context.symbol_space.get_type("kb!_task")
    assert template_a.vol.object_class is KernelATask
    assert template_b.vol.object_class is objects.StructType
    # The sibling table's cached templates must not have been disturbed.
    assert template_b.size == 24
    assert template_b.relative_child_offset("pid") == 16

    context.symbol_space["ka"].del_type_class("_task")
    assert (
        context.symbol_space.get_type("ka!_task").vol.object_class
        is objects.StructType
    )


def test_existing_objects_keep_their_class_after_a_later_override(
    two_kernel_context,
):
    context = two_kernel_context
    existing = context.symbol_space.get_type("ka!_task")
    original_class = existing.vol.object_class

    class KernelATask(objects.StructType):
        pass

    context.symbol_space["ka"].set_type_class("_task", KernelATask)
    # Already handed-out templates are frozen; only new resolutions change.
    assert existing.vol.object_class is original_class
    assert (
        context.symbol_space.get_type("ka!_task").vol.object_class is KernelATask
    )


def test_nested_struct_references_resolve_after_invalidation(tmp_path):
    isf = {
        "base_types": _base_types(),
        "enums": {},
        "metadata": {
            "format": "6.2.0",
            "producer": {"name": "isolation-test", "version": "1.0.0"},
        },
        "symbols": {},
        "user_types": {
            "_outer": {
                "kind": "struct",
                "size": 16,
                "fields": {
                    "inner": {
                        "offset": 0,
                        "type": {"kind": "struct", "name": "_inner"},
                    }
                },
            },
            "_inner": {
                "kind": "struct",
                "size": 8,
                "fields": {
                    "value": {
                        "offset": 0,
                        "type": {"kind": "base", "name": "unsigned int"},
                    }
                },
            },
        },
    }
    context = contexts.Context()
    table = _load(context, tmp_path, "nest", "nest.json", isf)

    class InnerExtension(objects.StructType):
        pass

    table.set_type_class("_inner", InnerExtension)
    outer = context.symbol_space.get_type("nest!_outer")
    inner = outer.child_template("inner")
    assert isinstance(inner, objects.templates.ObjectTemplate)
    assert inner.vol.object_class is InnerExtension


def test_table_mapping_preserves_cross_table_references(tmp_path):
    context = contexts.Context()
    _load(context, tmp_path, "real_nt", "nt.json", _kernel_a())
    _load(
        context,
        tmp_path,
        "cross",
        "cross.json",
        _cross_reference_table(),
        table_mapping={"nt_symbols": "real_nt"},
    )

    holder = context.symbol_space.get_type("cross!_holder")
    target = holder.child_template("task").vol["subtype"]
    assert target.vol.type_name == "real_nt!_task"
    assert context.symbol_space.get_type(target.vol.type_name).size == 16

    # A second context may map the identical ISF reference elsewhere without
    # touching the first context's interpretation.
    other = contexts.Context()
    _load(other, tmp_path, "nt_symbols", "nt_b.json", _kernel_b())
    _load(other, tmp_path, "cross2", "cross2.json", _cross_reference_table())
    other_holder = other.symbol_space.get_type("cross2!_holder")
    other_target = other_holder.child_template("task").vol["subtype"]
    assert other_target.vol.type_name == "nt_symbols!_task"
    assert other.symbol_space.get_type(other_target.vol.type_name).size == 24

    assert (
        holder.child_template("task").vol["subtype"].vol.type_name
        == "real_nt!_task"
    )
