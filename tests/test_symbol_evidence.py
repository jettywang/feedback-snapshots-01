from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.clfs.blf import BLF, BaseRecord, SymbolState
from dissect.clfs.c_clfs import c_clfs

if TYPE_CHECKING:
    from typing import BinaryIO

SECTOR_SIZE = 512
TOTAL_SECTORS = 40
RECORD_OFFSET = 112

SYMBOL_BASE = 0x1600
SYMBOL_STEP = 0x30
NAME_BASE = 0x3000
NAME_STEP = 0x40
CONTEXT_BASE = 0x2000
CONTEXT_STEP = 0x100
SYMBOL_ZONE = 0x1500


def _write_struct(data: bytearray, relative_offset: int, value: object) -> None:
    raw = value.dumps()
    start = RECORD_OFFSET + relative_offset
    data[start : start + len(raw)] = raw


def _build_block(
    symbols: list[dict],
    client_slots: list[int] | None = None,
    container_slots: list[int] | None = None,
    security_slots: list[int] | None = None,
) -> bytes:
    data = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    record = c_clfs.CLFS_BASE_RECORD_HEADER()
    record.RecordHeader.DumpCount = 1
    record.ClientSymbolTable = [0] * 11
    record.ContainerSymbolTable = [0] * 11
    record.SecuritySymbolTable = [0] * 11
    record.SymbolZone = SYMBOL_ZONE
    record.Clients = 1
    for index, offset in enumerate(client_slots or []):
        record.ClientSymbolTable[index] = offset
    for index, offset in enumerate(container_slots or []):
        record.ContainerSymbolTable[index] = offset
    for index, offset in enumerate(security_slots or []):
        record.SecuritySymbolTable[index] = offset
    _write_struct(data, 0, record)

    symbol_offset = SYMBOL_BASE
    name_offset = NAME_BASE
    context_offset = CONTEXT_BASE

    for index, item in enumerate(symbols):
        item["symbol_offset"] = symbol_offset
        item["name_offset"] = name_offset
        item["context_offset"] = context_offset

        symbol = c_clfs.CLFS_HASH_SYM()
        symbol.NodeId.Type = c_clfs.CLFS_NODE_TYPE.SYMBOL
        symbol.NodeId.Node = index + 1
        symbol.Below = item.get("below", 0)
        symbol.Above = item.get("above", 0)
        symbol.SymbolName = name_offset
        symbol.Offset = context_offset
        symbol.Deleted = item.get("deleted", 0)
        _write_struct(data, symbol_offset, symbol)

        name = item["name"].encode("utf-16-le") + b"\x00\x00"
        start = RECORD_OFFSET + name_offset
        data[start : start + len(name)] = name

        context_type = item.get("context_type", "client")
        if context_type == "client":
            context = c_clfs.CLFS_CLIENT_CONTEXT()
            context.NodeId.Type = c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT
            context.NodeId.Node = item.get("node_id", index + 1)
            context.ClientId = item.get("client_id", index)
            context.FileAttributes = c_clfs.FILE_ATTRIBUTES.HIDDEN | c_clfs.FILE_ATTRIBUTES.TEMPORARY
            context.LsnPhysicalBase.Offset.RecordIndex = 0x1234
        elif context_type == "container":
            context = c_clfs.CLFS_CONTAINER_CONTEXT()
            context.NodeId.Type = c_clfs.CLFS_NODE_TYPE.CONTAINER_CONTEXT
            context.NodeId.Node = item.get("node_id", index + 1)
            context.Container = 0x80000
            context.ContainerId = item.get("client_id", index)
        else:
            context = c_clfs.CLFS_SHARED_SECURITY_CONTEXT()
            context.NodeId.Type = c_clfs.CLFS_NODE_TYPE.SHARED_SECURITY_CONTEXT
            context.NodeId.Node = item.get("node_id", index + 1)
        _write_struct(data, context_offset, context)

        symbol_offset += SYMBOL_STEP
        name_offset += NAME_STEP
        context_offset += CONTEXT_STEP

    header = c_clfs.CLFS_LOG_BLOCK_HEADER()
    header.MajorVersion = 0x15
    header.Fixup = 1
    header.TotalSectors = TOTAL_SECTORS
    header.ValidSectors = TOTAL_SECTORS
    header.Flags = c_clfs.CLFS_LOG_BLOCK_FLAGS.ENCODED
    header.RecordOffsets[0] = RECORD_OFFSET
    header.FixupOffset = 0x3F8
    header_raw = header.dumps()
    data[: len(header_raw)] = header_raw

    return bytes(data)


def _slot(index: int) -> int:
    return SYMBOL_BASE + index * SYMBOL_STEP


def _record(data: bytes) -> BaseRecord:
    return BaseRecord(BytesIO(data), 0, int(c_clfs.CLFS_METADATA_BLOCK_TYPE.ClfsMetaBlockGeneral))


def _by_name(evidence: object, name: str) -> object:
    matches = [record for record in evidence if record.name == name]
    assert len(matches) == 1
    return matches[0]


def test_active_deleted_residual_conflict_are_separated() -> None:
    active = {"name": "active-client"}
    deleted = {"name": "deleted-client", "deleted": 1}
    conflict = {"name": "conflict-client", "deleted": 1}
    residual = {"name": "residual-client"}
    symbols = [active, deleted, conflict, residual]

    data = _build_block(
        symbols,
        client_slots=[_slot(0), _slot(2)],
    )
    base_record = _record(data)
    evidence = base_record.symbol_evidence

    assert [stream.name for stream in base_record.streams] == ["active-client"]
    assert [stream.name for stream in evidence.active_streams] == ["active-client"]

    assert [record.name for record in evidence.reachable()] == ["active-client", "conflict-client"]
    assert sorted(record.name for record in evidence.deleted()) == ["conflict-client", "deleted-client"]
    assert [record.name for record in evidence.deleted_only()] == ["deleted-client"]
    assert sorted(record.name for record in evidence.flagged_deleted()) == ["conflict-client", "deleted-client"]
    assert [record.name for record in evidence.residual()] == ["residual-client"]
    assert [record.name for record in evidence.conflicting()] == ["conflict-client"]

    assert _by_name(evidence, "active-client").state is SymbolState.ACTIVE
    assert _by_name(evidence, "deleted-client").deleted is True
    assert _by_name(evidence, "deleted-client").reachable is False
    assert _by_name(evidence, "residual-client").deleted is False
    assert _by_name(evidence, "residual-client").reachable is False
    assert "deleted_but_referenced" in _by_name(evidence, "conflict-client").problems
    assert [item.kind for item in evidence.conflicts] == ["deleted_but_referenced"]


def test_reference_basis_keeps_index_and_hash_tree_edges() -> None:
    root = {"name": "tree-root", "below": _slot(1), "above": _slot(2)}
    below_child = {"name": "below-child"}
    above_child = {"name": "above-child"}
    symbols = [root, below_child, above_child]

    data = _build_block(symbols, client_slots=[_slot(0)])
    evidence = _record(data).symbol_evidence

    root_record = _by_name(evidence, "tree-root")
    below_record = _by_name(evidence, "below-child")
    above_record = _by_name(evidence, "above-child")

    assert root_record.state is SymbolState.ACTIVE
    assert below_record.state is SymbolState.ACTIVE
    assert above_record.state is SymbolState.ACTIVE
    assert root_record.references[0].kind == "index"
    assert root_record.references[0].index == 0
    assert below_record.references == (
        type(below_record.references[0])(
            kind="below",
            symbol_offset=_slot(1),
            raw=_slot(1),
            table="client",
            from_offset=_slot(0),
        ),
    )
    assert above_record.references == (
        type(above_record.references[0])(
            kind="above",
            symbol_offset=_slot(2),
            raw=_slot(2),
            table="client",
            from_offset=_slot(0),
        ),
    )
    assert [stream.name for stream in _record(data).streams] == ["tree-root", "below-child", "above-child"]


def test_duplicate_names_and_same_name_across_types_do_not_merge() -> None:
    client = {"name": "shared-name", "context_type": "client"}
    container = {"name": "shared-name", "context_type": "container"}
    duplicate_a = {"name": "duplicate-client"}
    duplicate_b = {"name": "duplicate-client"}
    symbols = [client, container, duplicate_a, duplicate_b]

    data = _build_block(
        symbols,
        client_slots=[_slot(0), _slot(2), _slot(3)],
        container_slots=[_slot(1)],
    )
    base_record = _record(data)
    evidence = base_record.symbol_evidence

    assert sorted(stream.name for stream in base_record.streams) == [
        "duplicate-client",
        "duplicate-client",
        "shared-name",
    ]
    assert [item.name for item in base_record.containers] == ["shared-name"]
    assert any("multiple context tables" in issue for issue in evidence.issues)
    assert any("duplicate client symbol name" in issue for issue in evidence.issues)
    client_records = [record for record in evidence if record.table == "client"]
    container_records = [record for record in evidence if record.table == "container"]
    assert _by_name(client_records, "shared-name").state is SymbolState.ACTIVE
    assert _by_name(container_records, "shared-name").state is SymbolState.ACTIVE


def test_shared_context_is_reported_not_reassociated_by_name() -> None:
    first = {"name": "first-name"}
    second = {"name": "second-name"}
    symbols = [first, second]
    # Point both symbols at the same context record.
    second["context_type"] = "client"

    data = _build_block(symbols, client_slots=[_slot(0), _slot(1)])
    # Rewrite the second symbol to point at the first context.
    data_view = bytearray(data)
    second_symbol = c_clfs.CLFS_HASH_SYM(data_view[RECORD_OFFSET + SYMBOL_BASE + SYMBOL_STEP :][:40])
    first_context = CONTEXT_BASE
    second_symbol.Offset = first_context
    _write_struct(data_view, SYMBOL_BASE + SYMBOL_STEP, second_symbol)

    base_record = _record(bytes(data_view))
    evidence = base_record.symbol_evidence

    assert base_record.streams == []
    assert [item.kind for item in evidence.conflicts] == ["shared_context"]
    assert [record.state for record in evidence] == [SymbolState.CONFLICT, SymbolState.CONFLICT]
    assert {record.context_offset for record in evidence} == {first_context}


def test_corrupt_entry_does_not_empty_whole_table() -> None:
    active = {"name": "still-active"}
    other = {"name": "unused"}
    symbols = [active, other]
    data = bytearray(_build_block(symbols, client_slots=[_slot(0)]))

    # Add a second index slot that points at a symbol with an invalid node type.
    record = c_clfs.CLFS_BASE_RECORD_HEADER(data[RECORD_OFFSET : RECORD_OFFSET + 4917])
    bad_symbol_offset = 0x2500
    bad_symbol = c_clfs.CLFS_HASH_SYM()
    bad_symbol.NodeId.Type = c_clfs.CLFS_NODE_TYPE.CLIENT_CONTEXT
    bad_symbol.SymbolName = NAME_BASE
    bad_symbol.Offset = CONTEXT_BASE
    _write_struct(data, bad_symbol_offset, bad_symbol)
    record.ClientSymbolTable[1] = bad_symbol_offset
    _write_struct(data, 0, record)

    base_record = _record(bytes(data))
    evidence = base_record.symbol_evidence

    assert [stream.name for stream in base_record.streams] == ["still-active"]
    states = {record.symbol_offset: record.state for record in evidence}
    assert states[bad_symbol_offset] is SymbolState.CONFLICT
    assert _by_name(evidence, "still-active").state is SymbolState.ACTIVE


def test_unterminated_name_is_conflict_not_empty_table() -> None:
    active = {"name": "good"}
    broken = {"name": "broken"}
    symbols = [active, broken]
    data = bytearray(_build_block(symbols, client_slots=[_slot(0), _slot(1)]))

    # Remove every NUL-protected sector boundary as well, so the name truly runs to the end of the block.
    data[0x3F8 : 0x3F8 + 2 * TOTAL_SECTORS] = b"\x41\x00" * TOTAL_SECTORS
    start = RECORD_OFFSET + NAME_BASE + NAME_STEP
    data[start:] = b"\x41\x00" * ((len(data) - start) // 2)

    base_record = _record(bytes(data))
    evidence = base_record.symbol_evidence

    assert [stream.name for stream in base_record.streams] == ["good"]
    broken_record = next(record for record in evidence if record.symbol_offset == SYMBOL_BASE + SYMBOL_STEP)
    assert broken_record.state is SymbolState.CONFLICT
    assert "unterminated_name" in broken_record.problems


def test_duplicate_index_reference_is_conflict() -> None:
    active = {"name": "duplicated-index"}
    symbols = [active]
    data = _build_block(symbols, client_slots=[_slot(0), _slot(0)])

    base_record = _record(data)
    evidence = base_record.symbol_evidence

    assert base_record.streams == []
    assert [record.state for record in evidence] == [SymbolState.CONFLICT]
    assert "duplicate_index_reference" in evidence.records[0].problems
    assert [item.kind for item in evidence.conflicts] == ["duplicate_index_reference"]


def test_context_type_mismatch_is_not_active() -> None:
    wrong_type = {"name": "wrong-type", "context_type": "container"}
    symbols = [wrong_type]
    data = _build_block(symbols, client_slots=[_slot(0)])

    base_record = _record(data)
    evidence = base_record.symbol_evidence

    assert base_record.streams == []
    assert base_record.containers == []
    assert evidence.records[0].state is SymbolState.CONFLICT
    assert [item.kind for item in evidence.conflicts] == ["context_type_mismatch"]


def test_active_sample_filters_residual_contexts(dummy_blf: BinaryIO) -> None:
    blf = BLF(dummy_blf)
    base_records = list(blf.base_records())

    assert len(base_records) == 2
    for base_record in base_records:
        evidence = base_record.symbol_evidence
        assert len(evidence) == 3
        assert all(record.state is SymbolState.ACTIVE for record in evidence)
        assert len(base_record.streams) == 1
        assert len(base_record.containers) == 2
        assert evidence.conflicts == ()
