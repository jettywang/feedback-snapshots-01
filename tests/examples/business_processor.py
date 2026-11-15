"""Demonstration of typed CLFS record consumption.

This example models two consumers of :meth:`Container.log_records`:

1. An investigator report that explains *why* each byte range is recovery information, client data
   or unclassified evidence, including the raw type bits and LSN relationships.
2. A simulated business transaction processor that may only apply client data records. Restart
   records describe recovery state (never an application commit) and unknown type combinations are
   quarantined, so neither ever reaches the business handler.

Run it against the bundled sample container with:

    .venv/bin/python tests/examples/business_processor.py
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from dissect.clfs.container import Container
from dissect.clfs.records import RecordCategory

SAMPLE_CONTAINER = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "DRIVERS{53b39e70-18c4-11ea-a811-000d3aa4692b}.TMContainer00000000000000000001.regtrans-ms"
)


class BusinessTransaction(NamedTuple):
    """A minimal stand-in for an application-level transaction reconstructed from client data."""

    lsn: int
    payload: bytes


class BusinessTransactionProcessor:
    """Only complete client data records may become simulated business transactions."""

    def __init__(self) -> None:
        self.transactions: list[BusinessTransaction] = []
        self.quarantined: list[tuple[str, int, str]] = []

    def consume(self, record: object) -> None:
        category = record.category

        if category is RecordCategory.DATA and record.complete:
            self.transactions.append(BusinessTransaction(lsn=record.lsn_virtual.value, payload=record.payload))
            return

        if category is RecordCategory.RESTART:
            reason = "recovery state only; restart records do not assert an application commit"
        elif category is RecordCategory.UNKNOWN:
            reason = "undefined/contradictory record type bits; preserved as evidence, not parsed"
        elif category is RecordCategory.NULL:
            reason = "null padding record"
        else:
            reason = "incomplete record held back pending missing associated record"

        self.quarantined.append((category.value, record.raw_type, reason))


def explain_category(record: object) -> str:
    """Return a human readable justification for why a record got its category."""
    info = record.type_info
    if record.category is RecordCategory.DATA:
        return (
            f"type {info.raw_type:#04x} sets the ClfsDataRecord bit "
            f"(structural flags: {', '.join(info.flags) or 'none'}) -> client data"
        )
    if record.category is RecordCategory.RESTART:
        return (
            f"type {info.raw_type:#04x} sets the ClfsRestartRecord bit and no data bit -> "
            "client recovery state, not application data"
        )
    if record.category is RecordCategory.NULL:
        return f"type {info.raw_type:#04x} is ClfsNullRecord -> unused block padding"
    if info.has_contradictory_category:
        return f"type {info.raw_type:#04x} sets both data and restart bits -> no defined meaning"
    if info.has_undefined_bits:
        return f"type {info.raw_type:#04x} contains bits outside the documented 0x3F mask -> unknown"
    return f"type {info.raw_type:#04x} has no data/restart kind bit -> unknown"


def main() -> None:
    with SAMPLE_CONTAINER.open("rb") as fh:
        records = list(Container(fh=fh, offset=36864).log_records())

    print("=== Investigation report ===")
    for record in records:
        if record.category is RecordCategory.NULL:
            continue
        print(
            f"offset={record.offset:#08x} category={record.category.value:<7} "
            f"virtual_lsn={record.lsn_virtual.value:#018x} "
            f"previous_lsn={record.lsn_previous.value:#018x} payload={len(record.payload)} bytes"
        )
        print(f"    {explain_category(record)}")
        if not record.complete:
            print(f"    incomplete: {record.incomplete_reason}")

    processor = BusinessTransactionProcessor()
    for record in records:
        processor.consume(record)

    print("\n=== Simulated business transaction processor ===")
    print(f"applied data transactions: {len(processor.transactions)}")
    print(f"quarantined records: {len(processor.quarantined)}")
    for category, raw_type, reason in processor.quarantined:
        print(f"  - {category} (type {raw_type:#04x}): {reason}")

    applied_categories = {transaction.lsn for transaction in processor.transactions}
    assert all(
        record.category is RecordCategory.DATA
        for record in records
        if record.lsn_virtual.value in applied_categories
    )
    print("\nNo restart or unknown record entered the business transaction processor.")


if __name__ == "__main__":
    main()
