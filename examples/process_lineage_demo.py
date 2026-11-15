"""Build a small synthetic ETL and reconstruct evidence-based process lineage.

The trace deliberately contains the situations an investigator must handle:

* a normal parent/child creation;
* a rundown (``DCStart``) process that already existed before logging began;
* PID recycling (the same PID reused by a different ``UniqueProcessKey``);
* a missing end event;
* a child whose parent has no event in the trace;
* a child referencing a parent that already terminated.

Run it with ``python examples/process_lineage_demo.py`` from the repository root.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

# Allow the demo to import the in-repo test ETL factory without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dissect.etl.etl import ETL
from dissect.etl.lineage import build_process_lineage
from tests._etl_factory import DCSTART, END, START, RawProcessEvent, build_etl


def build_demo_events() -> list[RawProcessEvent]:
    return [
        # Rundown: services.exe (PID 500) was already running when the trace began.
        RawProcessEvent(DCSTART, 500, 400, 0x1111, "services.exe", 100),
        # Normal parent/child creation.
        RawProcessEvent(START, 600, 500, 0x2222, "cmd.exe", 200),
        # The first cmd.exe terminates; its end event is present.
        RawProcessEvent(END, 600, 500, 0x2222, "cmd.exe", 300),
        # PID 600 is recycled by a brand new process (different UniqueProcessKey).
        RawProcessEvent(START, 600, 500, 0x3333, "cmd.exe", 400),
        # This child's parent (PID 999) never appears in the trace.
        RawProcessEvent(START, 700, 999, 0x4444, "unknown_parent.exe", 500),
        # A short-lived parent terminates, then a child claims its PID afterwards.
        RawProcessEvent(START, 800, 500, 0x5555, "shortlived.exe", 600),
        RawProcessEvent(END, 800, 500, 0x5555, "shortlived.exe", 700),
        RawProcessEvent(START, 801, 800, 0x6666, "late_child.exe", 800),
        # cmd.exe (PID 600, key 0x3333) has no end event before the trace stops.
    ]


def main() -> None:
    etl_bytes = build_etl(build_demo_events())
    lineage = build_process_lineage(ETL(io.BytesIO(etl_bytes)))
    print(lineage.render_text())


if __name__ == "__main__":
    main()
