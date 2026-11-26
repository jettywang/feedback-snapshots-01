from __future__ import annotations

import json
import os
from datetime import datetime, timezone


def _record_import() -> None:
    log_path = os.environ.get("APPROVAL_RUNTIME_LOG")
    if not log_path:
        return
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "event": "package_import",
            "package": "hookpkg",
            "when": datetime.now(timezone.utc).isoformat(),
        }) + "\n")


_record_import()
VALUE = "hookpkg-build-script"
