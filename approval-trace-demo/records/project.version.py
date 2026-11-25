from __future__ import annotations

import hashlib
import json
import os
import sys
import time

path = __file__
try:
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
except OSError:
    digest = None
log_path = os.environ.get("PROBE_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "record": "project-code",
            "event": "version-code-import",
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "time_ns": time.time_ns(),
            "argv": sys.argv,
            "file": path,
            "sha256": digest,
        }, sort_keys=True) + "\n")

__version__ = "9.8.7"
