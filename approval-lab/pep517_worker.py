from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    hook = sys.argv[1]
    project_dir = Path(sys.argv[2]).resolve()
    work_dir = Path(sys.argv[3]).resolve()
    metadata_dir = Path(sys.argv[4]).resolve() if len(sys.argv) > 4 else None

    os.chdir(project_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    from poetry.core.masonry import api

    if hook == "requires":
        result = api.get_requires_for_build_wheel({})
    elif hook == "metadata":
        result = api.prepare_metadata_for_build_wheel(str(work_dir), {})
    elif hook == "metadata_editable":
        result = api.prepare_metadata_for_build_editable(str(work_dir), {})
    elif hook == "sdist":
        result = api.build_sdist(str(work_dir), {})
    elif hook == "wheel":
        result = api.build_wheel(
            str(work_dir), {}, metadata_directory=str(metadata_dir) if metadata_dir else None
        )
    elif hook == "editable":
        result = api.build_editable(
            str(work_dir), {}, metadata_directory=str(metadata_dir) if metadata_dir else None
        )
    else:
        raise ValueError(f"unknown hook: {hook}")

    print("APPROVAL_RESULT=" + json.dumps({"result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
