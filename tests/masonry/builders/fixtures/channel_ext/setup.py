import os
import sys

from pathlib import Path


def main() -> None:
    platlib = Path(sys.argv[sys.argv.index("--build-platlib") + 1])

    channel = os.environ["CHANNEL"]
    target_dir = platlib / "channel_ext"
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / f"channel_{channel}.py").write_text(
        f"CHANNEL = {channel!r}\n", encoding="utf-8"
    )

    if os.environ.get("FAIL_AFTER_WRITE"):
        sys.exit(1)


if __name__ == "__main__":
    main()
