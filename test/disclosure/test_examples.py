"""End-to-end evidence check for the disclosure example."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUN = ROOT / "examples" / "disclosure" / "run.py"
VERIFY = ROOT / "examples" / "disclosure" / "verify.py"


def _run(script, *args, home):
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PIP_NO_CACHE_DIR"] = "1"
    return subprocess.run(
        [sys.executable, str(script), *map(str, args)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def isolated_home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    return home


@pytest.mark.parametrize("mode", ["success", "failure"])
def test_example_evidence(tmp_path, isolated_home, mode):
    output = tmp_path / mode

    result = _run(RUN, mode, output, home=isolated_home)
    # Both modes contain findings or abort, so the audit exits non-zero.
    assert result.returncode == 1, (result.stdout, result.stderr)

    verified = _run(VERIFY, mode, output, home=isolated_home)
    assert verified.returncode == 0, verified.stderr

    if mode == "success":
        assert (output / "public.json").exists()
        assert (output / "internal.json").exists()
    else:
        assert not (output / "public.json").exists()
        assert (output / "internal.json").exists()
