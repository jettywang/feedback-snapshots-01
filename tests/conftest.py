from __future__ import annotations

import pytest

import dissect.etl.etl as etl_module
from dissect.etl.c_etl import c_etl


@pytest.fixture(autouse=True)
def restore_c_etl() -> None:
    """Some tests replace the module-level cstruct; keep the real one for the next test."""
    yield
    etl_module.c_etl = c_etl
