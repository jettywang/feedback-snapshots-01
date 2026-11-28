from __future__ import annotations

from colorama import Fore

from tox.execute.stream import SyncWrite
from tox.report import NamedBytesIO
from tox.util.shared_output import SharedOutput


def test_sync_write_repr() -> None:
    sync_write = SyncWrite(name="a", target=None, color=str(Fore.RED))
    assert repr(sync_write) == f"SyncWrite(name='a', target=None, color={Fore.RED!r})"


def test_sync_write_decode_surrogate() -> None:
    sync_write = SyncWrite(name="a", target=None)
    sync_write.handler(b"\xed\n")
    assert sync_write.text == "\udced\n"


def test_sync_write_masks_restricted_value_in_display_and_keeps_record() -> None:
    policy = SharedOutput()
    policy.add("/tmp/build-dir")
    target = NamedBytesIO("out")
    sync_write = SyncWrite("out", target)
    sync_write.shared_output = policy

    with sync_write:
        sync_write.handler(b"at /tmp/build-")
        sync_write.handler(b"dir now\n")

    assert target.getvalue() == b"at <restricted> now\n"
    assert sync_write.text == "at /tmp/build-dir now\n"


def test_sync_write_masks_restricted_value_split_across_chunks_before_newline() -> None:
    policy = SharedOutput()
    policy.add("/tmp/build-dir")
    target = NamedBytesIO("out")
    sync_write = SyncWrite("out", target)
    sync_write.shared_output = policy

    with sync_write:
        sync_write.handler(b"/tmp/build")
        sync_write.handler(b"-dir\n")

    assert target.getvalue() == b"<restricted>\n"
    assert sync_write.text == "/tmp/build-dir\n"


def test_sync_write_does_not_mask_without_restrictions() -> None:
    target = NamedBytesIO("out")
    sync_write = SyncWrite("out", target)

    with sync_write:
        sync_write.handler(b"plain text\n")

    assert target.getvalue() == b"plain text\n"
