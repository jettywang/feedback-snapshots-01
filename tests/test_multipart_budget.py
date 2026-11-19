"""Tests for the request-wide multipart resource budget."""

import asyncio
import base64
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.base_protocol import BaseProtocol
from aiohttp.multipart import (
    MultipartBudget,
    MultipartLimitExceeded,
    MultipartLimitKind,
    MultipartReader,
)
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_request
from aiohttp.web_exceptions import HTTPRequestEntityTooLarge

CONTENT_TYPE = "multipart/form-data; boundary=b"


@pytest.fixture
def protocol() -> BaseProtocol:
    return mock.Mock(_reading_paused=False)


def make_stream(protocol: BaseProtocol, body: bytes) -> StreamReader:
    payload = StreamReader(protocol, 2**16, loop=asyncio.get_running_loop())
    payload.feed_data(body)
    payload.feed_eof()
    return payload


def form_part(name: bytes, value: bytes, filename: bytes | None = None) -> bytes:
    disposition = b'Content-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        disposition += b'; filename="' + filename + b'"'
    return b"--b\r\n" + disposition + b"\r\n\r\n" + value + b"\r\n"


def form_body(parts: list[bytes]) -> bytes:
    return b"".join(parts) + b"--b--\r\n"


class TestMultipartBudgetUnit:
    def test_limits_disabled_by_default(self) -> None:
        budget = MultipartBudget()
        for _ in range(100):
            budget.add_field()
            budget.add_file()
        budget.check_bytes(10**12)
        assert budget.fields == 100
        assert budget.files == 100
        assert budget.bytes == 0

    @pytest.mark.parametrize("disabled", (0, -1))
    def test_zero_and_negative_disable_limits(self, disabled: int) -> None:
        budget = MultipartBudget(
            max_fields=disabled, max_files=disabled, max_bytes=disabled
        )
        budget.add_field()
        budget.add_file()
        budget.check_bytes(1)

    def test_field_limit(self) -> None:
        budget = MultipartBudget(max_fields=2)
        budget.add_field()
        budget.add_field()
        with pytest.raises(MultipartLimitExceeded) as exc:
            budget.add_field()
        assert exc.value.limit_kind is MultipartLimitKind.FIELDS
        assert exc.value.limit == 2
        assert exc.value.observed == 3

    def test_file_limit(self) -> None:
        budget = MultipartBudget(max_files=1)
        budget.add_file()
        with pytest.raises(MultipartLimitExceeded) as exc:
            budget.add_file()
        assert exc.value.limit_kind is MultipartLimitKind.FILES
        assert exc.value.limit == 1
        assert exc.value.observed == 2

    def test_byte_limit_explicit_value(self) -> None:
        budget = MultipartBudget(max_bytes=10)
        budget.check_bytes(10)
        with pytest.raises(MultipartLimitExceeded) as exc:
            budget.check_bytes(11)
        assert exc.value.limit_kind is MultipartLimitKind.BYTES
        assert exc.value.limit == 10
        assert exc.value.observed == 11

    async def test_byte_limit_from_bound_stream(self, protocol: BaseProtocol) -> None:
        payload = StreamReader(protocol, 2**16, loop=asyncio.get_running_loop())
        budget = MultipartBudget(max_bytes=4)
        budget.bind(payload)
        assert budget.bytes == 0
        payload.feed_data(b"12345")
        assert budget.bytes == 5
        with pytest.raises(MultipartLimitExceeded) as exc:
            budget.check_bytes()
        assert exc.value.observed == 5

    def test_error_cls_carries_identifying_attributes(self) -> None:
        budget = MultipartBudget(max_files=1, error_cls=HTTPRequestEntityTooLarge)
        budget.add_file()
        with pytest.raises(HTTPRequestEntityTooLarge) as exc:
            budget.add_file()
        assert exc.value.status_code == 413
        assert exc.value.limit_kind is MultipartLimitKind.FILES
        assert exc.value.limit == 1
        assert exc.value.observed == 2

    def test_error_cls_without_text_kwarg(self) -> None:
        class PlainError(Exception):
            pass

        budget = MultipartBudget(max_fields=1, error_cls=PlainError)
        budget.add_field()
        with pytest.raises(PlainError) as exc:
            budget.add_field()
        assert exc.value.limit_kind is MultipartLimitKind.FIELDS


class TestReaderBudget:
    async def test_budget_shared_between_parts(self, protocol: BaseProtocol) -> None:
        body = form_body([form_part(b"a", b"x"), form_part(b"b", b"yy")])
        payload = make_stream(protocol, body)
        reader = MultipartReader(
            {"Content-Type": CONTENT_TYPE},
            payload,
            budget=MultipartBudget(max_bytes=len(body) - 1),
        )
        with pytest.raises(MultipartLimitExceeded) as exc:
            while (part := await reader.next()) is not None:
                await part.read()
        assert exc.value.limit_kind is MultipartLimitKind.BYTES
        # The budget instance is the one the caller supplied.
        assert reader.budget.bytes == payload.total_bytes

    async def test_byte_budget_counts_framing_not_decoded(
        self, protocol: BaseProtocol
    ) -> None:
        encoded = base64.b64encode(b"A" * 32)
        body = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="f"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n" + encoded + b"\r\n--b--\r\n"
        )
        # The decoded content is 32 bytes but the wire body is larger; a
        # 33-byte budget must still reject based on received wire bytes.
        payload = make_stream(protocol, body)
        reader = MultipartReader(
            {"Content-Type": CONTENT_TYPE},
            payload,
            budget=MultipartBudget(max_bytes=33),
        )
        with pytest.raises(MultipartLimitExceeded):
            while (part := await reader.next()) is not None:
                await part.read()

    async def test_many_short_parts_share_one_counter(
        self, protocol: BaseProtocol
    ) -> None:
        parts = [form_part(f"f{i}".encode(), b"v") for i in range(20)]
        body = form_body(parts)
        payload = make_stream(protocol, body)
        reader = MultipartReader(
            {"Content-Type": CONTENT_TYPE},
            payload,
            budget=MultipartBudget(max_bytes=len(body) // 2),
        )
        with pytest.raises(MultipartLimitExceeded):
            while (part := await reader.next()) is not None:
                await part.release()

    async def test_default_budget_uses_client_max_size(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body([form_part(b"f", b"x" * 100)])
        payload = make_stream(protocol, body)
        reader = MultipartReader(
            {"Content-Type": CONTENT_TYPE},
            payload,
            client_max_size=10,
            max_size_error_cls=HTTPRequestEntityTooLarge,
        )
        with pytest.raises(HTTPRequestEntityTooLarge) as exc:
            while (part := await reader.next()) is not None:
                await part.read()
        assert exc.value.limit_kind is MultipartLimitKind.BYTES

    async def test_budget_does_not_restart_per_part(
        self, protocol: BaseProtocol
    ) -> None:
        # The same budget object is handed to every part reader, so each
        # part's checks draw from one cumulative counter rather than a
        # per-part one.
        parts = [form_part(f"f{i}".encode(), b"x" * 10) for i in range(5)]
        body = form_body(parts)
        payload = make_stream(protocol, body)
        budget = MultipartBudget(max_bytes=len(body))
        reader = MultipartReader(
            {"Content-Type": CONTENT_TYPE}, payload, budget=budget
        )
        seen_budgets: list[MultipartBudget] = []
        while (part := await reader.next()) is not None:
            seen_budgets.append(part._budget)
            await part.release()
        assert len(seen_budgets) == 5
        assert all(thing is budget for thing in seen_budgets)

    async def test_cumulative_counter_never_resets(self) -> None:
        budget = MultipartBudget(max_bytes=100)
        # Simulate successive parts each reporting their own growing offset;
        # a per-part reset would let the third call through.
        budget.check_bytes(40)
        budget.check_bytes(80)
        with pytest.raises(MultipartLimitExceeded) as exc:
            budget.check_bytes(120)
        assert exc.value.observed == 120


class TestRequestPostBudget:
    async def test_file_budget_rejected(self, protocol: BaseProtocol) -> None:
        body = form_body(
            [
                form_part(b"f1", b"a", filename=b"a.bin"),
                form_part(b"f2", b"b", filename=b"b.bin"),
            ]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_files=1,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.status_code == 413
        assert exc.value.limit_kind is MultipartLimitKind.FILES
        assert exc.value.limit == 1
        assert exc.value.observed == 2

    async def test_field_and_file_budgets_are_independent(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body(
            [
                form_part(b"text1", b"a"),
                form_part(b"text2", b"b"),
                form_part(b"file1", b"c", filename=b"c.bin"),
            ]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_fields=1,
            client_max_files=5,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.FIELDS

    async def test_empty_file_is_present_not_missing(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body([form_part(b"up", b"", filename=b"empty.bin")])
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_files=1,
        )
        result = await req.post()
        field = result["up"]
        assert isinstance(field, web.FileField)
        assert field.file.read() == b""
        req._finish()

    async def test_empty_file_counts_against_file_budget(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body(
            [
                form_part(b"f1", b"", filename=b"a.bin"),
                form_part(b"f2", b"", filename=b"b.bin"),
            ]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_files=1,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.FILES

    async def test_empty_text_field_counts_as_field(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body([form_part(b"f1", b""), form_part(b"f2", b"")])
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_fields=1,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.FIELDS
        assert exc.value.observed == 2

    async def test_byte_budget_cumulative_across_parts(
        self, protocol: BaseProtocol
    ) -> None:
        parts = [form_part(f"f{i}".encode(), b"x" * 100) for i in range(10)]
        body = form_body(parts)
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_size=200,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.BYTES
        assert exc.value.observed > 200

    async def test_oversize_rejection_closes_temp_files(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body(
            [
                form_part(b"ok", b"fine", filename=b"ok.bin"),
                form_part(b"next", b"more", filename=b"next.bin"),
            ]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            # The first file is fully spooled before the file budget rejects
            # the second one, exercising cleanup of an existing temp file.
            client_max_files=1,
        )
        created: list[mock.Mock] = []

        def factory(max_size: int) -> mock.Mock:
            tmp = mock.Mock()
            tmp.tell.return_value = 0
            created.append(tmp)
            return tmp

        with mock.patch(
            "aiohttp.web_request.SpooledTemporaryFile", side_effect=factory
        ):
            with pytest.raises(web.HTTPRequestEntityTooLarge):
                await req.post()
        assert len(created) == 1
        created[0].close.assert_called_once()

    async def test_mid_read_error_closes_temp_files(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body([form_part(b"f", b"abc", filename=b"x.bin")])
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
        )
        tmp = mock.Mock()
        tmp.tell.return_value = 0
        tmp.write.side_effect = OSError("disk full")
        with mock.patch(
            "aiohttp.web_request.SpooledTemporaryFile", return_value=tmp
        ):
            with pytest.raises(OSError):
                await req.post()
        tmp.close.assert_called_once()

    async def test_cancellation_closes_temp_files(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body([form_part(b"f", b"abc", filename=b"x.bin")])
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
        )
        tmp = mock.Mock()
        tmp.tell.return_value = 0
        tmp.write.side_effect = asyncio.CancelledError()
        with mock.patch(
            "aiohttp.web_request.SpooledTemporaryFile", return_value=tmp
        ):
            with pytest.raises(asyncio.CancelledError):
                await req.post()
        tmp.close.assert_called_once()

    async def test_normal_upload_bytes_unchanged(
        self, protocol: BaseProtocol
    ) -> None:
        text_value = "héllo".encode()
        body = form_body(
            [
                form_part(b"text", text_value),
                form_part(b"file", b"\x00\x01binary", filename=b"x.bin"),
            ]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
        )
        result = await req.post()
        assert result["text"] == text_value.decode()
        file_field = result["file"]
        assert isinstance(file_field, web.FileField)
        assert file_field.file.read() == b"\x00\x01binary"
        req._finish()

    async def test_large_part_mid_read_overflow_uses_real_spool(
        self, protocol: BaseProtocol
    ) -> None:
        # A single oversized file part never reaches a boundary; the
        # mid-read check must reject it and close the rolled-over spool.
        big = b"z" * (64 * 1024)
        body = form_body([form_part(b"big", big, filename=b"big.bin")])
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_size=128,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.BYTES

    async def test_base64_part_budget_counts_wire_bytes(
        self, protocol: BaseProtocol
    ) -> None:
        encoded = base64.b64encode(b"A" * 4096)
        body = (
            b"--b\r\n"
            b'Content-Disposition: form-data; name="f"; filename="x.bin"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n" + encoded + b"\r\n--b--\r\n"
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            # Larger than the decoded content but smaller than the wire body.
            client_max_size=4096,
        )
        with pytest.raises(web.HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.BYTES
        assert exc.value.observed == req._payload.total_bytes

    async def test_middleware_can_identify_limit_kind(
        self, protocol: BaseProtocol
    ) -> None:
        # Middleware catches HTTPRequestEntityTooLarge and branches on the
        # budget attributes; assert the full identification contract here.
        body = form_body(
            [
                form_part(b"f1", b"a", filename=b"a.bin"),
                form_part(b"f2", b"b", filename=b"b.bin"),
            ]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_files=1,
        )
        with pytest.raises(HTTPRequestEntityTooLarge) as exc:
            await req.post()
        assert exc.value.limit_kind is MultipartLimitKind.FILES
        assert exc.value.limit == 1
        assert exc.value.observed == 2
        assert exc.value.status_code == 413

    async def test_disabled_file_limit_accepts_many_files(
        self, protocol: BaseProtocol
    ) -> None:
        body = form_body(
            [form_part(f"f{i}".encode(), b"x", filename=f"{i}.bin".encode())
             for i in range(5)]
        )
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=make_stream(protocol, body),
            client_max_files=0,
            client_max_fields=0,
        )
        result = await req.post()
        assert len(result) == 5
        req._finish()

    async def test_normal_upload_raw_stream_bytes_unchanged(
        self, protocol: BaseProtocol
    ) -> None:
        # A successful parse must not alter how many bytes the stream reports
        # as received; the budget only observes the counter.
        body = form_body([form_part(b"text", b"value")])
        payload = make_stream(protocol, body)
        req = make_mocked_request(
            "POST",
            "/",
            headers={"Content-Type": CONTENT_TYPE},
            payload=payload,
        )
        await req.post()
        assert payload.total_bytes == len(body)
