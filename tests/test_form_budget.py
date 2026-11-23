import io

import pytest

from webob.request import (
    DisconnectionError,
    FormBudget,
    FormBudgetExceeded,
    FormStorageError,
    Request,
)

BODY = b"a=1&b=22"


class TrackedBytesIO(io.BytesIO):
    """Caller-held input stream double with close recording."""

    def __init__(self, data):
        super().__init__(data)
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        super().close()


class UnseekableTrackedStream:
    """Caller-held unseekable input stream double with close recording."""

    def __init__(self, data):
        self._buf = io.BytesIO(data)
        self.close_calls = 0

    def read(self, size=-1):
        return self._buf.read(size)

    def readline(self, size=-1):
        return self._buf.readline(size)

    def close(self):
        self.close_calls += 1


class AccountingTempFile:
    """Temporary-storage double that accounts writes and can fail midway."""

    def __init__(self, fail_after=None):
        self._buf = io.BytesIO()
        self.fail_after = fail_after
        self.written = 0
        self.close_calls = 0

    def write(self, data):
        if self.fail_after is not None:
            room = self.fail_after - self.written

            if room < len(data):
                if room > 0:
                    self._buf.write(data[:room])
                    self.written += room
                raise OSError("storage backend failed mid-write")
        self._buf.write(data)
        self.written += len(data)

        return len(data)

    def read(self, size=-1):
        return self._buf.read(size)

    def seek(self, offset, whence=0):
        return self._buf.seek(offset, whence)

    def tell(self):
        return self._buf.tell()

    def close(self):
        self.close_calls += 1
        self._buf.close()


class TempfileDoubleRequest(Request):
    def __init__(self, environ, tempfile_factory, **kw):
        super().__init__(environ, **kw)
        self.__dict__["_tempfile_factory"] = tempfile_factory

    def make_tempfile(self):
        return self._tempfile_factory()


def make_environ(body, stream=None, seekable=True, query_string="q=1"):
    if stream is None:
        stream = TrackedBytesIO(body)
    environ = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_NAME": "",
        "PATH_INFO": "/",
        "QUERY_STRING": query_string,
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "CONTENT_LENGTH": str(len(body)),
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "wsgi.url_scheme": "http",
        "wsgi.input": stream,
    }

    if seekable:
        environ["webob.is_body_seekable"] = True

    return environ


def test_budget_exactly_spent_admits_and_rereads_consistently():
    stream = TrackedBytesIO(BODY)
    req = Request(make_environ(BODY, stream))
    budget = FormBudget(read_limit=3 + len(BODY))
    req.form_budget = budget

    # middleware peeks at a few bytes before entering form parsing
    assert req.body_file.read(3) == b"a=1"
    assert budget.bytes_read == 3

    vars = req.POST

    # the parse read the whole body again and exactly spent the budget
    assert budget.bytes_read == 3 + len(BODY)
    assert vars["a"] == "1"
    assert vars["b"] == "22"

    # repeated access serves the published result and stays consistent
    assert req.POST is vars
    assert budget.bytes_read == 3 + len(BODY)
    assert list(req.params.items()) == [("q", "1"), ("a", "1"), ("b", "22")]
    assert req.GET["q"] == "1"

    # once admitted, the middleware detaches the budget and the
    # application can re-read the request freely
    req.form_budget = None
    assert req.body == BODY
    assert list(req.POST.items()) == [("a", "1"), ("b", "22")]
    assert stream.close_calls == 0


def test_read_budget_exceeded_publishes_nothing():
    stream = TrackedBytesIO(BODY)
    req = Request(make_environ(BODY, stream))
    budget = FormBudget(read_limit=3 + len(BODY) - 1)
    req.form_budget = budget
    assert req.body_file.read(3) == b"a=1"

    with pytest.raises(FormBudgetExceeded):
        req.POST

    # the reads still happened and are accounted for cumulatively
    assert budget.bytes_read == 3 + len(BODY)
    # no partial result was published to the application
    assert "webob._parsed_post_vars" not in req.environ
    # the GET view is unaffected by the failed form parse
    assert req.GET["q"] == "1"
    # the caller-held stream is not closed by the library
    assert stream.close_calls == 0


def test_storage_backend_error_is_distinct_and_cleans_up():
    stream = UnseekableTrackedStream(BODY)
    temp_file = AccountingTempFile(fail_after=4)
    req = TempfileDoubleRequest(
        make_environ(BODY, stream, seekable=False), lambda: temp_file
    )
    req.request_body_tempfile_limit = 0
    req.form_budget = FormBudget()

    with pytest.raises(FormStorageError) as excinfo:
        req.POST

    assert isinstance(excinfo.value.__cause__, OSError)
    assert not isinstance(excinfo.value, FormBudgetExceeded)
    assert not isinstance(excinfo.value, DisconnectionError)
    # the backend failed partway through the write
    assert temp_file.written == 4
    # the library closed the temporary object it created...
    assert temp_file.close_calls == 1
    # ...but not the caller-held stream
    assert stream.close_calls == 0
    assert "webob._parsed_post_vars" not in req.environ
    assert req.GET["q"] == "1"


def test_storage_budget_exceeded_publishes_nothing():
    stream = UnseekableTrackedStream(BODY)
    temp_file = AccountingTempFile()
    req = TempfileDoubleRequest(
        make_environ(BODY, stream, seekable=False), lambda: temp_file
    )
    req.request_body_tempfile_limit = 0
    req.form_budget = FormBudget(storage_limit=4)

    with pytest.raises(FormBudgetExceeded):
        req.POST

    # nothing reached the backend once the budget was spent
    assert temp_file.written == 0
    assert temp_file.close_calls == 1
    assert stream.close_calls == 0
    assert "webob._parsed_post_vars" not in req.environ
    assert req.GET["q"] == "1"


def test_truncated_input_is_disconnection_not_budget():
    stream = UnseekableTrackedStream(b"a=1&")
    # CONTENT_LENGTH promises 8 bytes but the stream ends after 4
    req = Request(make_environ(BODY, stream, seekable=False))
    req.form_budget = FormBudget(read_limit=100)

    with pytest.raises(DisconnectionError) as excinfo:
        req.POST

    assert not isinstance(excinfo.value, FormBudgetExceeded)
    assert not isinstance(excinfo.value, FormStorageError)
    assert "webob._parsed_post_vars" not in req.environ
    assert stream.close_calls == 0
    assert req.GET["q"] == "1"


def test_admitted_request_rereads_consistently_with_temp_storage():
    stream = UnseekableTrackedStream(BODY)
    temp_file = AccountingTempFile()
    req = TempfileDoubleRequest(
        make_environ(BODY, stream, seekable=False), lambda: temp_file
    )
    req.request_body_tempfile_limit = 0
    budget = FormBudget(read_limit=64, storage_limit=64)
    req.form_budget = budget

    first = req.POST

    # the body was read once to become seekable and once more to parse
    assert budget.bytes_read == 2 * len(BODY)
    assert budget.bytes_stored == len(BODY)

    # the middleware admits the request; the application re-reads it
    req.form_budget = None
    assert list(req.POST.items()) == list(first.items())
    assert list(req.params.items()) == [("q", "1"), ("a", "1"), ("b", "22")]
    assert req.body == BODY
    # the temporary object is now owned by the request, not cleaned up
    assert temp_file.close_calls == 0
    assert stream.close_calls == 0
