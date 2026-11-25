from __future__ import annotations

import json
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import gitlab
from gitlab._backends import RequestsBackend
from gitlab.boundary import NetworkBoundary
from gitlab.exceptions import BoundaryViolation


BASE_URL = "https://gitlab.example/internal/gitlab"
API_URL = f"{BASE_URL}/api/v4"
MIGRATION_ORIGIN = "https://mirror.example"
MIGRATION_BASE = f"{MIGRATION_ORIGIN}/internal/gitlab"
MIGRATION_API = f"{MIGRATION_BASE}/api/v4"
TOKEN = "secret-gitlab-token"


@dataclass
class RecordedCall:
    method: str
    url: str
    headers: dict[str, str]
    auth: Any


class StubResponse:
    def __init__(
        self,
        payload: Any,
        *,
        headers: dict[str, str] | None = None,
        status_code: int = 200,
    ) -> None:
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers or {})
        self.content = json.dumps(payload).encode()
        self.reason = "OK"
        self.history: list[Any] = []
        self.request = SimpleNamespace(headers=CaseInsensitiveDict())
        self.response = self
        self._payload = payload

    def json(self) -> Any:
        return self._payload

    @property
    def links(self) -> dict[str, dict[str, str]]:
        parsed_links = requests.utils.parse_header_links(self.headers.get("Link", ""))
        return {link["rel"]: {"url": link["url"]} for link in parsed_links}


class RecordingAPI(RequestsBackend):
    """A tiny no-network backend which records final request headers."""

    def __init__(self, handler: Any | None = None) -> None:
        super().__init__(session=requests.Session())
        self.handler = handler
        self.calls: list[RecordedCall] = []

    def http_request(self, method: str, url: str, **kwargs: Any) -> StubResponse:
        headers = CaseInsensitiveDict(kwargs.get("headers") or {})
        auth = kwargs.get("auth")
        prepared = requests.PreparedRequest()
        prepared.headers = headers
        if auth is not None:
            auth(prepared)

        request = requests.Request(
            method=method, url=url, params=kwargs.get("params")
        ).prepare()
        call = RecordedCall(
            method=method,
            url=request.url,
            headers=dict(prepared.headers),
            auth=auth,
        )
        self.calls.append(call)
        assert self.handler is not None
        return self.handler(call)


def pagination_headers(page: int, next_url: str | None) -> dict[str, str]:
    headers = {
        "X-Page": str(page),
        "X-Next-Page": str(page + 1) if next_url else "",
        "X-Per-Page": "1",
        "X-Total-Pages": "4" if page < 4 else "3",
    }
    if next_url:
        headers["Link"] = f'<{next_url}>; rel="next"'
    return headers


def page_handler(call: RecordedCall) -> StubResponse:
    parsed = urlparse(call.url)
    query = parse_qs(parsed.query)
    page = int(query.get("page", ["1"])[0])

    if parsed.netloc == "gitlab.example" and parsed.path.endswith("/items"):
        if page < 3:
            next_url = f"{API_URL}/items?per_page=1&page={page + 1}"
            return StubResponse(
                [{"id": f"same-{page}"}],
                headers=pagination_headers(page, next_url),
            )

        migration_url = f"{MIGRATION_API}/items?per_page=1&page=4"
        return StubResponse(
            [{"id": "same-3"}],
            headers=pagination_headers(3, migration_url),
        )

    if parsed.netloc == "mirror.example" and parsed.path.endswith("/items"):
        return StubResponse(
            [{"id": "migrated-4"}],
            headers=pagination_headers(4, None),
        )

    raise AssertionError(f"API stub received an unexpected connection: {call.url}")


def blocked_handler(call: RecordedCall) -> StubResponse:
    parsed = urlparse(call.url)
    page = int(parse_qs(parsed.query).get("page", ["1"])[0])

    if parsed.netloc == "gitlab.example" and parsed.path.endswith("/items"):
        if page < 3:
            next_url = f"{API_URL}/items?per_page=1&page={page + 1}"
        else:
            next_url = "https://outside.example/internal/gitlab/api/v4/items?page=4"
        return StubResponse(
            [{"id": f"same-{page}"}],
            headers=pagination_headers(page, next_url),
        )

    raise AssertionError(f"Boundary should block connection before stub: {call.url}")


def make_client(handler: Any, **kwargs: Any) -> tuple[gitlab.Gitlab, RecordingAPI]:
    gl = gitlab.Gitlab(
        BASE_URL,
        private_token=TOKEN,
        backend=RecordingAPI,
        handler=handler,
        **kwargs,
    )
    backend = gl._backend
    assert isinstance(backend, RecordingAPI)
    return gl, backend


@pytest.mark.parametrize("carry_identity", [False, True])
def test_three_prefix_pages_and_admitted_domain_page(carry_identity: bool) -> None:
    gl, backend = make_client(
        page_handler,
        allowed_migrations=[
            {
                "url": MIGRATION_BASE,
                "carry_gitlab_identity": carry_identity,
            }
        ],
    )

    items = gl.http_list("/items", iterator=True, per_page=1)
    result = list(items)

    assert [item["id"] for item in result] == [
        "same-1",
        "same-2",
        "same-3",
        "migrated-4",
    ]
    assert len(backend.calls) == 4
    assert items.completed_pages == [1, 2, 3, 4]
    assert items.last_completed_page == 4
    assert items.iteration_status == "complete"

    for call in backend.calls[:3]:
        assert urlparse(call.url).netloc == "gitlab.example"
        assert urlparse(call.url).path.startswith("/internal/gitlab/")
        assert call.headers["PRIVATE-TOKEN"] == TOKEN

    migrated_call = backend.calls[3]
    assert urlparse(migrated_call.url).netloc == "mirror.example"
    assert urlparse(migrated_call.url).path.startswith("/internal/gitlab/")
    if carry_identity:
        assert migrated_call.headers["PRIVATE-TOKEN"] == TOKEN
    else:
        assert "PRIVATE-TOKEN" not in migrated_call.headers
        assert "Authorization" not in migrated_call.headers
        assert "JOB-TOKEN" not in migrated_call.headers
        assert "Cookie" not in migrated_call.headers


def test_blocked_domain_keeps_checkpoint_at_last_completed_page() -> None:
    gl, backend = make_client(blocked_handler)
    pages = gl.http_list("/items", iterator=True, per_page=1)

    with pytest.warns(UserWarning, match="base URL"), pytest.raises(
        BoundaryViolation
    ) as exc_info:
        list(pages)

    assert len(backend.calls) == 3
    assert all(urlparse(call.url).netloc == "gitlab.example" for call in backend.calls)
    assert all(call.headers["PRIVATE-TOKEN"] == TOKEN for call in backend.calls)

    decision = exc_info.value.decision
    assert decision is not None
    assert decision.allowed is False
    assert "outside.example" in decision.url
    assert pages.completed_pages == [1, 2, 3]
    assert pages.last_completed_page == 3
    assert pages.loaded_pages == [1, 2, 3]
    assert pages.iteration_status == "blocked"
    assert pages.boundary_decision is decision
    assert pages.failed_url == decision.url

    state = pages.state
    assert state["completed_pages"] == [1, 2, 3]
    assert state["last_completed_page"] == 3
    assert state["status"] == "blocked"
    assert state["boundary_allowed"] is False


def test_starting_page_is_replaced_by_next_link_page() -> None:
    gl, backend = make_client(page_handler, allowed_migrations=[MIGRATION_BASE])

    with pytest.warns(UserWarning, match="page=1"):
        pages = gl.http_list("/items", iterator=True, page=1, per_page=1)
    list(pages)

    requested_pages = [
        parse_qs(urlparse(call.url).query).get("page", ["1"])[0]
        for call in backend.calls
    ]
    assert requested_pages == ["1", "2", "3", "4"]


def test_reverse_proxy_prefix_is_segment_aware() -> None:
    boundary = NetworkBoundary(BASE_URL)

    legal = boundary.classify(f"{API_URL}/projects?page=2")
    assert legal.allowed is True
    assert legal.same_instance is True
    assert legal.carry_gitlab_identity is True

    prefix_confusion = boundary.classify(
        "https://gitlab.example/internal/gitlab-evil/api/v4/projects?page=2"
    )
    assert prefix_confusion.allowed is False

    relative_link = boundary.classify("/internal/gitlab/api/v4/projects?page=3")
    assert relative_link.allowed is True


def test_migration_defaults_to_anonymous_and_can_be_credentialed() -> None:
    anonymous = NetworkBoundary(BASE_URL, allowed_migrations=[MIGRATION_BASE]).classify(
        f"{MIGRATION_API}/items?page=4"
    )
    assert anonymous.allowed is True
    assert anonymous.migration is True
    assert anonymous.carry_gitlab_identity is False

    credentialed = NetworkBoundary(
        BASE_URL,
        allowed_migrations={MIGRATION_BASE: True},
    ).classify(f"{MIGRATION_API}/items?page=4")
    assert credentialed.carry_gitlab_identity is True


def test_redirect_hook_strips_identity_for_anonymous_migration() -> None:
    gl = gitlab.Gitlab(
        BASE_URL,
        private_token=TOKEN,
        allowed_migrations=[gitlab.AllowedMigration(MIGRATION_BASE, False)],
    )
    request = requests.PreparedRequest()
    request.prepare(
        method="GET",
        url=f"{API_URL}/items",
        headers={"PRIVATE-TOKEN": TOKEN},
    )
    response = SimpleNamespace(
        url=f"{API_URL}/items",
        headers=CaseInsensitiveDict({"Location": f"{MIGRATION_API}/items?page=4"}),
        request=request,
    )

    gl._boundary_redirect_hook(response)

    assert "PRIVATE-TOKEN" not in request.headers


def test_redirect_hook_allows_credentialed_migration() -> None:
    gl = gitlab.Gitlab(
        BASE_URL,
        private_token=TOKEN,
        allowed_migrations={MIGRATION_BASE: True},
    )
    request = requests.PreparedRequest()
    request.prepare(
        method="GET",
        url=f"{API_URL}/items",
        headers={"PRIVATE-TOKEN": TOKEN},
    )
    response = SimpleNamespace(
        url=f"{API_URL}/items",
        headers=CaseInsensitiveDict({"Location": f"{MIGRATION_API}/items?page=4"}),
        request=request,
    )

    gl._boundary_redirect_hook(response)

    assert request.headers["PRIVATE-TOKEN"] == TOKEN


def test_redirect_hook_blocks_unadmitted_domain() -> None:
    gl = gitlab.Gitlab(BASE_URL, private_token=TOKEN)
    request = requests.PreparedRequest()
    request.prepare(method="GET", url=f"{API_URL}/items")
    response = SimpleNamespace(
        url=f"{API_URL}/items",
        headers=CaseInsensitiveDict(
            {"Location": "https://outside.example/internal/gitlab/api/v4/items"}
        ),
        request=request,
    )

    with pytest.raises(BoundaryViolation):
        gl._boundary_redirect_hook(response)


def test_transport_failure_keeps_last_completed_page() -> None:
    def failing_handler(call: RecordedCall) -> StubResponse:
        page = int(parse_qs(urlparse(call.url).query).get("page", ["1"])[0])
        if page <= 3:
            next_url = f"{API_URL}/items?per_page=1&page={page + 1}"
            return StubResponse(
                [{"id": f"same-{page}"}],
                headers=pagination_headers(page, next_url),
            )
        raise requests.ConnectionError("synthetic offline page")

    gl, backend = make_client(failing_handler)
    pages = gl.http_list("/items", iterator=True, per_page=1)

    with pytest.raises(requests.ConnectionError, match="synthetic offline page"):
        list(pages)

    assert len(backend.calls) == 4
    assert pages.completed_pages == [1, 2, 3]
    assert pages.last_completed_page == 3
    assert pages.iteration_status == "failed"
    assert pages.state["status"] == "failed"
    assert pages.state["error_type"] == "ConnectionError"
    assert "page=4" in (pages.failed_url or "")
