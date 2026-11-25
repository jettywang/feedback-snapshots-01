"""Tests for the conservative mutation outcome flow."""

import json

import pytest
import requests
import responses

import gitlab
from gitlab import base
from gitlab.mixins import CRUDMixin, SaveMixin
from gitlab.outcomes import UnconfirmedMutation
from tests.unit import helpers


class MemberLike(SaveMixin, base.RESTObject):
    pass


class MemberLikeManager(CRUDMixin[MemberLike]):
    _path = "/groups/1/members"
    _obj_cls = MemberLike


@pytest.fixture
def conservative_gl():
    return gitlab.Gitlab(
        "http://localhost",
        private_token="private_token",
        api_version="4",
        retry_transient_errors=True,
        conservative_mutations=True,
    )


@responses.activate
def test_mutation_commit_then_disconnect_returns_pending_once(conservative_gl):
    """The fake service applies the change, then drops the connection.

    The caller must get an explicit pending-verification result, and the
    change must have been sent exactly once instead of being retried.
    """
    state = {"access_level": 30}
    sends = 0
    url = "http://localhost/api/v4/groups/1/members/7"

    def callback(request):
        nonlocal sends
        sends += 1
        state["access_level"] = 40
        raise requests.ConnectionError("connection lost after applying change")

    responses.add_callback(
        method=responses.PUT,
        url=url,
        callback=callback,
        content_type="application/json",
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    member = MemberLikeManager(conservative_gl).get(7, lazy=True)
    member.access_level = 40

    result = member.save()

    assert isinstance(result, UnconfirmedMutation)
    assert result.pending is True
    assert result.outcome == "unknown"
    assert result.status == "pending_verification"
    assert result.verb == "put"
    assert result.attempts == 1
    assert sends == 1
    assert state == {"access_level": 40}

    # The local object must not pretend it was updated from a response that
    # never arrived.
    assert member._attrs.get("access_level") != 40

    # The caller reconciles the unknown outcome with an independent read that
    # shows the change did reach the server.
    responses.add(
        method=responses.GET,
        url=url,
        json={"id": 7, "access_level": 40},
        status=200,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )
    reconciled = MemberLikeManager(conservative_gl).get(7)
    assert reconciled.access_level == 40
    assert sends == 1


@responses.activate
def test_successful_mutation_keeps_object_update_contract(conservative_gl):
    calls = 0
    url = "http://localhost/api/v4/groups/1/members/7"

    def callback(request):
        nonlocal calls
        calls += 1
        return (
            200,
            {"Content-Type": "application/json"},
            json.dumps({"id": 7, "access_level": 40}),
        )

    responses.add_callback(
        method=responses.PUT,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    member = MemberLikeManager(conservative_gl).get(7, lazy=True)
    member.access_level = 30
    result = member.save()
    assert calls == 1

    # Successful calls still return server data and update the object, with
    # pending changes cleared.
    assert result == {"id": 7, "access_level": 40}
    assert member.access_level == 40
    assert member._updated_attrs == {}


@responses.activate
def test_paginated_read_still_retries_with_conservative_mutations():
    """Reads keep using the configured transient-error retry policy."""
    gl = gitlab.Gitlab(
        "http://localhost",
        private_token="private_token",
        api_version="4",
        retry_transient_errors=True,
        conservative_mutations=True,
    )
    url = "http://localhost/api/v4/tests"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return (503, {}, "")
        return (
            200,
            {
                "Content-Type": "application/json",
                "X-Page": "2",
                "X-Next-Page": "",
                "X-Per-Page": "1",
                "X-Total": "1",
            },
            json.dumps([{"id": 1, "name": "after-retry"}]),
        )

    responses.add_callback(
        method=responses.GET,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = gl.http_list("/tests", get_all=True, retry_transient_errors=True)
    assert [item["name"] for item in result] == ["after-retry"]
    assert calls == 2


@responses.activate
def test_read_timeout_still_retries_with_conservative_mutations(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _: None)
    gl = gitlab.Gitlab(
        "http://localhost",
        private_token="private_token",
        api_version="4",
        retry_transient_errors=True,
        conservative_mutations=True,
    )
    url = "http://localhost/api/v4/projects"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise requests.exceptions.Timeout("read timed out")
        return (200, {"Content-Type": "application/json"}, "[]")

    responses.add_callback(
        method=responses.GET,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = gl.http_get("/projects")
    assert result == []
    assert calls == 2


@responses.activate
def test_mutation_429_is_still_retried(conservative_gl, monkeypatch):
    """A rate-limited request was rejected before processing and is safe."""
    monkeypatch.setattr("time.sleep", lambda _: None)
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return (429, {"Retry-After": "0"}, "")
        return (201, {"Content-Type": "application/json"}, json.dumps({"id": 9}))

    responses.add_callback(
        method=responses.POST,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    member = MemberLikeManager(conservative_gl).create(
        {"access_level": 40, "user_id": 9}
    )
    assert not isinstance(member, UnconfirmedMutation)
    assert member.id == 9
    assert calls == 2


@responses.activate
def test_mutation_transient_status_returns_pending_without_retry(conservative_gl):
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        return (502, {}, "")

    responses.add_callback(
        method=responses.POST,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = MemberLikeManager(conservative_gl).create(
        {"access_level": 40, "user_id": 9}
    )
    assert isinstance(result, UnconfirmedMutation)
    assert result.attempts == 1
    assert "502" in result.error
    assert calls == 1


@responses.activate
def test_mutation_delete_returns_pending(conservative_gl):
    url = "http://localhost/api/v4/groups/1/members/7"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        raise requests.ConnectionError("connection reset")

    responses.add_callback(
        method=responses.DELETE,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = MemberLikeManager(conservative_gl).delete(7)
    assert isinstance(result, UnconfirmedMutation)
    assert result.verb == "delete"
    assert result.attempts == 1
    assert calls == 1


@responses.activate
def test_per_call_conservative_override_returns_pending(gl):
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        raise requests.exceptions.Timeout("request timed out")

    responses.add_callback(
        method=responses.POST,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = gl.http_post(
        "/groups/1/members",
        post_data={"access_level": 40, "user_id": 9},
        conservative_mutations=True,
        retry_transient_errors=True,
    )
    assert isinstance(result, UnconfirmedMutation)
    assert calls == 1


@responses.activate
def test_default_flow_keeps_retrying_mutations(gl_retry, monkeypatch):
    """Without the opt-in policy the historical retry behavior is unchanged."""
    monkeypatch.setattr("time.sleep", lambda _: None)
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise requests.exceptions.Timeout("request timed out")
        return (201, {"Content-Type": "application/json"}, json.dumps({"id": 9}))

    responses.add_callback(
        method=responses.POST,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = gl_retry.http_post(
        "/groups/1/members", post_data={"access_level": 40, "user_id": 9}
    )
    assert result == {"id": 9}
    assert calls == 2


def test_client_rejects_true_is_independent_from_retry_setting():
    gl = gitlab.Gitlab(
        "http://localhost",
        private_token="private_token",
        api_version="4",
        retry_transient_errors=False,
        conservative_mutations=True,
    )
    assert gl.conservative_mutations is True
    assert gl.retry_transient_errors is False


def test_unconfirmed_mutation_describe_is_serializable():
    outcome = UnconfirmedMutation(
        verb="put", path="/groups/1/members/7", error="timeout", attempts=1
    )
    described = outcome.describe()
    assert described == {
        "status": "pending_verification",
        "outcome": "unknown",
        "verb": "put",
        "path": "/groups/1/members/7",
        "error": "timeout",
        "attempts": 1,
    }
    assert "verify the remote state" in str(outcome)


@responses.activate
def test_pending_even_without_transient_retries(monkeypatch):
    """The conservative policy reports ambiguity regardless of retry config."""
    gl = gitlab.Gitlab(
        "http://localhost",
        private_token="private_token",
        api_version="4",
        retry_transient_errors=False,
        conservative_mutations=True,
    )
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        raise requests.exceptions.Timeout("request timed out")

    responses.add_callback(
        method=responses.POST,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = gl.http_post(
        "/groups/1/members", post_data={"access_level": 40, "user_id": 9}
    )
    assert isinstance(result, UnconfirmedMutation)
    assert calls == 1


@responses.activate
def test_resource_lock_conflict_is_retried(conservative_gl, monkeypatch):
    """409 'Resource lock' is a pre-processing rejection and stays retryable."""
    monkeypatch.setattr("time.sleep", lambda _: None)
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def response_callback(response):
        nonlocal calls
        calls += 1
        if calls == 1:
            response.reason = "Resource lock"
        return response

    with responses.RequestsMock(response_callback=response_callback) as rsps:
        rsps.add(
            method=responses.POST,
            url=url,
            status=409,
            json={"message": "locked"},
            match=helpers.MATCH_EMPTY_QUERY_PARAMS,
        )
        rsps.add(
            method=responses.POST,
            url=url,
            status=201,
            json={"id": 9},
            match=helpers.MATCH_EMPTY_QUERY_PARAMS,
        )
        result = MemberLikeManager(conservative_gl).create(
            {"access_level": 40, "user_id": 9}
        )

    assert not isinstance(result, UnconfirmedMutation)
    assert result.id == 9
    assert calls == 2


@responses.activate
def test_create_success_returns_object_with_conservative_policy(conservative_gl):
    url = "http://localhost/api/v4/groups/1/members"
    responses.add(
        method=responses.POST,
        url=url,
        json={"id": 9, "access_level": 40},
        status=201,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )
    member = MemberLikeManager(conservative_gl).create(
        {"access_level": 40, "user_id": 9}
    )
    assert isinstance(member, MemberLike)
    assert member.id == 9


@responses.activate
def test_mutation_pending_counts_single_attempt_even_with_many_retries(conservative_gl):
    """max_retries does not cause resends of a possibly-applied mutation."""
    url = "http://localhost/api/v4/groups/1/members"
    calls = 0

    def callback(request):
        nonlocal calls
        calls += 1
        raise requests.exceptions.Timeout("request timed out")

    responses.add_callback(
        method=responses.POST,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    result = conservative_gl.http_post(
        "/groups/1/members",
        post_data={"access_level": 40, "user_id": 9},
        max_retries=-1,
    )
    assert isinstance(result, UnconfirmedMutation)
    assert result.attempts == 1
    assert calls == 1


@responses.activate
def test_cli_reports_pending_update_without_faking_success(conservative_gl, capsys):
    from gitlab.v4.cli import run

    url = "http://localhost/api/v4/groups/1/members/7"

    def callback(request):
        raise requests.ConnectionError("connection lost")

    responses.add_callback(
        method=responses.PUT,
        url=url,
        callback=callback,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )

    args = {"group_id": 1, "id": 7, "access_level": 40}
    run(
        conservative_gl,
        "group-member",
        "update",
        args,
        verbose=False,
        output="json",
        fields=[],
    )
    out = capsys.readouterr().out
    assert "pending_verification" in out
    assert "unknown" in out
