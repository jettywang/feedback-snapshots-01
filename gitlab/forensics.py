"""Tamper-evident, offline-reviewable evidence exports.

The GitLab UI reflects the *current* state of a project. When a release tag is
force-rebuilt, the links shown for a release can silently start pointing at a
different build than the one users downloaded at the time of the incident.
This module captures the raw responses that were actually served, the moment
they were served, and cross-checks them so that the divergence can be reviewed
later without any network access.

The resulting document is plain JSON. Every raw response body is stored
verbatim together with its SHA-256 digest and the digest of the whole manifest,
so a reviewer can detect after-the-fact edits with
:func:`verify_forensic_export`.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import hashlib
import json
import pathlib
import re
import urllib.parse
from typing import Any, TYPE_CHECKING

import requests

from gitlab import exceptions, utils
from gitlab._version import __version__

if TYPE_CHECKING:
    from gitlab.client import Gitlab

__all__ = [
    "ForensicVerification",
    "ReleaseForensicCollector",
    "SCHEMA",
    "SCHEMA_VERSION",
    "summarize_export",
    "verify_forensic_export",
    "write_forensic_export",
]

SCHEMA = "python-gitlab/release-forensic-export"
SCHEMA_VERSION = 1

_JOB_REFERENCE_RE = re.compile(r"/-/jobs/(?P<job_id>\d+)(?:/|$)")
# GitLab occasionally publishes absolute URLs in the Link header. Keeping it
# in the evidence lets a reviewer see exactly how pagination was advertised.
_PAGINATION_HEADERS = (
    "x-page",
    "x-prev-page",
    "x-next-page",
    "x-per-page",
    "x-total",
    "x-total-pages",
    "link",
)


def _headers_for_export(headers: dict[str, str]) -> dict[str, str]:
    exported = {
        key: value for key, value in headers.items() if key in _PAGINATION_HEADERS
    }
    for key in ("content-type", "content-length", "etag", "last-modified"):
        value = headers.get(key)
        if value is not None:
            exported[key] = value
    return exported


def _utc_now() -> str:
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _canonical_json(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _manifest_digest(document: dict[str, Any]) -> str:
    payload = {key: value for key, value in document.items() if key != "integrity"}
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _encode_body(body: bytes) -> dict[str, Any]:
    """Return a lossless, JSON-safe representation of a raw response body."""
    try:
        text = body.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = base64.b64encode(body).decode("ascii")
        encoding = "base64"
    return {
        "encoding": encoding,
        "text": text,
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def _decode_body(body: dict[str, Any]) -> bytes:
    encoding = body.get("encoding", "utf-8")
    text = body.get("text", "")
    if encoding == "utf-8":
        return text.encode("utf-8")
    if encoding == "base64":
        return base64.b64decode(text, validate=True)
    raise ValueError(f"Unsupported body encoding: {encoding!r}")


def _coerce_int(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError) as exc:
        raise exceptions.GitlabParsingError(
            f"Expected an integer for forensic export option, got {value!r}"
        ) from exc


def _subject_project_id(project_id: int | str) -> int | str:
    if isinstance(project_id, int):
        return project_id
    text = urllib.parse.unquote(str(project_id))
    return int(text) if text.isdigit() else text


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise exceptions.GitlabParsingError(
        f"Expected a boolean value, got {value!r}"
    )


@dataclasses.dataclass
class _Observation:
    observation_id: str
    step: str
    label: str
    requested_at: str
    url: str
    path: str
    query: dict[str, Any]
    status: int | None
    headers: dict[str, str]
    body: bytes
    content_type: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "step": self.step,
            "label": self.label,
            "requested_at": self.requested_at,
            "request": {
                "method": "GET",
                "url": self.url,
                "path": self.path,
                "query": self.query,
            },
            "response": {
                "status": self.status,
                "headers": _headers_for_export(self.headers),
                "content_type": self.content_type,
                "body": _encode_body(self.body),
            },
        }


@dataclasses.dataclass
class _RequestFailure:
    kind: str
    status: int | None
    message: str
    observation_id: str | None = None


@dataclasses.dataclass
class _TagSnapshot:
    observation_id: str
    step: str
    label: str
    requested_at: str
    sha: str
    name: str | None


@dataclasses.dataclass
class _JobSnapshot:
    job_id: int
    observation_id: str
    status: int | None
    pipeline_id: int | None
    pipeline_sha: str | None
    ref: str | None
    error_code: str | None


@dataclasses.dataclass
class ForensicVerification:
    """Result of verifying a forensic export without contacting GitLab."""

    ok: bool
    problems: list[dict[str, Any]]
    summary: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "problems": self.problems,
            "summary": self.summary,
        }

    def __bool__(self) -> bool:
        return self.ok


class ReleaseForensicCollector:
    """Collect an offline-reviewable evidence slice for one release tag.

    The collector always stores the raw response body as it was served, plus
    the moment it was requested. If the tag moves between the first and the
    second read, both versions remain in the export. Permission errors and
    interrupted pagination are recorded as explicit :class:`EvidenceGap`
    entries instead of aborting the whole collection.

    Args:
        gl: Connected :class:`~gitlab.Gitlab` instance.
        project_id: ID or URL-encoded path of the project.
        tag_name: Release tag name to collect evidence for.
        per_page: Pagination size used for list endpoints. Defaults to the
            client-wide ``per_page`` or 100.
        include_jobs: Resolve CI job references found in asset links. Disable
            only if the caller deliberately does not want build provenance.
        recheck_tag: Read the tag once before and once after the asset links,
            so a tag migration during collection is observable.
        max_pages: Safety limit for paginated endpoints.
        jobs_limit: Safety limit for job lookups.
    """

    def __init__(
        self,
        gl: Gitlab,
        project_id: int | str,
        tag_name: str,
        *,
        per_page: int | None = None,
        include_jobs: bool = True,
        recheck_tag: bool = True,
        max_pages: int = 100,
        jobs_limit: int = 50,
    ) -> None:
        self._gl = gl
        self._project_id = _subject_project_id(project_id)
        self._project_path_id = utils.EncodedId(self._project_id)
        self._tag_name = tag_name
        self._tag_path_id = utils.EncodedId(tag_name)
        self._per_page = per_page or gl.per_page or 100
        self._include_jobs = include_jobs
        self._recheck_tag = recheck_tag
        self._max_pages = max_pages
        self._jobs_limit = jobs_limit

        self._observations: list[_Observation] = []
        self._steps: list[dict[str, Any]] = []
        self._steps_by_name: dict[str, dict[str, Any]] = {}
        self._gaps: list[dict[str, Any]] = []
        self._findings: list[dict[str, Any]] = []
        self._divergences: list[dict[str, Any]] = []
        self._next_observation = 1
        self._tag_snapshots: list[_TagSnapshot] = []
        self._job_snapshots: dict[int, _JobSnapshot] = {}
        self._link_records: list[tuple[dict[str, Any], str]] = []
        self._release: dict[str, Any] | None = None

    # ------------------------------------------------------------------
    # Export assembly helpers
    # ------------------------------------------------------------------
    def _begin_step(self, name: str, description: str) -> dict[str, Any]:
        step: dict[str, Any] = {
            "step": name,
            "description": description,
            "status": "ok",
            "observations": [],
            "evidence_gaps": [],
            "findings": [],
            "divergence_detected": False,
        }
        self._steps.append(step)
        self._steps_by_name[name] = step
        return step

    def _step_for(self, name: str) -> dict[str, Any]:
        step = self._steps_by_name.get(name)
        if step is None:
            step = self._begin_step(name, f"Evidence collected during {name}")
        return step

    def _record(
        self,
        *,
        step: str,
        label: str,
        requested_at: str,
        path: str,
        query: dict[str, Any],
        status: int | None,
        headers: dict[str, str],
        body: bytes,
        content_type: str | None,
    ) -> _Observation:
        observation_id = f"obs-{self._next_observation:03d}"
        self._next_observation += 1
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"{self._gl.api_url}{path}"
        observation = _Observation(
            observation_id=observation_id,
            step=step,
            label=label,
            requested_at=requested_at,
            url=url,
            path=path,
            query=query,
            status=status,
            headers=headers,
            body=body,
            content_type=content_type,
        )
        self._observations.append(observation)
        self._step_for(step)["observations"].append(observation_id)
        return observation

    def _add_gap(
        self,
        *,
        step: str,
        code: str,
        message: str,
        endpoint: str | None = None,
        status: int | None = None,
        blocking: bool = False,
        observation_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        gap: dict[str, Any] = {
            "code": code,
            "step": step,
            "message": message,
            "endpoint": endpoint,
            "status": status,
            "permission_denied": status in (401, 403),
            "blocking": blocking,
            "observation_id": observation_id,
        }
        if details:
            gap["details"] = details
        self._gaps.append(gap)
        step_doc = self._step_for(step)
        step_doc["evidence_gaps"].append(code)
        if blocking:
            step_doc["status"] = "incomplete"

    def _add_finding(
        self,
        *,
        code: str,
        step: str,
        severity: str,
        message: str,
        observations: list[str],
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        finding: dict[str, Any] = {
            "finding_id": f"F{len(self._findings) + 1}",
            "code": code,
            "step": step,
            "severity": severity,
            "message": message,
            "observations": observations,
        }
        if details:
            finding["details"] = details
        self._findings.append(finding)
        self._step_for(step)["findings"].append(finding["finding_id"])
        return finding

    # ------------------------------------------------------------------
    # Low-level request capture
    # ------------------------------------------------------------------
    def _request(
        self,
        step: str,
        label: str,
        path: str,
        query: dict[str, Any] | None = None,
    ) -> tuple[_Observation, Any | None, _RequestFailure | None]:
        requested_at = _utc_now()
        query_data = dict(query or {})
        try:
            # Disable retries and rate-limit sleeping on purpose: a forensic
            # capture must show the error the server actually returned rather
            # than block or silently retry.
            response = self._gl.http_request(
                "get",
                path,
                query_data=query_data,
                retry_transient_errors=False,
                obey_rate_limit=False,
                max_retries=0,
            )
        except (
            exceptions.GitlabHttpError,
            exceptions.GitlabAuthenticationError,
        ) as exc:
            status = exc.response_code
            raw = exc.response_body
            if raw is None:
                message = exc.error_message
                raw = (
                    message
                    if isinstance(message, bytes)
                    else str(message).encode("utf-8")
                )
            observation = self._record(
                step=step,
                label=label,
                requested_at=requested_at,
                path=path,
                query=query_data,
                status=status,
                headers={},
                body=raw,
                content_type=None,
            )
            return observation, None, _RequestFailure(
                kind="http",
                status=status,
                message=str(exc),
                observation_id=observation.observation_id,
            )
        except exceptions.GitlabError as exc:
            observation = self._record(
                step=step,
                label=label,
                requested_at=requested_at,
                path=path,
                query=query_data,
                status=exc.response_code,
                headers={},
                body=exc.response_body or str(exc).encode("utf-8"),
                content_type=None,
            )
            return observation, None, _RequestFailure(
                kind="gitlab-error",
                status=exc.response_code,
                message=str(exc),
                observation_id=observation.observation_id,
            )
        except requests.RequestException as exc:
            observation = self._record(
                step=step,
                label=label,
                requested_at=requested_at,
                path=path,
                query=query_data,
                status=None,
                headers={},
                body=b"",
                content_type=None,
            )
            return (
                observation,
                None,
                _RequestFailure(
                    kind="connection",
                    status=None,
                    message=str(exc),
                    observation_id=observation.observation_id,
                ),
            )

        body = response.content or b""
        headers = {
            str(key).lower(): str(value) for key, value in response.headers.items()
        }
        raw_content_type = response.headers.get("Content-Type")
        content_type = utils.get_content_type(raw_content_type)
        observation = self._record(
            step=step,
            label=label,
            requested_at=requested_at,
            path=path,
            query=query_data,
            status=response.status_code,
            headers=headers,
            body=body,
            content_type=(
                raw_content_type if raw_content_type is not None else content_type
            ),
        )

        if raw_content_type is not None and content_type != "application/json":
            return (
                observation,
                None,
                _RequestFailure(
                    kind="invalid-content-type",
                    status=response.status_code,
                    message=f"Expected JSON, got {content_type!r}",
                    observation_id=observation.observation_id,
                ),
            )
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            return (
                observation,
                None,
                _RequestFailure(
                    kind="invalid-json",
                    status=response.status_code,
                    message=f"Invalid JSON response: {exc}",
                    observation_id=observation.observation_id,
                ),
            )
        return observation, parsed, None

    @staticmethod
    def _gap_code(base: str, status: int | None) -> str:
        if status in (401, 403):
            return f"{base}_forbidden"
        if status == 404:
            return f"{base}_not_found"
        if status == 429:
            return f"{base}_rate_limited"
        return f"{base}_unavailable"

    # ------------------------------------------------------------------
    # Collection steps
    # ------------------------------------------------------------------
    def _collect_release(self) -> None:
        step = "release"
        path = (
            f"/projects/{self._project_path_id}/releases/{self._tag_path_id}"
        )
        observation, parsed, failure = self._request(step, "release", path)
        if failure:
            self._add_gap(
                step=step,
                code=self._gap_code("release", failure.status),
                message=f"Could not read the release object: {failure.message}",
                endpoint=path,
                status=failure.status,
                blocking=True,
                observation_id=failure.observation_id,
            )
            return
        if not isinstance(parsed, dict):
            self._add_gap(
                step=step,
                code="release_invalid_response",
                message="Release endpoint did not return a JSON object",
                endpoint=path,
                status=observation.status,
                blocking=True,
                observation_id=observation.observation_id,
            )
            return
        self._release = parsed

    def _read_tag(self, step: str, label: str) -> None:
        path = (
            f"/projects/{self._project_path_id}/repository/tags/"
            f"{self._tag_path_id}"
        )
        observation, parsed, failure = self._request(step, label, path)
        if failure:
            self._add_gap(
                step=step,
                code=self._gap_code("tag", failure.status),
                message=f"Could not read the tag object: {failure.message}",
                endpoint=path,
                status=failure.status,
                blocking=True,
                observation_id=failure.observation_id,
            )
            return
        sha: str | None = None
        name: str | None = None
        if isinstance(parsed, dict):
            name = parsed.get("name") if isinstance(parsed.get("name"), str) else None
            commit = parsed.get("commit")
            if isinstance(commit, dict) and isinstance(commit.get("id"), str):
                sha = commit["id"]
            if sha is None and isinstance(parsed.get("target"), str):
                sha = parsed["target"]
        if not sha:
            self._add_gap(
                step=step,
                code="tag_missing_commit",
                message="Tag response does not contain a resolvable commit SHA",
                endpoint=path,
                status=observation.status,
                blocking=True,
                observation_id=observation.observation_id,
            )
            return
        self._tag_snapshots.append(
            _TagSnapshot(
                observation_id=observation.observation_id,
                step=step,
                label=label,
                requested_at=observation.requested_at,
                sha=sha,
                name=name,
            )
        )

    def _collect_links(self) -> None:
        step = "release-links"
        path = (
            f"/projects/{self._project_path_id}/releases/"
            f"{self._tag_path_id}/assets/links"
        )
        page = 1
        pages_fetched = 0
        total: int | None = None
        total_pages: int | None = None

        while True:
            if pages_fetched >= self._max_pages:
                self._add_gap(
                    step=step,
                    code="pagination_limit_reached",
                    message=(
                        f"Stopped after {pages_fetched} pages because max_pages="
                        f"{self._max_pages} was reached"
                    ),
                    endpoint=path,
                    blocking=True,
                    details={"pages_fetched": pages_fetched},
                )
                break

            query = {"page": page, "per_page": self._per_page}
            observation, parsed, failure = self._request(
                step, f"links-page-{page}", path, query
            )
            pages_fetched += 1

            if failure:
                if failure.kind in ("invalid-json", "invalid-content-type"):
                    code = "links_invalid_response"
                elif page == 1:
                    code = self._gap_code("links", failure.status)
                else:
                    code = "pagination_aborted"
                self._add_gap(
                    step=step,
                    code=code,
                    message=(
                        f"Asset link collection stopped on page {page}: "
                        f"{failure.message}"
                    ),
                    endpoint=path,
                    status=failure.status,
                    blocking=True,
                    observation_id=failure.observation_id,
                    details={
                        "page": page,
                        "pages_fetched": pages_fetched,
                        "total": total,
                        "total_pages": total_pages,
                    },
                )
                break

            if not isinstance(parsed, list):
                self._add_gap(
                    step=step,
                    code="links_invalid_response",
                    message="Asset links endpoint did not return a JSON list",
                    endpoint=path,
                    status=observation.status,
                    blocking=True,
                    observation_id=observation.observation_id,
                    details={"page": page},
                )
                break

            for link in parsed:
                if isinstance(link, dict):
                    self._link_records.append((link, observation.observation_id))

            headers = observation.headers
            total = self._header_int(headers, "x-total", total)
            total_pages = self._header_int(headers, "x-total-pages", total_pages)
            next_page = self._header_int(headers, "x-next-page", None)

            if next_page is not None:
                page = next_page
                continue

            if total is not None and total > len(self._link_records):
                self._add_gap(
                    step=step,
                    code="pagination_incomplete",
                    message=(
                        f"Collected {len(self._link_records)} of {total} asset "
                        "links, but the server reported no next page"
                    ),
                    endpoint=path,
                    status=observation.status,
                    blocking=True,
                    observation_id=observation.observation_id,
                    details={
                        "collected": len(self._link_records),
                        "total": total,
                        "total_pages": total_pages,
                    },
                )
            elif (
                total is None
                and total_pages is None
                and len(parsed) >= self._per_page
            ):
                self._add_gap(
                    step=step,
                    code="pagination_unverifiable",
                    message=(
                        "Server returned a full page without pagination headers; "
                        "additional asset links may exist"
                    ),
                    endpoint=path,
                    status=observation.status,
                    blocking=False,
                    observation_id=observation.observation_id,
                    details={"page": page, "items": len(parsed)},
                )
            break

    @staticmethod
    def _header_int(
        headers: dict[str, str], name: str, default: int | None
    ) -> int | None:
        value = headers.get(name)
        if value is None or value == "":
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _job_ids_in_link(link: dict[str, Any]) -> list[int]:
        job_ids: list[int] = []
        for key in ("url", "direct_asset_url"):
            url = link.get(key)
            if not isinstance(url, str):
                continue
            match = _JOB_REFERENCE_RE.search(url)
            if match:
                job_id = int(match.group("job_id"))
                if job_id not in job_ids:
                    job_ids.append(job_id)
        return job_ids

    def _collect_jobs(self) -> None:
        step = "jobs"
        job_ids: list[int] = []
        for link, _observation_id in self._link_records:
            for job_id in self._job_ids_in_link(link):
                if job_id not in job_ids:
                    job_ids.append(job_id)

        for index, job_id in enumerate(job_ids):
            if index >= self._jobs_limit:
                self._add_gap(
                    step=step,
                    code="job_limit_reached",
                    message=(
                        f"Stopped resolving jobs after jobs_limit="
                        f"{self._jobs_limit}"
                    ),
                    blocking=True,
                    details={"unresolved_job_ids": job_ids[index:]},
                )
                break

            path = f"/projects/{self._project_path_id}/jobs/{job_id}"
            observation, parsed, failure = self._request(
                step, f"job-{job_id}", path
            )
            if failure:
                code = self._gap_code("job", failure.status)
                self._add_gap(
                    step=step,
                    code=code,
                    message=(
                        f"Could not resolve job {job_id} referenced by an asset "
                        f"link: {failure.message}"
                    ),
                    endpoint=path,
                    status=failure.status,
                    blocking=True,
                    observation_id=failure.observation_id,
                    details={"job_id": job_id},
                )
                self._job_snapshots[job_id] = _JobSnapshot(
                    job_id=job_id,
                    observation_id=failure.observation_id or observation.observation_id,
                    status=failure.status,
                    pipeline_id=None,
                    pipeline_sha=None,
                    ref=None,
                    error_code=code,
                )
                continue

            pipeline_id: int | None = None
            pipeline_sha: str | None = None
            ref: str | None = None
            if isinstance(parsed, dict):
                pipeline = parsed.get("pipeline")
                if isinstance(pipeline, dict):
                    if isinstance(pipeline.get("id"), int):
                        pipeline_id = pipeline["id"]
                    if isinstance(pipeline.get("sha"), str):
                        pipeline_sha = pipeline["sha"]
                commit = parsed.get("commit")
                if pipeline_sha is None and isinstance(commit, dict):
                    if isinstance(commit.get("id"), str):
                        pipeline_sha = commit["id"]
                if isinstance(parsed.get("ref"), str):
                    ref = parsed["ref"]

            if pipeline_id is None and pipeline_sha is None:
                self._add_gap(
                    step=step,
                    code="job_missing_pipeline",
                    message=(
                        f"Job {job_id} response does not identify its pipeline "
                        "or commit"
                    ),
                    endpoint=path,
                    status=observation.status,
                    blocking=True,
                    observation_id=observation.observation_id,
                    details={"job_id": job_id},
                )
                self._job_snapshots[job_id] = _JobSnapshot(
                    job_id=job_id,
                    observation_id=observation.observation_id,
                    status=observation.status,
                    pipeline_id=None,
                    pipeline_sha=None,
                    ref=ref,
                    error_code="job_missing_pipeline",
                )
                continue

            self._job_snapshots[job_id] = _JobSnapshot(
                job_id=job_id,
                observation_id=observation.observation_id,
                status=observation.status,
                pipeline_id=pipeline_id,
                pipeline_sha=pipeline_sha,
                ref=ref,
                error_code=None,
            )

    # ------------------------------------------------------------------
    # Cross-checks
    # ------------------------------------------------------------------
    def _cross_check(self) -> dict[str, Any]:
        self._begin_step(
            "cross-check",
            "Offline comparison of the captured release, tag and job evidence",
        )

        tag_shas = [snapshot.sha for snapshot in self._tag_snapshots]
        final_sha = tag_shas[-1] if tag_shas else None

        if len(tag_shas) >= 2:
            for index, snapshot in enumerate(self._tag_snapshots[1:], start=1):
                if snapshot.sha == tag_shas[0]:
                    continue
                before = self._tag_snapshots[0]
                self._add_finding(
                    code="tag_moved",
                    step="cross-check",
                    severity="critical",
                    message=(
                        f"Tag {self._tag_name} pointed at {before.sha} when first "
                        f"read, but at {snapshot.sha} when read again during "
                        "collection"
                    ),
                    observations=[before.observation_id, snapshot.observation_id],
                    details={
                        "tag_name": self._tag_name,
                        "before_sha": before.sha,
                        "after_sha": snapshot.sha,
                        "before_observation": before.observation_id,
                        "after_observation": snapshot.observation_id,
                        "before_requested_at": before.requested_at,
                        "after_requested_at": snapshot.requested_at,
                    },
                )
                self._step_for(snapshot.step)["divergence_detected"] = True
                self._divergences.append(
                    {
                        "code": "tag_moved",
                        "detected_at_step": snapshot.step,
                        "summary": (
                            f"Tag {self._tag_name} moved from {before.sha} to "
                            f"{snapshot.sha} during collection"
                        ),
                        "before": {
                            "sha": before.sha,
                            "observation_id": before.observation_id,
                            "requested_at": before.requested_at,
                            "step": before.step,
                        },
                        "after": {
                            "sha": snapshot.sha,
                            "observation_id": snapshot.observation_id,
                            "requested_at": snapshot.requested_at,
                            "step": snapshot.step,
                        },
                    }
                )
                break

        release_sha = self._release_commit_sha(self._release)
        if release_sha and final_sha and release_sha != final_sha:
            release_observation = self._release_observation_id()
            self._add_finding(
                code="release_commit_mismatch",
                step="cross-check",
                severity="critical",
                message=(
                    "Release object references a commit that no longer matches "
                    "the latest tag snapshot"
                ),
                observations=(
                    [release_observation] if release_observation else []
                ),
                details={
                    "release_sha": release_sha,
                    "latest_tag_sha": final_sha,
                    "release_observation": release_observation,
                },
            )

        tag_observation_by_sha: dict[str, str] = {}
        for snapshot in self._tag_snapshots:
            tag_observation_by_sha.setdefault(snapshot.sha, snapshot.observation_id)

        asset_links: list[dict[str, Any]] = []
        located: dict[tuple[int | None, str | None], dict[str, Any]] = {}

        for link, link_observation_id in self._link_records:
            link_id = link.get("id")
            link_name = link.get("name")
            link_url = link.get("url") or link.get("direct_asset_url")
            job_ids = self._job_ids_in_link(link)

            if not job_ids:
                asset_links.append(
                    {
                        "link_id": link_id,
                        "link_name": link_name,
                        "link_url": link_url,
                        "job_ids": [],
                        "relation": "not_applicable",
                        "observations": [link_observation_id],
                    }
                )
                self._add_finding(
                    code="asset_link_without_job_reference",
                    step="cross-check",
                    severity="info",
                    message=(
                        f"Asset link {link_name!r} does not reference a CI job, "
                        "so no build provenance can be derived from it"
                    ),
                    observations=[link_observation_id],
                    details={"link_id": link_id, "link_url": link_url},
                )
                continue

            for job_id in job_ids:
                snapshot = self._job_snapshots.get(job_id)
                if snapshot is None:
                    asset_links.append(
                        {
                            "link_id": link_id,
                            "link_name": link_name,
                            "link_url": link_url,
                            "job_id": job_id,
                            "pipeline_id": None,
                            "pipeline_sha": None,
                            "relation": "unresolved",
                            "gap_code": "job_not_collected",
                            "observations": [link_observation_id],
                        }
                    )
                    continue
                if snapshot.pipeline_sha is None:
                    asset_links.append(
                        {
                            "link_id": link_id,
                            "link_name": link_name,
                            "link_url": link_url,
                            "job_id": job_id,
                            "pipeline_id": None,
                            "pipeline_sha": None,
                            "relation": "unresolved",
                            "gap_code": snapshot.error_code,
                            "observations": [
                                link_observation_id,
                                snapshot.observation_id,
                            ],
                        }
                    )
                    self._add_finding(
                        code="asset_link_pipeline_unresolved",
                        step="cross-check",
                        severity="warning",
                        message=(
                            f"Could not resolve the pipeline for job {job_id} "
                            f"referenced by asset link {link_name!r}"
                        ),
                        observations=[
                            link_observation_id,
                            snapshot.observation_id,
                        ],
                        details={"link_id": link_id, "job_id": job_id},
                    )
                    continue

                if final_sha is None:
                    relation = "unverified"
                elif snapshot.pipeline_sha == final_sha:
                    relation = "current"
                elif snapshot.pipeline_sha in tag_shas:
                    relation = "historical"
                elif len(tag_shas) < 2:
                    relation = "unobserved"
                else:
                    relation = "unrelated"

                evidence = [link_observation_id, snapshot.observation_id]
                matching_tag_observation = tag_observation_by_sha.get(
                    snapshot.pipeline_sha
                )
                if matching_tag_observation:
                    evidence.append(matching_tag_observation)

                asset_links.append(
                    {
                        "link_id": link_id,
                        "link_name": link_name,
                        "link_url": link_url,
                        "job_id": job_id,
                        "pipeline_id": snapshot.pipeline_id,
                        "pipeline_sha": snapshot.pipeline_sha,
                        "relation": relation,
                        "observations": evidence,
                    }
                )

                key = (snapshot.pipeline_id, snapshot.pipeline_sha)
                located_entry = located.get(key)
                if located_entry is None:
                    located_entry = {
                        "pipeline_id": snapshot.pipeline_id,
                        "sha": snapshot.pipeline_sha,
                        "relation": relation,
                        "job_ids": [],
                        "asset_link_ids": [],
                        "observations": [snapshot.observation_id],
                    }
                    if matching_tag_observation:
                        located_entry["tag_observation_id"] = matching_tag_observation
                    located[key] = located_entry
                if job_id not in located_entry["job_ids"]:
                    located_entry["job_ids"].append(job_id)
                if link_id not in located_entry["asset_link_ids"]:
                    located_entry["asset_link_ids"].append(link_id)

                if relation == "historical":
                    self._add_finding(
                        code="historical_pipeline_located",
                        step="cross-check",
                        severity="info",
                        message=(
                            f"Asset link {link_name!r} points at job {job_id} "
                            f"from pipeline {snapshot.pipeline_id}, whose commit "
                            f"{snapshot.pipeline_sha} matches an earlier tag "
                            "observation"
                        ),
                        observations=evidence,
                        details={
                            "link_id": link_id,
                            "job_id": job_id,
                            "pipeline_id": snapshot.pipeline_id,
                            "pipeline_sha": snapshot.pipeline_sha,
                            "tag_sha_before": tag_shas[0] if tag_shas else None,
                            "tag_sha_after": final_sha,
                        },
                    )
                elif relation in ("unobserved", "unverified"):
                    self._add_finding(
                        code="asset_link_pipeline_unverified",
                        step="cross-check",
                        severity="warning",
                        message=(
                            f"Asset link {link_name!r} points at job {job_id} "
                            f"from pipeline {snapshot.pipeline_id} "
                            f"({snapshot.pipeline_sha}), which matches no "
                            "captured tag version"
                        ),
                        observations=evidence,
                        details={
                            "link_id": link_id,
                            "job_id": job_id,
                            "pipeline_id": snapshot.pipeline_id,
                            "pipeline_sha": snapshot.pipeline_sha,
                            "captured_tag_shas": tag_shas,
                        },
                    )
                elif relation == "unrelated":
                    self._add_finding(
                        code="asset_link_pipeline_mismatch",
                        step="cross-check",
                        severity="critical",
                        message=(
                            f"Asset link {link_name!r} points at job {job_id} "
                            f"from pipeline {snapshot.pipeline_id} "
                            f"({snapshot.pipeline_sha}), which matches no "
                            "captured tag version"
                        ),
                        observations=evidence,
                        details={
                            "link_id": link_id,
                            "job_id": job_id,
                            "pipeline_id": snapshot.pipeline_id,
                            "pipeline_sha": snapshot.pipeline_sha,
                            "captured_tag_shas": tag_shas,
                        },
                    )

        cross_check_step = self._steps_by_name["cross-check"]
        cross_check_step["divergence_detected"] = bool(self._divergences)

        return {
            "asset_links": asset_links,
            "located_pipelines": list(located.values()),
            "findings": self._findings,
            "divergences": self._divergences,
            "summary": {
                "observation_count": len(self._observations),
                "evidence_gap_count": len(self._gaps),
                "finding_count": len(self._findings),
                "asset_link_count": len(self._link_records),
                "located_pipeline_count": len(located),
                "divergence_detected": bool(self._divergences),
                "detected_at_step": (
                    self._divergences[0]["detected_at_step"]
                    if self._divergences
                    else None
                ),
                "tag_snapshots": [
                    {
                        "step": snapshot.step,
                        "observation_id": snapshot.observation_id,
                        "requested_at": snapshot.requested_at,
                        "sha": snapshot.sha,
                    }
                    for snapshot in self._tag_snapshots
                ],
            },
        }

    @staticmethod
    def _release_commit_sha(release: dict[str, Any] | None) -> str | None:
        if not isinstance(release, dict):
            return None
        commit = release.get("commit")
        if isinstance(commit, dict) and isinstance(commit.get("id"), str):
            return commit["id"]
        return None

    def _release_observation_id(self) -> str | None:
        for observation in self._observations:
            if observation.step == "release":
                return observation.observation_id
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def collect(self) -> dict[str, Any]:
        """Collect the evidence and return the export document as a dict."""
        self._begin_step("release", "Release object as served during collection")
        self._collect_release()

        self._begin_step("tag:initial", "Tag object before reading asset links")
        self._read_tag("tag:initial", "tag-before")

        self._begin_step(
            "release-links", "Release asset links, including pagination evidence"
        )
        self._collect_links()

        if self._recheck_tag:
            self._begin_step(
                "tag:reread",
                "Tag object re-read after asset links to expose migration",
            )
            self._read_tag("tag:reread", "tag-after")

        if self._include_jobs:
            self._begin_step("jobs", "CI jobs referenced by asset links")
            self._collect_jobs()
        elif self._link_records:
            self._add_gap(
                step="release-links",
                code="job_provenance_disabled",
                message=(
                    "Job resolution was disabled for this export, so asset "
                    "links cannot be tied back to pipelines"
                ),
                blocking=False,
                details={"asset_link_count": len(self._link_records)},
            )

        cross_checks = self._cross_check()

        release_id: int | None = None
        if isinstance(self._release, dict) and isinstance(
            self._release.get("id"), int
        ):
            release_id = self._release["id"]

        document: dict[str, Any] = {
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "generated_at": _utc_now(),
            "collector": {
                "name": "python-gitlab",
                "version": __version__,
                "server_url": self._gl.url,
                "api_version": self._gl.api_version,
            },
            "subject": {
                "project_id": self._project_id,
                "tag_name": self._tag_name,
                "release_id": release_id,
                "release_observation_id": self._release_observation_id(),
            },
            "steps": self._steps,
            "observations": [
                observation.to_dict() for observation in self._observations
            ],
            "evidence_gaps": self._gaps,
            "cross_checks": cross_checks,
        }
        document["integrity"] = {
            "algorithm": "sha256",
            "canonicalization": "json-sorted-utf8",
            "manifest_sha256": _manifest_digest(document),
        }
        return document


def summarize_export(document: dict[str, Any]) -> dict[str, Any]:
    """Return a compact, CLI-friendly summary of a full export document."""
    cross_checks = document.get("cross_checks", {})
    integrity = document.get("integrity", {})
    return {
        "schema": document.get("schema"),
        "schema_version": document.get("schema_version"),
        "generated_at": document.get("generated_at"),
        "subject": document.get("subject"),
        "observation_count": len(document.get("observations", [])),
        "evidence_gap_count": len(document.get("evidence_gaps", [])),
        "evidence_gaps": document.get("evidence_gaps", []),
        "cross_checks": cross_checks.get("summary", {}),
        "manifest_sha256": integrity.get("manifest_sha256"),
    }


def write_forensic_export(document: dict[str, Any], path: str | pathlib.Path) -> None:
    """Write an export document to ``path`` as UTF-8 JSON."""
    output = pathlib.Path(path).expanduser()
    output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_export(source: dict[str, Any] | str | pathlib.Path) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    if isinstance(source, pathlib.Path):
        text = source.read_text(encoding="utf-8")
    else:
        candidate = source.strip()
        if candidate.startswith("{"):
            text = candidate
        else:
            text = pathlib.Path(source).expanduser().read_text(encoding="utf-8")
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("Forensic export must be a JSON object")
    return parsed


def verify_forensic_export(
    source: dict[str, Any] | str | pathlib.Path,
) -> ForensicVerification:
    """Verify an export offline.

    The check has two independent layers:

    * each stored response body is re-hashed and compared to its recorded
      SHA-256 digest and size;
    * the manifest digest is recomputed from every field except ``integrity``,
      so any edit to timestamps, gaps, findings or digests is detected.

    Cross-references from steps, gaps and findings to observations are also
    validated. No network access is performed.

    Args:
        source: Export document, JSON string, or path to a JSON file.

    Returns:
        A :class:`ForensicVerification` with ``ok`` set to ``False`` and a
        list of structured problems when anything does not add up.
    """
    problems: list[dict[str, Any]] = []
    try:
        document = _load_export(source)
    except (OSError, ValueError, TypeError) as exc:
        return ForensicVerification(
            ok=False,
            problems=[
                {
                    "code": "malformed_export",
                    "message": f"Could not load forensic export: {exc}",
                }
            ],
            summary={},
        )

    if document.get("schema") != SCHEMA:
        problems.append(
            {
                "code": "schema_unsupported",
                "message": (
                    f"Expected schema {SCHEMA!r}, found "
                    f"{document.get('schema')!r}"
                ),
            }
        )
    if document.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            {
                "code": "schema_version_unsupported",
                "message": (
                    f"Expected schema version {SCHEMA_VERSION}, found "
                    f"{document.get('schema_version')!r}"
                ),
            }
        )

    observations = document.get("observations")
    if not isinstance(observations, list):
        problems.append(
            {
                "code": "malformed_export",
                "message": "Export has no observations list",
            }
        )
        observations = []

    known_ids: set[str] = set()
    body_count = 0
    for observation in observations:
        if not isinstance(observation, dict):
            problems.append(
                {
                    "code": "malformed_export",
                    "message": "Observation entry is not an object",
                }
            )
            continue
        observation_id = observation.get("observation_id")
        if isinstance(observation_id, str):
            if observation_id in known_ids:
                problems.append(
                    {
                        "code": "duplicate_observation_id",
                        "message": f"Duplicate observation id {observation_id}",
                        "observation_id": observation_id,
                    }
                )
            known_ids.add(observation_id)

        response = observation.get("response")
        body = response.get("body") if isinstance(response, dict) else None
        if not isinstance(body, dict):
            problems.append(
                {
                    "code": "malformed_export",
                    "message": "Observation has no response body",
                    "observation_id": observation_id,
                }
            )
            continue

        try:
            raw = _decode_body(body)
        except (ValueError, TypeError) as exc:
            problems.append(
                {
                    "code": "invalid_body_encoding",
                    "message": f"Could not decode body: {exc}",
                    "observation_id": observation_id,
                }
            )
            continue

        body_count += 1
        actual_digest = hashlib.sha256(raw).hexdigest()
        if actual_digest != body.get("sha256"):
            problems.append(
                {
                    "code": "body_sha256_mismatch",
                    "message": (
                        "Stored response body does not match its recorded "
                        "SHA-256 digest"
                    ),
                    "observation_id": observation_id,
                    "expected": body.get("sha256"),
                    "actual": actual_digest,
                }
            )
        if body.get("size") != len(raw):
            problems.append(
                {
                    "code": "body_size_mismatch",
                    "message": "Stored response body size does not match",
                    "observation_id": observation_id,
                    "expected": body.get("size"),
                    "actual": len(raw),
                }
            )

    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        problems.append(
            {
                "code": "missing_integrity",
                "message": "Export has no integrity block",
            }
        )
    else:
        expected_manifest = integrity.get("manifest_sha256")
        actual_manifest = _manifest_digest(document)
        if expected_manifest != actual_manifest:
            problems.append(
                {
                    "code": "manifest_sha256_mismatch",
                    "message": (
                        "The export manifest does not match its recorded digest"
                    ),
                    "expected": expected_manifest,
                    "actual": actual_manifest,
                }
            )

    def check_reference(observation_id: Any, context: str) -> None:
        if observation_id is None or observation_id == "":
            return
        if not isinstance(observation_id, str) or observation_id not in known_ids:
            problems.append(
                {
                    "code": "dangling_observation_reference",
                    "message": f"{context} references unknown observation",
                    "observation_id": observation_id,
                }
            )

    steps = document.get("steps", [])
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            for observation_id in step.get("observations", []) or []:
                check_reference(observation_id, f"Step {step.get('step')!r}")

    gaps = document.get("evidence_gaps", [])
    if isinstance(gaps, list):
        for gap in gaps:
            if isinstance(gap, dict):
                check_reference(gap.get("observation_id"), "Evidence gap")

    cross_checks = document.get("cross_checks", {})
    if isinstance(cross_checks, dict):
        for finding in cross_checks.get("findings", []) or []:
            if isinstance(finding, dict):
                for observation_id in finding.get("observations", []) or []:
                    check_reference(observation_id, "Finding")
        for pipeline in cross_checks.get("located_pipelines", []) or []:
            if isinstance(pipeline, dict):
                for observation_id in pipeline.get("observations", []) or []:
                    check_reference(observation_id, "Located pipeline")
        for link in cross_checks.get("asset_links", []) or []:
            if isinstance(link, dict):
                for observation_id in link.get("observations", []) or []:
                    check_reference(observation_id, "Asset link")

    return ForensicVerification(
        ok=not problems,
        problems=problems,
        summary={
            "observation_count": len(observations),
            "verified_body_count": body_count,
            "evidence_gap_count": len(gaps) if isinstance(gaps, list) else 0,
            "problem_count": len(problems),
            "manifest_sha256": (
                integrity.get("manifest_sha256")
                if isinstance(integrity, dict)
                else None
            ),
        },
    )
