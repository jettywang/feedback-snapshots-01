from __future__ import annotations

import pathlib
import re
from typing import Any

from gitlab import cli, forensics
from gitlab.base import RESTObject
from gitlab.mixins import CRUDMixin, ObjectDeleteMixin, SaveMixin
from gitlab.types import ArrayAttribute, RequiredOptional

__all__ = [
    "ProjectRelease",
    "ProjectReleaseManager",
    "ProjectReleaseLink",
    "ProjectReleaseLinkManager",
]


class ProjectRelease(SaveMixin, RESTObject):
    _id_attr = "tag_name"

    links: ProjectReleaseLinkManager

    @cli.register_custom_action(
        cls_names="ProjectRelease",
        optional=(
            "output_file",
            "include_jobs",
            "recheck_tag",
            "per_page",
            "max_pages",
            "jobs_limit",
        ),
        help="Collect an offline-reviewable forensic export for a release",
    )
    def forensic_export(
        self,
        *,
        output_file: str | pathlib.Path | None = None,
        include_jobs: bool | str | None = None,
        recheck_tag: bool | str | None = None,
        per_page: int | str | None = None,
        max_pages: int | str | None = None,
        jobs_limit: int | str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Collect an offline-reviewable evidence export for this release.

        The export preserves the raw responses and request timestamps exactly as
        they were served, so it stays valid even if the tag is rebuilt and no
        longer matches the pipeline that produced the downloaded asset. When
        ``output_file`` is given, the document is also written there as JSON.

        Args:
            output_file: Optional file path to write the JSON export to.
            include_jobs: Resolve CI jobs referenced by asset links.
            recheck_tag: Read the tag before and after the asset links so a tag
                migration during collection is detected and both raw responses
                are retained.
            per_page: Pagination size for list endpoints.
            max_pages: Safety limit for paginated endpoints.
            jobs_limit: Safety limit for job lookups.
            **kwargs: Extra options to send to the server (e.g. sudo). They are
                not forwarded to the individual evidence requests.

        Returns:
            The forensic export document as a dictionary.
        """
        project_id = getattr(self, "project_id", None)
        if project_id is None:
            project_id = self.manager.parent_attrs["project_id"]
        collector = forensics.ReleaseForensicCollector(
            self.manager.gitlab,
            project_id,
            self.tag_name,
            per_page=(
                None
                if per_page is None or per_page == ""
                else forensics._coerce_int(per_page, default=100)
            ),
            include_jobs=forensics._coerce_bool(include_jobs, default=True),
            recheck_tag=forensics._coerce_bool(recheck_tag, default=True),
            max_pages=forensics._coerce_int(max_pages, default=100),
            jobs_limit=forensics._coerce_int(jobs_limit, default=50),
        )
        document = collector.collect()
        if output_file is not None:
            forensics.write_forensic_export(document, output_file)
        return document


class ProjectReleaseManager(CRUDMixin[ProjectRelease]):
    _path = "/projects/{project_id}/releases"
    _obj_cls = ProjectRelease
    _from_parent_attrs = {"project_id": "id"}
    _create_attrs = RequiredOptional(
        required=("tag_name",), optional=("name", "description", "ref", "assets")
    )
    _list_filters = ("order_by", "sort", "include_html_description")
    _update_attrs = RequiredOptional(
        optional=("name", "description", "milestones", "released_at")
    )
    _types = {"milestones": ArrayAttribute}

    def forensic_export(
        self,
        tag_name: str,
        *,
        output_file: str | None = None,
        include_jobs: bool | str | None = None,
        recheck_tag: bool | str | None = None,
        per_page: int | str | None = None,
        max_pages: int | str | None = None,
        jobs_limit: int | str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Collect a release forensic export without pre-fetching the release.

        This is the manager-level entry point used by the CLI::

            gitlab project-release forensic-export --project-id 1 \\
                --tag-name v1.2.3 --output-file evidence.json

        See :meth:`ProjectRelease.forensic_export` for the arguments.
        """
        project_id = self._forensic_project_id()
        collector = forensics.ReleaseForensicCollector(
            self.gitlab,
            project_id,
            tag_name,
            per_page=(
                None
                if per_page is None or per_page == ""
                else forensics._coerce_int(per_page, default=100)
            ),
            include_jobs=forensics._coerce_bool(include_jobs, default=True),
            recheck_tag=forensics._coerce_bool(recheck_tag, default=True),
            max_pages=forensics._coerce_int(max_pages, default=100),
            jobs_limit=forensics._coerce_int(jobs_limit, default=50),
        )
        document = collector.collect()
        if output_file is not None:
            forensics.write_forensic_export(document, output_file)
        return document

    def _forensic_project_id(self) -> int | str:
        parent_attrs = self.parent_attrs
        if parent_attrs and "project_id" in parent_attrs:
            return parent_attrs["project_id"]
        match = re.search(r"/projects/(?P<project_id>[^/]+)/releases$", self.path)
        if match is None:  # pragma: no cover - malformed manager path
            raise ValueError("Cannot determine project ID from manager path")
        return match.group("project_id")


class ProjectReleaseLink(ObjectDeleteMixin, SaveMixin, RESTObject):
    pass


class ProjectReleaseLinkManager(CRUDMixin[ProjectReleaseLink]):
    _path = "/projects/{project_id}/releases/{tag_name}/assets/links"
    _obj_cls = ProjectReleaseLink
    _from_parent_attrs = {"project_id": "project_id", "tag_name": "tag_name"}
    _create_attrs = RequiredOptional(
        required=("name", "url"),
        optional=("filepath", "direct_asset_path", "link_type"),
    )
    _update_attrs = RequiredOptional(
        optional=("name", "url", "filepath", "direct_asset_path", "link_type")
    )
