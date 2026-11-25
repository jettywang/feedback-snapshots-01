"""
GitLab API:
https://docs.gitlab.com/ee/api/job_artifacts.html
"""

from __future__ import annotations

from typing import Any, Callable, Iterator, Literal, overload, TYPE_CHECKING

import requests

from gitlab import cli
from gitlab import exceptions as exc
from gitlab import transfer, utils
from gitlab.base import RESTManager, RESTObject

__all__ = ["ProjectArtifact", "ProjectArtifactManager"]


class ProjectArtifact(RESTObject):
    """Dummy object to manage custom actions on artifacts"""

    _id_attr = "ref_name"


class ProjectArtifactManager(RESTManager[ProjectArtifact]):
    _obj_cls = ProjectArtifact
    _path = "/projects/{project_id}/jobs/artifacts"
    _from_parent_attrs = {"project_id": "id"}

    def _fill_receipt(
        self,
        receipt: transfer.DownloadReceipt,
        *,
        ref_name: str,
        job: str,
        artifact_path: str | None,
    ) -> None:
        """Populate the project/job context of a download receipt."""
        receipt.project_id = (self.parent_attrs or {}).get("project_id")
        receipt.job_name = job
        receipt.ref_name = ref_name
        if artifact_path is not None:
            receipt.artifact_path = artifact_path

    @exc.on_http_error(exc.GitlabDeleteError)
    def delete(self, **kwargs: Any) -> None:
        """Delete the project's artifacts on the server.

        Args:
            **kwargs: Extra options to send to the server (e.g. sudo)

        Raises:
            GitlabAuthenticationError: If authentication is not correct
            GitlabDeleteError: If the server cannot perform the request
        """
        path = self._compute_path("/projects/{project_id}/artifacts")

        if TYPE_CHECKING:
            assert path is not None
        self.gitlab.http_delete(path, **kwargs)

    @overload
    def download(
        self,
        ref_name: str,
        job: str,
        streamed: Literal[False] = False,
        action: None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[False] = False,
        receipt: transfer.DownloadReceipt | None = None,
        **kwargs: Any,
    ) -> bytes: ...

    @overload
    def download(
        self,
        ref_name: str,
        job: str,
        streamed: bool = False,
        action: None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[True] = True,
        receipt: None = None,
        **kwargs: Any,
    ) -> Iterator[Any]: ...

    @overload
    def download(
        self,
        ref_name: str,
        job: str,
        streamed: Literal[True] = True,
        action: Callable[[bytes], Any] | None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[False] = False,
        receipt: transfer.DownloadReceipt | None = None,
        **kwargs: Any,
    ) -> None: ...

    @overload
    def download(
        self,
        ref_name: str,
        job: str,
        streamed: bool = False,
        action: None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[True] = True,
        receipt: transfer.DownloadReceipt,
        **kwargs: Any,
    ) -> transfer.AuditedStream: ...

    @cli.register_custom_action(
        cls_names="ProjectArtifactManager",
        required=("ref_name", "job"),
        optional=("job_token",),
    )
    @exc.on_http_error(exc.GitlabGetError)
    def download(
        self,
        ref_name: str,
        job: str,
        streamed: bool = False,
        action: Callable[[bytes], Any] | None = None,
        chunk_size: int = 1024,
        *,
        iterator: bool = False,
        receipt: transfer.DownloadReceipt | None = None,
        **kwargs: Any,
    ) -> bytes | Iterator[Any] | None:
        """Get the job artifacts archive from a specific tag or branch.

        Args:
            ref_name: Branch or tag name in repository. HEAD or SHA references
                are not supported.
            job: The name of the job.
            job_token: Job token for multi-project pipeline triggers.
            streamed: If True the data will be processed by chunks of
                `chunk_size` and each chunk is passed to `action` for
                treatment
            iterator: If True directly return the underlying response
                iterator
            action: Callable responsible of dealing with chunk of
                data
            chunk_size: Size of each chunk
            receipt: Optional :class:`~gitlab.transfer.DownloadReceipt`
                updated while chunks are received, providing an auditable
                record (project, job, received bytes, digest and completion
                state) of the download
            **kwargs: Extra options to send to the server (e.g. sudo)

        Raises:
            GitlabAuthenticationError: If authentication is not correct
            GitlabGetError: If the artifacts could not be retrieved

        Returns:
            The artifacts if `streamed` is False, None otherwise. When
            `iterator` and `receipt` are both provided, an
            :class:`~gitlab.transfer.AuditedStream` is returned.
        """
        path = f"{self.path}/{ref_name}/download"
        result = self.gitlab.http_get(
            path, job=job, streamed=streamed, raw=True, **kwargs
        )
        if TYPE_CHECKING:
            assert isinstance(result, requests.Response)
        if receipt is not None:
            self._fill_receipt(
                receipt, ref_name=ref_name, job=job, artifact_path=None
            )
        return utils.response_content(
            result, streamed, action, chunk_size, iterator=iterator, receipt=receipt
        )

    @overload
    def raw(
        self,
        ref_name: str,
        artifact_path: str,
        job: str,
        streamed: Literal[False] = False,
        action: None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[False] = False,
        receipt: transfer.DownloadReceipt | None = None,
        **kwargs: Any,
    ) -> bytes: ...

    @overload
    def raw(
        self,
        ref_name: str,
        artifact_path: str,
        job: str,
        streamed: bool = False,
        action: None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[True] = True,
        receipt: None = None,
        **kwargs: Any,
    ) -> Iterator[Any]: ...

    @overload
    def raw(
        self,
        ref_name: str,
        artifact_path: str,
        job: str,
        streamed: Literal[True] = True,
        action: Callable[[bytes], Any] | None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[False] = False,
        receipt: transfer.DownloadReceipt | None = None,
        **kwargs: Any,
    ) -> None: ...

    @overload
    def raw(
        self,
        ref_name: str,
        artifact_path: str,
        job: str,
        streamed: bool = False,
        action: None = None,
        chunk_size: int = 1024,
        *,
        iterator: Literal[True] = True,
        receipt: transfer.DownloadReceipt,
        **kwargs: Any,
    ) -> transfer.AuditedStream: ...

    @cli.register_custom_action(
        cls_names="ProjectArtifactManager",
        required=("ref_name", "artifact_path", "job"),
    )
    @exc.on_http_error(exc.GitlabGetError)
    def raw(
        self,
        ref_name: str,
        artifact_path: str,
        job: str,
        streamed: bool = False,
        action: Callable[[bytes], Any] | None = None,
        chunk_size: int = 1024,
        *,
        iterator: bool = False,
        receipt: transfer.DownloadReceipt | None = None,
        **kwargs: Any,
    ) -> bytes | Iterator[Any] | None:
        """Download a single artifact file from a specific tag or branch from
        within the job's artifacts archive.

        Args:
            ref_name: Branch or tag name in repository. HEAD or SHA references
                are not supported.
            artifact_path: Path to a file inside the artifacts archive.
            job: The name of the job.
            streamed: If True the data will be processed by chunks of
                `chunk_size` and each chunk is passed to `action` for
                treatment
            iterator: If True directly return the underlying response
                iterator
            action: Callable responsible of dealing with chunk of
                data
            chunk_size: Size of each chunk
            receipt: Optional :class:`~gitlab.transfer.DownloadReceipt`
                updated while chunks are received, providing an auditable
                record (project, job, received bytes, digest and completion
                state) of the download
            **kwargs: Extra options to send to the server (e.g. sudo)

        Raises:
            GitlabAuthenticationError: If authentication is not correct
            GitlabGetError: If the artifacts could not be retrieved

        Returns:
            The artifact if `streamed` is False, None otherwise. When
            `iterator` and `receipt` are both provided, an
            :class:`~gitlab.transfer.AuditedStream` is returned.
        """
        path = f"{self.path}/{ref_name}/raw/{artifact_path}"
        result = self.gitlab.http_get(
            path, streamed=streamed, raw=True, job=job, **kwargs
        )
        if TYPE_CHECKING:
            assert isinstance(result, requests.Response)
        if receipt is not None:
            self._fill_receipt(
                receipt,
                ref_name=ref_name,
                job=job,
                artifact_path=artifact_path,
            )
        return utils.response_content(
            result, streamed, action, chunk_size, iterator=iterator, receipt=receipt
        )
