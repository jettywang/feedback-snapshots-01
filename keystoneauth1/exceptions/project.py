# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystoneauth1.exceptions import base
from keystoneauth1.exceptions import catalog

__all__ = (
    'ProjectConstraintError',
    'ProjectIdentityUnavailable',
    'ProjectOwnershipError',
    'ProjectMismatch',
    'ProjectConstraintViolation',
    'ProjectEndpointError',
    'ProjectCatalogUnavailable',
    'StaleProjectEndpoint',
    'ProjectEndpointBlocked',
    'ProjectOwnershipViolation',
    'EndpointProjectMismatch',
    'UntrustedProjectEndpoint',
    'StaleEndpoint',
    'CatalogUnavailable',
)


class ProjectConstraintError(base.ClientException):
    """A project ownership constraint could not be satisfied."""

    message = "Project ownership constraint was not satisfied."
    default_reason_code = 'project_constraint_error'

    def __init__(self, message: str | None = None, **context: object) -> None:
        self.context = context
        self.project_id = context.get('project_id')
        self.expected_project_ids = context.get('expected_project_ids')
        self.state = context.get('state')
        self.reason = context.get('reason')
        self.url = context.get('url')
        self.reason_code = (
            context.get('reason_code')
            or getattr(self, 'default_reason_code', None)
        )
        self.code = self.reason_code
        super().__init__(message or self.message)


class ProjectIdentityUnavailable(ProjectConstraintError):
    """The current authentication evidence does not identify a project."""

    message = "The current authentication does not provide a project ID."
    default_reason_code = 'project_identity_unavailable'
    http_status = 401
    terminal = False
    retryable = True


class ProjectOwnershipError(ProjectConstraintError):
    """An endpoint or request belongs to a different project."""

    message = "Endpoint ownership does not match the project constraint."
    default_reason_code = 'project_mismatch'
    http_status = 403
    terminal = True
    retryable = False


# Descriptive aliases used by different callers/tests.
ProjectMismatch = ProjectOwnershipError
ProjectConstraintViolation = ProjectOwnershipError


class ProjectEndpointError(ProjectConstraintError, catalog.EndpointNotFound):
    """A project-owned endpoint cannot be used safely."""

    message = "No safe endpoint is available for the project constraint."
    default_reason_code = 'project_endpoint_unavailable'


class ProjectCatalogUnavailable(ProjectEndpointError):
    """Fresh catalog evidence is temporarily unavailable."""

    message = "The service catalog is unavailable for project verification."
    default_reason_code = 'catalog_unavailable'
    retryable = True
    terminal = False


class StaleProjectEndpoint(ProjectEndpointError):
    """A previously selected endpoint has not been revalidated."""

    message = "The selected project endpoint is stale and cannot be reused."
    default_reason_code = 'stale_endpoint'
    retryable = True
    terminal = False


class ProjectEndpointBlocked(ProjectEndpointError):
    """The project constraint stopped a request before it was sent."""

    message = "Request blocked by the project ownership constraint."
    default_reason_code = 'blocked'
    retryable = False
    terminal = True


ProjectOwnershipViolation = ProjectOwnershipError
EndpointProjectMismatch = ProjectMismatch
UntrustedProjectEndpoint = ProjectEndpointBlocked
StaleEndpoint = StaleProjectEndpoint
CatalogUnavailable = ProjectCatalogUnavailable
