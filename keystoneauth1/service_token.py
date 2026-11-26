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

"""A wrapper plugin to send service tokens with requests."""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from keystoneauth1 import discover
from keystoneauth1 import operation_authorization as op_auth
from keystoneauth1 import plugin
from keystoneauth1 import session as ks_session
from keystoneauth1.exceptions import auth_plugins

SERVICE_AUTH_HEADER_NAME = 'X-Service-Token'
USER_AUTH_HEADER_NAME = plugin.IDENTITY_AUTH_HEADER_NAME

__all__ = (
    'SERVICE_AUTH_HEADER_NAME',
    'USER_AUTH_HEADER_NAME',
    'ServiceTokenAuthWrapper',
    'OperationAuthorization',
    'OperationAuth',
    'OperationApproval',
    'OperationRequirement',
    'OperationGrant',
    'authorize_operation',
    'MissingUserCredentials',
    'MissingUserCredential',
    'MissingServiceCredentials',
    'MissingServiceCredential',
    'ServiceScopeMismatch',
)

OperationAuthorization = op_auth.OperationAuthorization
OperationAuth = OperationAuthorization
OperationApproval = OperationAuthorization
OperationRequirement = OperationAuthorization
OperationGrant = OperationAuthorization
authorize_operation = op_auth.operation_authorization_context
MissingUserCredentials = auth_plugins.MissingUserCredentials
MissingUserCredential = auth_plugins.MissingUserCredential
MissingServiceCredentials = auth_plugins.MissingServiceCredentials
MissingServiceCredential = auth_plugins.MissingServiceCredential
ServiceScopeMismatch = auth_plugins.ServiceScopeMismatch


class ServiceTokenAuthWrapper(plugin.BaseAuthPlugin):
    """A wrapper plugin that sends both a user token and a service token.

    This plugin combines a primary user authentication plugin and a secondary
    service authentication plugin. On outgoing HTTP requests, it injects both
    the standard user token (via ``X-Auth-Token``) and a service token (via
    ``X-Service-Token``).

    All other operations (such as token retrieval, endpoint discovery, version
    negotiation, and project/user ID resolution) are delegated to the
    underlying ``user_auth`` plugin.

    :param user_auth: The primary authentication plugin representing the user.
    :param service_auth: The secondary authentication plugin representing the
        service account.
    :param operation_authorization: Optional request-scoped authorization. When
        supplied, :meth:`get_headers` sends only the identities approved for
        the operation and validates the approved service scope.
    """

    def __init__(
        self,
        user_auth: plugin.BaseAuthPlugin,
        service_auth: plugin.BaseAuthPlugin,
        operation_authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
        **authorization_kwargs: Any,
    ):
        super().__init__()
        self.user_auth = user_auth
        self.service_auth = service_auth
        if operation_authorization is None and authorization_kwargs:
            operation_authorization = op_auth.OperationAuthorization(
                **authorization_kwargs
            )
        self.operation_authorization = op_auth.coerce_operation_authorization(
            operation_authorization
        )

    def for_operation(
        self,
        authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
        **kwargs: Any,
    ) -> 'ServiceTokenAuthWrapper':
        """Return a request-bound wrapper with its own operation approval.

        The returned wrapper shares the underlying user and service plugins,
        but its approval cannot be changed by another request's authentication
        or retry state.
        """
        if authorization is None and kwargs:
            authorization = op_auth.OperationAuthorization(**kwargs)
        approval = op_auth.coerce_operation_authorization(authorization)
        bound = type(self)(
            self.user_auth, self.service_auth, operation_authorization=approval
        )
        bound._discovery_cache = self._discovery_cache
        return bound

    bind_operation = for_operation

    @contextmanager
    def authorize(
        self,
        authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
        **kwargs: Any,
    ) -> Iterator['ServiceTokenAuthWrapper']:
        """Install an approval and yield a request-bound auth wrapper."""
        if authorization is None:
            approval = (
                op_auth.coerce_operation_authorization(
                    self.operation_authorization
                )
                if not kwargs
                else op_auth.OperationAuthorization(**kwargs)
            )
        else:
            approval = op_auth.coerce_operation_authorization(authorization)

        bound = self.for_operation(approval)
        with op_auth.operation_authorization_context(approval):
            yield bound

    operation = authorize

    def get_headers(
        self,
        session: ks_session.Session,
        authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
        *,
        operation_authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
        **authorization_kwargs: Any,
    ) -> dict[str, str] | None:
        """Fetch headers consistent with the operation's authorization.

        Without an operation authorization this preserves the wrapper's
        historical behavior: user headers plus a service token when one is
        available. With an authorization, missing approved credentials and
        service scope mismatches raise distinct exceptions instead of sending
        an incomplete identity set.
        """
        approval_value = (
            authorization
            if authorization is not None
            else operation_authorization
        )
        if approval_value is None and authorization_kwargs:
            approval_value = op_auth.OperationAuthorization(
                **authorization_kwargs
            )
        approval = op_auth.resolve_plugin_operation_authorization(
            approval_value, self
        )
        if approval is None:
            return self._get_legacy_headers(session)
        return self.get_operation_headers(session, approval)

    def _get_legacy_headers(
        self, session: ks_session.Session
    ) -> dict[str, str] | None:
        headers = self.user_auth.get_headers(session) or {}
        token = self.service_auth.get_token(session)
        if token:
            headers[SERVICE_AUTH_HEADER_NAME] = token

        return headers

    def get_operation_headers(
        self,
        session: ks_session.Session,
        authorization: op_auth.OperationAuthorization | None = None,
    ) -> dict[str, str]:
        """Return only the headers approved for ``authorization``."""
        approval = op_auth.resolve_plugin_operation_authorization(
            authorization, self
        )
        if approval is None:
            raise auth_plugins.OperationAuthorizationError(
                'An operation authorization is required.'
            )

        headers: dict[str, str] = {}

        if approval.requires_user:
            user_headers = self.user_auth.get_headers(session) or {}
            user_token = user_headers.get(USER_AUTH_HEADER_NAME)
            if not user_token:
                user_token = self.user_auth.get_token(session)
                if user_token:
                    user_headers[USER_AUTH_HEADER_NAME] = user_token
            if not user_token:
                raise auth_plugins.MissingUserCredentials()
            headers.update(user_headers)

        if approval.requires_service:
            service_token = self.service_auth.get_token(session)
            if not service_token:
                raise auth_plugins.MissingServiceCredentials()

            actual_scope = op_auth.extract_scope(self.service_auth, session)
            approval.require_scope_match(actual_scope)
            headers[SERVICE_AUTH_HEADER_NAME] = service_token

        return headers

    def invalidate(
        self,
        authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
        *,
        operation_authorization: (
            op_auth.OperationAuthorization | str | Mapping[str, Any] | None
        ) = None,
    ) -> bool:
        """Invalidate credentials allowed by the operation authorization.

        With no authorization, both plugins are invalidated to preserve the
        historical behavior. A user-only operation never invalidates the
        service credential.
        """
        approval_value = (
            authorization
            if authorization is not None
            else operation_authorization
        )
        approval = op_auth.resolve_plugin_operation_authorization(
            approval_value, self
        )
        if approval is None:
            return self._invalidate_both()

        changed = False
        if approval.requires_user:
            changed = bool(self.user_auth.invalidate()) or changed
        if approval.requires_service:
            changed = bool(self.service_auth.invalidate()) or changed
        return changed

    invalidate_operation = invalidate

    def _invalidate_both(self) -> bool:
        # NOTE(jamielennox): hmm, what to do here? Should we invalidate both
        # the service and user auth? Only one? There's no way to know what the
        # failure was to selectively invalidate.
        user = self.user_auth.invalidate()
        service = self.service_auth.invalidate()
        return user or service

    def get_connection_params(
        self, session: ks_session.Session
    ) -> plugin.ConnectionParams:
        """Return connection params from both plugins.

        Parameters from ``user_auth`` take priority over ``service_auth``
        parameters.
        """
        # NOTE(jamielennox): This is also a bit of a guess but unlikely to be a
        # problem in practice. We don't know how merging connection parameters
        # between these plugins will conflict - but there aren't many plugins
        # that set this anyway.
        # Take the service auth params first so that user auth params will be
        # given priority.
        params = self.service_auth.get_connection_params(session)
        params.update(self.user_auth.get_connection_params(session))
        return params

    # TODO(jamielennox): Everything below here is a generic wrapper that could
    # be extracted into a base wrapper class. We can do this as soon as there
    # is a need for it, but we may never actually need it.

    def get_token(self, session: ks_session.Session) -> str | None:
        return self.user_auth.get_token(session)

    def get_endpoint(
        self, session: ks_session.Session, **kwargs: Any
    ) -> str | None:
        return self.user_auth.get_endpoint(session, **kwargs)

    def get_endpoint_data(
        self,
        session: ks_session.Session,
        *,
        endpoint_override: str | None = None,
        discover_versions: bool = True,
        **kwargs: Any,
    ) -> discover.EndpointData | None:
        return self.user_auth.get_endpoint_data(
            session,
            endpoint_override=endpoint_override,
            discover_versions=discover_versions,
            **kwargs,
        )

    def get_api_major_version(
        self, session: ks_session.Session, **kwargs: Any
    ) -> tuple[int | float, ...] | None:
        return self.user_auth.get_api_major_version(session, **kwargs)

    def get_user_id(self, session: ks_session.Session) -> str | None:
        return self.user_auth.get_user_id(session)

    def get_project_id(self, session: ks_session.Session) -> str | None:
        return self.user_auth.get_project_id(session)

    def get_sp_auth_url(
        self, session: ks_session.Session, sp_id: str
    ) -> str | None:
        return self.user_auth.get_sp_auth_url(session, sp_id)

    def get_sp_url(
        self, session: ks_session.Session, sp_id: str
    ) -> str | None:
        return self.user_auth.get_sp_url(session, sp_id)
