# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Interfaces for asynchronous credentials."""

import copy

from google.auth import _helpers
from google.auth import authorization
from google.auth import exceptions
from google.auth._credentials_base import _BaseCredentials


class Credentials(_BaseCredentials):
    """Base class for all asynchronous credentials.

    All credentials have a :attr:`token` that is used for authentication and
    may also optionally set an :attr:`expiry` to indicate when the token will
    no longer be valid.

    Most credentials will be :attr:`invalid` until :meth:`refresh` is called.
    Credentials can do this automatically before the first HTTP request in
    :meth:`before_request`.

    Although the token and expiration will change as the credentials are
    :meth:`refreshed <refresh>` and used, credentials should be considered
    immutable. Various credentials will accept configuration such as private
    keys, scopes, and other options. These options are not changeable after
    construction. Some classes will provide mechanisms to copy the credentials
    with modifications such as :meth:`ScopedCredentials.with_scopes`.
    """

    def __init__(self):
        super(Credentials, self).__init__()

    async def apply(self, headers, token=None):
        """Apply the token to the authentication header.

        Args:
            headers (Mapping): The HTTP request headers.
            token (Optional[str]): If specified, overrides the current access
                token.
        """
        self._apply(headers, token=token)

    async def refresh(self, request):
        """Refreshes the access token.

        Args:
            request (google.auth.aio.transport.Request): The object used to make
                HTTP requests.

        Raises:
            google.auth.exceptions.RefreshError: If the credentials could
                not be refreshed.
        """
        raise NotImplementedError("Refresh must be implemented")

    @property
    def operation_permission(self):
        """Optional permission checked by :meth:`before_request`."""
        return getattr(self, "_operation_permission", None)

    @operation_permission.setter
    def operation_permission(self, value):
        self._operation_permission = value

    def with_operation_permission(self, operation_permission):
        """Returns a copy of these credentials with an operation permission.

        Args:
            operation_permission (Optional[Union[google.auth.authorization.OperationPermission, Callable]]):
                The permission to approve on :meth:`before_request`.

        Returns:
            google.auth.aio.credentials.Credentials: A copy with the permission.
        """
        credentials = copy.copy(self)
        credentials.operation_permission = operation_permission
        return credentials

    async def before_request(self, request, method, url, headers):
        """Performs credential-specific before request logic.

        Refreshes the credentials if necessary, then calls :meth:`apply` to
        apply the token to the authentication header.

        When the credential has an ``operation_permission`` attribute, it is
        checked against the supplied method and URL before the token is
        applied.

        Args:
            request (google.auth.aio.transport.Request): The object used to make
                HTTP requests.
            method (str): The request's HTTP method or the RPC method being
                invoked.
            url (str): The request's URI or the RPC service's URI.
            headers (Mapping): The request's headers.
        """
        authorization.check_operation_permission(
            getattr(self, "operation_permission", None), method, url
        )
        await self.apply(headers)


class StaticCredentials(Credentials):
    """Asynchronous Credentials representing an immutable access token.

    The credentials are considered immutable except the tokens which can be
    configured in the constructor ::

        credentials = StaticCredentials(token="token123")

    StaticCredentials does not support :meth `refresh` and assumes that the configured
    token is valid and not expired. StaticCredentials will never attempt to
    refresh the token.
    """

    def __init__(self, token):
        """
        Args:
            token (str): The access token.
        """
        super(StaticCredentials, self).__init__()
        self.token = token

    @_helpers.copy_docstring(Credentials)
    async def refresh(self, request):
        raise exceptions.InvalidOperation("Static credentials cannot be refreshed.")

    # Note: before_request should never try to refresh access tokens.
    # StaticCredentials intentionally does not support it.
    @_helpers.copy_docstring(Credentials)
    async def before_request(self, request, method, url, headers):
        await self.apply(headers)


class AnonymousCredentials(Credentials):
    """Asynchronous Credentials that do not provide any authentication information.

    These are useful in the case of services that support anonymous access or
    local service emulators that do not use credentials.
    """

    async def refresh(self, request):
        """Raises :class:``InvalidOperation``, anonymous credentials cannot be
        refreshed."""
        raise exceptions.InvalidOperation("Anonymous credentials cannot be refreshed.")

    async def apply(self, headers, token=None):
        """Anonymous credentials do nothing to the request.

        The optional ``token`` argument is not supported.

        Raises:
            google.auth.exceptions.InvalidValue: If a token was specified.
        """
        if token is not None:
            raise exceptions.InvalidValue("Anonymous credentials don't support tokens.")

    async def before_request(self, request, method, url, headers):
        """Anonymous credentials do nothing to the request."""
        pass
