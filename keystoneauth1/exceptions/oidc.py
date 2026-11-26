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


from keystoneauth1.exceptions import auth_plugins

__all__ = (
    'InvalidDiscoveryEndpoint',
    'InvalidOidcDiscoveryDocument',
    'OidcAccessTokenEndpointNotFound',
    'OidcAuthorizationEndpointNotFound',
    'OidcInvalidCodeChallengeMethod',
    'OidcLoginReopenRequired',
    'OidcLoginScopeMismatch',
    'OidcPluginNotSupported',
)


class InvalidDiscoveryEndpoint(auth_plugins.AuthPluginException):
    message = "OpenID Connect Discovery Document endpoint not set."


class InvalidOidcDiscoveryDocument(auth_plugins.AuthPluginException):
    message = "OpenID Connect Discovery Document is not valid JSON."


class OidcAccessTokenEndpointNotFound(auth_plugins.AuthPluginException):
    message = "OpenID Connect access token endpoint not provided."


class OidcAuthorizationEndpointNotFound(auth_plugins.AuthPluginException):
    message = "OpenID Connect authorization endpoint not provided."


class OidcDeviceAuthorizationEndpointNotFound(
    auth_plugins.AuthPluginException
):
    message = "OpenID Connect device authorization endpoint not provided."


class OidcDeviceAuthorizationTimeOut(auth_plugins.AuthPluginException):
    message = "Timeout for OpenID Connect device authorization."


class OidcInvalidCodeChallengeMethod(auth_plugins.AuthPluginException):
    message = "Invalid code challenge method."


class OidcPluginNotSupported(auth_plugins.AuthPluginException):
    message = "OpenID Connect grant type not supported by provider."


class OidcLoginReopenRequired(auth_plugins.AuthPluginException):
    """A login cannot finish under the configuration it started under.

    Raised when the approved identity provider configuration that an
    in-progress login is bound to has been withdrawn, retired, or is not
    known. The login has not been handed to Keystone; starting a new login
    uses the currently approved configuration instead.

    :param reason: Why the login cannot continue. One of ``withdrawn``,
        ``retired`` or ``unknown``.
    :param generation: Generation of the approval the login started under.
    :param login_id: The receipt's login identifier, if known.
    """

    message = (
        "The approved identity provider configuration for this login is no "
        "longer valid; start the login again."
    )

    def __init__(
        self,
        message: str | None = None,
        *,
        reason: str | None = None,
        generation: str | None = None,
        login_id: str | None = None,
    ):
        self.reason = reason
        self.generation = generation
        self.login_id = login_id
        message = message or self.message
        if reason:
            message = f'{message} (reason: {reason})'
        super().__init__(message)


class OidcLoginScopeMismatch(auth_plugins.AuthPluginException):
    """The scope finally handed to Keystone differs from the receipt.

    A login receipt records the scope chosen when the login was started. If
    the plugin is asked to finish that login with a different project, domain,
    system or trust, the receiving Keystone could not be sure which local
    principal the login was started for, so the login is refused rather than
    silently scoped somewhere else.

    :param receipt_scope: The scope recorded on the receipt.
    :param requested_scope: The scope the plugin would hand to Keystone.
    """

    message = "The login scope differs from the one it started with."

    def __init__(
        self,
        message: str | None = None,
        *,
        receipt_scope: dict[str, str] | None = None,
        requested_scope: dict[str, str] | None = None,
        login_id: str | None = None,
    ):
        self.receipt_scope = receipt_scope or {}
        self.requested_scope = requested_scope or {}
        self.login_id = login_id
        super().__init__(message or self.message)
