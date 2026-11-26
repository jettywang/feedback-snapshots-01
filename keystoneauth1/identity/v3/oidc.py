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

import abc
import base64
import copy
import hashlib
import logging
import os
import time
from typing import cast, ClassVar, TypeVar
from urllib import parse as urlparse

import requests

from keystoneauth1 import _utils as utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import approval
from keystoneauth1.identity.v3 import federation
from keystoneauth1 import session as ks_session

LOG = utils.get_logger(__name__)

__all__ = (
    'OidcAuthorizationCode',
    'OidcClientCredentials',
    'OidcPassword',
    'OidcAccessToken',
)

SENSITIVE_KEYS = ("password", "code", "token", "secret", "otp", "totp", "mfa")

HEADER_APPROVAL = 'X-Keystoneauth-Approval'
HEADER_LOGIN = 'X-Keystoneauth-Login'


_OidcBaseT = TypeVar('_OidcBaseT', bound='_OidcBase')


class _OidcBase(federation.FederationBaseAuth, metaclass=abc.ABCMeta):
    """Base class for different OpenID Connect based flows.

    The OpenID Connect specification can be found at::
    ``http://openid.net/specs/openid-connect-core-1_0.html``
    """

    grant_type: ClassVar[str]

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str | None,
        access_token_type: str,
        scope: str,
        access_token_endpoint: str | None,
        discovery_endpoint: str | None,
        *,
        trust_id: str | None,
        system_scope: str | None,
        domain_id: str | None,
        domain_name: str | None,
        project_id: str | None,
        project_name: str | None,
        project_domain_id: str | None,
        project_domain_name: str | None,
        reauthenticate: bool,
        include_catalog: bool,
        approvals: approval.ProviderApprovals | None,
    ):
        """The OpenID Connect plugin expects the following.

        :param auth_url: URL of the Identity Service
        :param identity_provider: Name of the Identity Provider the client will
            authenticate against
        :param protocol: Protocol name as configured in keystone
        :param client_id: OAuth 2.0 Client ID
        :param client_secret: OAuth 2.0 Client Secret
        :param access_token_type: OAuth 2.0 Authorization Server Introspection
            token type, it is used to decide which type of token will be used
            when processing token introspection. Valid values are:
            "access_token" or "id_token"
        :param access_token_endpoint: OpenID Connect Provider Token Endpoint,
            for example: https://localhost:8020/oidc/OP/token Note that if a
            discovery document is provided this value will override the
            discovered one.
        :param discovery_endpoint: OpenID Connect Discovery Document URL,
            for example:
            https://localhost:8020/oidc/.well-known/openid-configuration
        :param scope: OpenID Connect scope that is requested from OP, for
            example: "openid profile email", defaults to "openid profile". Note
            that OpenID Connect specification states that "openid" must be
            always specified.
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
        )

        self.client_id = client_id
        self.client_secret = client_secret

        self.discovery_endpoint = discovery_endpoint
        self._discovery_document: dict[str, object] = {}
        self.access_token_endpoint = access_token_endpoint

        self.access_token_type = access_token_type
        self.scope = scope

        # An approval registry replaces the endpoint parameters with the
        # approved generation's values, so a login cannot be pointed at a
        # provider other than the one it was started against.
        self.approvals = approvals
        self.login_receipt: approval.LoginReceipt | None = None
        self._approval: approval.ProviderApproval | None = None

    # -- approved configuration ------------------------------------------

    def set_approvals(
        self, approvals: approval.ProviderApprovals | None
    ) -> None:
        """Use the given registry for later logins."""
        self.approvals = approvals

    def _scope_elements(self) -> dict[str, str]:
        elements = {}
        for field in approval.SCOPE_FIELDS:
            value = getattr(self, field)
            if value is not None:
                elements[field] = str(value)
        return elements

    def start_login(
        self, approvals: approval.ProviderApprovals | None = None
    ) -> approval.LoginReceipt:
        """Record the approval and scope a new login is started under.

        Call this before presenting anything to the user. Keep the receipt
        with whatever lets the login resume - an authorization code, a device
        code - and pass it to :meth:`get_unscoped_auth_ref`. New logins use
        the current approval of the registry.

        :param approvals: Registry to use, if not the plugin's own.
        :returns: A receipt to store and hand back.
        """
        registry = approvals or self.approvals
        if registry is None:
            raise ValueError(
                'An approved configuration registry is required to start a '
                'login'
            )

        current = registry.current()
        self.approvals = registry
        self.bind_approval(current)
        receipt = approval.LoginReceipt(
            current.generation,
            self._scope_elements(),
            openid_scope=self.scope,
            identity_provider=self.identity_provider,
            protocol=self.protocol,
        )
        self.login_receipt = receipt
        return receipt

    def set_login_receipt(
        self, receipt: approval.LoginReceipt | str | None
    ) -> None:
        """Resume a login started earlier, using its receipt.

        Pass what :meth:`start_login` returned, or the string
        :meth:`~keystoneauth1.identity.v3.LoginReceipt.to_string` produces.
        The receipt pins the approval generation and the Keystone scope; the
        next authentication checks both.

        :raises ValueError: The input is not a login receipt.
        """
        if receipt is None:
            self.login_receipt = None
            return

        if isinstance(receipt, str):
            receipt = approval.LoginReceipt.from_string(receipt)
        elif not isinstance(receipt, approval.LoginReceipt):
            raise ValueError('Not a login receipt')

        self.login_receipt = receipt

    def bind_approval(
        self, approved: approval.ProviderApproval
    ) -> None:
        """Point the plugin at an approved generation's endpoints.

        An endpoint the approval names replaces the plugin's own option; one
        it leaves unset keeps the configured default. A cached discovery
        document is dropped whenever it belonged to a different generation,
        so it is refetched from the endpoint the login is now bound to.
        """
        previous = self._approval
        if previous is not None and (
            approved.generation == previous.generation
        ):
            return

        self._approval = approved
        self.identity_provider = approved.identity_provider
        self.protocol = approved.protocol
        self.auth_url = approved.auth_url

        if approved.discovery_endpoint is not None:
            if previous is not None and (
                approved.discovery_endpoint != self.discovery_endpoint
            ):
                self._discovery_document = {}
            self.discovery_endpoint = approved.discovery_endpoint

        if approved.access_token_endpoint is not None:
            self.access_token_endpoint = approved.access_token_endpoint

        if approved.device_authorization_endpoint is not None:
            self._device_authorization_endpoint = (
                approved.device_authorization_endpoint
            )

    def _bound_approval(self) -> approval.ProviderApproval | None:
        """The approval this login is bound to, resolved through the registry.

        A receipt always wins: it names the generation the login started
        under, and the registry is asked whether that generation is still
        valid. Without a receipt the plugin uses the current approval.
        """
        if self.login_receipt is None:
            if self.approvals is None:
                return self._approval
            return self.approvals.current()

        if self.approvals is None:
            if self._approval is None:
                raise exceptions.OidcLoginReopenRequired(
                    reason='unknown',
                    generation=self.login_receipt.generation,
                    login_id=self.login_receipt.login_id,
                )
            if self._approval.generation != self.login_receipt.generation:
                raise exceptions.OidcLoginReopenRequired(
                    reason='unknown',
                    generation=self.login_receipt.generation,
                    login_id=self.login_receipt.login_id,
                )
            return self._approval

        return self.approvals.resolve(self.login_receipt)

    def _check_scope(self, receipt: approval.LoginReceipt) -> None:
        """Refuse to hand Keystone a scope other than the receipt's."""
        receipt_scope = receipt.scope
        requested_scope = self._scope_elements()
        if receipt_scope != requested_scope:
            raise exceptions.OidcLoginScopeMismatch(
                receipt_scope=receipt_scope,
                requested_scope=requested_scope,
                login_id=receipt.login_id,
            )

    def _check_rescope_target(self) -> None:
        """Check the scope about to be handed to the identity service."""
        if self.login_receipt is not None:
            self._check_scope(self.login_receipt)

    def _unscoped_token_matches(
        self, auth_ref: access.AccessInfoV3
    ) -> bool:
        """Require a held token to name the approval it was obtained under.

        The base check compares the token's identity provider and protocol
        with the plugin's current ones. With an approval registry there can
        be two valid generations at once whose provider names coincide, so
        the token has to name the generation the login is bound to. Resolving
        the approval here means a withdrawn or retired receipt is refused
        even when a cached unscoped token is still held.
        """
        if not super()._unscoped_token_matches(auth_ref):
            return False

        approved = self._bound_approval()
        if approved is None:
            return True

        identity = self._unscoped_token_identity(auth_ref)
        return identity is not None and identity == (
            approved.identity_provider,
            approved.protocol,
        )

    def get_unscoped_cache_id_elements(self) -> dict[str, str | None]:
        """Add the OAuth client to what identifies the unscoped token.

        The token is issued to a particular client, so the client id and
        secret join the federation elements from the base. Including the
        secret means rotating it discards any cached token, matching how the
        password plugin treats a changed password. The elements are only
        ever hashed, never stored in the clear.
        """
        elements = super().get_unscoped_cache_id_elements()
        elements['client_id'] = self.client_id
        elements['client_secret'] = self.client_secret
        if self._approval is not None:
            elements['approval_generation'] = self._approval.generation
        return elements

    def _get_discovery_document(
        self, session: ks_session.Session
    ) -> dict[str, object]:
        """Get the contents of the OpenID Connect Discovery Document.

        This method grabs the contents of the OpenID Connect Discovery Document
        if a discovery_endpoint was passed to the constructor and returns it as
        a dict, otherwise returns an empty dict. Note that it will fetch the
        discovery document only once, so subsequent calls to this method will
        return the cached result, if any.

        :param session: a session object to send out HTTP requests.
        :returns: a dictionary containing the discovery document if any,
            else an empty dict.
        """
        if (
            self.discovery_endpoint is not None
            and not self._discovery_document
        ):
            try:
                resp = session.get(
                    self.discovery_endpoint, authenticated=False
                )
            except exceptions.HttpError:
                LOG.error(
                    "Cannot fetch discovery document %s",
                    self.discovery_endpoint,
                )
                raise

            try:
                self._discovery_document = resp.json()
            except Exception:  # noqa: S110
                # we handle this below
                pass

            if not self._discovery_document:
                raise exceptions.InvalidOidcDiscoveryDocument()

        return self._discovery_document

    def _get_access_token_endpoint(self, session: ks_session.Session) -> str:
        """Get the "token_endpoint" for the OpenID Connect flow.

        This method will return the correct access token endpoint to be used.
        If the user has explicitly passed an access_token_endpoint to the
        constructor that will be returned. If there is no explicit endpoint and
        a discovery url is provided, it will try to get it from the discovery
        document. If nothing is found, an exception will be raised.

        :param session: a session object to send out HTTP requests.
        :return: the endpoint to use
        """
        if self.access_token_endpoint is not None:
            return self.access_token_endpoint

        discovery = self._get_discovery_document(session)
        endpoint = discovery.get("token_endpoint")
        if endpoint is None:
            raise exceptions.OidcAccessTokenEndpointNotFound()
        return cast(str, endpoint)

    def _sanitize(self, data: dict[str, str | None]) -> dict[str, str | None]:
        sanitized = copy.deepcopy(data)
        for key in sanitized:
            if any(s in key for s in SENSITIVE_KEYS):
                sanitized[key] = "***"
        return sanitized

    def _prepare_login(self) -> approval.ProviderApproval:
        """Resolve and apply the approval this attempt must use.

        All three steps of a login - discovery, the token exchange and the
        federated endpoint that performs the local principal mapping - are
        built from the approval returned here, so they cannot disagree about
        which generation is in force.
        """
        approved = self._bound_approval()
        if approved is not None:
            self.bind_approval(approved)

        if self.login_receipt is not None:
            self._check_scope(self.login_receipt)

        return approved

    def _correlation_headers(self) -> dict[str, str]:
        """Headers that tie the requests to the receipt they belong to."""
        headers: dict[str, str] = {}
        if self._approval is not None:
            headers[HEADER_APPROVAL] = self._approval.generation
        if self.login_receipt is not None:
            headers[HEADER_LOGIN] = self.login_receipt.login_id
        return headers

    def _get_access_token(
        self, session: ks_session.Session, payload: dict[str, str | None]
    ) -> str:
        """Exchange a variety of user supplied values for an access token.

        :param session: a session object to send out HTTP requests.
        :param payload: a dict containing various OpenID Connect values, for
            example::

                {
                    'grant_type': 'password',
                    'username': self.username,
                    'password': self.password,
                    'scope': self.scope,
                }
        """
        if self.client_secret:
            client_auth = (self.client_id, self.client_secret)
        else:
            client_auth = None
            payload.setdefault('client_id', self.client_id)
        access_token_endpoint = self._get_access_token_endpoint(session)

        if LOG.isEnabledFor(logging.DEBUG):
            sanitized_payload = self._sanitize(payload)
            LOG.debug(
                "Making OpenID-Connect authentication request to %s with "
                "data %s",
                access_token_endpoint,
                sanitized_payload,
            )

        op_response = session.post(
            access_token_endpoint,
            requests_auth=client_auth,
            headers=self._correlation_headers(),
            data=payload,
            log=False,
            authenticated=False,
        )
        response = op_response.json()
        if LOG.isEnabledFor(logging.DEBUG):
            sanitized_response = self._sanitize(response)
            LOG.debug(
                "OpenID-Connect authentication response from %s is %s",
                access_token_endpoint,
                sanitized_response,
            )
        access_token = response[self.access_token_type]
        assert isinstance(access_token, str)  # nosec: B101
        return access_token

    def _get_keystone_token(
        self, session: ks_session.Session, access_token: str
    ) -> requests.Response:
        r"""Exchange an access token for a keystone token.

        By Sending the access token in an `Authorization: Bearer` header, to
        an OpenID Connect protected endpoint (Federated Token URL). The
        OpenID Connect server will use the access token to look up information
        about the authenticated user (this technique is called introspection).
        The output of the introspection will be an OpenID Connect Claim, that
        will be used against the mapping engine. Should the mapping engine
        succeed, a Keystone token will be presented to the user.

        :param session: a session object to send out HTTP requests.
        :param access_token: The OpenID Connect access token.
        """
        # use access token against protected URL
        headers = {'Authorization': 'Bearer ' + access_token}
        headers.update(self._correlation_headers())
        auth_response = session.post(
            self.federated_token_url, headers=headers, authenticated=False
        )
        return auth_response

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Authenticate with OpenID Connect and get back claims.

        This is a multi-step process:

        1.- An access token must be retrieved from the server. In order to do
            so, we need to exchange an authorization grant or refresh token
            with the token endpoint in order to obtain an access token. The
            authorization grant varies from plugin to plugin.

        2.- We then exchange the access token upon accessing the protected
            Keystone endpoint (federated auth URL). This will trigger the
            OpenID Connect Provider to perform a user introspection and
            retrieve information (specified in the scope) about the user in the
            form of an OpenID Connect Claim. These claims will be sent to
            Keystone in the form of environment variables.

        :param session: a session object to send out HTTP requests.
        :returns: a token data representation
        """
        # First of all, check if the grant type is supported
        self._prepare_login()
        discovery = self._get_discovery_document(session)
        grant_types = cast(
            list[str] | None, discovery.get("grant_types_supported")
        )
        if (
            grant_types
            and self.grant_type is not None
            and self.grant_type not in grant_types
        ):
            raise exceptions.OidcPluginNotSupported()

        # Get the payload
        payload = self.get_payload(session)
        payload.setdefault('grant_type', self.grant_type)

        # get an access token
        access_token = self._get_access_token(session, payload)

        response = self._get_keystone_token(session, access_token)

        # grab the unscoped token
        access_info = access.create(resp=response)
        assert isinstance(access_info, access.AccessInfoV3)  # nosec B101
        return access_info

    @abc.abstractmethod
    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, str | None]:
        """Get the plugin specific payload for obtaining an access token.

        OpenID Connect supports different grant types. This method should
        prepare the payload that needs to be exchanged with the server in
        order to get an access token for the particular grant type that the
        plugin is implementing.

        :param session: a session object to send out HTTP requests.
        :returns: a python dictionary containing the payload to be exchanged
        """
        raise NotImplementedError()


class OidcPassword(_OidcBase):
    """Implementation for OpenID Connect Resource Owner Password Credential."""

    grant_type = "password"

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str,
        access_token_type: str = 'access_token',  # noqa: S107
        scope: str = 'openid profile',
        access_token_endpoint: str | None = None,
        discovery_endpoint: str | None = None,
        username: str | None = None,
        password: str | None = None,
        idp_otp_key: str | None = None,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
        approvals: approval.ProviderApprovals | None = None,
    ):
        """The OpenID Password plugin expects the following.

        :param username: Username used to authenticate
        :param password: Password used to authenticate
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
            approvals=approvals,
        )
        self.username = username
        self.password = password
        self.idp_otp_key = idp_otp_key

    def get_unscoped_cache_id_elements(self) -> dict[str, str | None]:
        """Add the resource owner to what identifies the unscoped token.

        The token stands in for a particular user, so the username and
        password identify it. Without the username two users of the same
        client and identity provider would share one cached unscoped token;
        including the password discards it when the password changes, as the
        password plugin does.
        """
        elements = super().get_unscoped_cache_id_elements()
        elements['username'] = self.username
        elements['password'] = self.password
        return elements

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, str | None]:
        """Get an authorization grant for the "password" grant type.

        :param session: a session object to send out HTTP requests.
        :returns: a python dictionary containing the payload to be exchanged
        """
        payload = {
            'username': self.username,
            'password': self.password,
            'scope': self.scope,
        }

        self.manage_otp_from_session_or_request_to_the_user(payload, session)

        return payload

    def manage_otp_from_session_or_request_to_the_user(
        self, payload: dict[str, str | None], session: ks_session.Session
    ) -> None:
        """Get the OTP code from the session or else request to the user.

        When the OS_IDP_OTP_KEY environment variable is set, this method will
        verify if there is an OTP value in the current session, if it exists,
        we use it (the OTP from session) to send to the Identity Provider when
        retrieving the access token. If there is no OTP in the current session,
        we ask the user to enter it (the OTP), and we add it to the session to
        execute the authentication flow.

        The OTP is being stored in the session because in some flows, the CLI
        is doing the authentication process two times, so saving the OTP
        in the session, allow us to use the same OTP in a short time interval,
        avoiding to request it to the user twice in a row.

        :param payload:
        :param session:
        :return:
        """
        if not self.idp_otp_key:
            return

        otp_from_session = getattr(session, 'otp', None)
        if otp_from_session:
            payload[self.idp_otp_key] = otp_from_session
        else:
            payload[self.idp_otp_key] = input(
                "Please, enter the generated OTP code: "
            )
            setattr(session, 'otp', payload[self.idp_otp_key])


class OidcClientCredentials(_OidcBase):
    """Implementation for OpenID Connect Client Credentials."""

    grant_type = 'client_credentials'

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str,
        access_token_type: str = 'access_token',  # noqa: S107
        scope: str = 'openid profile',
        access_token_endpoint: str | None = None,
        discovery_endpoint: str | None = None,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
        approvals: approval.ProviderApprovals | None = None,
    ):
        """The OpenID Client Credentials expects the following.

        :param client_id: Client ID used to authenticate
        :param client_secret: Client Secret used to authenticate
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
            approvals=approvals,
        )

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, str | None]:
        """Get an authorization grant for the client credentials grant type.

        :param session: a session object to send out HTTP requests.
        :returns: a python dictionary containing the payload to be exchanged
        """
        payload: dict[str, str | None] = {'scope': self.scope}
        return payload


class OidcAuthorizationCode(_OidcBase):
    """Implementation for OpenID Connect Authorization Code."""

    # The user completes the authorization request in a browser.
    interactive_unscoped_auth = True

    grant_type = 'authorization_code'

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str,
        access_token_type: str = 'access_token',  # noqa: S107
        scope: str = 'openid profile',
        access_token_endpoint: str | None = None,
        discovery_endpoint: str | None = None,
        code: str | None = None,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
        redirect_uri: str | None = None,
        approvals: approval.ProviderApprovals | None = None,
    ):
        """The OpenID Authorization Code plugin expects the following.

        :param redirect_uri: OpenID Connect Client Redirect URL
        :param code: OAuth 2.0 Authorization Code
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
            approvals=approvals,
        )
        self.redirect_uri = redirect_uri
        self.code = code

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, str | None]:
        """Get an authorization grant for the "authorization_code" grant type.

        :param session: a session object to send out HTTP requests.
        :returns: a python dictionary containing the payload to be exchanged
        """
        payload = {'redirect_uri': self.redirect_uri, 'code': self.code}

        return payload


class OidcAccessToken(_OidcBase):
    """Implementation for OpenID Connect access token reuse."""

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        # client_id and client_id intentionally omitted since they don't make
        # sense with an access token
        access_token_type: str = 'access_token',  # noqa: S107
        scope: str = 'openid profile',
        access_token_endpoint: str | None = None,
        discovery_endpoint: str | None = None,
        access_token: str | None = None,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
        approvals: approval.ProviderApprovals | None = None,
    ):
        """The OpenID Connect plugin based on the Access Token.

        It expects the following:

        :param auth_url: URL of the Identity Service
        :param identity_provider: Name of the Identity Provider the client will
            authenticate against
        :param protocol: Protocol name as configured in keystone
        :param access_token: OpenID Connect Access token
        """
        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            # intentionally set client_id, client_secret to empty since we
            # don't need then
            client_id='',  # nosec B106
            client_secret='',  # nosec B106
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
            approvals=approvals,
        )
        assert access_token is not None  # nosec B101
        self.access_token = access_token

    def get_unscoped_cache_id_elements(self) -> dict[str, str | None]:
        """Add the access token to what identifies the unscoped token.

        The access token is the whole of the credential here, so it alone
        distinguishes one caller's unscoped token from another's.
        """
        elements = super().get_unscoped_cache_id_elements()
        elements['access_token'] = self.access_token
        return elements

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, str | None]:
        """OidcAccessToken does not require a payload."""  # noqa: D403
        return {}

    def get_unscoped_auth_ref(
        self, session: ks_session.Session
    ) -> access.AccessInfoV3:
        """Authenticate with OpenID Connect and get back claims.

        We exchange the access token upon accessing the protected Keystone
        endpoint (federated auth URL). This will trigger the OpenID Connect
        Provider to perform a user introspection and retrieve information
        (specified in the scope) about the user in the form of an OpenID
        Connect Claim. These claims will be sent to Keystone in the form of
        environment variables.

        :param session: a session object to send out HTTP requests.
        :returns: a token data representation
        """
        self._prepare_login()
        response = self._get_keystone_token(session, self.access_token)
        access_info = access.create(resp=response)
        assert isinstance(access_info, access.AccessInfoV3)  # nosec B101
        return access_info


class OidcDeviceAuthorization(_OidcBase):
    """Implementation for OAuth 2.0 Device Authorization Grant."""

    # The user visits the verification URI and enters a code.
    interactive_unscoped_auth = True

    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    HEADER_X_FORM = {"Content-Type": "application/x-www-form-urlencoded"}

    def __init__(
        self,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        client_id: str,
        client_secret: str | None = None,
        access_token_type: str = "access_token",  # noqa: S107
        scope: str = 'openid profile',
        access_token_endpoint: str | None = None,
        discovery_endpoint: str | None = None,
        device_authorization_endpoint: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        *,
        trust_id: str | None = None,
        system_scope: str | None = None,
        domain_id: str | None = None,
        domain_name: str | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        project_domain_id: str | None = None,
        project_domain_name: str | None = None,
        reauthenticate: bool = True,
        include_catalog: bool = True,
        approvals: approval.ProviderApprovals | None = None,
    ):
        """The OAuth 2.0 Device Authorization plugin expects the following.

        :param device_authorization_endpoint: OAuth 2.0 Device Authorization
            Endpoint, for example: https://localhost:8020/oidc/authorize/device
            Note that if a discovery document is provided this value will
            override the discovered one.
        :param code_challenge_method: PKCE Challenge Method (RFC 7636).
        """
        self.code_challenge_method = code_challenge_method

        super().__init__(
            auth_url=auth_url,
            identity_provider=identity_provider,
            protocol=protocol,
            client_id=client_id,
            client_secret=client_secret,
            access_token_type=access_token_type,
            scope=scope,
            access_token_endpoint=access_token_endpoint,
            discovery_endpoint=discovery_endpoint,
            trust_id=trust_id,
            system_scope=system_scope,
            domain_id=domain_id,
            domain_name=domain_name,
            project_id=project_id,
            project_name=project_name,
            project_domain_id=project_domain_id,
            project_domain_name=project_domain_name,
            reauthenticate=reauthenticate,
            include_catalog=include_catalog,
            approvals=approvals,
        )
        self.device_authorization_endpoint = device_authorization_endpoint

    @property
    def device_authorization_endpoint(self) -> str | None:
        """The endpoint the current approval names, or the configured one.

        Kept as a property so that binding an approval cannot leave the
        plugin pointed at a different provider's verification endpoint.
        """
        if (
            self._approval is not None
            and self._approval.device_authorization_endpoint is not None
        ):
            return self._approval.device_authorization_endpoint
        return self._device_authorization_endpoint

    @device_authorization_endpoint.setter
    def device_authorization_endpoint(self, value: str | None) -> None:
        if (
            self._approval is not None
            and self._approval.device_authorization_endpoint is not None
        ):
            return
        self._device_authorization_endpoint = value

    def _get_device_authorization_endpoint(
        self, session: ks_session.Session
    ) -> str | None:
        """Get the endpoint for the OAuth 2.0 Device Authorization flow.

        This method will return the correct device authorization endpoint to
        be used.
        If the user has explicitly passed an device_authorization_endpoint to
        the constructor that will be returned. If there is no explicit endpoint
        and a discovery url is provided, it will try to get it from the
        discovery document. If nothing is found, an exception will be raised.

        :param session: a session object to send out HTTP requests.
        :return: the endpoint to use
        """
        if self.device_authorization_endpoint is not None:
            return self.device_authorization_endpoint

        discovery = self._get_discovery_document(session)
        endpoint = discovery.get("device_authorization_endpoint")
        if endpoint is None:
            raise exceptions.oidc.OidcDeviceAuthorizationEndpointNotFound()
        return cast(str, endpoint)

    def _generate_pkce_verifier(self) -> str:
        """Generate PKCE verifier string as defined in RFC 7636."""
        raw_bytes = 42  # 32 is the minimum from the RFC, let's use a bit more
        _rand = os.urandom(raw_bytes)
        _rand_b64 = base64.urlsafe_b64encode(_rand).decode('ascii')
        code_verifier = _rand_b64.rstrip('=')  # strip padding as RFC says
        return code_verifier

    def _generate_pkce_challenge(self) -> str | None:
        """Generate PKCE challenge string as defined in RFC 7636."""
        if self.code_challenge_method not in ('plain', 'S256'):
            raise exceptions.OidcInvalidCodeChallengeMethod()
        self.code_verifier = self._generate_pkce_verifier()

        if self.code_challenge_method == 'plain':
            return self.code_verifier
        elif self.code_challenge_method == 'S256':
            _tmp = self.code_verifier.encode('ascii')
            _hash = hashlib.sha256(_tmp).digest()
            return base64.urlsafe_b64encode(_hash).decode('ascii').rstrip('=')

        return None

    def get_payload(
        self, session: ks_session.Session
    ) -> dict[str, str | None]:
        """Get an authorization grant for the "device_code" grant type.

        :param session: a session object to send out HTTP requests.
        :returns: a python dictionary containing the payload to be exchanged
        """
        payload: dict[str, str | None]
        device_authz_endpoint = self._get_device_authorization_endpoint(
            session
        )

        # TODO(stephenfin): This should be an error
        assert device_authz_endpoint is not None  # nosec B101

        if self.client_secret:
            client_auth = (self.client_id, self.client_secret)
        else:
            client_auth = None

        # rfc8628 does not require client_id when a client_secret is provided,
        # but Microsoft EntraID does; these should be ignored by other IDPs
        # when a client secret is provided.
        payload = {'client_id': self.client_id, 'scope': self.scope}

        if self.code_challenge_method:
            self.code_challenge = self._generate_pkce_challenge()
            payload.setdefault(
                'code_challenge_method', self.code_challenge_method
            )
            payload.setdefault('code_challenge', self.code_challenge)
        encoded_payload = urlparse.urlencode(payload)

        if LOG.isEnabledFor(logging.DEBUG):
            sanitized_payload = self._sanitize(payload)
            LOG.debug(
                "Making OpenID-Connect authentication request to %s with "
                "data %s",
                device_authz_endpoint,
                sanitized_payload,
            )
        headers = dict(self.HEADER_X_FORM)
        headers.update(self._correlation_headers())
        op_response = session.post(
            device_authz_endpoint,
            requests_auth=client_auth,
            headers=headers,
            data=encoded_payload,
            log=False,
            authenticated=False,
        )
        if LOG.isEnabledFor(logging.DEBUG):
            sanitized_response = self._sanitize(op_response.json())
            LOG.debug(
                "OpenID-Connect authentication response from %s is %s",
                device_authz_endpoint,
                sanitized_response,
            )

        self.expires_in = int(op_response.json()["expires_in"])
        self.timeout = time.time() + self.expires_in
        self.device_code = op_response.json()["device_code"]
        self.interval = int(op_response.json().get('interval', 5))
        self.user_code = op_response.json()["user_code"]
        self.verification_uri = op_response.json()["verification_uri"]
        self.verification_uri_complete = op_response.json().get(
            "verification_uri_complete"
        )

        payload = {'device_code': self.device_code}
        if self.code_challenge_method:
            payload.setdefault('code_verifier', self.code_verifier)
        return payload

    def _get_access_token(
        self, session: ks_session.Session, payload: dict[str, str | None]
    ) -> str:
        """Poll token endpoint for an access token.

        :param session: a session object to send out HTTP requests.
        :param payload: a dict containing various OpenID Connect values,
            for example::

                {
                    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
                    'device_code': self.device_code,
                }
        """  # noqa: E501
        # verification_uri_complete is optional and not implemented by EntraID
        if self.verification_uri_complete:
            LOG.warning(
                "To authenticate please go to: %s",
                self.verification_uri_complete,
            )
        else:
            LOG.warning(
                "To authenticate please go to %s and enter the code %s",
                self.verification_uri,
                self.user_code,
            )

        if self.client_secret:
            client_auth = (self.client_id, self.client_secret)
        else:
            client_auth = None

        # rfc8628 does not require client_id when a client_secret is provided,
        # but Microsoft EntraID does; this should be ignored by other IDPs
        # when a client secret is provided.
        payload.setdefault('client_id', self.client_id)

        access_token_endpoint = self._get_access_token_endpoint(session)
        encoded_payload = urlparse.urlencode(payload)

        while time.time() < self.timeout:
            try:
                if LOG.isEnabledFor(logging.DEBUG):
                    sanitized_payload = self._sanitize(payload)
                    LOG.debug(
                        "Making OpenID-Connect authentication request to %s "
                        "with data %s",
                        access_token_endpoint,
                        sanitized_payload,
                    )
                headers = dict(self.HEADER_X_FORM)
                headers.update(self._correlation_headers())
                op_response = session.post(
                    access_token_endpoint,
                    requests_auth=client_auth,
                    data=encoded_payload,
                    headers=headers,
                    log=False,
                    authenticated=False,
                )
                if LOG.isEnabledFor(logging.DEBUG):
                    sanitized_response = self._sanitize(op_response.json())
                    LOG.debug(
                        "OpenID-Connect authentication response from %s is %s",
                        access_token_endpoint,
                        sanitized_response,
                    )
            except exceptions.http.BadRequest as exc:
                if exc.response is None:
                    raise
                error = exc.response.json().get("error")
                if error != "authorization_pending":
                    raise
                time.sleep(self.interval)
                continue
            break
        else:
            if error == "authorization_pending":
                raise exceptions.oidc.OidcDeviceAuthorizationTimeOut()

        access_token = op_response.json()[self.access_token_type]
        assert isinstance(access_token, str)  # nosec B101
        return access_token
