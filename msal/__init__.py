#------------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# This code is licensed under the MIT License.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions :
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#------------------------------------------------------------------------------

from .application import (
    ClientApplication,
    ConfidentialClientApplication,
    PublicClientApplication,
    )
from .oauth2cli.assertion import AutoRefresher
from .oauth2cli.oidc import Prompt, IdTokenError
from .sku import __version__
from .token_cache import TokenCache, SerializableTokenCache
from .delegation import (
    AuthorizationDenied,
    AuthorizationReceipt,
    DelegationApproval,
    DelegationAuthorizer,
    DelegationCache,
    DelegationCheck,
    DelegationContext,
    DelegationDecision,
    DelegationDenialReceipt,
    DelegationDenied,
    DelegationDeniedError,
    DelegationEnforcer,
    DelegationError,
    DelegationGrant,
    DelegationGuard,
    DelegationManager,
    DelegationPolicy,
    DelegationReceipt,
    DelegationResultCache,
    DelegationService,
    DelegationTokenBroker,
    DelegationVerifier,
    DelegationAwareTokenClient,
    DenialReceipt,
    PermissionGrant,
    acquire_delegated_token,
    acquire_on_behalf_of_with_delegation,
    acquire_token_with_delegation,
    canonical_delegation_fingerprint,
    can_reuse_result,
    check_delegation,
    compute_delegation_fingerprint,
    decode_assertion_claims,
    delegation_identity,
    delegated_acquire_token,
    evaluate_delegation,
    install_delegation_check,
    is_delegation_current,
)
from .auth_scheme import PopAuthScheme
from .managed_identity import (
    SystemAssignedManagedIdentity, UserAssignedManagedIdentity,
    ManagedIdentityClient,
    ServiceFabricHttpOptions,
    ManagedIdentityError,
    ArcPlatformNotSupportedError,
    )

# Putting module-level exceptions into the package namespace, to make them
# 1. officially part of the MSAL public API, and
# 2. can still be caught by the user code even if we change the module structure.
from .oauth2cli.oauth2 import BrowserInteractionTimeoutError



def __getattr__(name):
    from . import delegation as _delegation
    if hasattr(_delegation, name):
        return getattr(_delegation, name)
    raise AttributeError("module {!r} has no attribute {!r}".format(__name__, name))
