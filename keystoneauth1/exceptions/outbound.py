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
    'OutboundPolicyViolation',
    'OutboundAddressDenied',
    'AddressNotAllowed',
    'OutboundAccessDenied',
    'OutboundEgressDenied',
    'UnapprovedAddress',
)


class OutboundPolicyViolation(base.ClientException):
    """An outbound request did not satisfy the configured network policy."""

    message = 'Request violates the configured outbound address policy.'

    def __init__(self, message=None, decision=None):
        super().__init__(message)
        self.decision = decision


class OutboundAddressDenied(OutboundPolicyViolation, catalog.EndpointNotFound):
    """The destination address is not approved for the current phase."""

    message = 'The destination address is not approved for this phase.'


# Descriptive aliases for callers and allow-list terminology.
AddressNotAllowed = OutboundAddressDenied
OutboundAccessDenied = OutboundAddressDenied
OutboundEgressDenied = OutboundAddressDenied
UnapprovedAddress = OutboundAddressDenied
