# Copyright 2021 Google LLC
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

"""Downscoping with Credential Access Boundaries

This module provides the ability to downscope credentials using
`Downscoping with Credential Access Boundaries`_. This is useful to restrict the
Identity and Access Management (IAM) permissions that a short-lived credential
can use.

To downscope permissions of a source credential, a Credential Access Boundary
that specifies which resources the new credential can access, as well as
an upper bound on the permissions that are available on each resource, has to
be defined. A downscoped credential can then be instantiated using the source
credential and the Credential Access Boundary.

The common pattern of usage is to have a token broker with elevated access
generate these downscoped credentials from higher access source credentials and
pass the downscoped short-lived access tokens to a token consumer via some
secure authenticated channel for limited access to Google Cloud Storage
resources.

For example, a token broker can be set up on a server in a private network.
Various workloads (token consumers) in the same network will send authenticated
requests to that broker for downscoped tokens to access or modify specific google
cloud storage buckets.

The broker will instantiate downscoped credentials instances that can be used to
generate short lived downscoped access tokens that can be passed to the token
consumer. These downscoped access tokens can be injected by the consumer into
google.oauth2.Credentials and used to initialize a storage client instance to
access Google Cloud Storage resources with restricted access.

Note: Only Cloud Storage supports Credential Access Boundaries. Other Google
Cloud services do not support this feature.

.. _Downscoping with Credential Access Boundaries: https://cloud.google.com/iam/docs/downscoping-short-lived-credentials
"""

import datetime
import hashlib
import json
import threading

from google.auth import _helpers
from google.auth import credentials
from google.auth import exceptions
from google.oauth2 import sts

# The maximum number of access boundary rules a Credential Access Boundary can
# contain.
_MAX_ACCESS_BOUNDARY_RULES_COUNT = 10
# The token exchange grant_type used for exchanging credentials.
_STS_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
# The token exchange requested_token_type. This is always an access_token.
_STS_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
# The STS token URL used to exchanged a short lived access token for a downscoped one.
_STS_TOKEN_URL_PATTERN = "https://sts.{}/v1/token"
# The STS token URL used to exchanged a short lived access token for a downscoped one.
_STS_TOKEN_URL_PATTERN = "https://sts.{}/v1/token"
# The STS URL used to revoke a downscoped access token when its policy is replaced.
_STS_REVOKE_TOKEN_URL_PATTERN = "https://sts.{}/v1/revoke"
# The subject token type to use when exchanging a short lived access token for a
# downscoped token.
_STS_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
_STS_ACCESS_TOKEN_TYPE_HINT = "access_token"


def _boundary_fingerprint(credential_access_boundary):
    boundary_json = json.dumps(
        credential_access_boundary.to_json(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(boundary_json).hexdigest()


class HandoffJournal(object):
    """Thread-safe in-memory audit trail for a policy/request handoff."""

    def __init__(self):
        self._events = []
        self._lock = threading.Lock()

    def record(self, event_type, **fields):
        """Records an event and returns an immutable copy of the event."""
        with self._lock:
            event = {"seq": len(self._events) + 1, "type": event_type}
            event.update(fields)
            self._events.append(event)
            return dict(event)

    @property
    def events(self):
        """Returns a copy of all recorded events."""
        with self._lock:
            return [dict(event) for event in self._events]

    def of_type(self, event_type):
        """Returns a copy of events with the requested type."""
        return [event for event in self.events if event["type"] == event_type]

    def clear(self):
        """Clears the journal."""
        with self._lock:
            self._events = []


class RevocationResult(object):
    """Outcome of an attempt to revoke a token minted by an old policy."""

    def __init__(
        self,
        policy_version,
        token=None,
        url=None,
        status="not_requested",
        response=None,
        error=None,
        reason=None,
    ):
        self.policy_version = policy_version
        self.token = token
        self.url = url
        self.status = status
        self.response = response
        self.error = error
        self.reason = reason

    @property
    def attempted(self):
        return self.status != "not_requested"

    @property
    def succeeded(self):
        return self.status == "succeeded"

    @property
    def revoked(self):
        return self.succeeded

    @property
    def failed(self):
        return self.status == "failed"

    def mark_succeeded(self, response=None):
        self.status = "succeeded"
        self.response = response or {}
        return self

    def mark_failed(self, error):
        self.status = "failed"
        self.error = error
        return self

    def to_dict(self):
        error_message = None
        if self.error is not None:
            error_message = str(self.error)
        return {
            "policy_version": self.policy_version,
            "token": self.token,
            "url": self.url,
            "status": self.status,
            "succeeded": self.succeeded,
            "revoked": self.revoked,
            "response": self.response,
            "error": error_message,
            "reason": self.reason,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]


class PolicyUpdateReceipt(object):
    """Explicit result of replacing a credential access boundary."""

    def __init__(
        self,
        old_policy_version,
        new_policy_version,
        boundary,
        revocation=None,
        metadata=None,
    ):
        self.old_policy_version = old_policy_version
        self.new_policy_version = new_policy_version
        self.policy_version = new_policy_version
        self.boundary = boundary
        self.revocation = revocation
        self.metadata = dict(metadata or {})

    @property
    def rule_count(self):
        return len(self.boundary.rules)

    def to_dict(self):
        return {
            "old_policy_version": self.old_policy_version,
            "new_policy_version": self.new_policy_version,
            "policy_version": self.new_policy_version,
            "rule_count": self.rule_count,
            "revocation": self.revocation.to_dict() if self.revocation else None,
            "metadata": self.metadata,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]


class StalePolicyExchangeError(exceptions.RefreshError):
    """An STS response was minted for a policy that is no longer current."""

    def __init__(
        self,
        message,
        exchange_policy_version=None,
        current_policy_version=None,
        exchange_id=None,
        revocation=None,
    ):
        super(StalePolicyExchangeError, self).__init__(message, retryable=True)
        self.exchange_policy_version = exchange_policy_version
        self.policy_version = exchange_policy_version
        self.current_policy_version = current_policy_version
        self.exchange_id = exchange_id
        self.revocation = revocation


class RequestAttempt(object):
    """Record of one authorization/send attempt for a queued request."""

    def __init__(self, number):
        self.number = number
        self.outcome = "pending"
        self.queued_policy_version = None
        self.policy_version = None
        self.policy_fingerprint = None
        self.status_code = None
        self.response = None
        self.error = None
        self.revocation = None

    def to_dict(self):
        return {
            "number": self.number,
            "outcome": self.outcome,
            "queued_policy_version": self.queued_policy_version,
            "policy_version": self.policy_version,
            "policy_fingerprint": self.policy_fingerprint,
            "status_code": self.status_code,
            "error": str(self.error) if self.error else None,
            "error_type": type(self.error).__name__ if self.error else None,
            "revocation": self.revocation.to_dict() if self.revocation else None,
        }


class HandoffResult(object):
    """Final and per-attempt result for a queued request."""

    def __init__(self, request_id, queued_policy_version):
        self.request_id = request_id
        self.queued_policy_version = queued_policy_version
        self.attempts = []
        self.response = None
        self.error = None
        self.sent_records = []

    @property
    def succeeded(self):
        return any(attempt.outcome == "sent" for attempt in self.attempts)

    @property
    def retried(self):
        return len(self.attempts) > 1

    @property
    def sent_policy_versions(self):
        return [record["policy_version"] for record in self.sent_records]

    @property
    def retry_result(self):
        return self.attempts[-1].to_dict() if len(self.attempts) > 1 else None

    def to_dict(self):
        return {
            "request_id": self.request_id,
            "queued_policy_version": self.queued_policy_version,
            "succeeded": self.succeeded,
            "retried": self.retried,
            "sent_policy_versions": self.sent_policy_versions,
            "retry_result": self.retry_result,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "sent_records": self.sent_records,
            "error": str(self.error) if self.error else None,
        }


class QueuedRequest(object):
    """A request whose Authorization header is applied only when it is sent."""

    def __init__(
        self,
        request_id,
        url,
        method="GET",
        headers=None,
        body=None,
        queued_policy_version=None,
    ):
        self.request_id = request_id
        self.url = url
        self.method = method
        self.headers = dict(headers or {})
        self.body = body
        self.queued_policy_version = queued_policy_version

    def to_dict(self):
        return {
            "request_id": self.request_id,
            "url": self.url,
            "method": self.method,
            "headers": dict(self.headers),
            "body": self.body,
            "queued_policy_version": self.queued_policy_version,
        }


class AccessBoundaryHandoff(object):
    """Queues requests and binds sends to the credential's current policy."""

    def __init__(
        self,
        credentials,
        request=None,
        sender=None,
        journal=None,
        max_attempts=2,
        retry_statuses=(401, 403),
    ):
        self.credentials = credentials
        self.request = request
        self._sender = sender
        self.journal = (
            journal
            or getattr(credentials, "journal", None)
            or HandoffJournal()
        )
        if hasattr(credentials, "_journal"):
            credentials._journal = self.journal
        self.max_attempts = max_attempts
        self.retry_statuses = set(retry_statuses or ())
        self._queue = {}
        self._results = {}
        self.sent_records = []
        self._lock = threading.RLock()
        self._request_counter = 0

    def update_access_boundary(
        self, credential_access_boundary, request=None, **kwargs
    ):
        """Updates policy through the handoff using its auth transport by default."""
        return self.credentials.update_access_boundary(
            credential_access_boundary,
            request=request or self.request,
            **kwargs
        )

    update_policy = update_access_boundary
    update_boundary = update_access_boundary
    tighten_access_boundary = update_access_boundary

    @property
    def policy_version(self):
        return self.credentials.policy_version

    @property
    def revocation_results(self):
        return getattr(self.credentials, "revocation_results", [])

    def enqueue(
        self,
        request_id=None,
        url=None,
        method="GET",
        headers=None,
        body=None,
        **request_kwargs
    ):
        """Adds a request without applying or freezing an access token."""
        if isinstance(request_id, QueuedRequest):
            queued = request_id
            with self._lock:
                if queued.request_id in self._queue:
                    raise exceptions.InvalidValue(
                        "Request {} is already queued.".format(queued.request_id)
                    )
                self._queue[queued.request_id] = queued
            return queued

        if isinstance(request_id, dict):
            request_data = dict(request_id)
            request_id = request_data.pop("request_id", None) or request_data.pop(
                "id", None
            )
            url = request_data.pop("url", url)
            method = request_data.pop("method", method)
            headers = request_data.pop("headers", headers)
            body = request_data.pop("body", request_data.pop("data", body))
            request_kwargs.update(request_data)

        if url is None and isinstance(request_id, str) and (
            "://" in request_id or request_id.startswith("/")
        ):
            url = request_id
            request_id = None

        with self._lock:
            self._request_counter += 1
            request_id = request_id or "request-{}".format(self._request_counter)
            if request_id in self._queue:
                raise exceptions.InvalidValue(
                    "Request {} is already queued.".format(request_id)
                )
            queued = QueuedRequest(
                request_id=request_id,
                url=url or request_kwargs.pop("uri", None),
                method=method,
                headers=headers,
                body=body if body is not None else request_kwargs.pop("data", None),
                queued_policy_version=self.credentials.policy_version,
            )
            self._queue[request_id] = queued
            self.journal.record(
                "request_queued",
                request_id=request_id,
                policy_version=queued.queued_policy_version,
                url=queued.url,
                method=queued.method,
            )
            return queued

    queue = enqueue
    enqueue_request = enqueue
    add_request = enqueue

    def _send(self, queued, headers, attempt):
        if self._sender is not None:
            return self._sender(
                {
                    "request_id": queued.request_id,
                    "url": queued.url,
                    "method": queued.method,
                    "headers": headers,
                    "body": queued.body,
                    "attempt": attempt.number,
                }
            )
        if self.request is None:
            raise exceptions.InvalidValue(
                "A request transport or sender is required to send queued requests."
            )
        return self.request(
            url=queued.url,
            method=queued.method,
            headers=headers,
            body=queued.body,
        )

    @staticmethod
    def _status_code(response):
        return getattr(response, "status", None) or getattr(
            response, "status_code", None
        )

    def process(self, request_id, request=None):
        """Sends one queued request, retrying stale-policy exchanges once."""
        if isinstance(request_id, QueuedRequest):
            request_id = request_id.request_id
        queued = self._queue[request_id]
        auth_request = request or self.request
        result = HandoffResult(request_id, queued.queued_policy_version)
        self._results[request_id] = result

        for number in range(1, self.max_attempts + 1):
            attempt = RequestAttempt(number)
            attempt.queued_policy_version = queued.queued_policy_version
            result.attempts.append(attempt)
            headers = dict(queued.headers)

            try:
                self.credentials.before_request(
                    auth_request, queued.method, queued.url, headers
                )
                attestation = self.credentials.policy_attestation()
                attempt.policy_version = attestation["policy_version"]
                attempt.policy_fingerprint = attestation["policy_fingerprint"]

                response = self._send(queued, headers, attempt)
                status_code = self._status_code(response)
                attempt.status_code = status_code
                attempt.response = response

                if status_code is not None and status_code >= 400:
                    attempt.outcome = "rejected"
                    attempt.error = exceptions.GoogleAuthError(
                        "Request {} failed with status {}.".format(
                            request_id, status_code
                        )
                    )
                    result.error = attempt.error
                    if (
                        status_code in self.retry_statuses
                        and number < self.max_attempts
                    ):
                        self.journal.record(
                            "request_retry_scheduled",
                            request_id=request_id,
                            attempt=number,
                            status_code=status_code,
                            policy_version=attempt.policy_version,
                        )
                        invalidate_token = getattr(
                            self.credentials, "invalidate_token", None
                        )
                        if callable(invalidate_token):
                            invalidate_token()
                        else:
                            self.credentials.token = None
                        continue
                    break

                attempt.outcome = "sent"
                result.response = response
                record = {
                    "request_id": request_id,
                    "attempt": number,
                    "policy_version": attestation["policy_version"],
                    "token_policy_version": attestation["token_policy_version"],
                    "policy_fingerprint": attestation["policy_fingerprint"],
                    "status_code": status_code,
                }
                attempt.sent_record = record
                result.sent_records.append(record)
                with self._lock:
                    self.sent_records.append(record)
                self.journal.record("request_sent", **record)
                return result

            except StalePolicyExchangeError as error:
                attempt.outcome = "stale_policy_exchange"
                attempt.error = error
                attempt.policy_version = error.current_policy_version
                attempt.revocation = error.revocation
                result.error = error
                self.journal.record(
                    "request_policy_mismatch",
                    request_id=request_id,
                    attempt=number,
                    exchange_policy_version=error.exchange_policy_version,
                    current_policy_version=error.current_policy_version,
                    revocation=(
                        error.revocation.to_dict() if error.revocation else None
                    ),
                )
                if number < self.max_attempts:
                    self.journal.record(
                        "request_retry_scheduled",
                        request_id=request_id,
                        attempt=number,
                        policy_version=error.current_policy_version,
                    )
                    continue
                break
            except Exception as error:
                attempt.outcome = "error"
                attempt.error = error
                result.error = error
                self.journal.record(
                    "request_failed",
                    request_id=request_id,
                    attempt=number,
                    error=type(error).__name__,
                )
                if number < self.max_attempts and getattr(error, "retryable", False):
                    continue
                break

        return result

    send = process
    dispatch = process
    send_request = process
    process_request = process

    def process_all(self, request=None):
        """Processes all queued requests in enqueue order."""
        with self._lock:
            request_ids = list(self._queue)
        return [self.process(request_id, request=request) for request_id in request_ids]

    drain = process_all

    @property
    def results(self):
        return dict(self._results)

    @property
    def records(self):
        return [dict(record) for record in self.sent_records]

    @property
    def sent_policy_versions(self):
        return [record["policy_version"] for record in self.sent_records]


PolicyRequestGate = AccessBoundaryHandoff
PolicyHandoff = AccessBoundaryHandoff
RequestHandoff = AccessBoundaryHandoff
InMemoryHandoffJournal = HandoffJournal


class CredentialAccessBoundary(object):
    """Defines a Credential Access Boundary which contains a list of access boundary
    rules. Each rule contains information on the resource that the rule applies to,
    the upper bound of the permissions that are available on that resource and an
    optional condition to further restrict permissions.
    """

    def __init__(self, rules=[]):
        """Instantiates a Credential Access Boundary. A Credential Access Boundary
        can contain up to 10 access boundary rules.

        Args:
            rules (Sequence[google.auth.downscoped.AccessBoundaryRule]): The list of
                access boundary rules limiting the access that a downscoped credential
                will have.
        Raises:
            InvalidType: If any of the rules are not a valid type.
            InvalidValue: If the provided rules exceed the maximum allowed.
        """
        self.rules = rules

    @property
    def rules(self):
        """Returns the list of access boundary rules defined on the Credential
        Access Boundary.

        Returns:
            Tuple[google.auth.downscoped.AccessBoundaryRule, ...]: The list of access
                boundary rules defined on the Credential Access Boundary. These are returned
                as an immutable tuple to prevent modification.
        """
        return tuple(self._rules)

    @rules.setter
    def rules(self, value):
        """Updates the current rules on the Credential Access Boundary. This will overwrite
        the existing set of rules.

        Args:
            value (Sequence[google.auth.downscoped.AccessBoundaryRule]): The list of
                access boundary rules limiting the access that a downscoped credential
                will have.
        Raises:
            InvalidType: If any of the rules are not a valid type.
            InvalidValue: If the provided rules exceed the maximum allowed.
        """
        if len(value) > _MAX_ACCESS_BOUNDARY_RULES_COUNT:
            raise exceptions.InvalidValue(
                "Credential access boundary rules can have a maximum of {} rules.".format(
                    _MAX_ACCESS_BOUNDARY_RULES_COUNT
                )
            )
        for access_boundary_rule in value:
            if not isinstance(access_boundary_rule, AccessBoundaryRule):
                raise exceptions.InvalidType(
                    "List of rules provided do not contain a valid 'google.auth.downscoped.AccessBoundaryRule'."
                )
        # Make a copy of the original list.
        self._rules = list(value)

    def add_rule(self, rule):
        """Adds a single access boundary rule to the existing rules.

        Args:
            rule (google.auth.downscoped.AccessBoundaryRule): The access boundary rule,
                limiting the access that a downscoped credential will have, to be added to
                the existing rules.
        Raises:
            InvalidType: If any of the rules are not a valid type.
            InvalidValue: If the provided rules exceed the maximum allowed.
        """
        if len(self.rules) == _MAX_ACCESS_BOUNDARY_RULES_COUNT:
            raise exceptions.InvalidValue(
                "Credential access boundary rules can have a maximum of {} rules.".format(
                    _MAX_ACCESS_BOUNDARY_RULES_COUNT
                )
            )
        if not isinstance(rule, AccessBoundaryRule):
            raise exceptions.InvalidType(
                "The provided rule does not contain a valid 'google.auth.downscoped.AccessBoundaryRule'."
            )
        self._rules.append(rule)

    def to_json(self):
        """Generates the dictionary representation of the Credential Access Boundary.
        This uses the format expected by the Security Token Service API as documented in
        `Defining a Credential Access Boundary`_.

        .. _Defining a Credential Access Boundary:
            https://cloud.google.com/iam/docs/downscoping-short-lived-credentials#define-boundary

        Returns:
            Mapping: Credential Access Boundary Rule represented in a dictionary object.
        """
        rules = []
        for access_boundary_rule in self.rules:
            rules.append(access_boundary_rule.to_json())

        return {"accessBoundary": {"accessBoundaryRules": rules}}


class AccessBoundaryRule(object):
    """Defines an access boundary rule which contains information on the resource that
    the rule applies to, the upper bound of the permissions that are available on that
    resource and an optional condition to further restrict permissions.
    """

    def __init__(
        self, available_resource, available_permissions, availability_condition=None
    ):
        """Instantiates a single access boundary rule.

        Args:
            available_resource (str): The full resource name of the Cloud Storage bucket
                that the rule applies to. Use the format
                "//storage.googleapis.com/projects/_/buckets/bucket-name".
            available_permissions (Sequence[str]): A list defining the upper bound that
                the downscoped token will have on the available permissions for the
                resource. Each value is the identifier for an IAM predefined role or
                custom role, with the prefix "inRole:". For example:
                "inRole:roles/storage.objectViewer".
                Only the permissions in these roles will be available.
            availability_condition (Optional[google.auth.downscoped.AvailabilityCondition]):
                Optional condition that restricts the availability of permissions to
                specific Cloud Storage objects.

        Raises:
            InvalidType: If any of the parameters are not of the expected types.
            InvalidValue: If any of the parameters are not of the expected values.
        """
        self.available_resource = available_resource
        self.available_permissions = available_permissions
        self.availability_condition = availability_condition

    @property
    def available_resource(self):
        """Returns the current available resource.

        Returns:
           str: The current available resource.
        """
        return self._available_resource

    @available_resource.setter
    def available_resource(self, value):
        """Updates the current available resource.

        Args:
            value (str): The updated value of the available resource.

        Raises:
            google.auth.exceptions.InvalidType: If the value is not a string.
        """
        if not isinstance(value, str):
            raise exceptions.InvalidType(
                "The provided available_resource is not a string."
            )
        self._available_resource = value

    @property
    def available_permissions(self):
        """Returns the current available permissions.

        Returns:
           Tuple[str, ...]: The current available permissions. These are returned
               as an immutable tuple to prevent modification.
        """
        return tuple(self._available_permissions)

    @available_permissions.setter
    def available_permissions(self, value):
        """Updates the current available permissions.

        Args:
            value (Sequence[str]): The updated value of the available permissions.

        Raises:
            InvalidType: If the value is not a list of strings.
            InvalidValue: If the value is not valid.
        """
        for available_permission in value:
            if not isinstance(available_permission, str):
                raise exceptions.InvalidType(
                    "Provided available_permissions are not a list of strings."
                )
            if available_permission.find("inRole:") != 0:
                raise exceptions.InvalidValue(
                    "available_permissions must be prefixed with 'inRole:'."
                )
        # Make a copy of the original list.
        self._available_permissions = list(value)

    @property
    def availability_condition(self):
        """Returns the current availability condition.

        Returns:
           Optional[google.auth.downscoped.AvailabilityCondition]: The current
               availability condition.
        """
        return self._availability_condition

    @availability_condition.setter
    def availability_condition(self, value):
        """Updates the current availability condition.

        Args:
            value (Optional[google.auth.downscoped.AvailabilityCondition]): The updated
                value of the availability condition.

        Raises:
            google.auth.exceptions.InvalidType: If the value is not of type google.auth.downscoped.AvailabilityCondition
                or None.
        """
        if not isinstance(value, AvailabilityCondition) and value is not None:
            raise exceptions.InvalidType(
                "The provided availability_condition is not a 'google.auth.downscoped.AvailabilityCondition' or None."
            )
        self._availability_condition = value

    def to_json(self):
        """Generates the dictionary representation of the access boundary rule.
        This uses the format expected by the Security Token Service API as documented in
        `Defining a Credential Access Boundary`_.

        .. _Defining a Credential Access Boundary:
            https://cloud.google.com/iam/docs/downscoping-short-lived-credentials#define-boundary

        Returns:
            Mapping: The access boundary rule represented in a dictionary object.
        """
        json = {
            "availablePermissions": list(self.available_permissions),
            "availableResource": self.available_resource,
        }
        if self.availability_condition:
            json["availabilityCondition"] = self.availability_condition.to_json()
        return json


class AvailabilityCondition(object):
    """An optional condition that can be used as part of a Credential Access Boundary
    to further restrict permissions."""

    def __init__(self, expression, title=None, description=None):
        """Instantiates an availability condition using the provided expression and
        optional title or description.

        Args:
            expression (str): A condition expression that specifies the Cloud Storage
                objects where permissions are available. For example, this expression
                makes permissions available for objects whose name starts with "customer-a":
                "resource.name.startsWith('projects/_/buckets/example-bucket/objects/customer-a')"
            title (Optional[str]): An optional short string that identifies the purpose of
                the condition.
            description (Optional[str]): Optional details about the purpose of the condition.

        Raises:
            InvalidType: If any of the parameters are not of the expected types.
            InvalidValue: If any of the parameters are not of the expected values.
        """
        self.expression = expression
        self.title = title
        self.description = description

    @property
    def expression(self):
        """Returns the current condition expression.

        Returns:
           str: The current conditon expression.
        """
        return self._expression

    @expression.setter
    def expression(self, value):
        """Updates the current condition expression.

        Args:
            value (str): The updated value of the condition expression.

        Raises:
            google.auth.exceptions.InvalidType: If the value is not of type string.
        """
        if not isinstance(value, str):
            raise exceptions.InvalidType("The provided expression is not a string.")
        self._expression = value

    @property
    def title(self):
        """Returns the current title.

        Returns:
           Optional[str]: The current title.
        """
        return self._title

    @title.setter
    def title(self, value):
        """Updates the current title.

        Args:
            value (Optional[str]): The updated value of the title.

        Raises:
            google.auth.exceptions.InvalidType: If the value is not of type string or None.
        """
        if not isinstance(value, str) and value is not None:
            raise exceptions.InvalidType("The provided title is not a string or None.")
        self._title = value

    @property
    def description(self):
        """Returns the current description.

        Returns:
           Optional[str]: The current description.
        """
        return self._description

    @description.setter
    def description(self, value):
        """Updates the current description.

        Args:
            value (Optional[str]): The updated value of the description.

        Raises:
            google.auth.exceptions.InvalidType: If the value is not of type string or None.
        """
        if not isinstance(value, str) and value is not None:
            raise exceptions.InvalidType(
                "The provided description is not a string or None."
            )
        self._description = value

    def to_json(self):
        """Generates the dictionary representation of the availability condition.
        This uses the format expected by the Security Token Service API as documented in
        `Defining a Credential Access Boundary`_.

        .. _Defining a Credential Access Boundary:
            https://cloud.google.com/iam/docs/downscoping-short-lived-credentials#define-boundary

        Returns:
            Mapping[str, str]: The availability condition represented in a dictionary
                object.
        """
        json = {"expression": self.expression}
        if self.title:
            json["title"] = self.title
        if self.description:
            json["description"] = self.description
        return json


class Credentials(credentials.CredentialsWithQuotaProject):
    """Defines a set of Google credentials that are downscoped from an existing set
    of Google OAuth2 credentials. This is useful to restrict the Identity and Access
    Management (IAM) permissions that a short-lived credential can use.
    The common pattern of usage is to have a token broker with elevated access
    generate these downscoped credentials from higher access source credentials and
    pass the downscoped short-lived access tokens to a token consumer via some
    secure authenticated channel for limited access to Google Cloud Storage
    resources.
    """

    def __init__(
        self,
        source_credentials,
        credential_access_boundary,
        quota_project_id=None,
        universe_domain=credentials.DEFAULT_UNIVERSE_DOMAIN,
        *,
        revoke_url=None,
        sts_client=None,
        journal=None,
        recorder=None,
    ):
        """Instantiates a downscoped credentials object using the provided source
        credentials and credential access boundary rules.
        To downscope permissions of a source credential, a Credential Access Boundary
        that specifies which resources the new credential can access, as well as an
        upper bound on the permissions that are available on each resource, has to be
        defined. A downscoped credential can then be instantiated using the source
        credential and the Credential Access Boundary.

        Args:
            source_credentials (google.auth.credentials.Credentials): The source credentials
                to be downscoped based on the provided Credential Access Boundary rules.
            credential_access_boundary (google.auth.downscoped.CredentialAccessBoundary):
                The Credential Access Boundary which contains a list of access boundary
                rules. Each rule contains information on the resource that the rule applies to,
                the upper bound of the permissions that are available on that resource and an
                optional condition to further restrict permissions.
            quota_project_id (Optional[str]): The optional quota project ID.
            universe_domain (Optional[str]): The universe domain value, default is googleapis.com
            revoke_url (Optional[str]): The token revocation endpoint. Defaults to the
                STS ``/v1/revoke`` endpoint for this universe.
            sts_client (Optional[google.oauth2.sts.Client]): An optional STS client,
                primarily useful for deterministic in-memory tests.
            journal (Optional[HandoffJournal]): Shared event journal for policy and
                request handoff records.
        Raises:
            google.auth.exceptions.RefreshError: If the source credentials
                return an error on token refresh.
            google.auth.exceptions.OAuthError: If the STS token exchange
                endpoint returned an error during downscoped token generation.
        """

        super(Credentials, self).__init__()
        self._source_credentials = source_credentials
        self._credential_access_boundary = credential_access_boundary
        self._quota_project_id = quota_project_id
        self._universe_domain = universe_domain or credentials.DEFAULT_UNIVERSE_DOMAIN
        self._revoke_url = revoke_url or _STS_REVOKE_TOKEN_URL_PATTERN.format(
            self.universe_domain
        )
        self._sts_client = sts_client or sts.Client(
            _STS_TOKEN_URL_PATTERN.format(self.universe_domain)
        )
        self._journal = journal or recorder or HandoffJournal()
        self._policy_lock = threading.RLock()
        self._policy_version = 1
        self._policy_fingerprint = _boundary_fingerprint(
            credential_access_boundary
        )
        self._token_policy_version = None
        self._token_policy_fingerprint = None
        self._exchange_counter = 0
        self.policy_updates = []
        self.revocation_results = []

    @property
    def policy_version(self):
        """Monotonically increasing version of this instance's boundary."""
        return self._policy_version

    @property
    def current_policy_version(self):
        """Alias for :attr:`policy_version`."""
        return self._policy_version

    @property
    def boundary_version(self):
        """Alias for :attr:`policy_version`."""
        return self._policy_version

    @property
    def access_boundary(self):
        """Returns the current credential access boundary."""
        return self._credential_access_boundary

    @property
    def credential_access_boundary(self):
        """Returns the current credential access boundary."""
        return self._credential_access_boundary

    @property
    def policy_fingerprint(self):
        """Canonical SHA-256 fingerprint of the current boundary."""
        return _boundary_fingerprint(self._credential_access_boundary)

    @property
    def token_policy_version(self):
        """Policy version that minted the currently installed token."""
        return self._token_policy_version

    @property
    def journal(self):
        """Event journal used by this credential."""
        return self._journal

    @property
    def recorder(self):
        """Alias for :attr:`journal`."""
        return self._journal

    @property
    def last_revocation_result(self):
        """Most recent token revocation result, if any."""
        return self.revocation_results[-1] if self.revocation_results else None

    @property
    def revocation_result(self):
        """Alias for :attr:`last_revocation_result`."""
        return self.last_revocation_result

    @property
    def revoke_url(self):
        """Endpoint used to revoke stale downscoped access tokens."""
        return self._revoke_url

    def policy_attestation(self):
        """Returns the policy attribution for the installed token.

        Tokens installed by :meth:`refresh` are bound to the exact policy
        version that produced them. A token assigned directly by a caller is
        reported as unmanaged for backwards compatibility.

        Raises:
            StalePolicyExchangeError: If a tracked token's policy attribution
                does not match the current boundary.
        """
        with self._policy_lock:
            current_version = self._policy_version
            current_fingerprint = self.policy_fingerprint
            if not self.token:
                raise StalePolicyExchangeError(
                    "There is no access token to authorize the request.",
                    exchange_policy_version=self._token_policy_version,
                    current_policy_version=current_version,
                )
            if self._token_policy_version is not None and (
                self._token_policy_version != current_version
                or self._token_policy_fingerprint != current_fingerprint
            ):
                raise StalePolicyExchangeError(
                    "The pending token does not belong to the current access boundary.",
                    exchange_policy_version=self._token_policy_version,
                    current_policy_version=current_version,
                )
            return {
                "policy_version": current_version,
                "token_policy_version": self._token_policy_version,
                "policy_fingerprint": current_fingerprint,
                "token_policy_fingerprint": self._token_policy_fingerprint,
                "attribution": "sts"
                if self._token_policy_version is not None
                else "unmanaged",
            }

    def _clear_token_state(self):
        self.token = None
        self.expiry = None
        self._token_policy_version = None
        self._token_policy_fingerprint = None

    def invalidate_token(self):
        """Detaches the installed token without changing the policy version."""
        with self._policy_lock:
            self._clear_token_state()

    def _revoke_token(
        self, request, token, policy_version, revoke_url=None, exchange_id=None
    ):
        url = revoke_url or self._revoke_url
        result = RevocationResult(
            policy_version=policy_version,
            token=token,
            url=url,
            status="pending",
        )
        self._journal.record(
            "token_revocation_started",
            policy_version=policy_version,
            exchange_id=exchange_id,
            revoke_url=url,
        )
        try:
            response = self._sts_client.revoke_token(
                request=request,
                token=token,
                token_type_hint=_STS_ACCESS_TOKEN_TYPE_HINT,
                revoke_url=url,
            )
            result.mark_succeeded(response or {})
        except Exception as error:
            result.mark_failed(error)
            self.revocation_results.append(result)
            self._journal.record(
                "token_revocation_failed",
                policy_version=policy_version,
                exchange_id=exchange_id,
                error=str(error),
            )
            return result

        self.revocation_results.append(result)
        self._journal.record(
            "token_revocation_succeeded",
            policy_version=policy_version,
            exchange_id=exchange_id,
            revoke_url=url,
        )
        return result

    def update_access_boundary(
        self,
        credential_access_boundary,
        request=None,
        revoke_current=True,
        revoke_url=None,
        metadata=None,
    ):
        """Replaces this instance's access boundary and advances its version.

        The update is instance-local. Other credential objects, including ones
        constructed with the same source credentials, keep their own policy
        version and boundary.

        Any token installed under the previous policy is detached immediately.
        When ``request`` is supplied, that token is also revoked and the explicit
        :class:`PolicyUpdateReceipt` contains the :class:`RevocationResult`.
        Responses from STS exchanges started under the old version are rejected
        by :meth:`refresh` and their tokens are revoked instead of installed.
        """
        if not isinstance(
            credential_access_boundary, CredentialAccessBoundary
        ):
            raise exceptions.InvalidType(
                "credential_access_boundary must be a "
                "google.auth.downscoped.CredentialAccessBoundary."
            )

        with self._policy_lock:
            old_version = self._policy_version
            old_token = self.token
            self._credential_access_boundary = credential_access_boundary
            self._policy_version = old_version + 1
            self._policy_fingerprint = _boundary_fingerprint(
                credential_access_boundary
            )
            self._clear_token_state()
            new_version = self._policy_version

            revocation = None
            if revoke_current and old_token:
                if request is None:
                    revocation = RevocationResult(
                        policy_version=old_version,
                        token=old_token,
                        url=revoke_url or self._revoke_url,
                        status="not_requested",
                        reason="A request transport is required to revoke the token.",
                    )
                # If a request was supplied, revocation runs after releasing
                # the state lock. The token has already been detached, so a
                # queued send cannot apply it after the update.

            self._journal.record(
                "boundary_updated",
                old_policy_version=old_version,
                new_policy_version=new_version,
                rule_count=len(credential_access_boundary.rules),
                metadata=dict(metadata or {}),
            )

        if revoke_current and old_token and request is not None:
            revocation = self._revoke_token(
                request,
                old_token,
                old_version,
                revoke_url=revoke_url,
            )

        receipt = PolicyUpdateReceipt(
            old_policy_version=old_version,
            new_policy_version=new_version,
            boundary=credential_access_boundary,
            revocation=revocation,
            metadata=metadata,
        )
        self.policy_updates.append(receipt)
        return receipt

    update_credential_access_boundary = update_access_boundary
    replace_access_boundary = update_access_boundary

    def revoke(self, request, revoke_url=None):
        """Revokes and detaches the token for the current policy."""
        with self._policy_lock:
            token = self.token
            policy_version = self._token_policy_version or self._policy_version
        if not token:
            raise exceptions.OAuthError(
                "The downscoped credentials do not contain an access token to revoke."
            )
        result = self._revoke_token(
            request, token, policy_version, revoke_url=revoke_url
        )
        if result.failed:
            raise result.error
        self.invalidate_token()
        return result

    @_helpers.copy_docstring(credentials.Credentials)
    def before_request(self, request, method, url, headers):
        super(Credentials, self).before_request(request, method, url, headers)
        self.policy_attestation()

    @_helpers.copy_docstring(credentials.Credentials)
    def refresh(self, request):
        with self._policy_lock:
            policy_version = self._policy_version
            policy_fingerprint = _boundary_fingerprint(
                self._credential_access_boundary
            )
            additional_options = self._credential_access_boundary.to_json()
            self._exchange_counter += 1
            exchange_id = "{}-{}".format(policy_version, self._exchange_counter)

        self._journal.record(
            "sts_exchange_started",
            exchange_id=exchange_id,
            policy_version=policy_version,
            policy_fingerprint=policy_fingerprint,
        )

        # Generate an access token from the source credentials.
        self._source_credentials.refresh(request)
        now = _helpers.utcnow()
        # Exchange the access token for a downscoped access token. The options
        # are snapshotted above so an update cannot mutate this exchange's rule set.
        response_data = self._sts_client.exchange_token(
            request=request,
            grant_type=_STS_GRANT_TYPE,
            subject_token=self._source_credentials.token,
            subject_token_type=_STS_SUBJECT_TOKEN_TYPE,
            requested_token_type=_STS_REQUESTED_TOKEN_TYPE,
            additional_options=additional_options,
        )
        access_token = response_data.get("access_token")
        # For downscoping CAB flow, the STS endpoint may not return the expiration
        # field for some flows. The generated downscoped token should always have
        # the same expiration time as the source credentials. When no expires_in
        # field is returned in the response, we can just get the expiration time
        # from the source credentials.
        if response_data.get("expires_in"):
            lifetime = datetime.timedelta(seconds=response_data.get("expires_in"))
            new_expiry = now + lifetime
        else:
            new_expiry = self._source_credentials.expiry

        with self._policy_lock:
            current_version = self._policy_version
            current_fingerprint = self.policy_fingerprint
            policy_is_current = (
                policy_version == current_version
                and policy_fingerprint == current_fingerprint
            )

            if not policy_is_current:
                self._journal.record(
                    "sts_exchange_rejected",
                    exchange_id=exchange_id,
                    exchange_policy_version=policy_version,
                    current_policy_version=current_version,
                )
                stale_token = access_token

        if not policy_is_current:
            revocation = None
            if stale_token:
                revocation = self._revoke_token(
                    request,
                    stale_token,
                    policy_version,
                    exchange_id=exchange_id,
                )
            error = StalePolicyExchangeError(
                "STS response for policy version {} arrived after the boundary "
                "was updated to version {}; the stale token was not installed.".format(
                    policy_version, current_version
                ),
                exchange_policy_version=policy_version,
                current_policy_version=current_version,
                exchange_id=exchange_id,
                revocation=revocation,
            )
            self._journal.record(
                "sts_exchange_policy_mismatch",
                exchange_id=exchange_id,
                exchange_policy_version=policy_version,
                current_policy_version=current_version,
                revocation=revocation.to_dict() if revocation else None,
            )
            raise error

        with self._policy_lock:
            self.token = access_token
            self.expiry = new_expiry
            self._token_policy_version = policy_version
            self._token_policy_fingerprint = policy_fingerprint
        self._journal.record(
            "sts_exchange_committed",
            exchange_id=exchange_id,
            policy_version=policy_version,
        )

    @_helpers.copy_docstring(credentials.CredentialsWithQuotaProject)
    def with_quota_project(self, quota_project_id):
        return self.__class__(
            self._source_credentials,
            self._credential_access_boundary,
            quota_project_id=quota_project_id,
            universe_domain=self.universe_domain,
            revoke_url=self._revoke_url,
        )


def update_access_boundary(
    credential, credential_access_boundary, request=None, **kwargs
):
    """Module-level convenience wrapper for :meth:`Credentials.update_access_boundary`."""
    return credential.update_access_boundary(
        credential_access_boundary, request=request, **kwargs
    )
