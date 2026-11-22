# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Optional handover records for migration and archive transfers.

The database of an archiving team typically only keeps the terminal status of
a transfer (e.g. "success").  That is not enough to prove *which version* of an
object was replicated nor what the destination actually contains.  A
:class:`HandoverRecorder` can be attached to an ``upload()`` or ``copy()``
call to collect a :class:`HandoverRecord` describing:

* the *scope* of the transfer (source and destination coordinates, including
  any source ``VersionId``), which is known before any data moves and is
  therefore available even when the transfer is cancelled;
* the *result evidence* returned by S3 once the destination object is finalized
  (destination ``VersionId``, ``ETag`` and the completed part list), which only
  exists on the success path;
* the number of HTTP-level retries that were needed along the way.

Only non-secret request and response metadata is ever captured.  Credentials
and SSE customer key material are deliberately not part of a record.
"""
import logging
import threading

logger = logging.getLogger(__name__)

# Event emitted by botocore after every HTTP attempt while it decides
# whether to retry.  Registered with ``register_last`` so the built-in
# retry handler has already run by the time the recorder observes the
# decision.
NEEDS_RETRY_EVENT = 'needs-retry.s3.*'

# Response metadata that can safely be handed over.  Anything potentially
# sensitive (for example SSE customer keys) is intentionally excluded.
_EVIDENCE_KEYS = (
    'VersionId',
    'ETag',
    'ChecksumCRC32',
    'ChecksumCRC32C',
    'ChecksumCRC64NVME',
    'ChecksumSHA1',
    'ChecksumSHA256',
    'ChecksumSHA512',
)


class HandoverRecord:
    """Serializable snapshot produced by a :class:`HandoverRecorder`.

    A record always carries the transfer ``status`` and its ``scope``.  The
    result evidence fields are only populated when the transfer reaches the
    ``success`` state; a cancelled or failed transfer has no destination object
    to attest to, so those fields stay ``None`` / empty.
    """

    def __init__(
        self,
        status,
        scope,
        destination_version_id=None,
        destination_etag=None,
        source_version_id=None,
        source_etag=None,
        upload_id=None,
        parts=None,
        attempts=1,
    ):
        self.status = status
        self.scope = dict(scope) if scope else {}
        self.destination_version_id = destination_version_id
        self.destination_etag = destination_etag
        self.source_version_id = source_version_id
        self.source_etag = source_etag
        self.upload_id = upload_id
        self.parts = list(parts) if parts else []
        self.attempts = attempts

    def to_dict(self):
        """Return a plain dictionary suitable for JSON-style persistence."""
        return {
            'status': self.status,
            'scope': dict(self.scope),
            'source_version_id': self.source_version_id,
            'source_etag': self.source_etag,
            'destination_version_id': self.destination_version_id,
            'destination_etag': self.destination_etag,
            'upload_id': self.upload_id,
            'parts': [dict(part) for part in self.parts],
            'attempts': self.attempts,
        }

    def __repr__(self):
        return (
            f'HandoverRecord(status={self.status!r}, scope={self.scope!r}, '
            f'destination_version_id={self.destination_version_id!r}, '
            f'destination_etag={self.destination_etag!r}, '
            f'attempts={self.attempts})'
        )

    def __eq__(self, other):
        if not isinstance(other, HandoverRecord):
            return NotImplemented
        return self.to_dict() == other.to_dict()


def _safe_evidence(response, keys=_EVIDENCE_KEYS):
    """Extract non-secret evidence fields from an S3 API response.

    ``CopyObject`` nests the object-level attributes under
    ``CopyObjectResult``, so both locations are considered.
    """
    if not response:
        return {}
    evidence = {key: response[key] for key in keys if key in response}
    nested = response.get('CopyObjectResult')
    if isinstance(nested, dict):
        for key in keys:
            if key not in evidence and key in nested:
                evidence[key] = nested[key]
    return evidence


class HandoverRecorder:
    """Collects a single :class:`HandoverRecord` for one transfer.

    A recorder is bound to one ``upload()`` or ``copy()`` call.  The recorder
    is thread-safe: the individual S3 tasks run on the manager's worker
    threads and update it concurrently.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._scope = None
        self._source_version_id = None
        self._source_etag = None
        self._upload_id = None
        self._parts = []
        self._result_evidence = {}
        # Maps a botocore invocation id (one per S3 operation call) to the
        # highest HTTP attempt observed for that call, so retries on one
        # operation do not inflate the attempt count of the others.
        self._attempts_by_invocation = {}
        self._record = None
        self._client = None
        self._retry_handler = None
        self._event_unique_id = f's3transfer-handover-{id(self)}'

    # -- wiring -------------------------------------------------------------
    def attach_to_client(self, client):
        """Start observing HTTP-level retries on a botocore S3 client.

        The handler is removed in :meth:`finalize` so recorders do not leave
        handlers behind on a shared client.
        """
        self._client = client
        self._retry_handler = self._on_retry_decision
        client.meta.events.register_last(
            NEEDS_RETRY_EVENT,
            self._retry_handler,
            unique_id=self._event_unique_id,
        )

    def detach_from_client(self):
        if self._client is not None and self._retry_handler is not None:
            self._client.meta.events.unregister(
                NEEDS_RETRY_EVENT,
                self._retry_handler,
                unique_id=self._event_unique_id,
            )
        self._retry_handler = None
        self._client = None

    def _on_retry_decision(
        self,
        attempts=None,
        response=None,
        caught_exception=None,
        request_dict=None,
        **kwargs,
    ):
        # The event fires once per HTTP attempt while botocore evaluates a
        # retry.  The request context's invocation id uniquely identifies the
        # S3 operation call, so the highest ``attempts`` value per invocation
        # is that call's total number of HTTP attempts.  ``register_last``
        # keeps this observer from influencing botocore's own retry decision.
        # ``response`` and ``caught_exception`` are part of the event contract
        # but are not needed to count attempts.
        if attempts is None or request_dict is None:
            return
        invocation_id = (
            request_dict.get('context', {})
            .get('retries', {})
            .get('invocation-id')
        )
        if invocation_id is None:
            return
        with self._lock:
            previous = self._attempts_by_invocation.get(invocation_id, 0)
            self._attempts_by_invocation[invocation_id] = max(
                previous, attempts
            )

    def _max_attempts(self):
        if not self._attempts_by_invocation:
            return 1
        return max(self._attempts_by_invocation.values())

    @property
    def attempts(self):
        """Highest HTTP attempt count observed for any single S3 operation."""
        with self._lock:
            return self._max_attempts()

    # -- scope (known before any data moves) --------------------------------
    def set_scope(self, scope):
        with self._lock:
            self._scope = dict(scope)
            self._source_version_id = scope.get('source_version_id')

    def note_head_object(self, response):
        """Record source coordinates discovered via HeadObject."""
        evidence = _safe_evidence(response)
        with self._lock:
            if self._scope is None:
                self._scope = {}
            self._source_etag = evidence.get('ETag')
            version_id = response.get('VersionId')
            if version_id is not None and not self._source_version_id:
                self._source_version_id = version_id
                self._scope['source_version_id'] = version_id

    # -- task hooks ---------------------------------------------------------
    def note_upload_id(self, upload_id):
        with self._lock:
            self._upload_id = upload_id

    def note_part(self, part):
        with self._lock:
            self._parts.append(dict(part))

    def note_result(self, response):
        """Record evidence from the final object-level S3 response."""
        with self._lock:
            self._result_evidence = _safe_evidence(response)

    # -- output -------------------------------------------------------------
    def finalize(self, status):
        """Freeze the record for the given terminal ``status``.

        Safe to call more than once; the first call wins so a late task
        callback can never rewrite an already published record.
        """
        with self._lock:
            if self._record is not None:
                return self._record
            scope = dict(self._scope) if self._scope else {}
            evidence = dict(self._result_evidence)
            record = HandoverRecord(
                status=status,
                scope=scope,
                source_version_id=self._source_version_id,
                source_etag=self._source_etag,
                upload_id=self._upload_id,
                parts=list(self._parts),
                attempts=self._max_attempts(),
                destination_version_id=evidence.get('VersionId'),
                destination_etag=evidence.get('ETag'),
            )
            self._record = record
        self.detach_from_client()
        logger.debug('Finalized handover record: %s', record)
        return record

    @property
    def record(self):
        """The finalized :class:`HandoverRecord`, or ``None`` if not done."""
        return self._record
