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
"""Compliance policy support for server-side copies.

A :class:`CopyCompliancePolicy` describes the compliance attributes that a
destination object must carry. The policy is resolved once, before either
copy path submits a destination request, so single-part ``CopyObject``
copies and multipart copies submit the same destination attributes.
"""

import datetime
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlencode

from botocore.exceptions import ClientError

from s3transfer.exceptions import (
    ComplianceViolationError,
    UnknownSourceComplianceError,
)

logger = logging.getLogger(__name__)

_RETENTION_MODE_RANK = {'GOVERNANCE': 1, 'COMPLIANCE': 2}
_VALID_UNKNOWN_SOURCE_POLICIES = ('fail', 'ignore')

# Arguments that can be forwarded to the object-level reads used to gather
# source compliance attributes.
_OBJECT_READ_ARGS = ('RequestPayer', 'ExpectedBucketOwner')

# S3 returns these codes when the object simply has no tag set or object
# lock configuration. They mean "known absence", not "unknown".
_KNOWN_ABSENT_RETENTION_CODES = ('NoSuchObjectLockConfiguration',)
_KNOWN_ABSENT_TAGGING_CODES = ('NoSuchTagSet',)


class CopyCompliancePolicy:
    """Configurable compliance policy for server-side copies.

    The policy is opt-in. If no policy is supplied to
    :meth:`TransferManager.copy <s3transfer.manager.TransferManager.copy>`,
    copies keep their previous behavior.

    :param required_tags: Iterable of tag keys that must exist on the
        destination object. Source tags are preserved as a whole and
        ``tag_overrides`` may add or replace values. If a required key is
        missing from both the source and the overrides, the copy fails with
        :class:`~s3transfer.exceptions.ComplianceViolationError`.

    :param tag_overrides: Mapping of tag keys to values applied to the
        destination. These values override the same keys read from the
        source. Supplying overrides without ``required_tags`` still makes
        tags policy-managed.

    :param preserve_object_lock: If True, the source retention mode,
        retention date, and legal hold status are carried to the
        destination. Missing source information is handled according to
        ``on_unknown_source``.

    :param minimum_retention_mode: Destination retention mode floor,
        ``'GOVERNANCE'`` or ``'COMPLIANCE'``. The destination never receives
        a mode weaker than the source mode or this value.

    :param minimum_retain_until: Destination retention date floor. The
        destination never receives a date earlier than the source date or
        this value.

    :param require_legal_hold: If True, the destination receives a legal
        hold of ``'ON'``. A source legal hold of ``'ON'`` is always
        preserved regardless of this value.

    :param on_unknown_source: Controls what happens when policy-required
        source attributes cannot be read. The default, ``'fail'``, raises
        :class:`~s3transfer.exceptions.UnknownSourceComplianceError` before
        any destination request is made. ``'ignore'`` continues without the
        unreadable attribute and logs a warning. Known absence (for example,
        no object lock configuration) is never treated as unknown.
    """

    VALID_UNKNOWN_SOURCE_POLICIES = _VALID_UNKNOWN_SOURCE_POLICIES

    def __init__(
        self,
        required_tags=None,
        tag_overrides=None,
        preserve_object_lock=False,
        minimum_retention_mode=None,
        minimum_retain_until=None,
        require_legal_hold=False,
        on_unknown_source='fail',
    ):
        self._manages_tags = bool(required_tags or ()) or bool(tag_overrides)
        if isinstance(required_tags, str):
            required_tags = (required_tags,)
        self.required_tags = _dedupe(required_tags or ())

        if tag_overrides is None:
            tag_overrides = {}
        if not isinstance(tag_overrides, Mapping):
            raise ValueError('tag_overrides must be a mapping of key to value')
        self.tag_overrides = {
            str(key): str(value) for key, value in tag_overrides.items()
        }

        if minimum_retention_mode is not None:
            minimum_retention_mode = minimum_retention_mode.upper()
            if minimum_retention_mode not in _RETENTION_MODE_RANK:
                raise ValueError(
                    'minimum_retention_mode must be one of '
                    f'{sorted(_RETENTION_MODE_RANK)}'
                )
        self.minimum_retention_mode = minimum_retention_mode

        if minimum_retain_until is not None and not isinstance(
            minimum_retain_until, datetime.datetime
        ):
            raise ValueError(
                'minimum_retain_until must be a datetime.datetime'
            )
        self.minimum_retain_until = minimum_retain_until

        if on_unknown_source not in _VALID_UNKNOWN_SOURCE_POLICIES:
            raise ValueError(
                'on_unknown_source must be one of '
                f'{_VALID_UNKNOWN_SOURCE_POLICIES}'
            )
        self.on_unknown_source = on_unknown_source
        self.preserve_object_lock = bool(preserve_object_lock)
        self.require_legal_hold = bool(require_legal_hold)

    @property
    def manages_tags(self):
        return self._manages_tags

    @property
    def manages_object_lock(self):
        return bool(
            self.preserve_object_lock
            or self.minimum_retention_mode
            or self.minimum_retain_until
            or self.require_legal_hold
        )

    @property
    def is_noop(self):
        return not self.manages_tags and not self.manages_object_lock


@dataclass(frozen=True)
class CopyCompliancePlan:
    """Resolved destination attributes for a copy.

    ``tag_set`` is the exact tag set to submit, or ``None`` when tags are not
    policy-managed. ``object_lock_args`` contains only the Object Lock
    arguments that must be submitted. ``unknown_attributes`` records
    attributes skipped because ``on_unknown_source='ignore'``.
    """

    tag_set: tuple | None = None
    object_lock_args: tuple = ()
    unknown_attributes: tuple = ()
    manages_object_lock: bool = False

    @property
    def tagging(self):
        if self.tag_set is None:
            return None
        return urlencode([(tag['Key'], tag['Value']) for tag in self.tag_set])

    @property
    def manages_tags(self):
        return self.tag_set is not None

    @property
    def is_noop(self):
        return not self.manages_tags and not self.manages_object_lock

    @property
    def object_lock_kwargs(self):
        return dict(self.object_lock_args)

    @property
    def destination_args(self):
        args = self.object_lock_kwargs
        if self.tagging:
            args['Tagging'] = self.tagging
        return args


def resolve_copy_compliance(
    policy,
    source_client,
    copy_source,
    source_version_id,
    extra_args,
    head_response=None,
):
    """Resolve a policy into destination arguments.

    All source reads happen here, before either copy path submits a
    destination request. This is what keeps the single-part and multipart
    paths on the same compliance contract.

    :raises UnknownSourceComplianceError: A required source attribute could
        not be read and ``on_unknown_source='fail'``.
    :raises ComplianceViolationError: The source and policy cannot produce a
        valid destination attribute set.
    """
    if policy is None or policy.is_noop:
        return CopyCompliancePlan()
    _validate_copy_source(copy_source)

    unknown = []
    tag_set = None
    if policy.manages_tags:
        tag_set = _resolve_tags(
            policy,
            source_client,
            copy_source,
            source_version_id,
            extra_args,
            unknown,
        )

    object_lock_args = {}
    if policy.manages_object_lock:
        object_lock_args = _resolve_object_lock(
            policy,
            source_client,
            copy_source,
            source_version_id,
            extra_args,
            head_response,
            unknown,
        )

    return CopyCompliancePlan(
        tag_set=tuple(tag_set) if tag_set is not None else None,
        object_lock_args=tuple(sorted(object_lock_args.items())),
        unknown_attributes=tuple(unknown),
        manages_object_lock=policy.manages_object_lock,
    )


def _resolve_tags(
    policy,
    source_client,
    copy_source,
    source_version_id,
    extra_args,
    unknown,
):
    try:
        source_tag_set = _get_source_tags(
            source_client, copy_source, source_version_id, extra_args
        )
    except ClientError as e:
        if _error_code(e) in _KNOWN_ABSENT_TAGGING_CODES:
            source_tag_set = []
        else:
            # _record_unknown raises immediately under the default 'fail'
            # setting, so a required-tag check never masks the unreadable
            # source attribute with a misleading "missing tag" error.
            _record_unknown(
                policy,
                unknown,
                'tags',
                _source_description(copy_source),
                e,
            )
            # Under 'ignore' only the explicit overrides can be applied.
            source_tag_set = []

    values = {tag['Key']: tag['Value'] for tag in source_tag_set}
    values.update(policy.tag_overrides)

    missing = [key for key in policy.required_tags if key not in values]
    if missing:
        raise ComplianceViolationError(
            f'Required tag(s) {missing} are missing from source '
            f'{_source_description(copy_source)} and no tag_overrides value '
            'was supplied.'
        )

    # Keep source ordering first, then append override-only keys.
    ordered_keys = [tag['Key'] for tag in source_tag_set]
    ordered_keys.extend(
        key for key in policy.tag_overrides if key not in ordered_keys
    )
    return [{'Key': key, 'Value': values[key]} for key in ordered_keys]


def _get_source_tags(
    source_client, copy_source, source_version_id, extra_args
):
    request = {
        'Bucket': copy_source['Bucket'],
        'Key': copy_source['Key'],
        **_object_read_args(extra_args),
    }
    if source_version_id:
        request['VersionId'] = source_version_id
    return source_client.get_object_tagging(**request).get('TagSet', [])


def _resolve_object_lock(
    policy,
    source_client,
    copy_source,
    source_version_id,
    extra_args,
    head_response,
    unknown,
):
    mode = None
    retain_until = None
    legal_hold = 'OFF'

    if policy.preserve_object_lock:
        source_description = _source_description(copy_source)
        try:
            retention = _get_source_retention(
                source_client,
                copy_source,
                source_version_id,
                extra_args,
                head_response,
            )
        except ClientError as e:
            if _error_code(e) in _KNOWN_ABSENT_RETENTION_CODES:
                retention = None
            else:
                _record_unknown(
                    policy,
                    unknown,
                    'object lock retention',
                    source_description,
                    e,
                )
                retention = None
        if retention:
            mode = retention.get('Mode')
            retain_until = retention.get('RetainUntilDate')

        try:
            legal_hold = _get_source_legal_hold(
                source_client,
                copy_source,
                source_version_id,
                extra_args,
                head_response,
            )
        except ClientError as e:
            if _error_code(e) in _KNOWN_ABSENT_RETENTION_CODES:
                legal_hold = 'OFF'
            else:
                _record_unknown(
                    policy,
                    unknown,
                    'object lock legal hold',
                    source_description,
                    e,
                )
                legal_hold = 'OFF'

    if policy.minimum_retention_mode is not None:
        if mode is None or _RETENTION_MODE_RANK[
            policy.minimum_retention_mode
        ] > _RETENTION_MODE_RANK.get(mode, 0):
            mode = policy.minimum_retention_mode

    if policy.minimum_retain_until is not None:
        minimum_retain_until = _as_utc(policy.minimum_retain_until)
        if (
            retain_until is None
            or _as_utc(retain_until) < minimum_retain_until
        ):
            retain_until = policy.minimum_retain_until

    # Caller-supplied Object Lock values are treated as additional floors.
    # The policy must never be used to undercut a stronger destination lock.
    caller_mode = extra_args.get('ObjectLockMode')
    if caller_mode is not None:
        caller_mode = caller_mode.upper()
        if _RETENTION_MODE_RANK.get(caller_mode, 0) > _RETENTION_MODE_RANK.get(
            mode, 0
        ):
            mode = caller_mode
    caller_retain_until = extra_args.get('ObjectLockRetainUntilDate')
    if caller_retain_until is not None and (
        retain_until is None
        or _as_utc(caller_retain_until) > _as_utc(retain_until)
    ):
        retain_until = caller_retain_until
    if extra_args.get('ObjectLockLegalHoldStatus') == 'ON':
        legal_hold = 'ON'

    if retain_until is not None and mode is None:
        raise ComplianceViolationError(
            'A destination retention date requires a retention mode. Set '
            'minimum_retention_mode or preserve a source retention mode.'
        )
    if mode is not None and retain_until is None:
        raise ComplianceViolationError(
            f'Retention mode {mode} requires a retention date. Set '
            'minimum_retain_until or preserve a source retention date.'
        )

    result = {}
    if mode is not None:
        result['ObjectLockMode'] = mode
        result['ObjectLockRetainUntilDate'] = retain_until
    if legal_hold == 'ON' or policy.require_legal_hold:
        result['ObjectLockLegalHoldStatus'] = 'ON'
    return result


def _get_source_retention(
    source_client, copy_source, source_version_id, extra_args, head_response
):
    if head_response is not None:
        mode = head_response.get('ObjectLockMode')
        retain_until = head_response.get('ObjectLockRetainUntilDate')
        if mode and retain_until:
            return {'Mode': mode, 'RetainUntilDate': retain_until}

    request = {
        'Bucket': copy_source['Bucket'],
        'Key': copy_source['Key'],
        **_object_read_args(extra_args),
    }
    if source_version_id:
        request['VersionId'] = source_version_id
    return source_client.get_object_retention(**request).get('Retention')


def _get_source_legal_hold(
    source_client, copy_source, source_version_id, extra_args, head_response
):
    if head_response is not None:
        status = head_response.get('ObjectLockLegalHoldStatus')
        if status:
            return status

    request = {
        'Bucket': copy_source['Bucket'],
        'Key': copy_source['Key'],
        **_object_read_args(extra_args),
    }
    if source_version_id:
        request['VersionId'] = source_version_id
    legal_hold = source_client.get_object_legal_hold(**request).get(
        'LegalHold'
    )
    if legal_hold:
        return legal_hold.get('Status', 'OFF')
    return 'OFF'


def _record_unknown(policy, unknown, attribute, source, error):
    prefix = f'Unable to determine source {attribute} for {source}: {error}. '
    if policy.on_unknown_source == 'fail':
        raise UnknownSourceComplianceError(
            prefix
            + 'The copy was stopped before any destination request was made. '
            "Set on_unknown_source='ignore' to continue without this "
            'attribute.'
        )
    logger.warning(
        prefix + 'Continuing without this attribute because '
        "on_unknown_source='ignore'."
    )
    unknown.append(attribute)


def _object_read_args(extra_args):
    return {
        key: extra_args[key] for key in _OBJECT_READ_ARGS if key in extra_args
    }


def _error_code(error):
    return error.response.get('Error', {}).get('Code', '')


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _source_description(copy_source):
    return f's3://{copy_source["Bucket"]}/{copy_source["Key"]}'


def _dedupe(values):
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return tuple(result)


def _validate_copy_source(copy_source):
    if not isinstance(copy_source, dict):
        raise TypeError(
            'Expecting dictionary formatted: '
            '{"Bucket": bucket_name, "Key": key} '
            f'but got {copy_source} or type {type(copy_source)}.'
        )
