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
"""Server-side encryption requirements for uploads.

A caller may attach an :class:`UploadEncryptionPolicy` to a single upload
request. The policy describes the server-side encryption settings that are
approved for the destination and is resolved exactly once, before any request
is made. The resolved settings are then applied to every request that writes
object data or creates the object, so a non-multipart upload and a multipart
upload make the same decision.

The policy only constrains server-side encryption. Parameters that are not
covered by the policy (for example ``ACL`` or ``Metadata``) are left alone,
and an upload without a policy behaves exactly as before.
"""

from s3transfer.exceptions import S3UploadEncryptionError

# Server-side encryption parameters that apply to object writes. These are the
# parameters that a policy is allowed to constrain and that are checked for
# consistency between the caller's request and the approved settings.
SSE_ALGORITHM_ARG = 'ServerSideEncryption'
SSE_KMS_KEY_ID_ARG = 'SSEKMSKeyId'
SSE_KMS_CONTEXT_ARG = 'SSEKMSEncryptionContext'
SSE_BUCKET_KEY_ARG = 'BucketKeyEnabled'
SSE_CUSTOMER_ALGORITHM_ARG = 'SSECustomerAlgorithm'
SSE_CUSTOMER_KEY_ARG = 'SSECustomerKey'
SSE_CUSTOMER_KEY_MD5_ARG = 'SSECustomerKeyMD5'

SSE_CUSTOMER_ARGS = (
    SSE_CUSTOMER_ALGORITHM_ARG,
    SSE_CUSTOMER_KEY_ARG,
    SSE_CUSTOMER_KEY_MD5_ARG,
)

SSE_MANAGED_ALGORITHMS = ('AES256', 'aws:kms', 'aws:kms:dsse')


class UploadEncryptionPolicy:
    """Approved server-side encryption settings for a single upload.

    The policy records the encryption settings that the caller has approved
    for the destination of one upload. Its attributes are read-only by
    convention: the same instance is evaluated once per upload and the
    resolved ``extra_args`` are forwarded to both the single request and
    multipart paths.

    :param server_side_encryption: The approved ``ServerSideEncryption``
        value, for example ``'AES256'`` or ``'aws:kms'``. When provided, every
        object write must use exactly this value.

    :param sse_kms_key_id: The approved KMS key for ``aws:kms`` (or
        ``aws:kms:dsse``) uploads. Supplying a key implies ``aws:kms`` when
        ``server_side_encryption`` is not provided.

    :param sse_kms_encryption_context: The approved KMS encryption context.
        When set, the caller must supply the same context and no other
        context may be used.

    :param bucket_key_enabled: The approved ``BucketKeyEnabled`` value.

    :param sse_customer_algorithm: The approved customer-provided encryption
        algorithm. When set, the caller must provide the customer key.

    :param require_existing_sse: When ``True`` the caller must already have
        supplied server-side encryption settings on the upload request and
        the policy only narrows them. When ``False`` (the default) the policy
        supplies its approved settings when the caller did not.

    :param allowed_regions: Optional iterable of region names. When provided,
        uploads issued through a client for another region are rejected
        before any request is made.
    """

    def __init__(
        self,
        server_side_encryption=None,
        sse_kms_key_id=None,
        sse_kms_encryption_context=None,
        bucket_key_enabled=None,
        sse_customer_algorithm=None,
        require_existing_sse=False,
        allowed_regions=None,
    ):
        self.server_side_encryption = server_side_encryption
        self.sse_kms_key_id = sse_kms_key_id
        self.sse_kms_encryption_context = sse_kms_encryption_context
        self.bucket_key_enabled = bucket_key_enabled
        self.sse_customer_algorithm = sse_customer_algorithm
        self.require_existing_sse = require_existing_sse
        if allowed_regions is None:
            self.allowed_regions = None
        else:
            self.allowed_regions = frozenset(allowed_regions)
        self._validate_policy()

    def _validate_policy(self):
        approved_managed = any(
            value is not None
            for value in (
                self.server_side_encryption,
                self.sse_kms_key_id,
                self.sse_kms_encryption_context,
                self.bucket_key_enabled,
            )
        )
        if not (
            approved_managed
            or self.sse_customer_algorithm is not None
            or self.allowed_regions is not None
            or self.require_existing_sse
        ):
            raise ValueError(
                'An upload encryption policy must approve or require at '
                'least one encryption setting.'
            )
        if (
            self.server_side_encryption is not None
            and self.server_side_encryption not in SSE_MANAGED_ALGORITHMS
        ):
            raise ValueError(
                'ServerSideEncryption must be one of: '
                f'{", ".join(SSE_MANAGED_ALGORITHMS)}'
            )
        if (
            self.server_side_encryption == 'AES256'
            and self.sse_kms_key_id is not None
        ):
            raise ValueError(
                'SSEKMSKeyId cannot be approved for AES256 uploads.'
            )
        if (
            self.sse_kms_encryption_context is not None
            and self.sse_kms_key_id is None
            and self.server_side_encryption
            not in ('aws:kms', 'aws:kms:dsse')
        ):
            raise ValueError(
                'SSEKMSEncryptionContext requires an approved KMS key or '
                'an aws:kms ServerSideEncryption value.'
            )
        if (
            self.bucket_key_enabled is not None
            and self.sse_kms_key_id is None
            and self.server_side_encryption
            not in ('aws:kms', 'aws:kms:dsse')
        ):
            raise ValueError(
                'BucketKeyEnabled requires an approved KMS key or an '
                'aws:kms ServerSideEncryption value.'
            )
        if (
            self.sse_customer_algorithm is not None
            and any(
                value is not None
                for value in (
                    self.server_side_encryption,
                    self.sse_kms_key_id,
                    self.sse_kms_encryption_context,
                    self.bucket_key_enabled,
                )
            )
        ):
            raise ValueError(
                'Customer-provided encryption and managed server-side '
                'encryption cannot both be approved.'
            )
        if self.allowed_regions is not None and not self.allowed_regions:
            raise ValueError('allowed_regions must not be empty when set.')

    def resolve(self, region_name, request_args):
        """Resolves the approved settings for one upload.

        :param region_name: The region configured on the client that will
            perform the upload.

        :param request_args: The ``extra_args`` supplied by the caller. The
            mapping is not mutated; a new dictionary is returned.

        :returns: A copy of ``request_args`` with the approved server-side
            encryption settings applied.

        :raises s3transfer.exceptions.S3UploadEncryptionError: If the upload
            cannot satisfy the approved settings. This is raised before any
            request is made, so no object data is written.
        """
        resolved = dict(request_args)
        self._validate_region(region_name)
        self._validate_customer_encryption(resolved)
        self._apply_managed_encryption(resolved)
        self._validate_kms_settings(resolved)
        return resolved

    def _validate_region(self, region_name):
        if (
            self.allowed_regions is not None
            and region_name not in self.allowed_regions
        ):
            raise S3UploadEncryptionError(
                'Upload encryption policy does not permit region '
                f'{region_name!r}. Allowed regions: '
                f'{", ".join(sorted(self.allowed_regions))}.'
            )

    def _validate_customer_encryption(self, request_args):
        provided = [
            arg for arg in SSE_CUSTOMER_ARGS if arg in request_args
        ]
        approved_algorithm = self.sse_customer_algorithm
        provided_algorithm = request_args.get(SSE_CUSTOMER_ALGORITHM_ARG)
        if approved_algorithm is None:
            if provided:
                raise S3UploadEncryptionError(
                    'Upload encryption policy does not permit '
                    'customer-provided encryption.'
                )
            return
        if provided_algorithm != approved_algorithm:
            raise S3UploadEncryptionError(
                'Upload encryption policy requires '
                f'{SSE_CUSTOMER_ALGORITHM_ARG}={approved_algorithm!r}.'
            )
        if SSE_CUSTOMER_KEY_ARG not in request_args:
            raise S3UploadEncryptionError(
                'Upload encryption policy requires a customer-provided key '
                f'with {SSE_CUSTOMER_ALGORITHM_ARG}.'
            )

    def _apply_managed_encryption(self, request_args):
        if self.sse_customer_algorithm is not None:
            return
        managed_args = (
            SSE_ALGORITHM_ARG,
            SSE_KMS_KEY_ID_ARG,
            SSE_KMS_CONTEXT_ARG,
            SSE_BUCKET_KEY_ARG,
        )
        provided = {
            arg: request_args[arg]
            for arg in managed_args
            if arg in request_args
        }
        if self.require_existing_sse and not (
            SSE_ALGORITHM_ARG in provided
            or SSE_KMS_KEY_ID_ARG in provided
        ):
            raise S3UploadEncryptionError(
                'Upload encryption policy requires the caller to supply '
                'ServerSideEncryption or SSEKMSKeyId on the request.'
            )
        expected_algorithm = self.server_side_encryption
        if expected_algorithm is None and self.sse_kms_key_id is not None:
            expected_algorithm = 'aws:kms'
        if expected_algorithm is None:
            # Nothing was approved. The caller may still have supplied
            # encryption settings; leave them untouched.
            return
        supplied_algorithm = provided.get(SSE_ALGORITHM_ARG)
        if (
            supplied_algorithm is not None
            and supplied_algorithm != expected_algorithm
        ):
            raise S3UploadEncryptionError(
                'Upload encryption policy requires '
                f'{SSE_ALGORITHM_ARG}={expected_algorithm!r}, not '
                f'{supplied_algorithm!r}.'
            )
        request_args[SSE_ALGORITHM_ARG] = expected_algorithm
        self._apply_kms_settings(request_args, provided)

    def _apply_kms_settings(self, request_args, provided):
        if self.sse_kms_key_id is not None:
            supplied_key = provided.get(SSE_KMS_KEY_ID_ARG)
            if (
                supplied_key is not None
                and supplied_key != self.sse_kms_key_id
            ):
                raise S3UploadEncryptionError(
                    'Upload encryption policy requires a different '
                    f'{SSE_KMS_KEY_ID_ARG} than the one supplied.'
                )
            request_args[SSE_KMS_KEY_ID_ARG] = self.sse_kms_key_id
        if self.sse_kms_encryption_context is not None:
            supplied_context = provided.get(SSE_KMS_CONTEXT_ARG)
            if (
                supplied_context is not None
                and supplied_context != self.sse_kms_encryption_context
            ):
                raise S3UploadEncryptionError(
                    'Upload encryption policy requires a different '
                    f'{SSE_KMS_CONTEXT_ARG} than the one supplied.'
                )
            request_args[SSE_KMS_CONTEXT_ARG] = (
                self.sse_kms_encryption_context
            )
        if self.bucket_key_enabled is not None:
            supplied_bucket_key = provided.get(SSE_BUCKET_KEY_ARG)
            if (
                supplied_bucket_key is not None
                and supplied_bucket_key != self.bucket_key_enabled
            ):
                raise S3UploadEncryptionError(
                    'Upload encryption policy requires a different '
                    f'{SSE_BUCKET_KEY_ARG} than the one supplied.'
                )
            request_args[SSE_BUCKET_KEY_ARG] = self.bucket_key_enabled

    def _validate_kms_settings(self, request_args):
        algorithm = request_args.get(SSE_ALGORITHM_ARG)
        kms_key_present = SSE_KMS_KEY_ID_ARG in request_args
        if kms_key_present and algorithm not in ('aws:kms', 'aws:kms:dsse'):
            raise S3UploadEncryptionError(
                f'{SSE_KMS_KEY_ID_ARG} requires ServerSideEncryption to be '
                'aws:kms or aws:kms:dsse.'
            )
        if algorithm == 'AES256' and kms_key_present:
            raise S3UploadEncryptionError(
                f'{SSE_KMS_KEY_ID_ARG} cannot be used with AES256.'
            )
