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
"""End-to-end checks for whole-content validation before publishing a
downloaded object to its final local filename.

The S3 client used here is a hand-rolled fake rather than a botocore
Stubber because the scenarios need control over *when* parallel ranged
GETs produce their bodies (out-of-order delivery) and need to inject a
mid-stream failure that forces a single part to be re-read.
"""

import glob
import hashlib
import os
import shutil
import tempfile
import threading
from io import BytesIO

from s3transfer.compat import SOCKET_ERROR
from s3transfer.exceptions import S3ValidationError
from s3transfer.manager import TransferConfig, TransferManager
from tests import StreamWithError, StubbedClientTest


class FakeS3Client:
    """A minimal S3 client that serves an object as two ranged parts.

    Delivery order is controlled with events so that tests can deterministically
    exercise out-of-order completion of the parallel GetObject requests.
    """

    def __init__(
        self,
        content,
        part_size,
        etag,
        *,
        release_order=(1, 0),
        fail_first_part_read=False,
    ):
        self._content = content
        self._part_size = part_size
        self._etag = etag
        self._fail_first_part_read = fail_first_part_read
        self.head_object_calls = []
        self.get_object_calls = []
        self._attempts_by_part = {}
        # Each part gets a release event. Every part except the last one in
        # ``release_order`` is allowed to stream immediately; the final part
        # stays blocked until the test releases it. That makes the two request
        # threads finish in ``release_order`` regardless of scheduling order.
        self._events = {i: threading.Event() for i in self._part_numbers()}
        self._entered = {i: threading.Event() for i in self._part_numbers()}
        for part_number in self._part_numbers():
            self._events[part_number].set()
        self._last_part_number = release_order[-1]
        self._events[self._last_part_number].clear()
        self.meta = SimpleMeta()

    def _part_numbers(self):
        return range(
            (len(self._content) + self._part_size - 1) // self._part_size
        )

    def head_object(self, Bucket, Key, **kwargs):
        self.head_object_calls.append({'Bucket': Bucket, 'Key': Key, **kwargs})
        return {
            'ContentLength': len(self._content),
            'ETag': f'"{self._etag}"',
        }

    def get_object(self, Bucket, Key, Range=None, **kwargs):
        start, end = self._parse_range(Range)
        part_number = start // self._part_size
        self.get_object_calls.append(
            {'Bucket': Bucket, 'Key': Key, 'Range': Range, **kwargs}
        )
        body = self._build_body(part_number, start, end)
        total_size = len(self._content)
        content_range = (
            f'bytes {start}-{end}/{total_size}'
            if end < total_size
            else f'bytes {start}-{total_size - 1}/{total_size}'
        )
        return {
            'Body': GatedBody(body, self, part_number),
            'ContentLength': end - start + 1,
            'ContentRange': content_range,
            'ETag': f'"{self._etag}"',
        }

    def _build_body(self, part_number, start, end):
        data = self._content[start : end + 1]
        attempt = self._attempts_by_part.get(part_number, 0)
        self._attempts_by_part[part_number] = attempt + 1
        if self._fail_first_part_read and part_number == 0 and attempt == 0:
            # Fail after the first chunk has been handed over on the first
            # attempt only, so the retry re-reads the part successfully.
            return StreamWithError(BytesIO(data), SOCKET_ERROR, num_reads=1)
        return BytesIO(data)

    def _parse_range(self, range_header):
        # Range looks like ``bytes=8-`` or ``bytes=0-7``.
        _, _, range_value = range_header.partition('=')
        start_text, _, end_text = range_value.partition('-')
        start = int(start_text)
        end = int(end_text) if end_text else len(self._content) - 1
        return start, end

    def _wait_for_release(self, part_number):
        self._entered[part_number].set()
        self._events[part_number].wait()

    def release_last_part(self):
        self._events[self._last_part_number].set()

    def wait_until_all_parts_started(self):
        for event in self._entered.values():
            event.wait()


class GatedBody:
    """A stream wrapper that blocks until the fake releases the part."""

    def __init__(self, body, client, part_number):
        self._body = body
        self._client = client
        self._part_number = part_number

    def read(self, amount=-1):
        self._client._wait_for_release(self._part_number)
        return self._body.read(amount)

    def close(self):
        self._body.close()


class SimpleMeta:
    def __init__(self):
        self.config = SimpleConfig()
        self.events = SimpleEvents()


class SimpleConfig:
    response_checksum_validation = 'when_supported'


class SimpleEvents:
    def register_first(self, *args, **kwargs):
        pass

    def register_last(self, *args, **kwargs):
        pass


class TestDownloadChecksumValidation(StubbedClientTest):
    def setUp(self):
        super().setUp()
        self.tempdir = tempfile.mkdtemp()
        self.filename = os.path.join(self.tempdir, 'myfile')
        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.part_size = 8
        # Two parts of 8 bytes each, deliberately sized so ranged downloads
        # always split into exactly two parallel GetObject requests.
        self.content = b'01234567abcdefgh'
        self.etag = hashlib.md5(self.content).hexdigest()

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.tempdir)

    def _temp_glob(self):
        return glob.glob(f'{self.filename}.*')

    def test_valid_object_passes_and_publishes_with_reversed_parts(self):
        fake_client = FakeS3Client(
            self.content,
            self.part_size,
            self.etag,
            release_order=(1, 0),
        )
        manager = TransferManager(
            fake_client,
            TransferConfig(
                max_request_concurrency=2,
                multipart_threshold=1,
                multipart_chunksize=self.part_size,
                validate_download_checksum=True,
            ),
        )
        self.addCleanup(manager.shutdown)

        future = manager.download(self.bucket, self.key, self.filename)
        fake_client.wait_until_all_parts_started()
        # Both parts are in flight; let the second part stream first so the
        # parts complete out of order.
        fake_client.release_last_part()
        future.result()

        # The valid object passes validation on the first attempt and is
        # published to its final location, with no temporary file left behind.
        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), self.content)
        self.assertEqual(self._temp_glob(), [])
        self.assertEqual(len(fake_client.get_object_calls), 2)
        requested_ranges = sorted(
            call['Range'] for call in fake_client.get_object_calls
        )
        self.assertEqual(requested_ranges, ['bytes=0-7', 'bytes=8-'])
        # The known whole-object checksum was also pinned with IfMatch.
        for call in fake_client.get_object_calls:
            self.assertEqual(call['IfMatch'], f'"{self.etag}"')

    def test_re_read_part_still_validates_and_publishes(self):
        fake_client = FakeS3Client(
            self.content,
            self.part_size,
            self.etag,
            release_order=(1, 0),
            fail_first_part_read=True,
        )
        manager = TransferManager(
            fake_client,
            TransferConfig(
                max_request_concurrency=2,
                multipart_threshold=1,
                multipart_chunksize=self.part_size,
                validate_download_checksum=True,
            ),
        )
        self.addCleanup(manager.shutdown)

        future = manager.download(self.bucket, self.key, self.filename)
        fake_client.wait_until_all_parts_started()
        fake_client.release_last_part()
        future.result()

        # The first part was read twice (initial failure plus retry) while the
        # second part only needed a single read; the assembled file still
        # validates and is published.
        first_part_calls = [
            call
            for call in fake_client.get_object_calls
            if call['Range'] == 'bytes=0-7'
        ]
        second_part_calls = [
            call
            for call in fake_client.get_object_calls
            if call['Range'] == 'bytes=8-'
        ]
        self.assertEqual(len(first_part_calls), 2)
        self.assertEqual(len(second_part_calls), 1)
        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), self.content)
        self.assertEqual(self._temp_glob(), [])

    def test_length_match_but_checksum_mismatch_fails_clearly(self):
        # Same length as the real content, but different bytes: the object's
        # ETag does not match the bytes the fake client serves.
        corrupt_content = b'XXXXXXXX' + self.content[8:]
        self.assertEqual(len(corrupt_content), len(self.content))
        fake_client = FakeS3Client(
            corrupt_content,
            self.part_size,
            self.etag,
            release_order=(1, 0),
        )
        manager = TransferManager(
            fake_client,
            TransferConfig(
                max_request_concurrency=2,
                multipart_threshold=1,
                multipart_chunksize=self.part_size,
                validate_download_checksum=True,
            ),
        )
        self.addCleanup(manager.shutdown)

        future = manager.download(self.bucket, self.key, self.filename)
        fake_client.wait_until_all_parts_started()
        fake_client.release_last_part()

        with self.assertRaises(S3ValidationError) as ctx:
            future.result()
        self.assertIn('Checksum mismatch', str(ctx.exception))
        self.assertIn(self.etag, str(ctx.exception))

        # Nothing was published and the temporary file was cleaned up.
        self.assertFalse(os.path.exists(self.filename))
        self.assertEqual(self._temp_glob(), [])

    def test_existing_destination_remains_usable_on_checksum_failure(self):
        original_contents = b'previously downloaded file contents'
        with open(self.filename, 'wb') as f:
            f.write(original_contents)

        corrupt_content = b'XXXXXXXX' + self.content[8:]
        fake_client = FakeS3Client(
            corrupt_content,
            self.part_size,
            self.etag,
            release_order=(1, 0),
        )
        manager = TransferManager(
            fake_client,
            TransferConfig(
                max_request_concurrency=2,
                multipart_threshold=1,
                multipart_chunksize=self.part_size,
                validate_download_checksum=True,
            ),
        )
        self.addCleanup(manager.shutdown)

        future = manager.download(self.bucket, self.key, self.filename)
        fake_client.wait_until_all_parts_started()
        fake_client.release_last_part()

        with self.assertRaises(S3ValidationError):
            future.result()

        # The old destination survives the failed validation byte-for-byte and
        # no temporary file lingers.
        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), original_contents)
        self.assertEqual(self._temp_glob(), [])

    def test_validation_disabled_skips_checksum(self):
        # The bytes do not match the ETag, but without the validation mode the
        # download must still publish its contents unchanged.
        corrupt_content = b'XXXXXXXX' + self.content[8:]
        fake_client = FakeS3Client(
            corrupt_content,
            self.part_size,
            self.etag,
            release_order=(1, 0),
        )
        manager = TransferManager(
            fake_client,
            TransferConfig(
                max_request_concurrency=2,
                multipart_threshold=1,
                multipart_chunksize=self.part_size,
                validate_download_checksum=False,
            ),
        )
        self.addCleanup(manager.shutdown)

        future = manager.download(self.bucket, self.key, self.filename)
        fake_client.wait_until_all_parts_started()
        fake_client.release_last_part()
        future.result()

        with open(self.filename, 'rb') as f:
            self.assertEqual(f.read(), corrupt_content)
        self.assertEqual(self._temp_glob(), [])
