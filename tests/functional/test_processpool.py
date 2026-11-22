# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import glob
import os
from io import BytesIO
from multiprocessing.managers import BaseManager

import botocore.exceptions
import botocore.session
from botocore.stub import Stubber

from s3transfer.exceptions import CancelledError
from s3transfer.processpool import (
    BaseClientFactory,
    ProcessPoolDownloader,
    ProcessTransferConfig,
)
from tests import FileCreator, mock, unittest


class StubbedClient:
    def __init__(self):
        self._client = botocore.session.get_session().create_client(
            's3',
            'us-west-2',
            aws_access_key_id='foo',
            aws_secret_access_key='bar',
        )
        self._stubber = Stubber(self._client)
        self._stubber.activate()
        self._caught_stubber_errors = []
        # Records the identity each client was created with alongside the
        # order in which the clients were created. The list lives behind a
        # manager proxy so it is shared across every subprocess.
        self.creation_records = []

    def get_object(self, **kwargs):
        return self._client.get_object(**kwargs)

    def head_object(self, **kwargs):
        return self._client.head_object(**kwargs)

    def add_response(self, *args, **kwargs):
        self._stubber.add_response(*args, **kwargs)

    def add_client_error(self, *args, **kwargs):
        self._stubber.add_client_error(*args, **kwargs)

    def record_client_creation(self, client_kwargs):
        self.creation_records.append(client_kwargs.get('aws_access_key_id'))

    def get_creation_records(self):
        return list(self.creation_records)


class StubbedClientManager(BaseManager):
    pass


StubbedClientManager.register('StubbedClient', StubbedClient)


# Ideally a Mock would be used here. However, they cannot be pickled
# for Windows. So instead we define a factory class at the module level that
# can return a stubbed client we initialized in the setUp.
class StubbedClientFactory(BaseClientFactory):
    def __init__(self, stubbed_client):
        self._stubbed_client = stubbed_client

    def __call__(self, *args, **kwargs):
        # The __call__ is defined so we can provide an instance of the
        # StubbedClientFactory to mock.patch() and have the instance be
        # returned when the patched class is instantiated.
        return self

    def create_client(self, client_kwargs=None):
        if client_kwargs:
            # Record which download identity the client belongs to and the
            # order in which scoped clients are created.
            self._stubbed_client.record_client_creation(client_kwargs)
        return self._stubbed_client


class TestProcessPoolDownloader(unittest.TestCase):
    def setUp(self):
        # The stubbed client needs to run in a manager to be shared across
        # processes and have it properly consume the stubbed response across
        # processes.
        self.manager = StubbedClientManager()
        self.manager.start()
        self.stubbed_client = self.manager.StubbedClient()
        self.stubbed_client_factory = StubbedClientFactory(self.stubbed_client)

        self.client_factory_patch = mock.patch(
            's3transfer.processpool.ClientFactory', self.stubbed_client_factory
        )
        self.client_factory_patch.start()
        self.files = FileCreator()

        self.config = ProcessTransferConfig(max_request_processes=1)
        self.downloader = ProcessPoolDownloader(config=self.config)
        self.bucket = 'mybucket'
        self.key = 'mykey'
        self.filename = self.files.full_path('filename')
        self.remote_contents = b'my content'
        self.stream = BytesIO(self.remote_contents)

    def tearDown(self):
        self.manager.shutdown()
        self.client_factory_patch.stop()
        self.files.remove_all()

    def assert_contents(self, filename, expected_contents):
        self.assertTrue(os.path.exists(filename))
        with open(filename, 'rb') as f:
            self.assertEqual(f.read(), expected_contents)

    def test_download_file(self):
        self.stubbed_client.add_response(
            'head_object', {'ContentLength': len(self.remote_contents)}
        )
        self.stubbed_client.add_response('get_object', {'Body': self.stream})
        with self.downloader:
            self.downloader.download_file(self.bucket, self.key, self.filename)
        self.assert_contents(self.filename, self.remote_contents)

    def test_download_multiple_files(self):
        self.stubbed_client.add_response('get_object', {'Body': self.stream})
        self.stubbed_client.add_response(
            'get_object', {'Body': BytesIO(self.remote_contents)}
        )
        with self.downloader:
            self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
            )
            other_file = self.files.full_path('filename2')
            self.downloader.download_file(
                self.bucket,
                self.key,
                other_file,
                expected_size=len(self.remote_contents),
            )
        self.assert_contents(self.filename, self.remote_contents)
        self.assert_contents(other_file, self.remote_contents)

    def test_download_file_ranged_download(self):
        half_of_content_length = int(len(self.remote_contents) / 2)
        self.stubbed_client.add_response(
            'head_object', {'ContentLength': len(self.remote_contents)}
        )
        self.stubbed_client.add_response(
            'get_object',
            {'Body': BytesIO(self.remote_contents[:half_of_content_length])},
        )
        self.stubbed_client.add_response(
            'get_object',
            {'Body': BytesIO(self.remote_contents[half_of_content_length:])},
        )
        downloader = ProcessPoolDownloader(
            config=ProcessTransferConfig(
                multipart_chunksize=half_of_content_length,
                multipart_threshold=half_of_content_length,
                max_request_processes=1,
            )
        )
        with downloader:
            downloader.download_file(self.bucket, self.key, self.filename)
        self.assert_contents(self.filename, self.remote_contents)

    def test_download_file_extra_args(self):
        self.stubbed_client.add_response(
            'head_object',
            {'ContentLength': len(self.remote_contents)},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'VersionId': 'versionid',
            },
        )
        self.stubbed_client.add_response(
            'get_object',
            {'Body': self.stream},
            expected_params={
                'Bucket': self.bucket,
                'Key': self.key,
                'VersionId': 'versionid',
            },
        )
        with self.downloader:
            self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                extra_args={'VersionId': 'versionid'},
            )
        self.assert_contents(self.filename, self.remote_contents)

    def test_download_file_expected_size(self):
        self.stubbed_client.add_response('get_object', {'Body': self.stream})
        with self.downloader:
            self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
            )
        self.assert_contents(self.filename, self.remote_contents)

    def test_cleans_up_tempfile_on_failure(self):
        self.stubbed_client.add_client_error('get_object', 'NoSuchKey')
        with self.downloader:
            self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
            )
        self.assertFalse(os.path.exists(self.filename))
        # Any tempfile should have been erased as well
        possible_matches = glob.glob(f'{self.filename}*' + os.extsep)
        self.assertEqual(possible_matches, [])

    def test_validates_extra_args(self):
        with self.downloader:
            with self.assertRaises(ValueError):
                self.downloader.download_file(
                    self.bucket,
                    self.key,
                    self.filename,
                    extra_args={'NotSupported': 'NotSupported'},
                )

    def test_result_with_success(self):
        self.stubbed_client.add_response('get_object', {'Body': self.stream})
        with self.downloader:
            future = self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
            )
            self.assertIsNone(future.result())

    def test_result_with_exception(self):
        self.stubbed_client.add_client_error('get_object', 'NoSuchKey')
        with self.downloader:
            future = self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
            )
            with self.assertRaises(botocore.exceptions.ClientError):
                future.result()

    def test_result_with_cancel(self):
        self.stubbed_client.add_response('get_object', {'Body': self.stream})
        with self.downloader:
            future = self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
            )
            future.cancel()
            with self.assertRaises(CancelledError):
                future.result()

    def identity(self, access_key):
        return {
            'aws_access_key_id': access_key,
            'aws_secret_access_key': f'{access_key}-secret',
            'aws_session_token': f'{access_key}-token',
        }

    def test_ranged_downloads_use_their_own_identities(self):
        half_of_content_length = int(len(self.remote_contents) / 2)
        config = ProcessTransferConfig(
            multipart_chunksize=half_of_content_length,
            multipart_threshold=half_of_content_length,
            max_request_processes=1,
        )
        identities = [
            self.identity('identity-a'),
            self.identity('identity-b'),
        ]
        for _ in range(4):
            self.stubbed_client.add_response(
                'get_object', {'Body': BytesIO(self.stream.read())}
            )
            self.stream.seek(0)
        downloader = ProcessPoolDownloader(config=config)
        first_file = self.files.full_path('filename-a')
        second_file = self.files.full_path('filename-b')
        with downloader:
            first_future = downloader.download_file(
                self.bucket,
                self.key,
                first_file,
                expected_size=len(self.remote_contents),
                client_kwargs=identities[0],
            )
            second_future = downloader.download_file(
                self.bucket,
                self.key,
                second_file,
                expected_size=len(self.remote_contents),
                client_kwargs=identities[1],
            )
            first_future.result()
            second_future.result()

        records = self.stubbed_client.get_creation_records()
        # Each download's segmented requests are served by a client created
        # with that download's identity, and the creation order follows the
        # order in which the downloads were submitted.
        self.assertEqual(records, ['identity-a', 'identity-b'])
        self.assert_contents(first_file, self.remote_contents)
        self.assert_contents(second_file, self.remote_contents)

    def test_incomplete_identity_gets_no_scoped_client(self):
        incomplete_identity = {
            'aws_access_key_id': 'incomplete-identity',
        }
        with self.downloader:
            with self.assertRaises(ValueError):
                self.downloader.download_file(
                    self.bucket,
                    self.key,
                    self.filename,
                    expected_size=len(self.remote_contents),
                    client_kwargs=incomplete_identity,
                )
        self.assertEqual(self.stubbed_client.get_creation_records(), [])
        self.assertFalse(os.path.exists(self.filename))

    def test_cancelled_identity_gets_no_scoped_client(self):
        identity = self.identity('cancelled-identity')
        self.stubbed_client.add_response(
            'get_object', {'Body': BytesIO(self.remote_contents)}
        )
        with self.downloader:
            future = self.downloader.download_file(
                self.bucket,
                self.key,
                self.filename,
                expected_size=len(self.remote_contents),
                client_kwargs=identity,
            )
            future.cancel()
            with self.assertRaises(CancelledError):
                future.result()
        self.assertEqual(self.stubbed_client.get_creation_records(), [])

    def test_normal_download_continues_after_process_recycling(self):
        identity = self.identity('scoped-identity')
        self.stubbed_client.add_response(
            'get_object', {'Body': BytesIO(self.remote_contents)}
        )
        self.stubbed_client.add_response(
            'get_object', {'Body': BytesIO(self.remote_contents)}
        )
        scoped_file = self.files.full_path('scoped-filename')
        normal_file = self.files.full_path('normal-filename')

        first_downloader = ProcessPoolDownloader(
            config=ProcessTransferConfig(max_request_processes=1)
        )
        with first_downloader:
            scoped_future = first_downloader.download_file(
                self.bucket,
                self.key,
                scoped_file,
                expected_size=len(self.remote_contents),
                client_kwargs=identity,
            )
            scoped_future.result()
        # The first downloader's processes have been reaped. A brand new
        # downloader must still be able to serve a download that relies on
        # the default identity rather than a per-download identity.
        recycled_downloader = ProcessPoolDownloader(
            config=ProcessTransferConfig(max_request_processes=1)
        )
        with recycled_downloader:
            normal_future = recycled_downloader.download_file(
                self.bucket,
                self.key,
                normal_file,
                expected_size=len(self.remote_contents),
            )
            normal_future.result()

        self.assertEqual(
            self.stubbed_client.get_creation_records(), ['scoped-identity']
        )
        self.assert_contents(scoped_file, self.remote_contents)
        self.assert_contents(normal_file, self.remote_contents)

    def test_shutdown_with_no_downloads(self):
        downloader = ProcessPoolDownloader()
        try:
            downloader.shutdown()
        except AttributeError:
            self.fail(
                'The downloader should be able to be shutdown even though '
                'the downloader was never started.'
            )

    def test_shutdown_with_no_downloads_and_ctrl_c(self):
        # Special shutdown logic happens if a KeyboardInterrupt is raised in
        # the context manager. However, this logic can not happen if the
        # downloader was never started. So a KeyboardInterrupt should be
        # the only exception propagated.
        with self.assertRaises(KeyboardInterrupt):
            with self.downloader:
                raise KeyboardInterrupt()
