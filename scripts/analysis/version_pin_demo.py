"""Local fake-response demo for s3transfer download version consistency.

Runs the real thread-based DownloadSubmissionTask (through TransferManager)
and the real process-pool GetObjectSubmitter/GetObjectWorker, but replaces the
S3 client with an in-process fake that can change the object between HEAD and
GETs. No network or multiprocessing manager is used.
"""
import os
import queue
import tempfile
from io import BytesIO

from botocore.exceptions import ClientError

from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.processpool import (
    DownloadFileRequest,
    GetObjectSubmitter,
    GetObjectWorker,
    ProcessTransferConfig,
    SHUTDOWN_SIGNAL,
    TransferMonitor,
)
from s3transfer.utils import OSUtils


class FakeS3:
    def __init__(
        self,
        versions,
        current='v1',
        change_after_get=None,
        change_before_first_get=False,
        head_etag=True,
        get_etag=True,
        honor_if_match=True,
        honor_version=True,
        response_checksum_validation='when_supported',
    ):
        self.versions = dict(versions)
        self.current = current
        self.change_after_get = change_after_get
        self.change_before_first_get = change_before_first_get
        self.head_etag = head_etag
        self.get_etag = get_etag
        self.honor_if_match = honor_if_match
        self.honor_version = honor_version
        self.checksum_mode = response_checksum_validation
        self.calls = []
        self.get_count = 0

    @property
    def meta(self):
        checksum_mode = self.checksum_mode

        class Meta:
            config = type(
                'Config',
                (),
                {'response_checksum_validation': checksum_mode},
            )()
            events = type(
                'Events',
                (),
                {
                    'register_first': lambda *a, **k: None,
                    'register_last': lambda *a, **k: None,
                    'register': lambda *a, **k: None,
                },
            )()

        return Meta()

    def _resolve(self, kw, operation):
        version = kw.get('VersionId', self.current)
        if not self.honor_version:
            version = self.current
        if version not in self.versions:
            raise ClientError(
                {
                    'Error': {'Code': 'NoSuchVersion'},
                    'ResponseMetadata': {'HTTPStatusCode': 404},
                },
                operation,
            )
        return version, self.versions[version]

    def head_object(self, **kw):
        version, data = self._resolve(kw, 'HeadObject')
        response = {'ContentLength': len(data), 'VersionId': version}
        if self.head_etag:
            response['ETag'] = f'"etag-{version}"'
        self.calls.append(
            ('HeadObject', cond(kw), version, len(data), None)
        )
        return response

    def get_object(self, **kw):
        if self.change_before_first_get and self.get_count == 0:
            self.current = 'v2'
        version, data = self._resolve(kw, 'GetObject')
        etag = f'"etag-{version}"'
        if self.honor_if_match and kw.get('IfMatch') not in (None, etag):
            self.calls.append(
                ('GetObject', cond(kw), version, 0, '412 PreconditionFailed')
            )
            raise ClientError(
                {
                    'Error': {'Code': 'PreconditionFailed'},
                    'ResponseMetadata': {'HTTPStatusCode': 412},
                },
                'GetObject',
            )
        start, end = 0, len(data) - 1
        has_range = 'Range' in kw
        if has_range:
            start_s, end_s = kw['Range'][len('bytes='):].split('-', 1)
            start = int(start_s)
            end = int(end_s) if end_s else len(data) - 1
            if start >= len(data):
                self.calls.append(
                    ('GetObject', cond(kw), version, 0, '416 InvalidRange')
                )
                raise ClientError(
                    {
                        'Error': {'Code': 'InvalidRange'},
                        'ResponseMetadata': {'HTTPStatusCode': 416},
                    },
                    'GetObject',
                )
            end = min(end, len(data) - 1)
        body = data[start:end + 1]
        response = {'Body': BytesIO(body), 'ContentLength': len(body)}
        if has_range:
            response['ContentRange'] = f'bytes {start}-{end}/{len(data)}'
        if self.get_etag:
            response['ETag'] = etag
        self.calls.append(
            ('GetObject', cond(kw), version, len(body), None)
        )
        self.get_count += 1
        if self.change_after_get == self.get_count:
            self.current = 'v2'
        return response


def cond(kw):
    return {
        k: kw[k]
        for k in ('Range', 'IfMatch', 'VersionId')
        if k in kw
    }


def thread_download(fake, path, extra_args=None, thread_config=None):
    config = thread_config or TransferConfig(
        multipart_threshold=4,
        multipart_chunksize=4,
        max_request_concurrency=1,
        max_io_queue_size=100,
    )
    manager = TransferManager(client=fake, config=config)
    try:
        future = manager.download(
            'bucket', 'key', path, extra_args=extra_args or {}
        )
        try:
            future.result()
            return 'success'
        except Exception as e:
            return f'{type(e).__name__}: {e}'
    finally:
        manager.shutdown()


def process_download(
    fake, path, extra_args=None, expected_size=None, threshold=4, chunksize=4
):
    req_q, job_q = queue.Queue(), queue.Queue()
    monitor = TransferMonitor()
    transfer_id = monitor.notify_new_transfer()
    config = ProcessTransferConfig(
        multipart_threshold=threshold,
        multipart_chunksize=chunksize,
        max_request_processes=1,
    )
    osutil = OSUtils()
    submitter = GetObjectSubmitter(
        config, None, monitor, osutil, req_q, job_q
    )
    submitter._client = fake
    req_q.put(
        DownloadFileRequest(
            transfer_id,
            'bucket',
            'key',
            path,
            extra_args or {},
            expected_size,
        )
    )
    req_q.put(SHUTDOWN_SIGNAL)
    submitter._do_run()

    worker = GetObjectWorker(job_q, None, monitor, osutil)
    worker._client = fake
    job_q.put(SHUTDOWN_SIGNAL)
    worker._do_run()
    try:
        monitor.poll_for_result(transfer_id)
        return 'success'
    except Exception as e:
        return f'{type(e).__name__}: {e}'


def run_case(title, fake, impl, **kwargs):
    root = tempfile.mkdtemp(prefix='version-pin-')
    path = os.path.join(root, 'archive.bin')
    outcome = impl(fake, path, **kwargs)
    exists = os.path.exists(path)
    content = open(path, 'rb').read() if exists else None
    leftovers = sorted(os.listdir(root))
    print(f'\n### {title}')
    for op, c, version, size, error in fake.calls:
        sent = ' '.join(f'{k}={v}' for k, v in c.items()) or '(none)'
        detail = f'{size}B' if error is None else error
        print(f'  {op:10} {sent:50} served={version:2} {detail}')
    print(f'  outcome : {outcome}')
    print(f'  final   : {"present" if exists else "absent"} {content!r}')
    print(f'  leftovers: {leftovers}')
    return {
        'title': title,
        'calls': fake.calls,
        'outcome': outcome,
        'content': content,
        'exists': exists,
        'leftovers': leftovers,
    }


def main():
    v1 = b'AAAAABBBBB'
    v2 = b'CCCCCDDDDD'
    v2_short = b'CCCCDD'

    single_get_config = TransferConfig(
        multipart_threshold=100,
        multipart_chunksize=4,
        max_request_concurrency=1,
        max_io_queue_size=100,
    )

    cases = [
        (
            'T-pinned: thread, caller VersionId=v1, overwrite after part 1',
            FakeS3({'v1': v1, 'v2': v2}, change_after_get=1),
            thread_download,
            {'extra_args': {'VersionId': 'v1'}},
        ),
        (
            'T-etag: thread, no VersionId, overwrite after part 1',
            FakeS3({'v1': v1, 'v2': v2}, change_after_get=1),
            thread_download,
            {},
        ),
        (
            'T-etag-first: thread, no VersionId, overwrite before part 1',
            FakeS3({'v1': v1, 'v2': v2}, change_before_first_get=True),
            thread_download,
            {},
        ),
        (
            'T-etag-nohead: thread, when_required, overwrite after part 1',
            FakeS3(
                {'v1': v1, 'v2': v2},
                change_after_get=1,
                response_checksum_validation='when_required',
            ),
            thread_download,
            {},
        ),
        (
            'T-noetag: thread, HEAD has no ETag, no VersionId',
            FakeS3({'v1': v1, 'v2': v2}, change_after_get=1, head_etag=False),
            thread_download,
            {},
        ),
        (
            'T-noetag-get: thread, when_required, first GET has no ETag',
            FakeS3(
                {'v1': v1, 'v2': v2},
                change_after_get=1,
                get_etag=False,
                response_checksum_validation='when_required',
            ),
            thread_download,
            {},
        ),
        (
            'T-ignore-ifmatch: thread, source ignores IfMatch',
            FakeS3(
                {'v1': v1, 'v2': v2},
                change_after_get=1,
                honor_if_match=False,
            ),
            thread_download,
            {},
        ),
        (
            'T-ignore-version: thread, source ignores VersionId but honors IfMatch',
            FakeS3(
                {'v1': v1, 'v2': v2},
                change_after_get=1,
                honor_version=False,
            ),
            thread_download,
            {'extra_args': {'VersionId': 'v1'}},
        ),
        (
            'T-single-mixed: thread, single GET, no VersionId, shorter v2',
            FakeS3({'v1': v1, 'v2': v2_short}, change_before_first_get=True),
            thread_download,
            {'thread_config': single_get_config},
        ),
        (
            'T-single-pinned: thread, single GET, VersionId=v1',
            FakeS3({'v1': v1, 'v2': v2_short}, change_before_first_get=True),
            thread_download,
            {
                'extra_args': {'VersionId': 'v1'},
                'thread_config': single_get_config,
            },
        ),
        (
            'P-pinned: process, caller VersionId=v1, overwrite after part 1',
            FakeS3({'v1': v1, 'v2': v2}, change_after_get=1),
            process_download,
            {'extra_args': {'VersionId': 'v1'}},
        ),
        (
            'P-mixed: process, no VersionId, same-size v2 after part 1',
            FakeS3({'v1': v1, 'v2': v2}, change_after_get=1),
            process_download,
            {},
        ),
        (
            'P-short: process, no VersionId, shorter v2 before part 1',
            FakeS3({'v1': v1, 'v2': v2_short}, change_before_first_get=True),
            process_download,
            {},
        ),
        (
            'P-new: process, no VersionId, same-size v2 before part 1',
            FakeS3({'v1': v1, 'v2': v2}, change_before_first_get=True),
            process_download,
            {},
        ),
        (
            'P-expected-size: process, expected_size skips HEAD, no VersionId',
            FakeS3({'v1': v1, 'v2': v2}, change_after_get=1),
            process_download,
            {'expected_size': len(v1)},
        ),
        (
            'P-single-short: process, single GET, no VersionId, shorter v2',
            FakeS3({'v1': v1, 'v2': v2_short}, change_before_first_get=True),
            process_download,
            {'threshold': 100},
        ),
        (
            'P-single-pinned: process, single GET, VersionId=v1',
            FakeS3({'v1': v1, 'v2': v2_short}, change_before_first_get=True),
            process_download,
            {'extra_args': {'VersionId': 'v1'}, 'threshold': 100},
        ),
        (
            'P-ignore-version: process, source ignores VersionId',
            FakeS3(
                {'v1': v1, 'v2': v2},
                change_after_get=1,
                honor_version=False,
            ),
            process_download,
            {'extra_args': {'VersionId': 'v1'}},
        ),
        (
            'P-expected-too-large: process, VersionId=v1, expected_size=12',
            FakeS3({'v1': v1}),
            process_download,
            {'extra_args': {'VersionId': 'v1'}, 'expected_size': 12},
        ),
    ]
    for title, fake, impl, kwargs in cases:
        run_case(title, fake, impl, **kwargs)


if __name__ == '__main__':
    main()
