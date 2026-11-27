import logging
import os
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from redis import Redis

from rq.utils import get_version


def find_empty_redis_database(ssl=False):
    """Tries to connect to a random Redis database (starting from 4), and
    will use/connect it when no keys are in there.
    """
    for dbnum in range(4, 17):
        connection_kwargs = {'db': dbnum}
        if ssl:
            connection_kwargs['port'] = 9736
            connection_kwargs['ssl'] = True
            # disable certificate validation
            connection_kwargs['ssl_cert_reqs'] = None  # type: ignore
        testconn = Redis(**connection_kwargs)  # type: ignore
        empty = testconn.dbsize() == 0
        if empty:
            return testconn
        testconn.close()
    assert False, 'No empty Redis database found to run tests in.'


def get_redis_version() -> tuple[int, ...]:
    if not redis_available():
        return (7, 2, 0)
    with Redis() as conn:
        return get_version(conn)


def min_redis_version(ver: tuple[int, ...]):
    ver_str = '.'.join(map(str, ver))
    return unittest.skipIf(get_redis_version() < ver, f'Skip if Redis server < {ver_str}')


def _redis_is_reachable() -> bool:
    try:
        with Redis(socket_connect_timeout=0.5, socket_timeout=0.5) as conn:
            conn.ping()
        return True
    except Exception:
        return False


REDIS_AVAILABLE = None


def redis_available() -> bool:
    """Whether a real Redis server is reachable.

    Tests default to a real Redis server. When none is configured (e.g. a locked-down
    sandbox), they fall back to an in-memory `fakeredis` server so the suite is still
    runnable. `fakeredis` is only an optional test dependency.
    """
    global REDIS_AVAILABLE
    if REDIS_AVAILABLE is None:
        REDIS_AVAILABLE = _redis_is_reachable()
    return REDIS_AVAILABLE


def _fake_connection(ssl: bool = False):
    import fakeredis

    kwargs = {}
    if ssl:
        kwargs.update({'ssl': True, 'ssl_cert_reqs': None})
    conn = fakeredis.FakeStrictRedis(server=fakeredis.FakeServer(), **kwargs)
    # fakeredis does not implement INFO; cache a modern version so RQ takes the
    # LMOVE / intermediate-queue code paths instead of the legacy fallback.
    setattr(conn, '__rq_redis_server_version', (7, 2, 0))
    return conn


def find_empty_redis_database(ssl=False):
    """Tries to connect to a random Redis database (starting from 4), and
    will use/connect it when no keys are in there.
    """
    if not redis_available():
        return _fake_connection(ssl=ssl)
    for dbnum in range(4, 17):
        connection_kwargs = {'db': dbnum}
        if ssl:
            connection_kwargs['port'] = 9736
            connection_kwargs['ssl'] = True
            # disable certificate validation
            connection_kwargs['ssl_cert_reqs'] = None  # type: ignore
        testconn = Redis(**connection_kwargs)  # type: ignore
        empty = testconn.dbsize() == 0
        if empty:
            return testconn
        testconn.close()
    assert False, 'No empty Redis database found to run tests in.'


def slow(f):
    f = pytest.mark.slow(f)
    return unittest.skipUnless(os.environ.get('RUN_SLOW_TESTS_TOO'), 'Slow tests disabled')(f)


@contextmanager
def system_timezone(name: str):
    """Temporarily set the process's local timezone, e.g. `America/New_York`"""
    try:
        with patch.dict(os.environ, {'TZ': name}):
            time.tzset()
            yield
    finally:
        time.tzset()


def ssl_test(f):
    f = pytest.mark.ssl_test(f)
    return unittest.skipUnless(os.environ.get('RUN_SSL_TESTS'), 'SSL tests disabled')(f)


class RQTestCase(unittest.TestCase):
    """Base class to inherit test cases from for RQ.

    It sets up the Redis connection (available via self.connection), turns off
    logging to the terminal and flushes the Redis database before and after
    running each test.
    """

    @classmethod
    def setUpClass(cls):
        # Set up connection to Redis
        cls.connection = find_empty_redis_database()

        # Shut up logging
        logging.disable(logging.ERROR)

    def setUp(self):
        # Flush beforewards (we like our hygiene)
        self.connection.flushdb()

    def tearDown(self):
        # Flush afterwards
        self.connection.flushdb()

    @classmethod
    def tearDownClass(cls):
        logging.disable(logging.NOTSET)
        cls.connection.close()
