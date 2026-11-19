"""Regression tests for pooled resources across a fork.

A worker may build its connection pool before forking.  Every child must
discard the broker sessions inherited from the parent, while the parent
must keep ownership of its own sessions after the fork.
"""

from __future__ import annotations

import multiprocessing
import os
import queue
import traceback

import pytest

from kombu import Connection, pools
from kombu.connection import ConnectionPool
from kombu.utils.functional import lazy

_FORK = (
    multiprocessing.get_context('fork')
    if 'fork' in multiprocessing.get_all_start_methods()
    else None
)

pytestmark = pytest.mark.skipif(
    _FORK is None, reason='fork start method is not available',
)


class StampedConnection:
    """Stand-in broker session recording which process touched it."""

    def __init__(self):
        self.created_by = os.getpid()
        self.borrowed_by = None
        self.returned_by = None
        self.closed_by = None
        self.operations = []

    def _debug(self, msg):
        pass

    def collect(self, socket_timeout=None):
        self.closed_by = os.getpid()

    def close(self):
        self.closed_by = os.getpid()

    def use(self, operation):
        pid = os.getpid()
        self.operations.append((operation, pid))
        return pid


class StampedConnectionPool(ConnectionPool):
    """Connection pool stamping acquire, release, and collect hooks."""

    def new(self):
        return StampedConnection()

    def prepare(self, resource):
        if isinstance(resource, lazy):
            resource = resource()
        resource.borrowed_by = os.getpid()
        return resource

    def release_resource(self, resource):
        resource.returned_by = os.getpid()


class StampedConnections(pools.Connections):

    def create(self, connection, limit):
        return StampedConnectionPool(connection, limit=limit)


class StampedProducer:
    """Producer stand-in using the same connection contract as ProducerPool."""

    def __init__(self, connection=None):
        self.created_by = os.getpid()
        self.published_by = None
        self.__connection__ = None
        self._channel = None
        if connection is not None:
            self.revive(connection)

    @property
    def channel(self):
        return self._channel

    @channel.setter
    def channel(self, value):
        self._channel = value

    def revive(self, connection):
        self.__connection__ = connection
        self._channel = object()

    def publish(self, body=None):
        self.published_by = self.__connection__.use('publish')
        return self.published_by


class StampedProducerPool(pools.ProducerPool):
    Producer = StampedProducer


class StampedProducers(pools.Producers):

    def __init__(self, connections, *args, **kwargs):
        self._connections = connections
        super().__init__(*args, **kwargs)

    def create(self, connection, limit):
        return StampedProducerPool(
            self._connections[connection], limit=limit)


def run_in_forked_child(target, *args):
    result_queue = _FORK.Queue()
    process = _FORK.Process(target=target, args=(result_queue, *args))
    process.start()
    process.join(10)
    if process.is_alive():
        process.terminate()
        process.join()
        pytest.fail('forked child did not exit')
    if process.exitcode != 0:
        pytest.fail(f'forked child exited with {process.exitcode}')
    try:
        result = result_queue.get(timeout=5)
    except queue.Empty:
        pytest.fail('forked child returned no result')
    if 'error' in result:
        pytest.fail(result['error'])
    return result


def _acquire_idle_in_child(result_queue, group, connection, parent_pool,
                           parent_idle):
    try:
        pid = os.getpid()
        result = {
            'pid': pid,
            'parent_pool_closed': parent_pool._closed,
            'parent_idle_closed': parent_idle.closed_by,
        }
        pool = group[connection]
        result['used_parent_pool'] = pool is parent_pool
        resource = pool.acquire()
        result['used_parent_resource'] = resource is parent_idle
        result['created_by'] = resource.created_by
        result['borrowed_by'] = resource.borrowed_by
        result['first_operation_pid'] = resource.use('idle-resource')
        result['operations'] = list(resource.operations)
        resource.release()
        result['returned_by'] = resource.returned_by
    except BaseException:
        result = {'error': traceback.format_exc()}
    result_queue.put(result)


def _acquire_borrowed_in_child(result_queue, group, connection, parent_pool,
                               parent_borrowed):
    try:
        pid = os.getpid()
        result = {
            'pid': pid,
            'parent_pool_closed': parent_pool._closed,
            'parent_borrowed_closed': parent_borrowed.closed_by,
        }
        pool = group[connection]
        result['used_parent_pool'] = pool is parent_pool
        resource = pool.acquire()
        result['used_parent_resource'] = resource is parent_borrowed
        result['created_by'] = resource.created_by
        result['borrowed_by'] = resource.borrowed_by
        result['first_operation_pid'] = resource.use('borrowed-resource')
        result['operations'] = list(resource.operations)
        resource.release()
        result['returned_by'] = resource.returned_by
    except BaseException:
        result = {'error': traceback.format_exc()}
    result_queue.put(result)


def _publish_in_child(result_queue, producers, connection, parent_pool,
                      parent_producer):
    try:
        pid = os.getpid()
        result = {
            'pid': pid,
            'parent_pool_closed': parent_pool._closed,
            'parent_connection_closed': parent_producer.__connection__.closed_by,
        }
        pool = producers[connection]
        result['used_parent_pool'] = pool is parent_pool
        producer = pool.acquire()
        producer_connection = producer.__connection__
        result['used_parent_producer'] = producer is parent_producer
        result['used_parent_connection'] = (
            producer_connection is parent_producer.__connection__)
        result['producer_created_by'] = producer.created_by
        result['connection_created_by'] = producer_connection.created_by
        result['connection_borrowed_by'] = producer_connection.borrowed_by
        result['first_operation_pid'] = producer.publish('child-message')
        result['published_by'] = producer.published_by
        result['connection_operations'] = list(producer_connection.operations)
        producer.release()
        result['connection_returned_by'] = producer_connection.returned_by
    except BaseException:
        result = {'error': traceback.format_exc()}
    result_queue.put(result)


def test_forked_child_does_not_reuse_idle_parent_connection():
    parent_pid = os.getpid()
    connection = Connection('memory://')
    group = StampedConnections(limit=2)
    pool = group[connection]

    idle = pool.acquire()
    idle.release()
    assert idle.created_by == parent_pid
    assert idle.borrowed_by == parent_pid
    assert idle.returned_by == parent_pid
    assert idle.closed_by is None

    result = run_in_forked_child(
        _acquire_idle_in_child, group, connection, pool, idle)

    assert result['pid'] != parent_pid
    assert result['parent_pool_closed'] is True
    assert result['parent_idle_closed'] == result['pid']
    assert result['used_parent_pool'] is False
    assert result['used_parent_resource'] is False
    assert result['created_by'] == result['pid']
    assert result['borrowed_by'] == result['pid']
    assert result['first_operation_pid'] == result['created_by']
    assert result['operations'] == [('idle-resource', result['pid'])]
    assert result['returned_by'] == result['pid']

    assert idle.closed_by is None
    assert pool._closed is False
    reused = pool.acquire()
    assert reused is idle
    assert reused.created_by == parent_pid
    reused.release()
    assert reused.returned_by == parent_pid


def test_forked_child_does_not_reuse_connection_borrowed_by_parent():
    parent_pid = os.getpid()
    connection = Connection('memory://')
    group = StampedConnections(limit=2)
    pool = group[connection]

    borrowed = pool.acquire()
    assert borrowed.created_by == parent_pid
    assert borrowed.borrowed_by == parent_pid

    result = run_in_forked_child(
        _acquire_borrowed_in_child, group, connection, pool, borrowed)

    assert result['pid'] != parent_pid
    assert result['parent_pool_closed'] is True
    assert result['parent_borrowed_closed'] == result['pid']
    assert result['used_parent_pool'] is False
    assert result['used_parent_resource'] is False
    assert result['created_by'] == result['pid']
    assert result['borrowed_by'] == result['pid']
    assert result['first_operation_pid'] == result['created_by']
    assert result['operations'] == [('borrowed-resource', result['pid'])]
    assert result['returned_by'] == result['pid']

    assert borrowed.closed_by is None
    borrowed.release()
    assert borrowed.returned_by == parent_pid
    assert pool._closed is False
    assert pool.acquire() is borrowed


def test_forked_child_producer_publishes_over_its_own_connection():
    parent_pid = os.getpid()
    connection = Connection('memory://')
    connections = StampedConnections(limit=2)
    producers = StampedProducers(connections, limit=2)
    pool = producers[connection]

    parent_producer = pool.acquire()
    assert parent_producer.publish('parent-message') == parent_pid
    parent_connection = parent_producer.__connection__
    assert parent_connection.created_by == parent_pid
    parent_producer.release()
    assert parent_connection.returned_by == parent_pid

    result = run_in_forked_child(
        _publish_in_child, producers, connection, pool, parent_producer)

    assert result['pid'] != parent_pid
    assert result['parent_pool_closed'] is True
    assert result['parent_connection_closed'] == result['pid']
    assert result['used_parent_pool'] is False
    assert result['used_parent_producer'] is False
    assert result['used_parent_connection'] is False
    assert result['producer_created_by'] == result['pid']
    assert result['connection_created_by'] == result['pid']
    assert result['connection_borrowed_by'] == result['pid']
    assert result['first_operation_pid'] == result['pid']
    assert result['published_by'] == result['pid']
    assert result['connection_operations'] == [('publish', result['pid'])]
    assert result['connection_returned_by'] == result['pid']

    assert parent_connection.closed_by is None
    assert producers[connection] is pool
    assert pool._closed is False
    reused = pool.acquire()
    assert reused is parent_producer
    assert reused.publish('parent-message-after-fork') == parent_pid
    assert reused.__connection__ is parent_connection
    assert parent_connection.operations == [
        ('publish', parent_pid), ('publish', parent_pid),
    ]
    reused.release()
    assert parent_connection.returned_by == parent_pid
