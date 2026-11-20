"""
Ownership-aware task locks: hold, takeover, and a late release.

This script uses only local storage (the in-process MemoryHuey) and no external
services, so it can be run directly:

    python examples/lock_ownership.py

Scenario
--------
A scheduled audit must never run concurrently, so it guards itself with an
ownership-aware lock (``owner=True``). Only one task can hold the lock at a
time.

1. The old audit run acquires the lock.
2. After a machine restart, emergency cleanup force-releases the stale lock so
   a new run can take over. The cleanup is written to the audit log.
3. The old run's cleanup code finally receives its termination notification
   and calls ``release()`` late. Because its owner token no longer matches, the
   release is a no-op -- the current holder keeps the lock and finishes.
4. Only when the current holder ends normally is the lock released.
"""
import logging

from huey import MemoryHuey
from huey.exceptions import TaskLockedException


logging.basicConfig(level=logging.WARNING,
                    format='%(levelname)s %(name)s: %(message)s')

huey = MemoryHuey('audit-demo', utc=False)
LOCK = 'nightly-audit'


def main():
    # 1. Old run starts first and becomes the sole holder.
    old = huey.lock_task(LOCK, owner=True)
    old.acquire()
    print('1. old run acquired lock, owner=%s' % old.get_owner())

    # A second run cannot acquire while the lock is held.
    contender = huey.lock_task(LOCK, owner=True)
    try:
        contender.acquire()
    except TaskLockedException:
        print('   concurrent run blocked: only one task may hold the lock')

    # 2. Machine recovery: operator force-clears the stale lock, then the new
    #    run takes over. flush_locks() records an auditable entry.
    huey.flush_locks(LOCK, reason='machine crash recovery')
    current = huey.lock_task(LOCK, owner=True)
    current.acquire()
    print('2. new run took over, owner=%s' % current.get_owner())

    # 3. The old run's termination/cleanup notification arrives late.
    removed = old.release()
    print('3. stale release from old owner removed the lock? %s' % removed)
    print('   lock still held by current run? %s' % huey.is_locked(LOCK))
    print('   current owner unchanged? %s' %
          (current.get_owner() == current._token))

    # A non-holder still cannot release it directly.
    print('   non-holder release refused? %s' %
          (contender.release() is False))

    # 4. Only the actual holder's normal completion releases the lock.
    current.release()
    print('4. current holder finished; lock free? %s' %
          (not huey.is_locked(LOCK)))


if __name__ == '__main__':
    main()
