"""Export a canceled task and an operator-approved rescheduled task id.

Run with::

    python examples/ops_reschedule/main.py

Uses the in-memory queue, so no external services are required.
"""
import json

from huey import MemoryHuey
from huey.exceptions import RescheduleDenied


huey = MemoryHuey('security-ops', utc=False)


@huey.task(task_type='security-collection')
def collect_findings(run_id):
    return {'run_id': run_id}


@huey.task(task_type='secret-key-rotation', retryable=False)
def rotate_key(key_id):
    return {'key_id': key_id}


def main():
    # A canceled security collection may be rescheduled by on-call staff.
    canceled = collect_findings('scan-42')
    canceled.revoke()

    approved = canceled.ops_reschedule(
        task_type='security-collection',
        approval_id='CHG-1001',
        operator='oncall-ada',
        reason='source typo while re-running the scheduled scan')

    # A canceled secret-key job must never be rescheduled.
    protected = rotate_key('kms/prod/primary')
    protected.revoke()
    denied = None
    try:
        protected.ops_reschedule(
            task_type='secret-key-rotation',
            approval_id='CHG-1002',
            operator='oncall-ada')
    except RescheduleDenied as exc:
        denied = {'reason': exc.reason, 'state': exc.state}

    print(json.dumps({
        'canceled_task_id': canceled.id,
        'approved_reschedule_task_id': approved.new_task_id,
        'protected_task_id': protected.id,
        'protected_reschedule': denied,
        'canceled_history': huey.task_history(canceled.id),
        'rescheduled_history': huey.task_history(approved.new_task_id),
    }, indent=2, sort_keys=True))

    # The original stays canceled; the replacement is the queued task.
    assert canceled.is_revoked()
    assert protected.is_revoked()
    assert approved.new_task_id in [t.id for t in huey.pending()]


if __name__ == '__main__':
    main()
