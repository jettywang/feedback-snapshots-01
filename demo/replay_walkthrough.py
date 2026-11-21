#!/usr/bin/env python3
"""Local, offline walkthrough of the minimal-evidence replay interface.

Run with the repository virtualenv:

    .venv/bin/python demo/replay_walkthrough.py

The script never opens a socket. The "live remote" action is replayed
through an injected stand-in that models the risk service returning a
different answer today.
"""

from __future__ import annotations

import json
from unittest import mock

from oslo_config import cfg
from oslo_policy import _checks
from oslo_policy import _external
from oslo_policy import policy
from oslo_policy import replay

# A consuming service registers the shipped remote check kind.
_checks.registered_checks['http'] = _external.HttpCheck

SECRET = b'audit-enclave-hmac-key'


class FakeHttpResponse:
    """Stand-in for requests.Response; supports contextlib.closing."""

    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code

    def close(self) -> None:
        pass


def build_enforcer(rules: dict[str, str]) -> policy.Enforcer:
    conf = cfg.ConfigOpts()
    enforcer = policy.Enforcer(conf, use_conf=False)
    enforcer.set_rules(policy.Rules.from_dict(rules))
    return enforcer


def heading(title: str) -> None:
    print('\n' + '=' * 72)
    print(title)
    print('=' * 72)


def show_report(report: replay.ReplayReport) -> None:
    payload = report.to_dict()
    print(f'verdict                 : {report.verdict}')
    print(f'decision seen then      : {report.observed_decision}')
    print(f'decision recomputed now : {report.recomputed_decision}')
    print('leaf classification     :')
    for leaf in report.leaves:
        print(
            f'  - {leaf.kind:5s} {leaf.status:10s} '
            f'seen={leaf.observed_result!s:5s} '
            f'now={leaf.recomputed_result}'
        )
    print(f"recomputable_now        : {payload['recomputable_now']}")
    print("not_verifiable_offline  : " f"{payload['not_verifiable_offline']}")
    if report.reasons:
        print(f'reasons                 : {report.reasons}')


heading('Scenario inputs (the full ticket payload, NOT retained)')
target = {
    'case_id': 'C-2026-1121',
    'project_id': 'p-123',
    'victim_email': 'victim@example.com',
}
creds = {
    'roles': ['support'],
    'project_id': 'p-123',
    'token': 'bearer-secret-value',
}
print(json.dumps({'target': target, 'creds': creds}, indent=2))

# -------------------------------------------------------------------
# Action A: fully deterministic - every leaf recomputes offline.
# -------------------------------------------------------------------
heading('Action A - deterministic: role:support AND rule:is_owner')
deterministic_rules = {
    'complaint:view': 'role:support and rule:is_owner',
    'is_owner': 'project_id:%(project_id)s',
}
enforcer_a = build_enforcer(deterministic_rules)
decision_a, record_a = replay.record_decision(
    enforcer_a,
    'complaint:view',
    target,
    creds,
    decision_id='FB-149-A',
    recorded_at='2026-11-20T08:30:00Z',
    secret=SECRET,
)
print(f'native enforce decision : {decision_a}')
print('persisted evidence (note: no email, no token, no project id):')
print(record_a.to_json())

report_a = replay.DecisionReplayer(
    record_a,
    secret=SECRET,
    mode='offline',
).replay(enforcer_a, target, creds)
show_report(report_a)

# -------------------------------------------------------------------
# Action B: depends on a live remote risk service.
# -------------------------------------------------------------------
heading('Action B - live remote: role:support AND http risk check')
remote_rules = {
    'complaint:triage': ('role:support and http://risk.example/%(case_id)s'),
}
enforcer_b = build_enforcer(remote_rules)
recorder_b = replay.DecisionRecorder(
    'FB-149-B',
    '2026-11-20T08:30:05Z',
    secret=SECRET,
)
# Intercept requests.post so recording stays fully local; only digests
# of the wire request/response are kept in the evidence.
with mock.patch(
    'requests.post',
    return_value=FakeHttpResponse('True'),
):
    decision_b, record_b = recorder_b.record(
        enforcer_b,
        'complaint:triage',
        target,
        creds,
    )
print(f'native enforce decision : {decision_b}')
print('remote evidence (digests only):')
print(
    json.dumps(
        [call.to_dict() for call in record_b.external_calls],
        indent=2,
    )
)

heading('Action B - offline replay (no network available)')
with mock.patch(
    'requests.post',
    side_effect=AssertionError('must not call network'),
):
    report_b_offline = replay.DecisionReplayer(
        record_b,
        secret=SECRET,
        mode='offline',
    ).replay(enforcer_b, target, creds)
show_report(report_b_offline)

heading('Action B - live replay, risk service still returns True')


def risk_allows(
    check: _checks.Check,
    live_target: dict,
    live_creds: dict,
    current_rule: str | None,
) -> bool:
    return live_target['case_id'] == 'C-2026-1121'


report_b_live_ok = replay.DecisionReplayer(
    record_b,
    secret=SECRET,
    mode='live',
    remote_provider=risk_allows,
).replay(enforcer_b, target, creds)
show_report(report_b_live_ok)

heading('Action B - live replay, risk service now returns False')
report_b_live_changed = replay.DecisionReplayer(
    record_b,
    secret=SECRET,
    mode='live',
    remote_provider=lambda *args: False,
).replay(enforcer_b, target, creds)
show_report(report_b_live_changed)

heading('Tamper detection - flip the stored decision without the key')
tampered = json.loads(record_a.to_json())
tampered['observed_decision'] = not tampered['observed_decision']
tampered_record = replay.DecisionRecord.from_dict(tampered)
tampered_report = replay.DecisionReplayer(
    tampered_record,
    secret=SECRET,
).replay(enforcer_a, target, creds)
show_report(tampered_report)
