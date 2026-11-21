"""End-to-end migration demo for removing deprecated oslo.policy aliases.

Run with the repository venv:
    .venv/bin/python demo/run_demo.py all
    .venv/bin/python demo/run_demo.py phaseA
    .venv/bin/python demo/run_demo.py phaseB
    .venv/bin/python demo/run_demo.py phaseC
    .venv/bin/python demo/run_demo.py wrong-order
    .venv/bin/python demo/run_demo.py exceptions
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
import tempfile
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake_service import (  # noqa: E402
    TARGET, USERS, build_enforcer,
)

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY_DIR = os.path.join(HERE, 'policies')
BACKUP_DIR = os.path.join(HERE, 'backups')

RULES = ['widget:create', 'gizmo:update', 'thing:admin']


class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def _short_warning(message):
    text = str(message)
    return text if len(text) <= 220 else text[:217] + '...'


def inspect(release, policy_file, enforce_new_defaults=True, label=''):
    print('=' * 78)
    print(f'SCENARIO: {label}')
    print(f'  service release     : {release}')
    print(f'  policy file         : {os.path.relpath(policy_file, HERE)}')
    print(f'  enforce_new_defaults: {enforce_new_defaults}')
    print('-' * 78)

    log_capture = LogCapture()
    logger = logging.getLogger('oslo_policy')
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    logger.addHandler(log_capture)
    # authorize() re-runs load_rules(); keep all re-load noise off stderr while
    # the inner block records the first-load warnings as evidence.
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            enforcer = build_enforcer(release, policy_file, enforce_new_defaults)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                enforcer.load_rules()
        finally:
            logger.removeHandler(log_capture)

        print('  effective in-memory rules after load:')
        for name in RULES:
            present = name in enforcer.rules
            print(f'    {name:15s} -> {enforcer.rules[name] if present else "<absent, fail-closed>"}')

        print('  rules loaded from the site file (file_rules):')
        print('   ', sorted(enforcer.file_rules) or '(none)')

        deprecation = [_short_warning(w.message) for w in caught
                       if issubclass(w.category, (UserWarning, DeprecationWarning))]
        if deprecation:
            print('  DEPRECATION warnings (the engine telling you an alias is in play):')
            for msg in deprecation:
                for line in msg.splitlines():
                    print('    !', line)
        redundant = [m for m in log_capture.records if 'redundant' in m]
        for msg in redundant:
            print('  LOG:', msg)

        print('  AUTHORIZATION EVIDENCE (real Enforcer.authorize results):')
        width = 18
        print('    rule \\ user      ' + ''.join(f'{u:>{width}s}' for u in USERS))
        for rule in RULES:
            cells = []
            for user, creds in USERS.items():
                try:
                    allowed = enforcer.authorize(rule, TARGET, creds)
                    cells.append('ALLOW' if allowed else 'DENY')
                except Exception as exc:  # e.g. PolicyNotRegistered
                    cells.append('NOT-REGISTERED')
            print(f'    {rule:17s} ' + ''.join(f'{c:>{width}s}' for c in cells))
        print()
        return enforcer


def phase_a(end=True):
    return inspect('old', os.path.join(POLICY_DIR, 'phaseA_aliases.yaml'),
                   end, f'PHASE A - old service + site file on ALIASES (END={end})')


def phase_b(end=True):
    return inspect('old', os.path.join(POLICY_DIR, 'phaseB_canonical.yaml'),
                   end, f'PHASE B - old service + site file migrated to CANONICAL names (END={end})')


def phase_c():
    return inspect('new', os.path.join(POLICY_DIR, 'phaseC_cleanup.yaml'),
                   True, 'PHASE C - new service + dead overrides removed (closeout)')


def wrong_order():
    inspect('new', os.path.join(POLICY_DIR, 'wrong_order_orphan_aliases.yaml'),
            True, 'COUNTER-EXAMPLE - new service FIRST, orphan aliases left behind')


def reload_rollback_demo():
    print('=' * 78)
    print('SCENARIO: hot reload + rollback inside one long-lived enforcer process')
    print('-' * 78)
    workdir = tempfile.mkdtemp(prefix='policy-rollback-')
    live = os.path.join(workdir, 'policy.yaml')
    backup = os.path.join(BACKUP_DIR, 'phaseA_aliases.yaml.bak')
    shutil.copy(os.path.join(POLICY_DIR, 'phaseA_aliases.yaml'), live)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    shutil.copy(live, backup)

    enforcer = build_enforcer('old', live)
    enforcer.suppress_deprecation_warnings = True
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        enforcer.load_rules()
    legacy = USERS['legacy-user']
    print('  1) initial state (Phase A alias override):')
    print('     widget:create for legacy-user =',
          enforcer.authorize('widget:create', TARGET, legacy))

    shutil.copy(os.path.join(POLICY_DIR, 'phaseB_canonical.yaml'), live)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        enforcer.load_rules(force_reload=True)
    print('  2) after swapping in Phase B file and force_reload:')
    print('     widget:create for legacy-user =',
          enforcer.authorize('widget:create', TARGET, legacy),
          '(must equal step 1)')

    shutil.copy(backup, live)
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        enforcer.load_rules(force_reload=True)
    print('  3) ROLLBACK: restored backup, force_reload again:')
    print('     widget:create for legacy-user =',
          enforcer.authorize('widget:create', TARGET, legacy),
          '(back to step 1)')
    print(f'  rollback artifact kept at: {os.path.relpath(backup, HERE)}')
    print()


def exceptions_demo():
    print('=' * 78)
    print('SCENARIO: exception injection and where the rollback point is')
    print('-' * 78)
    workdir = tempfile.mkdtemp(prefix='policy-bad-')
    good = os.path.join(POLICY_DIR, 'phaseB_canonical.yaml')
    live = os.path.join(workdir, 'policy.yaml')
    backup = os.path.join(BACKUP_DIR, 'phaseB_canonical.yaml.bak')
    shutil.copy(good, live)
    shutil.copy(good, backup)

    enforcer = build_enforcer('old', live)
    enforcer.suppress_deprecation_warnings = True
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        enforcer.load_rules()
    print('  1) good file loads; gizmo:update for ops-user =',
          enforcer.authorize('gizmo:update', TARGET, USERS['ops-user']))

    with open(live, 'w') as fh:
        fh.write('"widget:create": "rule:does_not_exist"\n')
    fresh = build_enforcer('old', live)
    fresh.suppress_deprecation_warnings = True
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        fresh.load_rules()
    undefined = [r for r, c in fresh.rules.items() if fresh._undefined_check(c)]
    print('  2) broken file (references undefined rule):')
    print('     check_rules flags undefined rule names:', undefined)
    print('     authorize still fail-closed for legacy-user =',
          fresh.authorize('widget:create', TARGET, USERS['legacy-user']))

    with open(live, 'w') as fh:
        fh.write('"widget:create": "role:viewer"\n this: is: not: valid: policy: yaml\n')
    print('  3) malformed YAML on next load:')
    try:
        broken = build_enforcer('old', live)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            broken.load_rules(force_reload=True)
    except ValueError as exc:
        print('     ValueError raised by parser:', str(exc).splitlines()[0])
        print('     -> the previously running process keeps its last good in-memory')
        print('        rules until restart; restart would fail, so restore the backup.')

    shutil.copy(backup, live)
    restored = build_enforcer('old', live)
    restored.suppress_deprecation_warnings = True
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        restored.load_rules()
    print('  4) after restoring backup, gizmo:update for ops-user =',
          restored.authorize('gizmo:update', TARGET, USERS['ops-user']))
    print(f'  rollback artifact kept at: {os.path.relpath(backup, HERE)}')
    print()


SCENARIOS = {
    'phaseA': lambda: (phase_a(True), phase_a(False)),
    'phaseB': lambda: (phase_b(True), phase_b(False)),
    'phaseC': phase_c,
    'wrong-order': wrong_order,
    'reload': reload_rollback_demo,
    'exceptions': exceptions_demo,
}


def main():
    logging.disable(logging.WARNING)
    which = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if which == 'all':
        phase_a(True)
        phase_a(False)
        phase_b(True)
        phase_b(False)
        phase_c()
        wrong_order()
        reload_rollback_demo()
        exceptions_demo()
    elif which in SCENARIOS:
        SCENARIOS[which]()
    else:
        print('unknown scenario:', which)
        sys.exit(1)


if __name__ == '__main__':
    main()
