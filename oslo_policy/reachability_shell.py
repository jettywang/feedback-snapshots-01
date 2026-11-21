#!/usr/bin/env python3

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Command line interface for the read-only policy reachability check.

Two input modes are supported:

* ``--policy-file`` analyzes a standalone YAML policy file. Every policy in the
  file is treated as a registered action (a root), which matches how an
  operator reviews an authorization configuration before publishing it.
* ``--namespace`` resolves a service's real :class:`~.Enforcer` through the
  ``oslo.policy.enforcer`` entry point, so roots are the policies the service
  actually registers in code, including deprecated aliases.
"""

import argparse
import logging
import sys
from collections.abc import Sequence

from oslo_config import cfg

from oslo_policy import _parser
from oslo_policy import policy
from oslo_policy import reachability


def _build_file_enforcer(
    policy_file: str,
) -> tuple[policy.Enforcer, list[str]]:
    with open(policy_file, encoding='utf-8') as fh:
        parsed = policy.parse_file_contents(fh.read())

    # A use_conf=False enforcer never touches disk on its own. We populate its
    # registered actions and effective rules in memory so the read-only
    # analyzer sees exactly what the file defines; nothing is written back.
    enforcer = policy.Enforcer(cfg.ConfigOpts(), use_conf=False)
    enforcer.set_rules(
        {name: _parser.parse_rule(expr) for name, expr in parsed.items()}
    )
    for name, expr in parsed.items():
        enforcer.registered_rules[name] = policy.RuleDefault(name, expr)
    return enforcer, sorted(parsed)


def _build_namespace_enforcer(
    namespace: str,
) -> tuple[policy.Enforcer, list[str]]:
    # Imported lazily so the standalone --policy-file mode does not require
    # stevedore entry points to be installed.
    from oslo_policy import generator

    enforcer = generator._get_enforcer(namespace)
    enforcer.suppress_deprecation_warnings = True
    enforcer.load_rules()
    return enforcer, sorted(enforcer.registered_rules)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='oslopolicy-reachability',
        description=(
            'Read-only check of which policy rules are reachable from '
            'registered actions, flagging undefined and cyclical references.'
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--policy-file', help='path to a YAML policy file.')
    source.add_argument(
        '--namespace',
        help=(
            'namespace under "oslo.policy.enforcer" holding the service '
            'Enforcer.'
        ),
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='only report blocking issues, suppress advisory sections.',
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING, format='%(levelname)s: %(message)s'
    )

    if args.policy_file:
        enforcer, roots = _build_file_enforcer(args.policy_file)
    else:
        enforcer, roots = _build_namespace_enforcer(args.namespace)

    report = reachability.check_reachability(enforcer, roots)

    if args.quiet:
        for issue in report.issues:
            print(f'[{issue.kind}] action "{issue.source}": {issue.path}')
    else:
        print(reachability.format_report(report))

    # Unreachable policies are advisory; only broken references fail the run.
    return 0 if report.ok else 1


if __name__ == '__main__':
    sys.exit(main())
