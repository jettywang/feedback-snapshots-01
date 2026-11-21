"""Command line entry point for the offline policy upgrade diff tool."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from policy_diff import engine, loader, report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='python -m policy_diff',
        description=(
            'Compare effective oslo.policy authorization before and after a '
            'policy-in-code default upgrade, using local policy files and '
            'credential samples. All enforcers are throwaway objects; the '
            'running service enforcer is not touched.'
        ),
    )
    parser.add_argument(
        '--before-defaults',
        required=True,
        help='YAML file with the currently deployed registered '
        'policy defaults.',
    )
    parser.add_argument(
        '--after-defaults',
        required=True,
        help='YAML file with the upgraded registered policy defaults.',
    )
    parser.add_argument(
        '--before-policy-file',
        help='Operator policy.yaml used by the current deployment (before).',
    )
    parser.add_argument(
        '--after-policy-file',
        help='Operator policy.yaml that will be present after upgrade. '
        'Defaults to --before-policy-file when omitted.',
    )
    parser.add_argument(
        '--credentials',
        required=True,
        nargs='+',
        help='Credential JSON files or directories containing *.json samples.',
    )
    parser.add_argument(
        '--target',
        help='Optional target JSON used while evaluating every action.',
    )
    parser.add_argument(
        '--before-enforce-new-defaults',
        action=argparse.BooleanOptionalAction,
        default=False,
        help='enforce_new_defaults value for the before snapshot '
        '(default: False, i.e. deprecated OR-compat behavior).',
    )
    parser.add_argument(
        '--after-enforce-new-defaults',
        action=argparse.BooleanOptionalAction,
        default=True,
        help='enforce_new_defaults value for the after snapshot '
        '(default: True, i.e. only new defaults are enforced).',
    )
    parser.add_argument(
        '--rule',
        help='Explain where the effective policy of one action comes from '
        'instead of printing the full diff.',
    )
    parser.add_argument(
        '--format',
        choices=('text', 'json'),
        default='text',
        help='Report format (default: text).',
    )
    return parser


def _context_payload(context: engine.SnapshotContext) -> dict[str, object]:
    return {
        'label': context.label,
        'defaults_file': context.defaults_file,
        'policy_file': context.policy_file,
        'enforce_new_defaults': context.enforce_new_defaults,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    after_policy_file = args.after_policy_file or args.before_policy_file

    try:
        before_defaults = loader.load_defaults(args.before_defaults)
        after_defaults = loader.load_defaults(args.after_defaults)
        samples = loader.load_credentials(args.credentials)
        if not samples:
            print('error: no credential samples found', file=sys.stderr)
            return 2

        fallback_target = {
            'user_id': samples[0].creds.get('user_id', '')
        }
        if samples[0].creds.get('project_id'):
            fallback_target['project_id'] = samples[0].creds['project_id']
        target = loader.load_target(args.target, fallback_target)

        before_context = engine.SnapshotContext(
            label='before-upgrade',
            defaults_file=args.before_defaults,
            policy_file=args.before_policy_file,
            enforce_new_defaults=args.before_enforce_new_defaults,
        )
        after_context = engine.SnapshotContext(
            label='after-upgrade',
            defaults_file=args.after_defaults,
            policy_file=after_policy_file,
            enforce_new_defaults=args.after_enforce_new_defaults,
        )

        before = engine.build_snapshot(before_context, before_defaults)
        after = engine.build_snapshot(after_context, after_defaults)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2

    if args.rule:
        side = after
        if (
            args.rule not in after.registered
            and args.rule in before.registered
        ):
            side = before
        trace = engine.explain_action(side, args.rule)
        sys.stdout.write(
            report.render_explain(side.context.label, args.rule, trace)
        )
        return 0

    all_actions = sorted(before.actions | after.actions)
    engine.populate_evaluations(before, samples, target, all_actions)
    engine.populate_evaluations(after, samples, target, all_actions)
    rows = engine.diff_snapshots(before, after, samples)

    if args.format == 'json':
        sys.stdout.write(
            report.render_json(
                rows,
                _context_payload(before_context),
                _context_payload(after_context),
            )
        )
    else:
        sys.stdout.write(
            report.render_text(
                rows,
                before_context.label,
                after_context.label,
            )
        )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
