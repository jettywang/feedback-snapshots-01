import argparse
from typing import cast


def add_audit_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'audit',
        help='Manually assesses a baseline to determine validity of secrets found.',
        description=(
            'Auditing a baseline allows analysts to label results, and optimize plugins for '
            'the highest signal-to-noise ratio for their environment.'
        ),
    )

    parser.add_argument(
        'filename',
        nargs='*',
        help=(
            'Audit a given baseline file to distinguish the difference '
            'between false and true positives.'
        ),
    )

    _add_mode_parser(parser)
    _add_review_package_module(parser)
    _add_report_module(parser)
    _add_statistics_module(parser)
    return cast(argparse.ArgumentParser, parser)


def _add_mode_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--diff',
        action='store_true',
        help=(
            'Allows the comparison of two baseline files, in order to '
            'effectively distinguish the difference between various '
            'plugin configurations.'
        ),
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help=(
            'Displays the results of an interactive auditing session '
            'which have been saved to a baseline file.'
        ),
    )

    parser.add_argument(
        '--report',
        action='store_true',
        help=(
            'Displays a report with the secrets detected'
        ),
    )


def _add_review_package_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='redacted review packages',
        description=(
            'Exchange audit decisions without sharing source files. Packages contain only '
            'the finding category, evidence location, and an opaque finding id.'
        ),
    )

    review_parser = parser.add_mutually_exclusive_group()
    review_parser.add_argument(
        '--export-review',
        metavar='PACKAGE',
        help=(
            'Exports a redacted review package from the specified baseline. '
            'e.g. `detect-secrets audit .secrets.baseline --export-review review.json`'
        ),
    )
    review_parser.add_argument(
        '--review-package',
        metavar='PACKAGE',
        help=(
            'Interactively reviews a package without access to source files. '
            'e.g. `detect-secrets audit --review-package review.json`'
        ),
    )
    review_parser.add_argument(
        '--import-review',
        metavar='PACKAGE',
        help=(
            'Imports reviewed decisions into the specified baseline. '
            'e.g. `detect-secrets audit .secrets.baseline --import-review review.reviewed.json`'
        ),
    )
    parser.add_argument(
        '--output',
        metavar='PACKAGE',
        help=(
            'Where to write the reviewed package. Defaults to writing in the current '
            'directory. Only used with --review-package.'
        ),
    )


def _add_report_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='reporting',
        description=(
            'Display a report with all the findings and the made decisions. '
            'To be used with the report mode (--report).'
        ),
    )

    report_parser = parser.add_mutually_exclusive_group()
    report_parser.add_argument(
        '--only-real',
        action='store_true',
        help=(
            'Only includes real secrets in the report'
        ),
    )

    report_parser.add_argument(
        '--only-false',
        action='store_true',
        help=(
            'Only includes false positives in the report'
        ),
    )


def _add_statistics_module(parent: argparse.ArgumentParser) -> None:
    parser = parent.add_argument_group(
        title='analytics',
        description=(
            'Quantify the success of your plugins based on the labelled results '
            'in your baseline. To be used with the statistics mode (--stats).'
        ),
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Outputs results in a machine-readable format.',
    )


def parse_args(args: argparse.Namespace) -> None:
    if args.action != 'audit':
        return

    if args.review_package:
        if args.filename:
            raise argparse.ArgumentTypeError(
                '--review-package does not require a baseline file.',
            )
        return
    elif args.output:
        raise argparse.ArgumentTypeError(
            '--output can only be used with --review-package.',
        )

    if args.export_review or args.import_review:
        if len(args.filename) != 1:
            raise argparse.ArgumentTypeError(
                '--export-review and --import-review require exactly one baseline file.',
            )
        return

    if args.diff and len(args.filename) != 2:
        raise argparse.ArgumentTypeError(
            '--diff mode requires two files to compare with each other.',
        )
    elif not args.diff and len(args.filename) != 1:
        raise argparse.ArgumentTypeError(
            'Can only specify one baseline at a time.',
        )
