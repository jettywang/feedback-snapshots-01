"""
Command-line interface for the FileStorage -> SQLite migration toolkit.

Examples::

    # Read-only check before any data has been copied.
    python -m huey.contrib.migration_cli verify ./var/huey ./var/huey.db

    # Copy the paused queue into SQLite (source is never modified).
    python -m huey.contrib.migration_cli migrate ./var/huey ./var/huey.db

    # Re-check after the copy; exits non-zero while anything needs review.
    python -m huey.contrib.migration_cli verify ./var/huey ./var/huey.db --strict

The CLI performs structural verification only. To also reject payloads that
cannot be deserialized (or that reference unregistered tasks), drive
MigrationVerifier / migrate_file_queue_to_sqlite from Python and pass your
Huey instance.
"""
import argparse
import json
import sys

from huey.contrib.migration import MigrationVerifier
from huey.contrib.migration import migrate_file_queue_to_sqlite
from huey.contrib.migration import ZONES


def _common(parser):
    parser.add_argument('source', help='FileStorage directory (the old queue)')
    parser.add_argument('database', help='target SQLite database file')
    parser.add_argument('--name', default='huey',
                        help='Huey queue name stored in each row')
    parser.add_argument('--levels', type=int, default=2,
                        help='FileStorage result-key sharding levels')
    parser.add_argument('--zones', nargs='+', default=list(ZONES),
                        choices=list(ZONES),
                        help='storage areas to process')
    parser.add_argument('--json', action='store_true',
                        help='emit a machine-readable JSON report')


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='migration_cli',
        description='Verify and migrate a Huey FileStorage queue to SQLite.')
    sub = parser.add_subparsers(dest='command', required=True)

    verify = sub.add_parser('verify', help='read-only verification')
    _common(verify)
    verify.add_argument('--strict', action='store_true',
                        help='exit non-zero unless cutover is ready')

    migrate = sub.add_parser('migrate', help='copy records into SQLite')
    _common(migrate)
    migrate.add_argument('--fail-after', type=int, default=None,
                         help='simulate a failure after N rows (rollback test)')

    args = parser.parse_args(argv)
    zones = tuple(args.zones)

    if args.command == 'migrate':
        result = migrate_file_queue_to_sqlite(
            args.source, args.database, name=args.name, levels=args.levels,
            zones=zones, fail_after=args.fail_after)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    verifier = MigrationVerifier(args.source, (args.database, args.name),
                                 zones=zones)
    report = verifier.verify()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.to_text())
    if args.strict and not report.is_cutover_ready():
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
