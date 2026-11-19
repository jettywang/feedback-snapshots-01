import argparse
from typing import cast


def add_fingerprint_action(parent: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = parent.add_parser(
        'fingerprint',
        help='Adds or verifies outbound fingerprints for a baseline.',
        description=(
            'Produces tenant-scoped, keyed fingerprints that can be sent to a shared '
            'aggregation system. Local hashed_secret values (and therefore audit '
            'compatibility) are left unchanged.'
        ),
    )

    parser.add_argument(
        'filename',
        help='Baseline file to annotate or verify.',
    )
    parser.add_argument(
        '--config',
        required=True,
        metavar='FILENAME',
        help=(
            'Fingerprint config JSON: approved "scopes" and versioned "keys". The '
            'highest key version mints new fingerprints; all keys can verify old ones.'
        ),
    )
    parser.add_argument(
        '--scope',
        help=(
            'Approved scope to fingerprint under. Required when the config declares '
            'more than one scope.'
        ),
    )
    parser.add_argument(
        '--verify',
        action='store_true',
        help=(
            'Verify the outbound fingerprints already stored in the baseline, instead '
            'of generating new ones.'
        ),
    )
    parser.add_argument(
        '--output',
        metavar='FILENAME',
        help='Write the annotated baseline here instead of printing it to stdout.',
    )

    return cast(argparse.ArgumentParser, parser)
