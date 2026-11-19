import pytest

from detect_secrets.core.usage import ParserBuilder


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()


def test_normal_mode_requires_single_file(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', 'fileB'])


def test_diff_mode_requires_two_files(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', '--diff'])


def test_journal_requires_reviewer(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', '--journal', 'journal.json'])


def test_journal_rejects_non_interactive_modes(parser):
    for extra in (['--stats'], ['--report'], ['--diff', 'fileB']):
        with pytest.raises(SystemExit):
            parser.parse_args(
                ['audit', 'fileA', '--journal', 'journal.json', '--reviewer', 'alice', *extra],
            )


def test_journal_arguments_are_parsed(parser):
    args = parser.parse_args(
        ['audit', 'fileA', '--journal', 'journal.json', '--reviewer', 'alice'],
    )
    assert args.journal == 'journal.json'
    assert args.reviewer == 'alice'


def test_journal_arguments_default_to_none(parser):
    args = parser.parse_args(['audit', 'fileA'])
    assert args.journal is None
    assert args.reviewer is None
