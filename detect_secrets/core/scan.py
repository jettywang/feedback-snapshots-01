import os
import subprocess
from typing import Any
from typing import cast
from typing import Dict
from typing import Generator
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union

from ..exceptions import DiffInputLimitExceeded
from ..filters.allowlist import is_line_allowlisted
from ..settings import get_filters
from ..settings import get_plugins
from ..settings import get_settings
from ..transformers import get_transformed_file
from ..types import NamedIO
from ..types import SelfAwareCallable
from ..util import git
from ..util.code_snippet import CodeSnippet
from ..util.code_snippet import get_code_snippet
from ..util.inject import call_function_with_arguments
from ..util.path import get_relative_path
from .log import log
from .plugins import Plugin
from .potential_secret import PotentialSecret


def get_files_to_scan(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
) -> Generator[str, None, None]:
    """
    If we specify specific files, we should be able to scan them. This abides by the
    Principle of Least Surprise -- so users don't have to do:

        $ detect-secrets scan test_data/config.env --all-files

    to scan the specific file.

        >>> list(get_files_to_scan('test_data/config.env')) == ['test_data/config.env']

    In a similar way,

        >>> list(get_files_to_scan('test_data/config.env', '.secrets.baseline')) == \
        ...     ['test_data/config.env', '.secrets.baseline']

    If we specify directories, then we should use git tracked files when possible. To
    override this behavior, we can specify `should_scan_all_files=True`, which will force
    the scan for all files.

    See test cases for more details.

    :param root: if not specified, will assume current repository as root.
    """
    if root:
        root = os.path.realpath(root)

    # First, we determine the appropriate filtering mode to be used.
    # If this is True, then it will consider everything to be valid.
    # Otherwise, it will only list the files that are valid.
    valid_paths: Union[bool, Set[str]] = True
    for path in paths:
        # Since this is not a directory, we assume that it is a file proper, and automatically
        # consider it valid.
        if not os.path.isdir(path):
            continue

        if not should_scan_all_files:
            try:
                valid_paths = git.get_tracked_files(git.get_root_directory(root))
            except subprocess.CalledProcessError:
                log.warning('Did not detect git repository. Try scanning all files instead.')
                valid_paths = False

        # Since valid_paths attempts to get *all* tracked files in the repository, we just need
        # to initialize it once.
        break

    if not valid_paths:
        yield from []
        return

    for path in paths:
        iterator = (
            cast(List[Tuple], [(root or os.getcwd(), None, [path])])
            if os.path.isfile(path)
            else os.walk(path)
        )

        for path_root, _, filenames in iterator:
            for filename in filenames:
                relative_path = get_relative_path(
                    root=root or os.getcwd(),
                    path=os.path.join(path_root, filename),
                )
                if not relative_path:
                    # e.g. symbolic links may be pointing outside the root directory
                    continue

                if (
                    valid_paths is True
                    or relative_path in valid_paths
                ):
                    yield relative_path


def scan_line(line: str) -> Generator[PotentialSecret, None, None]:
    """Used for adhoc string scanning."""
    # Disable this, since it doesn't make sense to run this for adhoc usage.
    get_settings().disable_filters(
        'detect_secrets.filters.common.is_invalid_file',
    )
    get_filters.cache_clear()
    context = get_code_snippet(lines=[line], line_number=1)

    yield from (
        secret
        for plugin in get_plugins()
        for secret in _scan_line(
            plugin=plugin,
            filename='adhoc-string-scan',
            line=line,
            line_number=0,
            enable_eager_search=True,
            context=context,
        )
        if not _is_filtered_out(
            required_filter_parameters=['context'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
            context=context,
        )
    )


def scan_file(filename: str) -> Generator[PotentialSecret, None, None]:
    try:
        if not get_plugins():   # pragma: no cover
            log.error('No plugins to scan with!')
            return
    except FileNotFoundError:
        log.error('Unable to load plugins!')
        return

    if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
        return

    try:
        has_secret = False
        for lines in _get_lines_from_file(filename):
            for secret in _process_line_based_plugins(
                lines=list(enumerate(lines, start=1)),
                filename=filename,
            ):
                has_secret = True
                yield secret

            if has_secret:
                break
    except IOError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    """
    :raises: ImportError
    :raises: DiffInputLimitExceeded if the configured diff input limit is reached,
        or the diff cannot be read in full. Secrets yielded before the failure only
        cover the fully-consumed files reported by the exception.
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    reader = _DiffInputReader(iter(diff.splitlines(keepends=True)), get_settings().diff_input_limit)
    try:
        for filename, lines in _iter_lines_from_diff(reader):
            yield from _process_line_based_plugins(lines, filename=filename)
    finally:
        reader.close()


def scan_for_allowlisted_secrets_in_file(filename: str) -> Generator[PotentialSecret, None, None]:
    """
    Developers are able to add individual lines to the allowlist using
    `detect_secrets.filters.allowlist.is_line_allowlisted`. However, there are
    times when we want to verify that no *actual* secrets are added to the codebase
    via this feature.

    This scans specifically for these lines, and ignores everything else.
    """
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    if _is_filtered_out(
        required_filter_parameters=['filename'],
        filename=filename,
    ):
        return

    # NOTE: Unlike `scan_file`, we don't ever have to use eager file transformers, since we already
    # know which lines we want to scan.
    try:
        for lines in _get_lines_from_file(filename):
            yield from _scan_for_allowlisted_secrets_in_lines(enumerate(lines, start=1), filename)
            break
    except IOError:
        log.warning(f'Unable to open file: {filename}')
        return


def scan_for_allowlisted_secrets_in_diff(diff: str) -> Generator[PotentialSecret, None, None]:
    if not get_plugins():   # pragma: no cover
        log.error('No plugins to scan with!')
        return

    reader = _DiffInputReader(iter(diff.splitlines(keepends=True)), get_settings().diff_input_limit)
    try:
        for filename, lines in _iter_lines_from_diff(reader):
            yield from _scan_for_allowlisted_secrets_in_lines(lines, filename)
    finally:
        reader.close()


def _scan_for_allowlisted_secrets_in_lines(
    lines: Iterable[Tuple[int, str]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    # We control the setting here because it makes more sense than requiring the caller
    # to set this setting before calling this function.
    get_settings().disable_filters('detect_secrets.filters.allowlist.is_line_allowlisted')
    get_filters.cache_clear()

    line_numbers, lines = zip(*lines)
    line_content = [line.rstrip() for line in lines]
    for line_number, line in zip(line_numbers, line_content):
        context = get_code_snippet(line_content, line_number)
        if not is_line_allowlisted(
            filename=filename,
            line=line,
            context=context,
        ):
            continue

        if _is_filtered_out(required_filter_parameters=['line'], filename=filename, line=line):
            continue

        for plugin in get_plugins():
            yield from _scan_line(
                plugin=plugin,
                filename=filename,
                line=line,
                line_number=line_number,
                context=context,
            )


def _get_lines_from_file(filename: str) -> Generator[List[str], None, None]:
    """
    This attempts to get lines in a given file. If no more lines are needed, the caller
    is responsible for breaking out of this loop.

    :raises: IOError
    :raises: FileNotFoundError
    """
    with open(filename) as f:
        log.info(f'Checking file: {filename}')

        try:
            lines = get_transformed_file(cast(NamedIO, f))
            if not lines:
                lines = f.readlines()
        except UnicodeDecodeError:
            # We flat out ignore binary files
            return

        yield lines

        # If the above lines don't prove to be useful to the caller, try using eager transformers.
        f.seek(0)
        lines = get_transformed_file(cast(NamedIO, f), use_eager_transformers=True)
        if not lines:
            return

        yield lines


def _iter_lines_from_diff(
    reader: '_DiffInputReader',
) -> Generator[Tuple[str, List[Tuple[int, str]]], None, None]:
    """
    Consumes the diff one patched file at a time, so that secrets found in
    earlier files are emitted before a later file trips the input limit (or
    turns out to be unreadable).

    :raises: ImportError
    :raises: DiffInputLimitExceeded
    """
    # Local imports, so that we don't need to require unidiff for versions of
    # detect-secrets that don't use it.
    from unidiff import PatchSet
    from unidiff.errors import UnidiffParseError

    for filename, fragment in reader.iter_file_fragments():
        if _is_filtered_out(required_filter_parameters=['filename'], filename=filename):
            continue

        try:
            patch_set = PatchSet.from_string(fragment)
        except UnidiffParseError:
            # The fragment ends in a hunk whose body was cut off: there is
            # nothing scannable in it, and the interruption is already reported
            # via DiffInputLimitExceeded by the reader.
            continue

        yield (
            filename,
            [
                (line.target_line_no, line.value)
                for patch_file in patch_set
                for hunk in patch_file
                # target_lines refers to incoming (new) changes
                for line in hunk.target_lines()
                if line.is_added
            ],
        )


class _DiffInputReader:
    """
    Iterable, text-mode view over a diff's lines, which enforces an independent,
    configurable byte budget.

    The reader streams the diff's lines while enforcing the byte budget, and
    tracks diff file and hunk boundaries as it goes. When the input cannot be
    fully consumed (the limit is reached, or an underlying read fails), it
    reports which files were completely covered together with the target line
    range each of them spans.

    :param lines: iterator producing the diff's text lines (with line endings)
    :param limit: maximum number of bytes to consume, or ``None`` for no limit
    """

    def __init__(self, lines: Iterator[str], limit: Optional[int]) -> None:
        self._lines = lines
        self.limit = limit
        self.bytes_read = 0
        self._current_file: Optional[str] = None
        # Target line ranges of hunks whose bodies have been fully consumed.
        self._completed_hunk_ranges: List[Tuple[int, int]] = []
        # Target line range of the hunk currently being consumed.
        self._hunk_target_start = 0
        self._hunk_target_length = 0
        # Remaining source/target lines declared by the current hunk's header.
        self._hunk_source_remaining = 0
        self._hunk_target_remaining = 0
        self._hunk_in_progress = False
        self._scanned_files: Dict[str, Tuple[int, int]] = {}
        self._partial_file: Optional[str] = None
        self._failure: Optional[DiffInputLimitExceeded] = None

        # Local imports, so that unidiff remains an optional dependency.
        from unidiff.constants import RE_DIFF_GIT_HEADER
        from unidiff.constants import RE_HUNK_HEADER

        self._diff_git_header = RE_DIFF_GIT_HEADER
        self._hunk_header = RE_HUNK_HEADER

    def __iter__(self) -> Iterator[str]:
        return self

    def __next__(self) -> str:
        if self._failure is not None:
            raise self._failure

        try:
            line = next(self._lines)
        except StopIteration:
            raise
        except Exception as error:
            self._fail('unreadable_input', error)

        line_size = len(line.encode('utf-8'))
        if self.limit is not None and self.bytes_read + line_size > self.limit:
            self._fail('limit_exceeded')

        self.bytes_read += line_size
        self._track_boundary(line)
        return line

    def iter_file_fragments(self) -> Generator[Tuple[str, str], None, None]:
        """
        Yields each patched file's path and its standalone, parseable unified-diff
        fragment, in input order.

        :raises: DiffInputLimitExceeded if the input cannot be read in full; any
            fragments already yielded cover the files reported by the exception.
        """
        fragment: List[str] = []
        filename: Optional[str] = None

        while True:
            try:
                line = next(self)
            except StopIteration:
                if filename is not None:
                    self._finish_file(filename)
                    yield filename, ''.join(fragment)
                return
            except DiffInputLimitExceeded as error:
                if filename is not None and self._hunk_is_complete():
                    # The current file's hunks were fully consumed before the
                    # failure: emit it as a completed fragment.
                    error.partial_file = None
                    self._finish_file(filename)
                    error.scanned_files = dict(self._scanned_files)
                    yield filename, ''.join(fragment)
                raise

            fragment.append(line)
            header = self._diff_git_header.match(line)
            if not header:
                continue

            if filename is not None:
                # The previous file ends right where this new one begins. Only
                # emit it if its hunks were fully consumed; otherwise the earlier
                # read failure already decided how to report it.
                if self._hunk_is_complete():
                    self._finish_file(filename)
                    yield filename, ''.join(fragment[:-1])
                fragment = [line]

            filename = _strip_diff_path_prefix(header.group('target'))

    def close(self) -> None:
        close = getattr(self._lines, 'close', None)
        if callable(close):
            close()

    def _hunk_is_complete(self) -> bool:
        return not self._hunk_in_progress

    def _finish_file(self, filename: str) -> None:
        """Marks a file as fully consumed, recording its covered target range."""
        if self._completed_hunk_ranges:
            self._scanned_files[filename] = (
                min(start for start, _ in self._completed_hunk_ranges),
                max(end for _, end in self._completed_hunk_ranges),
            )

    def _track_boundary(self, line: str) -> None:
        header = self._diff_git_header.match(line)
        if header:
            new_file = _strip_diff_path_prefix(header.group('target'))
            if self._current_file is not None and self._current_file != new_file:
                self._finish_file(self._current_file)
            self._current_file = new_file
            self._completed_hunk_ranges = []
            self._hunk_source_remaining = 0
            self._hunk_target_remaining = 0
            self._hunk_in_progress = False
            return

        hunk = self._hunk_header.match(line)
        if hunk:
            self._hunk_target_start = int(hunk.group(3))
            self._hunk_target_length = int(hunk.group(4) or 1)
            self._hunk_source_remaining = int(hunk.group(2) or 1)
            self._hunk_target_remaining = self._hunk_target_length
            self._hunk_in_progress = True
            return

        if not self._hunk_in_progress:
            return

        if not line or line[0] == '\n':
            line_type = ' '
        else:
            line_type = line[0]

        if line_type not in ('+', '-', ' '):
            # e.g. the ``\ No newline at end of file`` marker: not a hunk line.
            return

        if line_type == '+':
            self._hunk_target_remaining -= 1
        elif line_type == '-':
            self._hunk_source_remaining -= 1
        else:
            self._hunk_source_remaining -= 1
            self._hunk_target_remaining -= 1

        if self._hunk_source_remaining == 0 and self._hunk_target_remaining == 0:
            self._completed_hunk_ranges.append(
                (
                    self._hunk_target_start,
                    self._hunk_target_start + self._hunk_target_length - 1,
                ),
            )
            self._hunk_target_length = 0
            self._hunk_in_progress = False

    def _fail(self, reason: str, cause: Optional[Exception] = None) -> None:
        if self._current_file is not None and self._hunk_in_progress:
            # The current file was interrupted mid-hunk: it is not fully covered,
            # so it must only appear as the partial file -- never in scanned_files.
            self._partial_file = self._current_file
            self._scanned_files.pop(self._current_file, None)
        elif self._current_file is not None:
            # The failure struck outside an active hunk (e.g. on the trailing
            # line of an otherwise complete final file): record its coverage.
            self._finish_file(self._current_file)

        self._failure = DiffInputLimitExceeded(
            reason=reason,
            limit=self.limit,
            bytes_read=self.bytes_read,
            scanned_files=dict(self._scanned_files),
            partial_file=self._partial_file,
        )
        if cause is not None:
            self._failure.__cause__ = cause
        raise self._failure


def _strip_diff_path_prefix(path: Optional[str]) -> Optional[str]:
    if path is None:
        return None
    if path.startswith(('a/', 'b/')):
        return path[2:]
    return path


def _process_line_based_plugins(
    lines: List[Tuple[int, str]],
    filename: str,
) -> Generator[PotentialSecret, None, None]:
    line_content = [line[1] for line in lines]

    # NOTE: We iterate through lines *then* plugins, because we want to quit early if any of the
    # filters return True.
    for line_number, line in lines:
        log.debug(f'Processing {filename}:{line_number}')
        line = line.rstrip()
        code_snippet = get_code_snippet(
            lines=line_content,
            line_number=line_number,
        )

        # We apply line-specific filters, and see whether that allows us to quit early.
        if _is_filtered_out(
            required_filter_parameters=['line'],
            filename=filename,
            line=line,
            context=code_snippet,
        ):
            continue

        yield from (
            secret
            for plugin in get_plugins()
            for secret in _scan_line(
                plugin=plugin,
                filename=filename,
                line=line,
                line_number=line_number,
                context=code_snippet,
            )
            if not _is_filtered_out(
                required_filter_parameters=['context'],
                filename=secret.filename,
                secret=secret.secret_value,
                plugin=plugin,
                line=line,
                context=code_snippet,
            )
        )


def _scan_line(
    plugin: Plugin,
    filename: str,
    line: str,
    line_number: int,
    context: CodeSnippet,
    **kwargs: Any,
) -> Generator[PotentialSecret, None, None]:
    # NOTE: We don't apply filter functions here yet, because we don't have any filters
    # that operate on (filename, line, plugin) without `secret`
    secrets = call_function_with_arguments(
        plugin.analyze_line,
        filename=filename,
        line=line,
        line_number=line_number,
        context=context,
        **kwargs,
    )
    if not secrets:
        return

    yield from (
        secret
        for secret in secrets
        if not _is_filtered_out(
            required_filter_parameters=['secret'],
            filename=secret.filename,
            secret=secret.secret_value,
            plugin=plugin,
            line=line,
        )
    )


def _is_filtered_out(required_filter_parameters: Iterable[str], **kwargs: Any) -> bool:
    for filter_fn in get_filters_with_parameter(*required_filter_parameters):
        try:
            if call_function_with_arguments(filter_fn, **kwargs):
                if 'secret' in kwargs:
                    debug_msg = f'Skipping "{0}" due to `{1}`.'.format(
                        kwargs['secret'],
                        filter_fn.path,
                    )
                elif list(kwargs.keys()) == ['filename']:
                    # We want to make sure this is only run if we're skipping files (as compared
                    # to other filters that may include `filename` as a parameter).
                    debug_msg = 'Skipping "{0}" due to `{1}`'.format(
                        kwargs['filename'],
                        filter_fn.path,
                    )
                else:
                    debug_msg = 'Skipping secret due to `{0}`.'.format(filter_fn.path)

                log.info(debug_msg)
                return True
        except TypeError:
            # Skipping non-compatible filters
            pass

    return False


def get_filters_with_parameter(*parameters: str) -> List[SelfAwareCallable]:
    """
    The issue of our method of dependency injection is that functions will be called multiple
    times. For example, if we have two functions:

    >>> def foo(filename: str): ...
    >>> def bar(filename: str, secret: str): ...

    our invocation of `call_function_with_arguments(filename=filename, secret=secret)`
    will run both of these functions. While expected, this results in multiple invocations of
    the same function, which can be less than ideal (especially if we have a heavy duty filter).

    To address this, we filter our filters with this function. It will return the functions
    that accept a minimum set of parameters, to avoid duplicative work. For instance,

    >>> get_filters_with_parameter('secret')
    [bar]
    """
    minimum_parameters = set(parameters)

    return [
        filter
        for filter in get_filters()
        if minimum_parameters <= filter.injectable_variables
    ]
