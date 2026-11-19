from typing import Dict
from typing import Optional
from typing import Tuple


class UnableToReadBaselineError(ValueError):
    """Think of this as a 404, if getting a baseline had a HTTPError code."""
    pass


class InvalidBaselineError(ValueError):
    """Think of this as a 400, if getting a baseline had a HTTPError code."""
    pass


class InvalidFile(ValueError):
    """Think of this as a 400, if FileNotFoundError was a 404 HTTPError code."""
    pass


class DiffInputLimitExceeded(Exception):
    """
    Raised when a diff scan cannot consume its complete input: either the configured
    input size limit was reached, or the underlying input could not be read in full.

    This is deliberately distinct from a scan that simply found no secrets: callers
    need to know that the results they received only cover a (reported) fragment of
    the diff.

    :param reason: machine-readable cause, either ``limit_exceeded`` or
        ``unreadable_input``
    :param limit: configured byte limit, if any
    :param bytes_read: number of bytes successfully consumed before stopping
    :param scanned_files: files whose diff hunks were fully consumed (each mapped to
        the target line range that was covered)
    :param partial_file: file whose diff was being consumed when the scan stopped,
        if applicable
    """

    def __init__(
        self,
        reason: str,
        limit: Optional[int] = None,
        bytes_read: int = 0,
        scanned_files: Optional[Dict[str, Tuple[int, int]]] = None,
        partial_file: Optional[str] = None,
    ) -> None:
        self.reason = reason
        self.limit = limit
        self.bytes_read = bytes_read
        self.scanned_files = scanned_files or {}
        self.partial_file = partial_file

        if reason == 'limit_exceeded':
            message = (
                f'diff input exceeded the configured limit of {limit} bytes '
                f'(read {bytes_read} bytes before stopping)'
            )
        else:
            message = (
                f'unable to read the complete diff input '
                f'(read {bytes_read} bytes before the read failure)'
            )

        coverage = ', '.join(
            f'{filename}: lines {start}-{end}'
            for filename, (start, end) in sorted(self.scanned_files.items())
        )
        if coverage:
            message += f'; completed coverage: {coverage}'
        if partial_file:
            message += f'; incomplete file: {partial_file}'

        super().__init__(message)


class SecretNotFoundOnSpecifiedLineError(Exception):
    def __init__(self, line: int) -> None:
        super().__init__(
            'ERROR: Secret not found on line {}!\n'.format(line)
            + 'Try recreating your baseline to fix this issue.',
        )


class NoLineNumberError(Exception):
    def __init__(self) -> None:
        super().__init__(
            'ERROR: No line numbers found in baseline! Line numbers are needed '
            'for auditing secret occurrences. Try recreating your baseline to fix '
            'this issue.',
        )
