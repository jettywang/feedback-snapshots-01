from typing import Optional


class UnableToReadBaselineError(ValueError):
    """Think of this as a 404, if getting a baseline had a HTTPError code."""
    pass


class InvalidBaselineError(ValueError):
    """Think of this as a 400, if getting a baseline had a HTTPError code."""
    pass


class InvalidFile(ValueError):
    """Think of this as a 400, if FileNotFoundError was a 404 HTTPError code."""
    pass


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


class PluginExecutionError(Exception):
    """Raised when a plugin fails while scanning a line.

    The original exception may have embedded the scanned line (and therefore any
    plaintext secret on it) in its message or traceback. Since this exception is
    allowed to travel across process boundaries (e.g. from a multiprocessing worker
    back to the parent process), it deliberately carries only locating metadata --
    never the line content or the secret value -- so that a worker failure cannot
    leak plaintext through the parent process's output.
    """

    def __init__(
        self,
        plugin_name: str = '',
        filename: str = '',
        line_number: int = 0,
        cause: Optional['BaseException'] = None,
        cause_type: str = '',
    ) -> None:
        # Keep the locating metadata in dedicated fields (rather than parsing the message)
        # so it is reliable to assert on, and give every argument a default so that the
        # default exception pickling (which rebuilds via ``__init__(*args)``) round-trips.
        self.plugin_name = plugin_name
        self.filename = filename
        self.line_number = line_number
        self.cause_type = cause_type or (type(cause).__name__ if cause is not None else '')
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        return (
            'Plugin `{plugin}` failed while scanning {filename}:{line_number} '
            '({cause}). The offending line and any secret on it are intentionally '
            'omitted to avoid leaking plaintext.'.format(
                plugin=self.plugin_name,
                filename=self.filename,
                line_number=self.line_number,
                cause=self.cause_type,
            )
        )

    def __reduce__(self) -> tuple:
        # Only locating metadata crosses the process boundary -- never the original
        # exception's args/message, which may contain the scanned line's plaintext.
        return (
            self.__class__,
            (
                self.plugin_name,
                self.filename,
                self.line_number,
                None,
                self.cause_type,
            ),
            self.__getstate__(),
        )

    def __getstate__(self) -> dict:
        # Drop the base exception's `args` (the human-readable message) entirely: the
        # message is rebuilt from the sanitized locating fields on the receiving side.
        return {
            'plugin_name': self.plugin_name,
            'filename': self.filename,
            'line_number': self.line_number,
            'cause_type': self.cause_type,
        }

    def __setstate__(self, state: dict) -> None:
        self.plugin_name = state['plugin_name']
        self.filename = state['filename']
        self.line_number = state['line_number']
        self.cause_type = state['cause_type']
        self.args = (self._build_message(),)
