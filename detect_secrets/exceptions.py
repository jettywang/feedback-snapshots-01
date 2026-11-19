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


class DecisionJournalError(ValueError):
    """Base class for errors raised while working with an audit decision journal."""
    pass


class DuplicateDecisionError(DecisionJournalError):
    """Raised when a decision entry with the same id is submitted twice."""
    def __init__(self, entry_id: str) -> None:
        super().__init__(
            f'A decision with id `{entry_id}` has already been recorded. '
            'Refusing to apply the same decision twice.',
        )
        self.entry_id = entry_id


class BaselineMismatchError(DecisionJournalError):
    """Raised when a journal is reconciled against a different baseline than its anchor."""
    def __init__(self, expected_hash: str, actual_hash: str) -> None:
        super().__init__(
            'The baseline does not match the journal\'s anchored baseline '
            f'(expected `{expected_hash}`, got `{actual_hash}`). '
            'Start a new journal for this baseline before recording decisions.',
        )
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
