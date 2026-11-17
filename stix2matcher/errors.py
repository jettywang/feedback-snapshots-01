"""
Exceptions used by the pattern matcher.

These are kept in a separate module so that the budget machinery can refer to
them without creating an import cycle with :mod:`stix2matcher.matcher`.
"""


class MatcherException(Exception):
    """Base class for matcher exceptions."""
    pass


class MatcherInternalError(MatcherException):
    """For errors that probably represent bugs or incomplete matcher
    implementation."""
    pass


class UnsupportedOperatorError(MatcherInternalError):
    """This means I just haven't yet added support for a particular operator.
    (A genuinely invalid operator ought to be caught during parsing right??)
    I found I was throwing internal errors for this in several places, so I
    just gave the error its own class to make it easier.
    """
    def __init__(self, op_str):
        super(UnsupportedOperatorError, self).__init__(
            u"Unsupported operator: '{}'".format(op_str)
        )


class UnsupportedRuleError(MatcherException):
    """
    Raised when a pattern uses a construct which cannot be executed within a
    bounded work budget.

    The matcher rejects the rule rather than accepting it with an unbounded
    worst case.  ``reason`` says which construct or shape was refused,
    ``capability`` states the supported subset, and ``pattern`` carries the
    offending pattern text so callers can report it.

    This is an error, not a non-match: the rule was never evaluated against
    the observations.
    """

    def __init__(self, pattern, reason, capability):
        self.pattern = pattern
        self.reason = reason
        self.capability = capability
        super(UnsupportedRuleError, self).__init__(
            u"Unsupported pattern ({}): {}. {}".format(
                pattern, reason, capability
            )
        )
