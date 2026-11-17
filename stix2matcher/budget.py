"""
Cooperative work budgeting for a single pattern match.

The matcher is generator based, so most of its work is performed lazily while
bindings are consumed.  A wall-clock timeout around the outer call is not
enough: the matching work would keep running (and holding references) after the
caller gave up.  Instead, every expensive operation charges a :class:`WorkBudget`
*before* doing the work.  When the budget is exhausted, the charge raises
:class:`BudgetExhausted` from inside the operation, which unwinds and closes the
generator chain.

The units are deterministic accounting units, not seconds.  That makes limits
reproducible: a match which completes at exactly ``max_work`` units is
unaffected, and the next unit of work fails.  One unit corresponds to a small
bounded operation (one object/step examined, one binding pair considered, one
regex check, etc.).  Exact per-operation costs are implementation details; the
contracts that matter are:

* work is charged before it is performed;
* exhaustion is signalled with the stage which was executing, so callers can
  tell where the match stopped;
* an exhausted budget refuses all further work.
"""

import contextlib


# Identifiable stages at which a match can stop.  Stages are coarse enough to
# explain where a budget went without tying callers to implementation
# minutiae, but distinct enough to separate the expensive work classes:
# scanning paths, dereferencing, combining bindings, and running regexes.
STAGE_PREFLIGHT = "preflight"
STAGE_INPUT = "input-normalization"
STAGE_PATH = "path-traversal"
STAGE_DEREFERENCE = "path-dereference"
STAGE_PROPERTY_TEST = "property-test"
STAGE_REGEX_COMPILE = "regex-compile"
STAGE_REGEX = "regex-execution"
STAGE_COMBINATION = "binding-combination"
STAGE_RESULT = "binding-yield"


class BudgetExhausted(Exception):
    """
    Raised when a match's work budget is exhausted.

    This is deliberately distinct from a normal non-match: a non-match means
    the observations were scanned (as far as the pattern requires) and nothing
    matched, while this exception means the scan was cut short.  Callers must
    not treat it as either "no match" or "safe".

    :ivar stage: the stage which was executing when the budget ran out, e.g.
        ``"binding-combination"``.  See the ``STAGE_*`` constants in
        :mod:`stix2matcher.budget`.
    :ivar work_used: units charged when the budget stopped.  This never exceeds
        ``work_limit``.
    :ivar work_limit: the configured limit.
    :ivar detail: a short human-readable description of the operation which
        could not be started.
    :ivar already_exhausted: True if the budget had been exhausted by an
        earlier operation, and this charge was refused before doing any work.
    """

    def __init__(self, stage, work_used, work_limit, detail=None,
                 already_exhausted=False):
        self.stage = stage
        self.work_used = work_used
        self.work_limit = work_limit
        self.detail = detail
        self.already_exhausted = already_exhausted

        message = (
            u"Work budget exhausted during '{}': used {}/{} units".format(
                stage, work_used, work_limit
            )
        )
        if detail:
            message += u" while attempting {}".format(detail)
        if already_exhausted:
            message += u" (the budget was previously exhausted)"
        super(BudgetExhausted, self).__init__(message)


class WorkBudget(object):
    """
    A budget for the work performed by one match.

    ``max_work`` is an integer number of accounting units, or ``None`` for an
    unlimited budget.  An unlimited budget preserves the historical matcher
    behaviour (apart from rejecting rules which cannot be bounded; see
    :class:`stix2matcher.errors.UnsupportedRuleError`).

    The object is mutable so it can be shared with the matcher, and is not
    reusable after exhaustion.  Create a new budget for each match.
    """

    __slots__ = (
        "_limit", "_used", "_stage", "_stage_usage", "_exhaustion"
    )

    def __init__(self, max_work=None, limit=None):
        if limit is not None:
            if max_work is not None:
                raise ValueError(
                    u"Specify either max_work or limit, not both"
                )
            max_work = limit

        if max_work is not None:
            if isinstance(max_work, bool) or not isinstance(max_work, int):
                raise TypeError(u"max_work must be an integer or None")
            if max_work < 0:
                raise ValueError(u"max_work must be >= 0")

        self._limit = max_work
        self._used = 0
        self._stage = STAGE_PREFLIGHT
        self._stage_usage = {}
        self._exhaustion = None

    # -- state ----------------------------------------------------------

    @property
    def limit(self):
        return self._limit

    @property
    def work_limit(self):
        return self._limit

    @property
    def used(self):
        return self._used

    @property
    def work_used(self):
        return self._used

    @property
    def remaining(self):
        if self._limit is None:
            return None
        return self._limit - self._used

    @property
    def exhausted(self):
        return self._exhaustion is not None

    @property
    def stop_stage(self):
        return self._exhaustion.stage if self._exhaustion else None

    @property
    def stage(self):
        return self._stage

    @property
    def stage_usage(self):
        """A snapshot mapping stage name to units charged in that stage."""
        return dict(self._stage_usage)

    # -- operation ------------------------------------------------------

    def enter_stage(self, stage):
        self._stage = stage

    @contextlib.contextmanager
    def at_stage(self, stage):
        """Set the current stage for the duration of the block."""
        previous = self._stage
        self._stage = stage
        try:
            yield self
        finally:
            self._stage = previous

    def charge(self, amount=1, stage=None, detail=None):
        """
        Charge ``amount`` units, raising :class:`BudgetExhausted` if that would
        exceed the limit.  The work described by the charge has not happened
        yet when the exception is raised.

        Charging an already-exhausted budget raises immediately without
        performing any work.
        """
        if stage is not None:
            self._stage = stage
        current_stage = self._stage

        if self._exhaustion is not None:
            previous = self._exhaustion
            raise BudgetExhausted(
                previous.stage, previous.work_used, previous.work_limit,
                detail or previous.detail, already_exhausted=True
            )

        if amount < 0:
            raise ValueError(u"amount must be >= 0")
        if amount == 0:
            return

        if self._limit is not None and self._used + amount > self._limit:
            # Record the budget at its limit, not beyond it: the refused work
            # was never performed.
            self._used = self._limit
            self._exhaustion = BudgetExhausted(
                current_stage, self._used, self._limit, detail
            )
            raise self._exhaustion

        self._used += amount
        self._stage_usage[current_stage] = \
            self._stage_usage.get(current_stage, 0) + amount

    def __repr__(self):
        limit = u"unlimited" if self._limit is None else u"{}".format(
            self._limit
        )
        return u"<WorkBudget used={} limit={} stage={}>".format(
            self._used, limit, self._stage
        )
