#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from pysnmp.smi import error

__all__ = [
    "DEFAULT_TRAVERSAL_CANDIDATE_LIMIT",
    "TraversalBudget",
]

#: Default number of candidate OIDs a single SNMP request may examine while
#: resolving GETNEXT/GETBULK successors.  The limit bounds the work spent
#: skipping subtrees that are hidden by the requester's MIB view.
#:
#: A budget is shared by every varbind in a request and by every GETBULK
#: repetition.  Exhausting it raises
#: :py:class:`~pysnmp.smi.error.TraversalBudgetExceededError`, which command
#: responders map to the ``resourceUnavailable`` error status.
DEFAULT_TRAVERSAL_CANDIDATE_LIMIT = 4096


class TraversalBudget:
    """Per-request accounting of MIB candidates examined during traversal.

    A command responder creates one budget per incoming PDU and passes it to
    every :py:meth:`~pysnmp.smi.instrum.MibInstrumController.read_next_variables`
    call made while producing the response.  This way all varbinds and all
    GETBULK repetitions share the same allowance.

    Only distinct candidate OIDs examined within one traversal operation are
    counted.  The two-phase ``readTestNext``/``readGetNext`` lookup of the same
    candidate therefore consumes a single unit.  Each call into the
    instrumentation starts a new operation, so re-checking an OID during the
    next repetition is accounted for again.

    When the allowance is exhausted the next candidate examination raises
    :py:class:`~pysnmp.smi.error.TraversalBudgetExceededError`.  A responder
    turns that exception into an explicit SNMP error response; it is never
    converted into ``endOfMibView``.
    """

    def __init__(self, limit: "int | None" = DEFAULT_TRAVERSAL_CANDIDATE_LIMIT):
        """Create a traversal budget.

        Args:
            limit (int | None): Maximum number of candidate OIDs to examine.
                ``None`` disables the limit.  The default is
                :py:data:`DEFAULT_TRAVERSAL_CANDIDATE_LIMIT`.

        Raises:
            ValueError: If limit is negative or not an integer.
        """
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int):
                raise ValueError(f"Invalid traversal candidate limit {limit!r}")
            if limit < 0:
                raise ValueError(f"Invalid traversal candidate limit {limit!r}")

        self.limit = limit
        self.consumed = 0
        # OIDs examined so far, in examination order.
        self.probed = []
        # Request varbind indexes that caused each examination.
        self.probed_indexes = []
        self._current = set()

    def __repr__(self):
        """Return a debug representation."""
        return (
            f"{self.__class__.__name__}(limit={self.limit!r}, consumed={self.consumed})"
        )

    @property
    def examined(self):
        """Number of candidate OIDs examined so far."""
        return self.consumed

    @property
    def candidates(self):
        """List of examined candidate OIDs, in examination order."""
        return self.probed

    @property
    def remaining(self):
        """Number of candidates still available, or ``None`` if unlimited."""
        if self.limit is None:
            return None
        return max(self.limit - self.consumed, 0)

    @property
    def exhausted(self):
        """Return True when no more candidates may be examined."""
        return self.limit is not None and self.consumed >= self.limit

    def start_operation(self):
        """Start a new instrumentation lookup operation."""
        self._current.clear()

    @staticmethod
    def translate_index(idx, idx_map):
        """Translate a local varbind index into a request-wide index."""
        if idx is None or idx_map is None:
            return idx
        try:
            return idx_map[idx]
        except (IndexError, TypeError):
            return idx

    def consume_for_context(self, oid, context):
        """Account for a candidate using the traversal context.

        The context may carry ``idx`` (local varbind index) and
        ``traversal_idx_map`` (mapping local indexes to request indexes).
        """
        return self.consume(
            oid,
            idx=self.translate_index(
                context.get("idx"), context.get("traversal_idx_map")
            ),
        )

    def consume(self, oid, idx=None):
        """Account for one candidate OID examined during traversal.

        Args:
            oid (tuple): Candidate OID being examined.
            idx (int): Index of the request varbind that caused the
                examination, if known.

        Returns:
            bool: True if the candidate was newly counted, False if it was
            already examined within the current operation.

        Raises:
            TraversalBudgetExceededError: If the allowance is exhausted.
        """
        candidate = tuple(oid)
        key = idx, candidate

        if key in self._current:
            return False

        # Re-examination is free, but the very first look at a candidate
        # must fit within the allowance.  ``exhausted`` means a further
        # candidate would exceed the limit.

        if self.exhausted:
            raise error.TraversalBudgetExceededError(
                idx=idx,
                candidate=candidate,
                limit=self.limit,
                examined=self.consumed,
                reason=(
                    "traversal candidate budget exhausted before a "
                    "lexicographic successor could be established"
                ),
            )

        self._current.add(key)
        self.consumed += 1
        self.probed.append(candidate)
        self.probed_indexes.append(idx)

        return True
