"""GETNEXT/GETBULK traversal budget and authorization tests.

These tests build an in-memory MIB consisting of many sibling scalar
subtrees, expose only a few of them through VACM, and then drive the real
command responders without any network transport.  They record which
candidate OIDs were examined and what the responder actually produced.

The behaviours under test:

* a sparse read-only view resolves the correct lexicographic successor;
* a single request's work is bounded by an explicit candidate budget shared
  by all varbinds and all GETBULK repetitions;
* exhausting the budget produces an explicit error (``resourceUnavailable``)
  rather than a fake ``endOfMibView``;
* backends that do not advance, or return values the requester cannot read,
  are stopped without leaking those values;
* a legal request that follows a limited one is still handled normally.
"""

import pytest

from pysnmp.entity import config, engine
from pysnmp.entity.observer import MetaObserver
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import rfc1905
from pysnmp.proto.api import v2c
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.smi import error as smi_error
from pysnmp.smi.budget import (
    DEFAULT_TRAVERSAL_CANDIDATE_LIMIT,
    TraversalBudget,
)
from pysnmp.smi.builder import MibBuilder
from pysnmp.smi.instrum import MibInstrumController

BASE = (1, 3, 6, 1, 4, 1, 99999, 42)
SCALAR = BASE + (1,)

# Scalars 1..120 all have a single instance .0.  Only these scalar subtree
# numbers are visible, forming several short intervals among long hidden runs.
VISIBLE_SCALARS = (10, 11, 12, 60, 61, 119)
TOTAL_SCALARS = 120


def _scalar_oid(number):
    return BASE + (number,)


def _instance_oid(number):
    return BASE + (number, 0)


def _build_builder():
    """Return a MibBuilder with TOTAL_SCALARS initialized scalar subtrees."""
    builder = MibBuilder()
    (
        MibIdentifier,
        MibScalar,
        MibScalarInstance,
        Integer32,
    ) = builder.import_symbols(
        "SNMPv2-SMI",
        "MibIdentifier",
        "MibScalar",
        "MibScalarInstance",
        "Integer32",
    )

    symbols = {"root": MibIdentifier(BASE)}
    for number in range(1, TOTAL_SCALARS + 1):
        scalar = MibScalar(_scalar_oid(number), Integer32())
        symbols[f"scalar{number}"] = scalar
        symbols[f"instance{number}"] = MibScalarInstance(
            scalar.name, (0,), Integer32(number)
        )

    builder.export_symbols("__TRAVERSAL-TEST-MIB", **symbols)

    return builder


class SparseAgent:
    """Engine + context + sparse VACM view, without any transport."""

    def __init__(self, visible=VISIBLE_SCALARS):
        self.visible = tuple(visible)
        self.snmp_engine = engine.SnmpEngine()
        self.builder = _build_builder()
        self.snmp_engine.message_dispatcher.mib_instrum_controller = (
            MibInstrumController(self.builder)
        )
        self.snmp_context = context.SnmpContext(self.snmp_engine)

        config.add_vacm_group(self.snmp_engine, "g", 2, OctetString("public"))
        config.add_vacm_access(self.snmp_engine, "g", b"", 2, 1, "exact", "v", "", "")
        config.add_context(self.snmp_engine, b"")

        for number in self.visible:
            config.add_vacm_view(
                self.snmp_engine,
                "v",
                "included",
                _scalar_oid(number),
                b"",
            )

        self.snmp_engine.observer = MetaObserver()
        self._store_request_context()

    def _store_request_context(self):
        request_pdu = rfc1905.GetNextRequestPDU()
        self.snmp_engine.observer.store_execution_context(
            self.snmp_engine,
            "rfc3412.receiveMessage:request",
            dict(
                securityModel=2,
                securityName=OctetString("public"),
                securityLevel=1,
                contextName=b"",
                pdu=request_pdu,
            ),
        )

    def responder(self, cls=cmdrsp.NextCommandResponder, **options):
        responder = cls(self.snmp_engine, self.snmp_context, **options)
        self._store_request_context()
        return responder

    def request(self, cls, starts, repetitions=0, non_repeaters=0):
        if cls is cmdrsp.NextCommandResponder:
            pdu = rfc1905.GetNextRequestPDU()
            v2c.apiPDU.set_defaults(pdu)
            v2c.apiPDU.set_varbinds(pdu, starts)
            return pdu

        pdu = rfc1905.GetBulkRequestPDU()
        v2c.apiBulkPDU.set_defaults(pdu)
        v2c.apiBulkPDU.set_non_repeaters(pdu, non_repeaters)
        v2c.apiBulkPDU.set_max_repetitions(pdu, repetitions)
        v2c.apiPDU.set_varbinds(pdu, starts)
        return pdu

    def run(self, responder, pdu):
        """Invoke a responder and return (status, index, varBinds)."""
        responses = []
        responder.send_pdu = (
            lambda snmpEngine, stateReference, responsePdu: responses.append(
                responsePdu
            )
        )

        responder.process_pdu(
            self.snmp_engine,
            1,
            2,
            OctetString("public"),
            1,
            self.snmp_context.contextEngineId,
            b"",
            1,
            pdu,
            65507,
            ("state-reference",),
        )

        assert responses, "responder produced no response"

        response = responses[-1]
        return (
            v2c.apiPDU.get_error_status(response),
            int(v2c.apiPDU.get_error_index(response, muteErrors=True)),
            v2c.apiPDU.get_varbinds(response),
        )


@pytest.fixture
def agent():
    return SparseAgent()


def _names(var_binds):
    return [tuple(name) for name, _ in var_binds]


def test_normal_next_skips_long_hidden_region(agent):
    """The exact next visible instance is returned with bounded work."""
    responder = agent.responder(traversal_candidate_limit=32)

    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(_instance_oid(1), None)]),
    )

    assert int(status) == 0
    assert index == 0
    assert _names(response) == [_instance_oid(10)]
    assert int(response[0][1]) == 10

    budget = responder.last_traversal_budget
    # One candidate per hidden scalar node (2..9), then scalar 10 and its
    # instance.  The starting instance is examined too.  Denied scalar nodes
    # short-circuit their instances, so the hidden run costs one each.
    assert budget.examined == 11
    assert budget.candidates == [
        _instance_oid(1),
        *[_scalar_oid(number) for number in range(2, 10)],
        _scalar_oid(10),
        _instance_oid(10),
    ]


def test_next_across_multiple_visible_intervals(agent):
    """Successive requests cross every visible interval in order."""
    responder = agent.responder(traversal_candidate_limit=256)

    cursor = _instance_oid(1)
    observed = []
    for _ in range(len(VISIBLE_SCALARS)):
        status, index, response = agent.run(
            responder,
            agent.request(cmdrsp.NextCommandResponder, [(cursor, None)]),
        )
        assert int(status) == 0
        assert index == 0
        name, value = response[0]
        observed.append((tuple(name), int(value)))
        cursor = tuple(name)

    assert observed == [(_instance_oid(number), number) for number in VISIBLE_SCALARS]


def test_budget_exhaustion_reports_resource_unavailable(agent):
    """An under-sized budget fails explicitly instead of faking endOfMibView."""
    responder = agent.responder(traversal_candidate_limit=10)

    start = _instance_oid(1)
    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(start, None)]),
    )

    assert int(status) == 13
    assert index == 1
    # The failed request's varbind is echoed; no traversal value leaks.
    assert _names(response) == [start]
    # The error response echoes the request value (Null), never a fabricated
    # successor or an endOfMibView marker.
    assert not isinstance(response[0][1], (v2c.Integer32, rfc1905.EndOfMibView))

    budget = responder.last_traversal_budget
    assert budget.limit == 10
    assert budget.examined == 10
    # The hidden run was actually visited up to the limit.
    assert _scalar_oid(9) in budget.candidates
    assert _instance_oid(10) not in budget.candidates


def test_budget_failure_then_next_legal_request_works(agent):
    """A rejected request must not poison the following normal request."""
    responder = agent.responder(traversal_candidate_limit=4)

    status, _, _ = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(_instance_oid(1), None)]),
    )
    assert int(status) == 13
    assert responder.last_traversal_budget.examined == 4

    # Same responder, next request: the budget is fresh, and this successor
    # is close enough to resolve within the same limit.
    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(_scalar_oid(9), None)]),
    )

    assert int(status) == 0
    assert index == 0
    assert _names(response) == [_instance_oid(10)]
    assert int(response[0][1]) == 10
    assert responder.last_traversal_budget.examined == 3


def test_budget_is_shared_by_all_bulk_repeaters(agent):
    """GETBULK repetitions and columns draw from one per-request budget."""
    responder = agent.responder(
        cmdrsp.BulkCommandResponder, traversal_candidate_limit=25
    )

    starts = [(_instance_oid(1), None), (_instance_oid(60), None)]
    status, index, response = agent.run(
        responder,
        agent.request(
            cmdrsp.BulkCommandResponder,
            starts,
            repetitions=4,
            non_repeaters=0,
        ),
    )

    assert int(status) == 13  # resourceUnavailable
    assert index >= 1
    assert _names(response) == [start for start, _ in starts]
    assert not any(isinstance(value, v2c.Integer32) for _, value in response)

    budget = responder.last_traversal_budget
    assert budget.examined == 25
    # Work from both columns is part of the shared accounting: column 0 got
    # through the first visible interval, column 1 entered the hidden run
    # after scalar 61.
    assert _instance_oid(1) in budget.candidates
    assert _instance_oid(10) in budget.candidates
    assert _instance_oid(60) in budget.candidates
    assert _instance_oid(61) in budget.candidates
    assert any(
        candidate == _scalar_oid(number)
        for candidate in budget.candidates
        for number in range(62, TOTAL_SCALARS + 1)
    )


def test_bulk_columns_end_independently(agent):
    """One column reaching endOfMibView does not end the other columns."""
    responder = agent.responder(cmdrsp.BulkCommandResponder)

    starts = [(_instance_oid(60), None), (_instance_oid(119), None)]
    status, index, response = agent.run(
        responder,
        agent.request(
            cmdrsp.BulkCommandResponder,
            starts,
            repetitions=3,
            non_repeaters=0,
        ),
    )

    assert int(status) == 0
    assert index == 0
    assert _names(response) == [
        _instance_oid(61),  # column 0 advances
        _instance_oid(119),  # column 1 has no successor: original name, EOM
        _instance_oid(119),  # column 0 crosses the hidden run
        _instance_oid(119),  # column 1 stays at its last name, EOM
        _instance_oid(119),  # column 0 ends
        _instance_oid(119),  # column 1 stays at its last name, EOM
    ]

    has_value = [isinstance(value, v2c.Integer32) for _, value in response]
    assert has_value == [True, False, True, False, False, False]


def test_instrumentation_level_candidate_accounting():
    """The instrumentation counts distinct candidates per operation."""
    builder = _build_builder()
    controller = MibInstrumController(builder)

    def access(view_type, var_bind, **kwargs):
        # Deny every scalar subtree except the visible intervals.  Both the
        # scalar node (BASE + (n,)) and its instance (BASE + (n, 0)) carry
        # the scalar number right after BASE.
        oid = tuple(var_bind[0])
        return oid[len(BASE)] not in VISIBLE_SCALARS

    budget = TraversalBudget(limit=None)
    result = controller.read_next_variables(
        (_instance_oid(1), None),
        acFun=access,
        traversal_budget=budget,
    )

    assert result[0][0] == _instance_oid(10)
    assert int(result[0][1]) == 10
    # Two-phase Test/Get of the same candidate consumes one unit.
    assert budget.examined == len(budget.candidates)
    assert budget.examined == 11
    assert budget.candidates[:4] == [
        _instance_oid(1),
        _scalar_oid(2),
        _scalar_oid(3),
        _scalar_oid(4),
    ]

    # A fresh operation re-counts candidates it needs to re-examine.
    previous = budget.examined
    result = controller.read_next_variables(
        (_instance_oid(10), None),
        acFun=access,
        traversal_budget=budget,
    )
    assert result[0][0] == _instance_oid(11)
    assert budget.examined == previous + 3


class _StuckBackend:
    """Backend that always returns the same OID with the same value."""

    def __init__(self):
        self.calls = 0

    def read_next_variables(self, *var_binds, **kwargs):
        self.calls += 1
        if self.calls > 1000:
            raise AssertionError("traversal did not stop")
        return [(tuple(var_binds[0][0]), v2c.Integer32(7))] * len(var_binds)


def test_non_advancing_backend_stops(agent):
    """A backend that never advances produces an explicit failure."""
    stuck = _StuckBackend()
    agent.snmp_context.context_names[b""] = stuck

    responder = agent.responder(traversal_candidate_limit=16)
    start = _instance_oid(1)
    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(start, None)]),
    )

    assert int(status) == 5
    assert index == 1
    # The backend was consulted once, not spun in a loop.
    assert stuck.calls == 1
    # The repeated value is not returned.
    assert _names(response) == [start]
    assert not isinstance(response[0][1], (v2c.Integer32, rfc1905.EndOfMibView))


def test_instrumentation_exception_value_is_rejected(agent):
    """A backend answering with noSuchInstance is refused, not relayed."""
    hidden = _scalar_oid(20)

    class NoSuchBackend:
        def read_next_variables(self, *var_binds, **kwargs):
            return [(hidden, rfc1905.noSuchInstance)] * len(var_binds)

    agent.snmp_context.context_names[b""] = NoSuchBackend()

    responder = agent.responder()
    start = _instance_oid(1)
    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(start, None)]),
    )

    assert int(status) == 5
    assert index == 1
    assert _names(response) == [start]
    assert not isinstance(response[0][1], type(rfc1905.noSuchInstance))


def test_unauthorized_candidate_value_not_returned(agent):
    """A value for a denied candidate never reaches the response."""
    denied = _instance_oid(20)

    class SneakyBackend:
        def read_next_variables(self, *var_binds, **kwargs):
            return [(denied, v2c.Integer32(20))] * len(var_binds)

    agent.snmp_context.context_names[b""] = SneakyBackend()

    responder = agent.responder()
    start = _instance_oid(1)
    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(start, None)]),
    )

    assert int(status) == 16
    assert index == 1
    assert _names(response) == [start]
    # Neither the denied OID nor its value survives into the response.
    assert not any(name == denied for name in _names(response))
    assert not isinstance(response[0][1], v2c.Integer32)


def test_traversal_budget_primitive():
    assert DEFAULT_TRAVERSAL_CANDIDATE_LIMIT > 0

    budget = TraversalBudget()
    assert budget.limit == DEFAULT_TRAVERSAL_CANDIDATE_LIMIT
    assert budget.examined == 0

    assert budget.consume((1, 3, 6), idx=0) is True
    assert budget.examined == 1
    assert budget.candidates == [(1, 3, 6)]

    # Re-examining the same candidate inside one operation is not re-counted.
    assert budget.consume((1, 3, 6), idx=0) is False
    assert budget.examined == 1

    budget.start_operation()
    assert budget.consume((1, 3, 6), idx=0) is True
    assert budget.examined == 2

    with pytest.raises(smi_error.TraversalBudgetExceededError):
        TraversalBudget(0).consume((0,))

    budget = TraversalBudget(1)
    budget.consume((0,))
    assert budget.exhausted
    with pytest.raises(smi_error.TraversalBudgetExceededError):
        budget.consume((1,))

    with pytest.raises(ValueError):
        TraversalBudget(-1)


def test_unlimited_budget_reaches_end_of_mib(agent):
    """With no budget, the walk still terminates at endOfMibView correctly."""
    responder = agent.responder(traversal_candidate_limit=None)
    start = _instance_oid(119)
    status, index, response = agent.run(
        responder,
        agent.request(cmdrsp.NextCommandResponder, [(start, None)]),
    )

    assert int(status) == 0
    assert index == 0
    assert _names(response) == [start]
    assert isinstance(response[0][1], rfc1905.EndOfMibView)
