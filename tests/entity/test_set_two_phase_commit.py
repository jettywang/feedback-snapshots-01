"""Regression tests for multi-varbind SET: authorization, commit and rollback.

RFC 3416 section 4.2.5 defines SET as a two-phase operation. Phase one
validates every varbind, including the write view check. Phase two commits
all variables and, if any commit fails, undoes all assignments. If undoing
is impossible the response must be ``undoFailed`` with a zero
``errorIndex``; it must never be ``commitFailed`` and never success while a
rollback error was swallowed.

These tests drive a real ``SnmpEngine`` message dispatcher end to end: an
encoded SNMPv2c SET goes in and an encoded Response-PDU comes out. The MIB
under test is a trio of scalar instances that log every
``writeTest``/``writeCommit``/``writeUndo``/``writeCleanup`` call, so each
wire response is checked against the actual managed values and the actual
phase sequence.
"""

from pyasn1.codec.ber import encoder, decoder

import pytest

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp
from pysnmp.entity.rfc3413 import context as rfc3413_context
from pysnmp.proto.api import v2c
from pysnmp.smi import error as smi_error
from pysnmp.smi.builder import MibBuilder
from pysnmp.smi.instrum import MibInstrumController


BASE = (1, 3, 6, 1, 4, 1, 99999, 1)
TRANSPORT_DOMAIN = udp.SNMP_UDP_DOMAIN
TRANSPORT_ADDRESS = ("127.0.0.1", 161)


class _CaptureDispatcher:
    """Transport dispatcher double that records outgoing messages.

    Responses are delivered in-process: the tests never open a UDP socket,
    which keeps them usable in restricted CI sandboxes.
    """

    def __init__(self):
        self.messages = []

    def send_message(self, outgoing_message, transport_domain, transport_address):
        self.messages.append(outgoing_message)

    def get_timer_resolution(self):
        return 1

    def get_timer_ticks(self):
        return 0

    def __getattr__(self, attr):
        if attr.startswith("__"):
            raise AttributeError(attr)
        return lambda *args, **kwargs: None


def _install_scalars(mib_builder, module_name, log, instances=None):
    """(Re)register the three scalar columns and fresh recording instances.

    ``instances`` is reused when the caller wants to replace the instances
    of an already-indexed MIB (it keeps the same class and module name, so
    the instrumentation rebuilds its tree from the new objects).
    """
    (MibScalar, MibScalarInstance, Integer32) = mib_builder.import_symbols(
        "SNMPv2-SMI", "MibScalar", "MibScalarInstance", "Integer32"
    )

    class _RecordingInstance(MibScalarInstance):
        # column (1..3) -> {"commit": bool, "undo": bool}
        faults = {}
        # column (1..3) -> callable run inside writeTest before the real test
        test_hooks = {}

        def _column(self):
            return self.name[8]

        def writeTest(self, var_bind, **context):  # noqa: N802
            column = self._column()
            log.append(("test", column))
            hook = self.test_hooks.get(column)
            if hook is not None:
                hook()
            return super().writeTest(var_bind, **context)

        def writeCommit(self, var_bind, **context):  # noqa: N802
            column = self._column()
            log.append(("commit", column))
            result = super().writeCommit(var_bind, **context)
            if self.faults.get(column, {}).get("commit"):
                raise smi_error.CommitFailedError(
                    name=self.name, idx=context.get("idx")
                )
            return result

        def writeUndo(self, var_bind, **context):  # noqa: N802
            column = self._column()
            log.append(("undo", column))
            if self.faults.get(column, {}).get("undo"):
                raise smi_error.UndoFailedError(name=self.name, idx=context.get("idx"))
            return super().writeUndo(var_bind, **context)

        def writeCleanup(self, var_bind, **context):  # noqa: N802
            log.append(("cleanup", self._column()))
            return super().writeCleanup(var_bind, **context)

    symbols = {}
    created = {}
    for column in (1, 2, 3):
        symbols[f"scalar{column}"] = MibScalar(
            BASE + (column,), Integer32()
        ).set_max_access("read-write")
        instance = _RecordingInstance(BASE + (column,), (0,), Integer32(100 + column))
        created[column] = instance
        symbols[f"scalar{column}Instance"] = instance

    mib_builder.export_symbols(module_name, **symbols)
    return created


def _install_into_controller(controller, module_name, log):
    return _install_scalars(controller.get_mib_builder(), module_name, log)


class _Response:
    def __init__(self, request_id, error_status, error_index, var_binds):
        self.request_id = request_id
        self.error_status = error_status
        self.error_index = error_index
        self.var_binds = var_binds

    def __repr__(self):
        return (
            "_Response(request_id={!r}, error_status={!r}, "
            "error_index={!r}, var_binds={!r})"
        ).format(
            self.request_id, self.error_status, self.error_index, self.var_binds
        )


class _DeferredAuthorizationSetResponder(cmdrsp.SetCommandResponder):
    """Deliberately broken responder: authorization runs after the commit.

    Used as a control to prove the test would notice real unauthorized side
    effects. It performs the two-phase write without ``acFun`` (so phase one
    never checks the view) and only then applies the VACM decision. The
    response still says ``noAccess`` even though the MIB has already been
    modified.
    """

    def handle_management_operation(
        self, snmpEngine, stateReference, contextName, PDU
    ):
        mgmtFun = self.snmpContext.get_mib_instrum(contextName).write_variables
        varBinds = v2c.apiPDU.get_varbinds(PDU)
        context = dict(snmpEngine=snmpEngine, cbCtx=self.cbCtx)

        try:
            self.snmpContext.get_mib_instrum(contextName).write_variables(
                *varBinds, **context
            )
        except smi_error.SmiError:
            pass

        for idx, (name, val) in enumerate(varBinds):
            try:
                denied = self.verify_access(
                    "write", (name, val), snmpEngine=snmpEngine, idx=idx
                )
            except smi_error.SmiError:
                denied = True
            if denied:
                raise smi_error.NoAccessError(name=name, idx=idx)

        self.send_varbinds(snmpEngine, stateReference, 0, 0, varBinds)
        self.release_state_information(stateReference)


class _Agent:
    """In-process SNMPv2c agent with one or two contexts."""

    def __init__(
        self,
        write_excluded=None,
        read_excluded=None,
        second_context=False,
        second_write_excluded=None,
    ):
        self.engine = engine.SnmpEngine()
        self.dispatcher = _CaptureDispatcher()
        self.engine.transport_dispatcher = self.dispatcher
        self.log = []
        self.second_log = []

        config.add_v1_system(self.engine, "public", "public")
        config.add_context(self.engine, b"")
        config.add_vacm_group(self.engine, "group-a", 2, "public")
        config.add_vacm_access(
            self.engine, "group-a", b"", 2, 1, "exact", "read-a", "write-a", ""
        )
        config.add_vacm_view(self.engine, "read-a", "included", BASE, b"")
        config.add_vacm_view(self.engine, "write-a", "included", BASE, b"")
        if write_excluded is not None:
            config.add_vacm_view(
                self.engine, "write-a", "excluded", write_excluded, b""
            )
        if read_excluded is not None:
            config.add_vacm_view(self.engine, "read-a", "excluded", read_excluded, b"")

        self.context = rfc3413_context.SnmpContext(self.engine)
        self.instances = _install_into_controller(
            self.context.get_mib_instrum(), "__SET-FAULT-A", self.log
        )
        self.second_instances = None

        if second_context:
            config.add_v1_system(
                self.engine, "public-b", "public-b", contextName=b"ctx-b"
            )
            config.add_context(self.engine, b"ctx-b")
            config.add_vacm_group(self.engine, "group-b", 2, "public-b")
            config.add_vacm_access(
                self.engine, "group-b", b"ctx-b", 2, 1, "exact", "read-b", "write-b", ""
            )
            config.add_vacm_view(self.engine, "read-b", "included", BASE, b"")
            config.add_vacm_view(self.engine, "write-b", "included", BASE, b"")
            if second_write_excluded is not None:
                config.add_vacm_view(
                    self.engine, "write-b", "excluded", second_write_excluded, b""
                )

            second_builder = MibBuilder()
            self.second_instances = _install_scalars(
                second_builder, "__SET-FAULT-B", self.second_log
            )
            self.context.register_context_name(
                b"ctx-b", MibInstrumController(second_builder)
            )

        cmdrsp.GetCommandResponder(self.engine, self.context)
        self.set_responder = cmdrsp.SetCommandResponder(self.engine, self.context)

    def use_deferred_authorization(self):
        """Swap in a responder that checks the view only after committing."""
        self.set_responder.close(self.engine)
        self.set_responder = _DeferredAuthorizationSetResponder(
            self.engine, self.context
        )

    def values(self, instances=None):
        chosen = self.instances if instances is None else instances
        return {column: int(instance.syntax) for column, instance in chosen.items()}

    def fault(self, column, phase, instances=None):
        chosen = self.instances if instances is None else instances
        chosen[column].faults.setdefault(column, {})[phase] = True

    def hook(self, column, callback, instances=None):
        chosen = self.instances if instances is None else instances
        chosen[column].test_hooks[column] = callback

    def phases(self, log=None):
        chosen = self.log if log is None else log
        return [phase for phase, _column in chosen]

    def send(
        self,
        var_binds,
        community="public",
        request_id=9000,
        transport_address=TRANSPORT_ADDRESS,
    ):
        self.dispatcher.messages.clear()

        pdu = v2c.SetRequestPDU()
        v2c.apiPDU.set_defaults(pdu)
        v2c.apiPDU.set_request_id(pdu, request_id)
        v2c.apiPDU.set_varbinds(pdu, var_binds)

        message = v2c.Message()
        v2c.apiMessage.set_defaults(message)
        v2c.apiMessage.set_community(message, community)
        v2c.apiMessage.set_pdu(message, pdu)

        self.engine.message_dispatcher.receive_message(
            self.engine,
            TRANSPORT_DOMAIN,
            transport_address,
            encoder.encode(message),
        )

        assert len(self.dispatcher.messages) >= 1, "no Response-PDU produced"

        # The last message is the response to this request (re-entrant tests
        # may also have produced a nested response before it).
        response, _ = decoder.decode(
            self.dispatcher.messages[-1], asn1Spec=v2c.Message()
        )
        response_pdu = v2c.apiMessage.get_pdu(response)

        return _Response(
            request_id=int(v2c.apiPDU.get_request_id(response_pdu)),
            error_status=str(v2c.apiPDU.get_error_status(response_pdu)),
            error_index=int(v2c.apiPDU.get_error_index(response_pdu)),
            var_binds=[
                (tuple(oid), value.prettyPrint())
                for oid, value in v2c.apiPDU.get_varbinds(response_pdu)
            ],
        )


def _set_three(values):
    return [
        (BASE + (column, 0), v2c.Integer32(value))
        for column, value in enumerate(values, start=1)
    ]


def _assert_untouched(agent):
    assert agent.values() == {1: 101, 2: 102, 3: 103}


# ---------------------------------------------------------------------------
# Fault position to wire response and final state
# ---------------------------------------------------------------------------

# Each row is a fault injected into a three-varbind SET of 11/12/13 against
# initial values 101/102/103, the response the agent must emit, and the final
# managed values. Keeping this as a table makes the coupling between a phase,
# the reported error and the observable state explicit.

TABLE = [
    (
        "clean",
        {},
        ("noError", 0),
        {1: 11, 2: 12, 3: 13},
    ),
    (
        "vacm-denied-1",
        {"write_excluded": BASE + (1,)},
        ("noAccess", 1),
        {1: 101, 2: 102, 3: 103},
    ),
    (
        "vacm-denied-2",
        {"write_excluded": BASE + (2,)},
        ("noAccess", 2),
        {1: 101, 2: 102, 3: 103},
    ),
    (
        "vacm-denied-3",
        {"write_excluded": BASE + (3,)},
        ("noAccess", 3),
        {1: 101, 2: 102, 3: 103},
    ),
    (
        "commit-fails-1",
        {"fault": (1, "commit")},
        ("commitFailed", 1),
        {1: 101, 2: 102, 3: 103},
    ),
    (
        "commit-fails-2",
        {"fault": (2, "commit")},
        ("commitFailed", 2),
        {1: 101, 2: 102, 3: 103},
    ),
    (
        "commit-fails-3",
        {"fault": (3, "commit")},
        ("commitFailed", 3),
        {1: 101, 2: 102, 3: 103},
    ),
    (
        "commit-2-undo-1",
        {"faults": [(2, "commit"), (1, "undo")]},
        ("undoFailed", 0),
        {1: 11, 2: 102, 3: 103},
    ),
    (
        "commit-3-undo-2",
        {"faults": [(3, "commit"), (2, "undo")]},
        ("undoFailed", 0),
        {1: 101, 2: 12, 3: 103},
    ),
]


@pytest.mark.parametrize(
    "name,spec,expected_response,expected_state",
    TABLE,
    ids=[row[0] for row in TABLE],
)
def test_fault_matrix(name, spec, expected_response, expected_state):
    """Every fault position maps to one consistent response and final state."""
    agent = _Agent(
        write_excluded=spec.get("write_excluded"),
    )
    if "fault" in spec:
        agent.fault(*spec["fault"])
    for fault in spec.get("faults", []):
        agent.fault(*fault)

    response = agent.send(_set_three([11, 12, 13]))

    assert (response.error_status, response.error_index) == expected_response
    assert agent.values() == expected_state

    if expected_response[0] in ("noAccess",):
        # Phase one rejected the request: nothing may be committed.
        assert "commit" not in agent.phases()
    if expected_response[0] == "noError":
        assert agent.phases()[-3:] == ["cleanup", "cleanup", "cleanup"]


# ---------------------------------------------------------------------------
# Authorization phase
# ---------------------------------------------------------------------------


def test_vacm_denied_middle_var_bind_stops_phase_one():
    """A denial on varbind 2 reports noAccess/2 and commits nothing."""
    agent = _Agent(write_excluded=BASE + (2,))

    response = agent.send(_set_three([11, 12, 13]))

    assert response.error_status == "noAccess"
    assert response.error_index == 2
    _assert_untouched(agent)
    assert agent.log == [("test", 1), ("cleanup", 1), ("cleanup", 2), ("cleanup", 3)]


def test_vacm_denied_first_var_bind_stops_before_testing():
    """The very first varbind can be denied; later ones are never tested."""
    agent = _Agent(write_excluded=BASE + (1,))

    response = agent.send(_set_three([11, 12, 13]))

    assert (response.error_status, response.error_index) == ("noAccess", 1)
    _assert_untouched(agent)
    assert ("test", 2) not in agent.log
    assert ("test", 3) not in agent.log


def test_vacm_write_view_is_independent_of_read_view():
    """Only the write view governs SET; a narrower read view is irrelevant."""
    agent = _Agent(read_excluded=BASE + (2,))

    response = agent.send(_set_three([11, 12, 13]))

    assert response.error_status == "noError"
    assert agent.values() == {1: 11, 2: 12, 3: 13}


# ---------------------------------------------------------------------------
# Type validation
# ---------------------------------------------------------------------------


def test_type_error_middle_var_bind_reports_wrong_type():
    """An ASN.1 type inconsistent with the column is wrongType at its index."""
    agent = _Agent()

    response = agent.send(
        [
            (BASE + (1, 0), v2c.Integer32(21)),
            (BASE + (2, 0), v2c.OctetString("not-an-integer")),
            (BASE + (3, 0), v2c.Integer32(23)),
        ]
    )

    assert response.error_status == "wrongType"
    assert response.error_index == 2
    _assert_untouched(agent)
    assert "commit" not in agent.phases()


# ---------------------------------------------------------------------------
# Commit failure with complete rollback
# ---------------------------------------------------------------------------


def test_commit_failure_middle_rolls_back_committed_prefix():
    """commitFailed/2 must leave every value at its pre-SET snapshot."""
    agent = _Agent()
    agent.fault(2, "commit")

    response = agent.send(_set_three([31, 32, 33]))

    assert response.error_status == "commitFailed"
    assert response.error_index == 2
    _assert_untouched(agent)
    assert agent.phases()[-3:] == ["undo", "undo", "undo"]
    assert "cleanup" not in agent.phases()


# ---------------------------------------------------------------------------
# Undo failure must be reported, never swallowed
# ---------------------------------------------------------------------------


def test_undo_failure_reports_undo_failed_with_zero_index():
    """A failed rollback is undoFailed/0, not commitFailed or success."""
    agent = _Agent()
    agent.fault(2, "commit")
    agent.fault(1, "undo")

    response = agent.send(_set_three([41, 42, 43]))

    assert response.error_status == "undoFailed"
    assert response.error_index == 0
    # Varbind 1 could not be restored; that partial write is the evidence.
    assert agent.values() == {1: 41, 2: 102, 3: 103}


def test_undo_failure_keeps_best_effort_rollback_of_remaining_var_binds():
    """A failed undo on varbind 2 must not skip undoing varbind 3."""
    agent = _Agent()
    agent.fault(3, "commit")
    agent.fault(2, "undo")

    response = agent.send(_set_three([51, 52, 53]))

    assert (response.error_status, response.error_index) == ("undoFailed", 0)
    # 1 and 3 were committed and successfully undone; only 2 stays new.
    assert agent.values() == {1: 101, 2: 52, 3: 103}
    assert agent.phases().count("undo") == 3


def test_no_success_status_while_a_rollback_error_exists():
    """The response can not be noError when any undo raised."""
    agent = _Agent()
    agent.fault(2, "commit")
    agent.fault(2, "undo")

    response = agent.send(_set_three([61, 62, 63]))

    assert response.error_status != "noError"
    assert response.error_status == "undoFailed"
    assert response.error_index == 0
    assert agent.values() == {1: 101, 2: 62, 3: 103}


def test_clean_set_commits_and_cleans_up_every_var_bind():
    """Baseline: all three varbinds commit, then cleanup, in order."""
    agent = _Agent()

    response = agent.send(_set_three([71, 72, 73]))

    assert (response.error_status, response.error_index) == ("noError", 0)
    assert agent.values() == {1: 71, 2: 72, 3: 73}
    assert agent.log == [
        ("test", 1),
        ("test", 2),
        ("test", 3),
        ("commit", 1),
        ("commit", 2),
        ("commit", 3),
        ("cleanup", 1),
        ("cleanup", 2),
        ("cleanup", 3),
    ]
    assert response.var_binds == [
        (BASE + (1, 0), "71"),
        (BASE + (2, 0), "72"),
        (BASE + (3, 0), "73"),
    ]


def test_response_echoes_request_id_and_var_binds():
    """The Response-PDU must keep the request-id and return all name/value pairs."""
    agent = _Agent()

    response = agent.send(_set_three([81, 82, 83]), request_id=4242)

    assert response.request_id == 4242
    assert [oid for oid, _value in response.var_binds] == [
        BASE + (1, 0),
        BASE + (2, 0),
        BASE + (3, 0),
    ]
    assert [value for _oid, value in response.var_binds] == ["81", "82", "83"]


# ---------------------------------------------------------------------------
# Two contexts: access basis and uncommitted values must not leak
# ---------------------------------------------------------------------------


def test_second_context_uses_its_own_access_and_values():
    """A SET in the default context must not touch the other context's MIB.

    Both contexts expose the same OIDs but own separate instrumentation and
    separate VACM entries. Writing through ``public`` must not change what
    ``public-b`` sees, and the reverse.
    """
    agent = _Agent(second_context=True)

    first = agent.send(_set_three([11, 12, 13]), community="public")
    second = agent.send(_set_three([21, 22, 23]), community="public-b")

    assert first.error_status == "noError"
    assert second.error_status == "noError"
    assert agent.values() == {1: 11, 2: 12, 3: 13}
    assert agent.values(agent.second_instances) == {1: 21, 2: 22, 3: 23}
    assert all(column in (1, 2, 3) for _phase, column in agent.second_log)


def test_denial_in_one_context_does_not_leak_into_the_other():
    """VACM for context B must not be applied to context A or vice versa."""
    agent = _Agent(second_context=True, second_write_excluded=BASE + (2,))

    allowed = agent.send(_set_three([31, 32, 33]), community="public")
    denied = agent.send(_set_three([41, 42, 43]), community="public-b")

    assert allowed.error_status == "noError"
    assert agent.values() == {1: 31, 2: 32, 3: 33}

    assert (denied.error_status, denied.error_index) == ("noAccess", 2)
    # The denied request must not have staged or committed anything in B.
    assert agent.values(agent.second_instances) == {1: 101, 2: 102, 3: 103}
    assert ("commit", 1) not in agent.second_log


def test_uncommitted_values_are_invisible_to_the_other_context():
    """While context A's SET is staged, context B must still read old values."""
    agent = _Agent(second_context=True)
    observed = []

    def nested_request():
        # Runs inside A's writeTest, after A saw the first new value but
        # before any commit. B must not observe A's pending assignment.
        observed.append(dict(agent.values(agent.second_instances)))
        response = agent.send(
            _set_three([51, 52, 53]), community="public-b", request_id=5555
        )
        observed.append(response.error_status)

    agent.hook(1, nested_request)

    outer = agent.send(_set_three([61, 62, 63]), community="public", request_id=6666)

    # Both requests complete, each attributed to its own context.
    assert outer.error_status == "noError"
    assert observed[-1] == "noError"
    assert observed[0] == {1: 101, 2: 102, 3: 103}
    assert agent.values(agent.second_instances) == {1: 51, 2: 52, 3: 53}
    assert agent.values() == {1: 61, 2: 62, 3: 63}


# ---------------------------------------------------------------------------
# Delayed authorization must be detected as an unauthorized side effect
# ---------------------------------------------------------------------------


def test_delayed_authorization_is_caught_as_an_unauthorized_side_effect():
    """An agent that authorizes after commit must be caught, not trusted.

    The control responder below performs the two-phase write without the
    write-view check and applies VACM afterwards. It still reports
    ``noAccess``, but the MIB has already changed. Running the same
    assertions against it must expose the unauthorized side effect; the real
    responder must not produce one.

    This is what makes the regression meaningful: a test that only looked at
    ``errorStatus`` would pass for both agents.
    """
    agent = _Agent(write_excluded=BASE + (2,))

    # Correct responder: phase one denies, nothing changes.
    honest = agent.send(_set_three([11, 12, 13]))
    assert (honest.error_status, honest.error_index) == ("noAccess", 2)
    _assert_untouched(agent)

    # Broken responder: same wire status, but the writes already happened.
    agent.use_deferred_authorization()
    delayed = agent.send(_set_three([21, 22, 23]))
    assert (delayed.error_status, delayed.error_index) == ("noAccess", 2)
    assert agent.values() != {1: 101, 2: 102, 3: 103}, (
        "the delayed-authorization responder was expected to leave an "
        "unauthorized side effect; if it did not, this control is broken"
    )


def test_delayed_authorization_control_does_not_mask_a_real_regression():
    """The honest responder must never leave the side effect the control does."""
    agent = _Agent(write_excluded=BASE + (2,))

    response = agent.send(_set_three([31, 32, 33]))

    assert response.error_status == "noAccess"
    _assert_untouched(agent)
    assert "commit" not in agent.phases()


def test_authorization_check_precedes_every_commit():
    """The phase log must show all writeTest calls before any writeCommit."""
    agent = _Agent(write_excluded=BASE + (3,))

    agent.send(_set_three([11, 12, 13]))

    phases = agent.phases()
    if "commit" in phases:
        first_commit = phases.index("commit")
        assert "test" not in phases[first_commit:], (
            "authorization/validation must finish before commit begins"
        )
    else:
        assert phases.count("test") < 3


def test_authorization_is_not_rechecked_from_another_context():
    """A nested request must not change the outer request's access basis.

    The observer execution context is per request; a re-entrant SET in
    context B must restore A's securityName/contextName on return. If it did
    not, A's remaining varbinds would be authorized against B's identity.
    """
    agent = _Agent(second_context=True, write_excluded=BASE + (3,))

    def nested_request():
        agent.send(_set_three([91, 92, 93]), community="public-b", request_id=7777)

    agent.hook(1, nested_request)

    response = agent.send(_set_three([81, 82, 83]), community="public", request_id=8888)

    # A must still be denied on its own varbind 3, not B's view.
    assert (response.error_status, response.error_index) == ("noAccess", 3)
    assert agent.values() == {1: 101, 2: 102, 3: 103}
    assert agent.values(agent.second_instances) == {1: 91, 2: 92, 3: 93}
