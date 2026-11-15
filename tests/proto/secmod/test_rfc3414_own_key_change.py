"""
Tests for RFC 3414 own key change (usmUserOwnAuthKeyChange/usmUserOwnPrivKeyChange).

Covers:
  - localkey.produce_key_change/resolve_key_change: known-answer vectors for the
    SHA-256 auth + AES-128 priv combination and round-trip properties.
  - MIB instrumentation: own-user/USM enforcement, one-way transform commit into
    the LCD, two-phase commit rollback, empty-string reads.
"""

from hashlib import sha256

import pytest

from pysnmp.entity import config, engine
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.smi import error as smi_error


# ---------------------------------------------------------------------------
# KeyChange algorithm (RFC 3414 A.5 / KeyChange TC)
# ---------------------------------------------------------------------------


class TestKeyChangeAlgorithm:
    # SHA-256 localized auth key is 32 octets, so the KeyChange value is
    # 32 octets of randomness followed by 32 octets of delta
    OLD_AUTH_KEY = bytes(range(0x00, 0x20))
    NEW_AUTH_KEY = bytes(range(0x20, 0x40))
    AUTH_RANDOM = bytes(range(0x40, 0x60))
    AUTH_KEY_CHANGE = AUTH_RANDOM + bytes.fromhex(
        "d85dc9c669413ad51a1f7d778b15333b326f8ad83217098101c887f531feda9b"
    )

    # AES-128 localized priv key is 16 octets, hashed with SHA-256
    OLD_PRIV_KEY = bytes(range(0x00, 0x10))
    NEW_PRIV_KEY = bytes(range(0x10, 0x20))
    PRIV_RANDOM = bytes(range(0x64, 0x74))
    PRIV_KEY_CHANGE = PRIV_RANDOM + bytes.fromhex("c69f1208b84339992c94b53e6b792c40")

    def test_produce_auth_key_change_known_vector(self):
        kc = localkey.produce_key_change(
            self.OLD_AUTH_KEY, self.NEW_AUTH_KEY, sha256, rand=self.AUTH_RANDOM
        )
        assert kc.asOctets() == self.AUTH_KEY_CHANGE

    def test_resolve_auth_key_change_known_vector(self):
        new_key = localkey.resolve_key_change(
            self.OLD_AUTH_KEY, self.AUTH_KEY_CHANGE, sha256
        )
        assert new_key.asOctets() == self.NEW_AUTH_KEY

    def test_produce_priv_key_change_known_vector(self):
        kc = localkey.produce_key_change(
            self.OLD_PRIV_KEY, self.NEW_PRIV_KEY, sha256, rand=self.PRIV_RANDOM
        )
        assert kc.asOctets() == self.PRIV_KEY_CHANGE

    def test_resolve_priv_key_change_known_vector(self):
        new_key = localkey.resolve_key_change(
            self.OLD_PRIV_KEY, self.PRIV_KEY_CHANGE, sha256
        )
        assert new_key.asOctets() == self.NEW_PRIV_KEY

    def test_round_trip_with_generated_randomness(self):
        kc = localkey.produce_key_change(self.OLD_AUTH_KEY, self.NEW_AUTH_KEY, sha256)
        assert len(kc) == 2 * len(self.OLD_AUTH_KEY)
        # the new key must not appear in the KeyChange value
        assert bytes(self.NEW_AUTH_KEY) not in kc.asOctets()
        resolved = localkey.resolve_key_change(self.OLD_AUTH_KEY, kc, sha256)
        assert resolved.asOctets() == self.NEW_AUTH_KEY

    def test_resolve_with_wrong_old_key_yields_different_key(self):
        kc = localkey.produce_key_change(self.OLD_AUTH_KEY, self.NEW_AUTH_KEY, sha256)
        other_old_key = bytes(b ^ 0xFF for b in self.OLD_AUTH_KEY)
        resolved = localkey.resolve_key_change(other_old_key, kc, sha256)
        assert resolved.asOctets() != self.NEW_AUTH_KEY


# ---------------------------------------------------------------------------
# MIB instrumentation
# ---------------------------------------------------------------------------

USER_NAME = "usr-sha256-aes"
OTHER_USER_NAME = "usr-other"
OLD_AUTH_PASSPHRASE = b"authpassword"
NEW_AUTH_PASSPHRASE = b"newauthpassword"
OLD_PRIV_PASSPHRASE = b"privpassword"
NEW_PRIV_PASSPHRASE = b"newprivpassword"


def _localize(passphrase, engineId, length=None):
    master_key = localkey.hash_passphrase(passphrase, sha256)
    local_key = localkey.localize_key(master_key, engineId, sha256)
    if length is not None:
        local_key = local_key[:length]
    return local_key


def _make_engine():
    snmpEngine = engine.SnmpEngine()
    config.add_v3_user(
        snmpEngine,
        userName=USER_NAME,
        authKey=OLD_AUTH_PASSPHRASE,
        authProtocol=config.USM_AUTH_HMAC192_SHA256,
        privKey=OLD_PRIV_PASSPHRASE,
        privProtocol=config.USM_PRIV_CFB128_AES,
    )
    config.add_v3_user(
        snmpEngine,
        userName=OTHER_USER_NAME,
        authKey=OLD_AUTH_PASSPHRASE,
        authProtocol=config.USM_AUTH_HMAC192_SHA256,
        privKey=OLD_PRIV_PASSPHRASE,
        privProtocol=config.USM_PRIV_CFB128_AES,
    )
    # load the instrumented own-key-change columns
    snmpEngine.get_mib_builder().import_symbols(
        "__SNMP-USER-BASED-SM-MIB", "usmUserSpinLock"
    )
    return snmpEngine


def _store_request_context(snmpEngine, securityName, securityModel=3):
    snmpEngine.observer.store_execution_context(
        snmpEngine,
        "rfc3412.receiveMessage:request",
        dict(
            securityModel=securityModel,
            securityName=OctetString(securityName),
            securityLevel=3,
        ),
    )


def _clear_request_context(snmpEngine):
    snmpEngine.observer.clear_execution_context(
        snmpEngine, "rfc3412.receiveMessage:request"
    )


class _OwnKeyChangeFixture:
    def __init__(self):
        self.snmpEngine = _make_engine()
        mibBuilder = self.snmpEngine.get_mib_builder()
        (self.usmUserEntry,) = mibBuilder.import_symbols(
            "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
        )
        (snmpEngineID,) = mibBuilder.import_symbols(
            "__SNMP-FRAMEWORK-MIB", "snmpEngineID"
        )
        self.engineId = snmpEngineID.syntax
        self.tblIdx = self.usmUserEntry.getInstIdFromIndices(self.engineId, USER_NAME)
        self.otherTblIdx = self.usmUserEntry.getInstIdFromIndices(
            self.engineId, OTHER_USER_NAME
        )
        (self.authColumn,) = mibBuilder.import_symbols(
            "SNMP-USER-BASED-SM-MIB", "usmUserOwnAuthKeyChange"
        )
        (self.privColumn,) = mibBuilder.import_symbols(
            "SNMP-USER-BASED-SM-MIB", "usmUserOwnPrivKeyChange"
        )
        (self.keyEntry,) = mibBuilder.import_symbols(
            "PYSNMP-USM-MIB", "pysnmpUsmKeyEntry"
        )

    def lcd_auth_key(self, tblIdx=None):
        node = self.keyEntry.getNode(
            self.keyEntry.name + (1,) + (tblIdx or self.tblIdx)
        )
        return node.syntax.asOctets()

    def lcd_priv_key(self, tblIdx=None):
        node = self.keyEntry.getNode(
            self.keyEntry.name + (2,) + (tblIdx or self.tblIdx)
        )
        return node.syntax.asOctets()


@pytest.fixture
def fixture():
    return _OwnKeyChangeFixture()


class TestOwnKeyChangeColumns:
    def test_columns_are_instrumented(self, fixture):
        assert type(fixture.authColumn).__name__ == "UsmUserOwnAuthKeyChangeColumn"
        assert type(fixture.privColumn).__name__ == "UsmUserOwnPrivKeyChangeColumn"

    def test_read_returns_empty_string(self, fixture):
        oid = fixture.authColumn.name + fixture.tblIdx
        fixture.authColumn.readTest((oid, None), snmpEngine=fixture.snmpEngine)
        name, val = fixture.authColumn.readGet(
            (oid, None), snmpEngine=fixture.snmpEngine
        )
        assert name == oid
        assert val.asOctets() == b""
        oid = fixture.privColumn.name + fixture.tblIdx
        fixture.privColumn.readTest((oid, None), snmpEngine=fixture.snmpEngine)
        name, val = fixture.privColumn.readGet(
            (oid, None), snmpEngine=fixture.snmpEngine
        )
        assert val.asOctets() == b""

    def test_read_nonexistent_row_raises(self, fixture):
        oid = fixture.authColumn.name + (1, 0xDE, 4) + tuple(b"nope")
        with pytest.raises(smi_error.NoSuchInstanceError):
            fixture.authColumn.readTest((oid, None), snmpEngine=fixture.snmpEngine)

    def test_own_auth_key_change_commits_new_key(self, fixture):
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        assert fixture.lcd_auth_key() == old_local_key.asOctets()

        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(kc))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
            fixture.authColumn.writeCommit(varBind, snmpEngine=fixture.snmpEngine)
            fixture.authColumn.writeCleanup(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == new_local_key.asOctets()
        # priv key must be untouched
        assert (
            fixture.lcd_priv_key()
            == _localize(OLD_PRIV_PASSPHRASE, fixture.engineId, 16).asOctets()
        )

    def test_own_priv_key_change_commits_new_key(self, fixture):
        old_local_key = _localize(OLD_PRIV_PASSPHRASE, fixture.engineId, 16)
        new_local_key = _localize(NEW_PRIV_PASSPHRASE, fixture.engineId, 16)

        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        assert len(kc) == 32
        oid = fixture.privColumn.name + fixture.tblIdx
        varBind = (oid, fixture.privColumn.syntax.clone(kc))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            fixture.privColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
            fixture.privColumn.writeCommit(varBind, snmpEngine=fixture.snmpEngine)
            fixture.privColumn.writeCleanup(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_priv_key() == new_local_key.asOctets()

    def test_cross_user_set_is_denied(self, fixture):
        """A caller must not change another user's key via the Own columns."""
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)

        # requester is USER_NAME but the row belongs to OTHER_USER_NAME
        oid = fixture.authColumn.name + fixture.otherTblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(kc))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            with pytest.raises(smi_error.NoAccessError):
                fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key(fixture.otherTblIdx) == old_local_key.asOctets()

    def test_non_usm_security_model_is_denied(self, fixture):
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(kc))

        # securityModel 2 == SNMPv2c community-based
        _store_request_context(fixture.snmpEngine, USER_NAME, securityModel=2)
        try:
            with pytest.raises(smi_error.NoAccessError):
                fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == old_local_key.asOctets()

    def test_missing_request_context_is_denied(self, fixture):
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(kc))

        with pytest.raises(smi_error.NoAccessError):
            fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)

        assert fixture.lcd_auth_key() == old_local_key.asOctets()

    def test_bad_length_is_rejected(self, fixture):
        oid = fixture.authColumn.name + fixture.tblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(b"\x01" * 10))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            with pytest.raises(smi_error.WrongLengthError):
                fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        oid = fixture.privColumn.name + fixture.tblIdx
        varBind = (oid, fixture.privColumn.syntax.clone(b"\x01" * 64))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            with pytest.raises(smi_error.WrongLengthError):
                fixture.privColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

    def test_write_undo_rolls_back_committed_key(self, fixture):
        """A failure after commit must restore the previous key."""
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(kc))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
            fixture.authColumn.writeCommit(varBind, snmpEngine=fixture.snmpEngine)
            # key is committed at this point
            assert fixture.lcd_auth_key() == new_local_key.asOctets()
            # ...but a later var-bind failed, so the SET rolls back
            fixture.authColumn.writeUndo(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == old_local_key.asOctets()

    def test_write_undo_without_commit_keeps_old_key(self, fixture):
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx
        varBind = (oid, fixture.authColumn.syntax.clone(kc))

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            fixture.authColumn.writeTest(varBind, snmpEngine=fixture.snmpEngine)
            fixture.authColumn.writeUndo(varBind, snmpEngine=fixture.snmpEngine)
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == old_local_key.asOctets()


class TestOwnKeyChangeSetFsm:
    """Drive the full MIB write FSM the way SetCommandResponder does."""

    @staticmethod
    def _write_vars(fixture, *varBinds):
        mibInstrum = fixture.snmpEngine.message_dispatcher.mib_instrum_controller
        return mibInstrum.write_variables(
            *varBinds, snmpEngine=fixture.snmpEngine, acFun=lambda *a, **k: 0
        )

    def test_set_response_contains_empty_strings(self, fixture):
        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            outVarBinds = self._write_vars(
                fixture, (oid, fixture.authColumn.syntax.clone(kc))
            )
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == new_local_key.asOctets()
        assert len(outVarBinds) == 1
        assert outVarBinds[0][0] == oid
        assert outVarBinds[0][1].asOctets() == b""

    def test_simultaneous_auth_and_priv_change(self, fixture):
        old_auth_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_auth_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        old_priv_key = _localize(OLD_PRIV_PASSPHRASE, fixture.engineId, 16)
        new_priv_key = _localize(NEW_PRIV_PASSPHRASE, fixture.engineId, 16)
        kc_auth = localkey.produce_key_change(old_auth_key, new_auth_key, sha256)
        kc_priv = localkey.produce_key_change(old_priv_key, new_priv_key, sha256)
        auth_oid = fixture.authColumn.name + fixture.tblIdx
        priv_oid = fixture.privColumn.name + fixture.tblIdx

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            outVarBinds = self._write_vars(
                fixture,
                (auth_oid, fixture.authColumn.syntax.clone(kc_auth)),
                (priv_oid, fixture.privColumn.syntax.clone(kc_priv)),
            )
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == new_auth_key.asOctets()
        assert fixture.lcd_priv_key() == new_priv_key.asOctets()
        assert [val.asOctets() for _, val in outVarBinds] == [b"", b""]

    def test_commit_failure_rolls_back_all_keys(self, fixture):
        """A failing commit later in the SET must undo the key change."""
        mibBuilder = fixture.snmpEngine.get_mib_builder()
        MibScalar, MibScalarInstance = mibBuilder.import_symbols(
            "SNMPv2-SMI", "MibScalar", "MibScalarInstance"
        )
        from pysnmp.proto.api import v2c

        class CommitFailingInstance(MibScalarInstance):
            def writeCommit(self, varBind, **context):
                raise smi_error.CommitFailedError(
                    name=varBind[0], idx=context.get("idx")
                )

            def writeUndo(self, varBind, **context):
                pass

        mibBuilder.export_symbols(
            "__FAILING-MIB",
            MibScalar((1, 3, 6, 1, 4, 1, 99999, 1), v2c.Integer32()).setMaxAccess(
                "read-write"
            ),
            CommitFailingInstance((1, 3, 6, 1, 4, 1, 99999, 1), (0,), v2c.Integer32(0)),
        )

        old_auth_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_auth_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        old_priv_key = _localize(OLD_PRIV_PASSPHRASE, fixture.engineId, 16)
        new_priv_key = _localize(NEW_PRIV_PASSPHRASE, fixture.engineId, 16)
        kc_auth = localkey.produce_key_change(old_auth_key, new_auth_key, sha256)
        kc_priv = localkey.produce_key_change(old_priv_key, new_priv_key, sha256)
        auth_oid = fixture.authColumn.name + fixture.tblIdx
        priv_oid = fixture.privColumn.name + fixture.tblIdx

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            with pytest.raises(smi_error.CommitFailedError):
                self._write_vars(
                    fixture,
                    (auth_oid, fixture.authColumn.syntax.clone(kc_auth)),
                    (priv_oid, fixture.privColumn.syntax.clone(kc_priv)),
                    ((1, 3, 6, 1, 4, 1, 99999, 1, 0), v2c.Integer32(1)),
                )
        finally:
            _clear_request_context(fixture.snmpEngine)

        # no half-updated state: both keys are back to their old values
        assert fixture.lcd_auth_key() == old_auth_key.asOctets()
        assert fixture.lcd_priv_key() == old_priv_key.asOctets()

    def test_failed_test_phase_leaves_keys_untouched(self, fixture):
        """A bad var-bind later in the SET prevents any key change."""
        old_auth_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_auth_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc_auth = localkey.produce_key_change(old_auth_key, new_auth_key, sha256)
        auth_oid = fixture.authColumn.name + fixture.tblIdx
        # the second var-bind carries a bad-length KeyChange value
        priv_oid = fixture.privColumn.name + fixture.tblIdx

        _store_request_context(fixture.snmpEngine, USER_NAME)
        try:
            with pytest.raises(smi_error.WrongLengthError):
                self._write_vars(
                    fixture,
                    (auth_oid, fixture.authColumn.syntax.clone(kc_auth)),
                    (priv_oid, fixture.privColumn.syntax.clone(b"\x01" * 7)),
                )
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == old_auth_key.asOctets()

    def test_write_with_real_vacm(self, fixture):
        """The SET flows through the real VACM access control function."""
        from pysnmp.entity.rfc3413.cmdrsp import CommandResponderBase
        from pysnmp.proto import rfc1905

        config.add_vacm_user(
            fixture.snmpEngine, 3, USER_NAME, "authPriv", (1, 3, 6), (1, 3, 6)
        )

        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        oid = fixture.authColumn.name + fixture.tblIdx

        fixture.snmpEngine.observer.store_execution_context(
            fixture.snmpEngine,
            "rfc3412.receiveMessage:request",
            dict(
                securityModel=3,
                securityName=OctetString(USER_NAME),
                securityLevel=3,
                contextName=b"",
                pdu=rfc1905.SetRequestPDU(),
            ),
        )
        try:
            outVarBinds = fixture.snmpEngine.message_dispatcher.mib_instrum_controller.write_variables(
                (oid, fixture.authColumn.syntax.clone(kc)),
                snmpEngine=fixture.snmpEngine,
                acFun=CommandResponderBase.verify_access,
            )
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key() == new_local_key.asOctets()
        assert outVarBinds[0][1].asOctets() == b""

    def test_write_with_real_vacm_cross_user_still_denied(self, fixture):
        """VACM write access must not let a user change another user's key."""
        from pysnmp.entity.rfc3413.cmdrsp import CommandResponderBase
        from pysnmp.proto import rfc1905

        # the requester has full VACM write access to the whole tree
        config.add_vacm_user(
            fixture.snmpEngine, 3, USER_NAME, "authPriv", (1, 3, 6), (1, 3, 6)
        )

        old_local_key = _localize(OLD_AUTH_PASSPHRASE, fixture.engineId)
        new_local_key = _localize(NEW_AUTH_PASSPHRASE, fixture.engineId)
        kc = localkey.produce_key_change(old_local_key, new_local_key, sha256)
        # row belongs to OTHER_USER_NAME
        oid = fixture.authColumn.name + fixture.otherTblIdx

        fixture.snmpEngine.observer.store_execution_context(
            fixture.snmpEngine,
            "rfc3412.receiveMessage:request",
            dict(
                securityModel=3,
                securityName=OctetString(USER_NAME),
                securityLevel=3,
                contextName=b"",
                pdu=rfc1905.SetRequestPDU(),
            ),
        )
        try:
            with pytest.raises(smi_error.NoAccessError):
                fixture.snmpEngine.message_dispatcher.mib_instrum_controller.write_variables(
                    (oid, fixture.authColumn.syntax.clone(kc)),
                    snmpEngine=fixture.snmpEngine,
                    acFun=CommandResponderBase.verify_access,
                )
        finally:
            _clear_request_context(fixture.snmpEngine)

        assert fixture.lcd_auth_key(fixture.otherTblIdx) == old_local_key.asOctets()


# ---------------------------------------------------------------------------
# Socket-free end-to-end: two engines wired through a loopback dispatcher
# ---------------------------------------------------------------------------

import collections

from pysnmp.entity.rfc3413 import cmdgen, cmdrsp
from pysnmp.entity.rfc3413 import context as snmp_context
from pysnmp.proto.secmod.rfc3826.priv import aes as _aes

requires_crypto_backend = pytest.mark.skipif(
    _aes.PysnmpCryptoError, reason="cryptography backend too old for AES"
)


class _LoopbackTransport:
    """Stub transport only carrying the address type for target lookup."""

    from pysnmp.carrier.asyncio.dgram.udp import UdpTransportAddress as ADDRESS_TYPE


class _LoopbackNetwork:
    """Address-routed, queue-based network connecting several engines.

    Messages are queued, not delivered inline, so that a response never
    re-enters the requester before its request state is registered.
    """

    def __init__(self):
        self._nodes = {}
        self._queue = collections.deque()

    def attach(self, snmpEngine, address):
        self._nodes[tuple(address)] = snmpEngine
        snmpEngine.transport_dispatcher = _LoopbackDispatcher(self, address)

    def send(self, sourceAddress, destinationAddress, transportDomain, message):
        self._queue.append((
            self._nodes[tuple(destinationAddress)],
            transportDomain,
            sourceAddress,
            message,
        ))

    def pump(self):
        """Deliver queued messages until all engines go quiet."""
        while self._queue:
            snmpEngine, domain, address, message = self._queue.popleft()
            snmpEngine.message_dispatcher.receive_message(
                snmpEngine, domain, address, message
            )


class _LoopbackDispatcher:
    """Minimal transport dispatcher handing messages to a loopback network."""

    def __init__(self, network, address):
        self._network = network
        self._address = address

    def get_transport(self, transportDomain):
        return _LoopbackTransport()

    def send_message(self, outgoingMessage, transportDomain, transportAddress):
        self._network.send(
            self._address, transportAddress, transportDomain, outgoingMessage
        )

    def get_timer_resolution(self):
        return 1.0

    def get_timer_ticks(self):
        return 0

    def job_started(self, jobId, count=1):
        pass

    def job_finished(self, jobId, count=1):
        pass

    def close_dispatcher(self):
        pass


USM_USER_OWN_AUTH_KEY_CHANGE = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 7)
USM_USER_OWN_PRIV_KEY_CHANGE = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 10)
USM_USER_PUBLIC = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 11)


def _usm_user_oid(column, engine_id, user_name):
    engine_id = tuple(engine_id.asNumbers())
    user_name = tuple(user_name.encode())
    return tuple(column) + (len(engine_id),) + engine_id + (len(user_name),) + user_name


class _Loopback:
    """An agent and zero or more managers wired through a loopback network."""

    UDP_DOMAIN = (1, 3, 6, 1, 6, 1, 1)
    AGENT_ADDRESS = ("127.0.0.1", 1161)

    def __init__(self, use_priv):
        self._use_priv = use_priv
        self._network = _LoopbackNetwork()
        self._next_manager_port = 1162

        self.agent = engine.SnmpEngine()
        for user_name in (USER_NAME, OTHER_USER_NAME):
            config.add_v3_user(
                self.agent,
                userName=user_name,
                authKey=OLD_AUTH_PASSPHRASE,
                authProtocol=config.USM_AUTH_HMAC192_SHA256,
                privKey=use_priv and OLD_PRIV_PASSPHRASE or None,
                privProtocol=use_priv
                and config.USM_PRIV_CFB128_AES
                or config.USM_PRIV_NONE,
            )
            config.add_vacm_user(
                self.agent,
                3,
                user_name,
                use_priv and "authPriv" or "authNoPriv",
                (1, 3, 6),
                (1, 3, 6),
            )
        agent_context = snmp_context.SnmpContext(self.agent)
        cmdrsp.GetCommandResponder(self.agent, agent_context)
        cmdrsp.SetCommandResponder(self.agent, agent_context)

        self._network.attach(self.agent, self.AGENT_ADDRESS)

    @property
    def engine_id(self):
        return self.agent.snmpEngineID

    @property
    def security_level(self):
        return self._use_priv and "authPriv" or "authNoPriv"

    def make_manager(self, auth_passphrase, priv_passphrase=None):
        manager = engine.SnmpEngine()
        config.add_v3_user(
            manager,
            userName=USER_NAME,
            authKey=auth_passphrase,
            authProtocol=config.USM_AUTH_HMAC192_SHA256,
            privKey=self._use_priv and priv_passphrase or None,
            privProtocol=self._use_priv
            and config.USM_PRIV_CFB128_AES
            or config.USM_PRIV_NONE,
        )
        config.add_target_parameters(
            manager, "params", USER_NAME, self.security_level, 3
        )
        config.add_target_address(
            manager,
            "agent",
            self.UDP_DOMAIN,
            self.AGENT_ADDRESS,
            "params",
            timeout=100,
            retryCount=0,
        )
        manager_address = ("127.0.0.1", self._next_manager_port)
        self._next_manager_port += 1
        self._network.attach(manager, manager_address)
        return manager

    def pump(self):
        """Deliver queued messages until all engines go quiet."""
        self._network.pump()

    def send(self, manager, generator, var_binds):
        """Send a request through the loopback and return the response."""
        result = {}

        def cbFun(
            snmpEngine,
            sendRequestHandle,
            errorIndication,
            errorStatus,
            errorIndex,
            varBinds,
            cbCtx,
        ):
            result["errorIndication"] = errorIndication
            result["errorStatus"] = errorStatus
            result["errorIndex"] = errorIndex
            result["varBinds"] = varBinds

        generator().send_varbinds(manager, "agent", None, "", var_binds, cbFun, None)
        self.pump()
        return result


class TestOwnKeyChangeLoopback:
    def _run_auth_key_change_flow(self, use_priv):
        loopback = _Loopback(use_priv)
        engine_id = loopback.engine_id

        old_auth_key = _localize(OLD_AUTH_PASSPHRASE, engine_id)
        new_auth_key = _localize(NEW_AUTH_PASSPHRASE, engine_id)

        # independently generated KeyChange values (manager side)
        kc_auth = localkey.produce_key_change(old_auth_key, new_auth_key, sha256)
        assert new_auth_key.asOctets() not in kc_auth.asOctets()

        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)
        public_oid = _usm_user_oid(USM_USER_PUBLIC, engine_id, USER_NAME)

        var_binds = [
            (auth_oid, OctetString(kc_auth)),
            (public_oid, OctetString("random123")),
        ]

        if use_priv:
            old_priv_key = _localize(OLD_PRIV_PASSPHRASE, engine_id, 16)
            new_priv_key = _localize(NEW_PRIV_PASSPHRASE, engine_id, 16)
            kc_priv = localkey.produce_key_change(old_priv_key, new_priv_key, sha256)
            assert new_priv_key.asOctets() not in kc_priv.asOctets()
            priv_oid = _usm_user_oid(USM_USER_OWN_PRIV_KEY_CHANGE, engine_id, USER_NAME)
            var_binds.insert(1, (priv_oid, OctetString(kc_priv)))

        # SET authenticated with the OLD keys; the response must travel
        # under the original request's security state (old keys), which
        # is what lets the manager verify it before switching keys
        manager = loopback.make_manager(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE)

        rsp = loopback.send(manager, cmdgen.SetCommandGenerator, var_binds)
        assert rsp["errorIndication"] is None
        assert int(rsp["errorStatus"]) == 0
        # key change columns read back as zero-length strings
        values = {tuple(name): val for name, val in rsp["varBinds"]}
        assert values[auth_oid].asOctets() == b""
        if use_priv:
            assert values[priv_oid].asOctets() == b""
        assert values[public_oid] == OctetString("random123")

        # subsequent requests work with the NEW keys
        manager_new = loopback.make_manager(NEW_AUTH_PASSPHRASE, NEW_PRIV_PASSPHRASE)

        rsp = loopback.send(
            manager_new,
            cmdgen.GetCommandGenerator,
            [(public_oid, None), (auth_oid, None)],
        )
        assert rsp["errorIndication"] is None
        assert int(rsp["errorStatus"]) == 0
        values = {tuple(name): val for name, val in rsp["varBinds"]}
        assert values[public_oid] == OctetString("random123")
        assert values[auth_oid].asOctets() == b""

        # the OLD keys are rejected now
        rsp = loopback.send(manager, cmdgen.GetCommandGenerator, [(public_oid, None)])
        assert "digest" in str(rsp["errorIndication"]).lower()

    def test_auth_key_change_and_followup_requests(self):
        self._run_auth_key_change_flow(use_priv=False)

    @requires_crypto_backend
    def test_auth_priv_key_change_and_followup_requests(self):
        self._run_auth_key_change_flow(use_priv=True)

    def test_cross_user_set_denied_over_the_wire(self):
        loopback = _Loopback(use_priv=False)
        engine_id = loopback.engine_id

        old_auth_key = _localize(OLD_AUTH_PASSPHRASE, engine_id)
        new_auth_key = _localize(NEW_AUTH_PASSPHRASE, engine_id)
        kc_auth = localkey.produce_key_change(old_auth_key, new_auth_key, sha256)

        # the row belongs to a different user than the requester
        other_oid = _usm_user_oid(
            USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, OTHER_USER_NAME
        )

        manager = loopback.make_manager(OLD_AUTH_PASSPHRASE)

        rsp = loopback.send(
            manager, cmdgen.SetCommandGenerator, [(other_oid, OctetString(kc_auth))]
        )
        assert rsp["errorIndication"] is None
        assert rsp["errorStatus"].prettyPrint() == "noAccess"

        # the other user's key is untouched: it can still talk
        manager_other = engine.SnmpEngine()
        config.add_v3_user(
            manager_other,
            userName=OTHER_USER_NAME,
            authKey=OLD_AUTH_PASSPHRASE,
            authProtocol=config.USM_AUTH_HMAC192_SHA256,
        )
        config.add_target_parameters(
            manager_other, "params", OTHER_USER_NAME, "authNoPriv", 3
        )
        config.add_target_address(
            manager_other,
            "agent",
            loopback.UDP_DOMAIN,
            loopback.AGENT_ADDRESS,
            "params",
            timeout=100,
            retryCount=0,
        )
        loopback._network.attach(manager_other, ("127.0.0.1", 1199))

        public_oid = _usm_user_oid(USM_USER_PUBLIC, engine_id, OTHER_USER_NAME)
        rsp = loopback.send(
            manager_other, cmdgen.GetCommandGenerator, [(public_oid, None)]
        )
        assert rsp["errorIndication"] is None
        assert int(rsp["errorStatus"]) == 0

    def test_wrong_length_denied_over_the_wire(self):
        loopback = _Loopback(use_priv=False)
        engine_id = loopback.engine_id
        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)

        manager = loopback.make_manager(OLD_AUTH_PASSPHRASE)

        rsp = loopback.send(
            manager,
            cmdgen.SetCommandGenerator,
            [(auth_oid, OctetString(b"\x01" * 10))],
        )
        assert rsp["errorIndication"] is None
        assert rsp["errorStatus"].prettyPrint() == "wrongLength"
