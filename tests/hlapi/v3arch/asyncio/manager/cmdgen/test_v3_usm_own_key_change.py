"""
End-to-end tests for RFC 3414 own key change over the wire.

A SHA-256 auth / AES-128 priv USM user updates its own localized keys by
SETting usmUserOwnAuthKeyChange/usmUserOwnPrivKeyChange with a KeyChange
value (one-way transform - the new key never appears on the wire). The
response travels with the security state of the original request (old
keys), after which the new keys are active.
"""

from hashlib import sha256

import pytest
from pysnmp.entity import config
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    get_cmd,
    set_cmd,
    SnmpEngine,
    UdpTransportTarget,
    USM_AUTH_HMAC192_SHA256,
    USM_PRIV_CFB128_AES,
    UsmUserData,
)
from pysnmp.proto.api import v2c
from pysnmp.proto.errind import WrongDigest
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.smi.error import CommitFailedError
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType
from tests.agent_context import AGENT_PORT, AgentContextManager

# SNMP-USER-BASED-SM-MIB column OIDs
USM_USER_OWN_AUTH_KEY_CHANGE = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 7)
USM_USER_OWN_PRIV_KEY_CHANGE = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 10)
USM_USER_PUBLIC = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 11)

USER_NAME = "usr-sha256-aes"
OTHER_USER_NAME = "usr-sha-aes"

OLD_AUTH_PASSPHRASE = "authkey1"
NEW_AUTH_PASSPHRASE = "newauthkey1"
OLD_PRIV_PASSPHRASE = "privkey1"
NEW_PRIV_PASSPHRASE = "newprivkey1"


def _usm_user_oid(column, engine_id, user_name):
    """Build a usmUserTable column instance OID from row indices."""
    engine_id = tuple(engine_id.asNumbers())
    user_name = tuple(user_name.encode())
    return tuple(column) + (len(engine_id),) + engine_id + (len(user_name),) + user_name


def _localized_key(passphrase, engine_id, key_length=None):
    """Derive the localized key the way a manager would from a passphrase."""
    master_key = localkey.hash_passphrase(passphrase.encode(), sha256)
    local_key = localkey.localize_key(master_key, engine_id, sha256)
    if key_length is not None:
        local_key = local_key[:key_length]
    return local_key


def _user_data(auth_passphrase, priv_passphrase):
    return UsmUserData(
        USER_NAME,
        auth_passphrase,
        priv_passphrase,
        authProtocol=USM_AUTH_HMAC192_SHA256,
        privProtocol=USM_PRIV_CFB128_AES,
    )


async def _get_sysdescr(snmpEngine, authData):
    return await get_cmd(
        snmpEngine,
        authData,
        await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )


@pytest.mark.asyncio
async def test_own_key_change_and_subsequent_requests():
    """Full key change flow: SET with old keys, then use the new keys."""
    async with AgentContextManager() as agent:
        engine_id = agent.snmpEngineID

        old_auth_key = _localized_key(OLD_AUTH_PASSPHRASE, engine_id)
        new_auth_key = _localized_key(NEW_AUTH_PASSPHRASE, engine_id)
        old_priv_key = _localized_key(OLD_PRIV_PASSPHRASE, engine_id, 16)
        new_priv_key = _localized_key(NEW_PRIV_PASSPHRASE, engine_id, 16)

        # independently generate the KeyChange values (manager side)
        auth_key_change = localkey.produce_key_change(
            old_auth_key, new_auth_key, sha256
        )
        priv_key_change = localkey.produce_key_change(
            old_priv_key, new_priv_key, sha256
        )
        assert len(auth_key_change) == 64  # 2 x SHA-256 key length
        assert len(priv_key_change) == 32  # 2 x AES-128 key length
        # the new keys must not be recoverable from the wire values
        assert new_auth_key.asOctets() not in auth_key_change.asOctets()
        assert new_priv_key.asOctets() not in priv_key_change.asOctets()

        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)
        priv_oid = _usm_user_oid(USM_USER_OWN_PRIV_KEY_CHANGE, engine_id, USER_NAME)
        public_oid = _usm_user_oid(USM_USER_PUBLIC, engine_id, USER_NAME)

        with SnmpEngine() as snmpEngine:
            # the SET is authenticated/encrypted with the OLD keys; the
            # response must come back under the same (original) security
            # state, otherwise the manager could not verify it
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                snmpEngine,
                _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(auth_oid), OctetString(auth_key_change)),
                ObjectType(ObjectIdentity(priv_oid), OctetString(priv_key_change)),
                ObjectType(ObjectIdentity(public_oid), OctetString("random123")),
            )

            assert errorIndication is None
            assert errorStatus == 0
            assert len(varBinds) == 3
            # key change columns read back as zero-length strings: no
            # key material leaks through the management protocol
            assert varBinds[0][0].asNumbers() == auth_oid
            assert varBinds[0][1] == OctetString("")
            assert varBinds[1][0].asNumbers() == priv_oid
            assert varBinds[1][1] == OctetString("")
            assert varBinds[2][1] == OctetString("random123")

        # subsequent requests must use the NEW keys
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await _get_sysdescr(
                snmpEngine, _user_data(NEW_AUTH_PASSPHRASE, NEW_PRIV_PASSPHRASE)
            )
            assert errorIndication is None
            assert errorStatus == 0
            assert varBinds[0][0].prettyPrint() == "SNMPv2-MIB::sysDescr.0"

        # usmUserPublic confirms the change took effect
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                snmpEngine,
                _user_data(NEW_AUTH_PASSPHRASE, NEW_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(public_oid)),
            )
            assert errorIndication is None
            assert errorStatus == 0
            assert varBinds[0][1] == OctetString("random123")

        # the OLD keys are no longer accepted
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await _get_sysdescr(
                snmpEngine, _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE)
            )
            assert isinstance(errorIndication, WrongDigest)


@pytest.mark.asyncio
async def test_own_key_change_read_returns_empty_string():
    """Reads of the own key change columns always yield zero-length strings."""
    async with AgentContextManager() as agent:
        engine_id = agent.snmpEngineID
        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)
        priv_oid = _usm_user_oid(USM_USER_OWN_PRIV_KEY_CHANGE, engine_id, USER_NAME)

        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                snmpEngine,
                _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(auth_oid)),
                ObjectType(ObjectIdentity(priv_oid)),
            )

            assert errorIndication is None
            assert errorStatus == 0
            assert len(varBinds) == 2
            assert varBinds[0][1] == OctetString("")
            assert varBinds[1][1] == OctetString("")


@pytest.mark.asyncio
async def test_own_key_change_cross_user_denied():
    """A user must not change another user's key via the Own columns."""
    async with AgentContextManager() as agent:
        engine_id = agent.snmpEngineID

        # KeyChange value crafted for the OTHER user's (SHA-1) auth key
        from hashlib import sha1

        old_auth_key = localkey.localize_key(
            localkey.hash_passphrase(OLD_AUTH_PASSPHRASE.encode(), sha1),
            engine_id,
            sha1,
        )
        new_auth_key = localkey.localize_key(
            localkey.hash_passphrase(NEW_AUTH_PASSPHRASE.encode(), sha1),
            engine_id,
            sha1,
        )
        auth_key_change = localkey.produce_key_change(old_auth_key, new_auth_key, sha1)

        # the row belongs to OTHER_USER_NAME, the requester is USER_NAME
        auth_oid = _usm_user_oid(
            USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, OTHER_USER_NAME
        )

        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                snmpEngine,
                _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(auth_oid), OctetString(auth_key_change)),
            )

            assert errorIndication is None
            assert errorStatus.prettyPrint() == "noAccess"

        # the other user's key is untouched: it can still talk
        with SnmpEngine() as snmpEngine:
            authData = UsmUserData(
                OTHER_USER_NAME,
                OLD_AUTH_PASSPHRASE,
                OLD_PRIV_PASSPHRASE,
                authProtocol=config.USM_AUTH_HMAC96_SHA,
                privProtocol=config.USM_PRIV_CFB128_AES,
            )
            errorIndication, errorStatus, errorIndex, varBinds = await _get_sysdescr(
                snmpEngine, authData
            )
            assert errorIndication is None
            assert errorStatus == 0


@pytest.mark.asyncio
async def test_own_key_change_non_usm_denied():
    """The Own columns reject requests not authenticated via USM."""
    async with AgentContextManager() as agent:
        engine_id = agent.snmpEngineID
        old_auth_key = _localized_key(OLD_AUTH_PASSPHRASE, engine_id)
        new_auth_key = _localized_key(NEW_AUTH_PASSPHRASE, engine_id)
        auth_key_change = localkey.produce_key_change(
            old_auth_key, new_auth_key, sha256
        )
        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)

        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                snmpEngine,
                CommunityData("public"),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(auth_oid), OctetString(auth_key_change)),
            )

            assert errorIndication is None
            assert errorStatus.prettyPrint() == "noAccess"

        # key unchanged: the user can still talk with its old keys
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await _get_sysdescr(
                snmpEngine, _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE)
            )
            assert errorIndication is None
            assert errorStatus == 0


@pytest.mark.asyncio
async def test_own_key_change_wrong_length():
    """A malformed KeyChange value is rejected with wrongLength."""
    async with AgentContextManager() as agent:
        engine_id = agent.snmpEngineID
        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)
        priv_oid = _usm_user_oid(USM_USER_OWN_PRIV_KEY_CHANGE, engine_id, USER_NAME)

        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                snmpEngine,
                _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(auth_oid), OctetString(b"\x01" * 10)),
            )

            assert errorIndication is None
            assert errorStatus.prettyPrint() == "wrongLength"

        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                snmpEngine,
                _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(priv_oid), OctetString(b"\x01" * 64)),
            )

            assert errorIndication is None
            assert errorStatus.prettyPrint() == "wrongLength"


@pytest.mark.asyncio
async def test_own_key_change_commit_failure_rolls_back():
    """A mid-commit failure must roll back both keys and report an error."""
    async with AgentContextManager() as agent:
        engine_id = agent.snmpEngineID

        # register a MIB object whose commit always fails
        mibBuilder = agent.get_mib_builder()
        MibScalar, MibScalarInstance = mibBuilder.import_symbols(
            "SNMPv2-SMI", "MibScalar", "MibScalarInstance"
        )

        class CommitFailingInstance(MibScalarInstance):
            def writeCommit(self, varBind, **context):
                raise CommitFailedError(name=varBind[0], idx=context.get("idx"))

            def writeUndo(self, varBind, **context):
                pass

        mibBuilder.export_symbols(
            "__FAILING-MIB",
            MibScalar(
                (1, 3, 6, 1, 4, 1, 60069, 9, 99, 1), v2c.Integer32()
            ).setMaxAccess("read-write"),
            CommitFailingInstance(
                (1, 3, 6, 1, 4, 1, 60069, 9, 99, 1), (0,), v2c.Integer32(0)
            ),
        )

        old_auth_key = _localized_key(OLD_AUTH_PASSPHRASE, engine_id)
        new_auth_key = _localized_key(NEW_AUTH_PASSPHRASE, engine_id)
        old_priv_key = _localized_key(OLD_PRIV_PASSPHRASE, engine_id, 16)
        new_priv_key = _localized_key(NEW_PRIV_PASSPHRASE, engine_id, 16)
        auth_key_change = localkey.produce_key_change(
            old_auth_key, new_auth_key, sha256
        )
        priv_key_change = localkey.produce_key_change(
            old_priv_key, new_priv_key, sha256
        )

        auth_oid = _usm_user_oid(USM_USER_OWN_AUTH_KEY_CHANGE, engine_id, USER_NAME)
        priv_oid = _usm_user_oid(USM_USER_OWN_PRIV_KEY_CHANGE, engine_id, USER_NAME)

        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                snmpEngine,
                _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE),
                await UdpTransportTarget.create(("localhost", AGENT_PORT), retries=0),
                ContextData(),
                ObjectType(ObjectIdentity(auth_oid), OctetString(auth_key_change)),
                ObjectType(ObjectIdentity(priv_oid), OctetString(priv_key_change)),
                ObjectType(
                    ObjectIdentity((1, 3, 6, 1, 4, 1, 60069, 9, 99, 1, 0)),
                    v2c.Integer32(1),
                ),
            )

            assert errorIndication is None
            assert errorStatus.prettyPrint() == "commitFailed"

        # no half-updated state: the OLD keys still work...
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await _get_sysdescr(
                snmpEngine, _user_data(OLD_AUTH_PASSPHRASE, OLD_PRIV_PASSPHRASE)
            )
            assert errorIndication is None
            assert errorStatus == 0

        # ...and the new keys were never activated
        with SnmpEngine() as snmpEngine:
            errorIndication, errorStatus, errorIndex, varBinds = await _get_sysdescr(
                snmpEngine, _user_data(NEW_AUTH_PASSPHRASE, NEW_PRIV_PASSPHRASE)
            )
            assert isinstance(errorIndication, WrongDigest)
