#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.smi import error, exval

(MibScalarInstance, MibTableColumn) = mibBuilder.import_symbols(
    "SNMPv2-SMI", "MibScalarInstance", "MibTableColumn"
)

(
    usmStatsUnsupportedSecLevels,
    usmStatsNotInTimeWindows,
    usmStatsUnknownUserNames,
    usmStatsUnknownEngineIDs,
    usmStatsWrongDigests,
    usmStatsDecryptionErrors,
    usmUserSpinLock,
    usmUserOwnAuthKeyChange,
    usmUserOwnPrivKeyChange,
) = mibBuilder.import_symbols(
    "SNMP-USER-BASED-SM-MIB",
    "usmStatsUnsupportedSecLevels",
    "usmStatsNotInTimeWindows",
    "usmStatsUnknownUserNames",
    "usmStatsUnknownEngineIDs",
    "usmStatsWrongDigests",
    "usmStatsDecryptionErrors",
    "usmUserSpinLock",
    "usmUserOwnAuthKeyChange",
    "usmUserOwnPrivKeyChange",
)

__usmStatsUnsupportedSecLevels = MibScalarInstance(
    usmStatsUnsupportedSecLevels.name,
    (0,),
    usmStatsUnsupportedSecLevels.syntax.clone(0),
)
__usmStatsNotInTimeWindows = MibScalarInstance(
    usmStatsNotInTimeWindows.name, (0,), usmStatsNotInTimeWindows.syntax.clone(0)
)
__usmStatsUnknownUserNames = MibScalarInstance(
    usmStatsUnknownUserNames.name, (0,), usmStatsUnknownUserNames.syntax.clone(0)
)
__usmStatsUnknownEngineIDs = MibScalarInstance(
    usmStatsUnknownEngineIDs.name, (0,), usmStatsUnknownEngineIDs.syntax.clone(0)
)
__usmStatsWrongDigests = MibScalarInstance(
    usmStatsWrongDigests.name, (0,), usmStatsWrongDigests.syntax.clone(0)
)
__usmStatsDecryptionErrors = MibScalarInstance(
    usmStatsDecryptionErrors.name, (0,), usmStatsDecryptionErrors.syntax.clone(0)
)
__usmUserSpinLock = MibScalarInstance(
    usmUserSpinLock.name, (0,), usmUserSpinLock.syntax.clone(0)
)


class UsmUserOwnKeyChangeColumn(MibTableColumn):
    """RFC 3414 own key change column instrumentation.

    Implements the write side of usmUserOwnAuthKeyChange and
    usmUserOwnPrivKeyChange: the KeyChange value carried by the SET is
    run through the one-way transform of RFC 3414 A.5 against the
    requester's current localized key, and the resulting new localized
    key is committed into the LCD (PYSNMP-USM-MIB::pysnmpUsmKeyEntry)
    through the regular two-phase MIB commit/rollback machinery.

    The SET only succeeds if the request was authenticated by the USM
    security model and the authenticated securityName matches the
    usmUserName indexing the target row - a caller can never change
    another user's key even if VACM lets it write this column.

    Reads of these columns always yield the zero-length string, so the
    key material is never exposed through the management protocol.
    """

    SECURITY_MODEL_USM = 3

    # usmUserEntry column IDs
    STATUS_COLUMN_ID = 13
    AUTH_PROTOCOL_COLUMN_ID = 5

    # protocol OIDs
    NO_AUTH_PROTOCOL = (1, 3, 6, 1, 6, 3, 10, 1, 1, 1)  # usmNoAuthProtocol
    NO_PRIV_PROTOCOL = (1, 3, 6, 1, 6, 3, 10, 1, 2, 1)  # usmNoPrivProtocol

    # subclass configuration
    KEY_COLUMN_ID = None  # pysnmpUsmKeyEntry column with the localized key
    PROTOCOL_COLUMN_ID = None  # usmUserEntry column with the protocol
    NO_PROTOCOL_ID = None  # protocol OID meaning "not configured"

    def __init__(self, name, syntax):
        MibTableColumn.__init__(self, name, syntax)
        # instance name -> [LCD key node, committed flag]
        self._staged_key_writes = {}

    @staticmethod
    def __get_row_node(usmUserEntry, columnId, instId, context):
        try:
            return usmUserEntry.getNode(
                usmUserEntry.name + (columnId,) + instId, **context
            )
        except error.NoSuchInstanceError:
            raise error.InconsistentNameError(
                name=usmUserEntry.name + (columnId,) + instId, idx=context.get("idx")
            )

    def __verify_own_user(self, name, instId, context):
        snmpEngine = context.get("snmpEngine")
        if snmpEngine is None:
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        try:
            execCtx = snmpEngine.observer.get_execution_context(
                "rfc3412.receiveMessage:request"
            )
        except (KeyError, AttributeError):
            # not a management-protocol request - deny
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        # RFC 3414: the operation must use the USM security model
        if execCtx.get("securityModel") != self.SECURITY_MODEL_USM:
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        mibBuilder = snmpEngine.get_mib_builder()
        (usmUserEntry,) = mibBuilder.import_symbols(
            "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
        )

        try:
            indices = usmUserEntry.getIndicesFromInstId(instId)
            rowUserName = indices[1].asOctets()
        except (error.SmiError, PyAsn1Error, IndexError, AttributeError):
            raise error.NoSuchInstanceError(name=name, idx=context.get("idx"))

        securityName = execCtx.get("securityName")
        if securityName is None:
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        # RFC 3414: the requester's usmUserName must match the row index
        if univ.OctetString(securityName).asOctets() != rowUserName:
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        return snmpEngine, mibBuilder, usmUserEntry

    def __row_exists(self, usmUserEntry, instId, context):
        try:
            usmUserEntry.getNode(
                usmUserEntry.name + (self.STATUS_COLUMN_ID,) + instId, **context
            )
        except error.NoSuchInstanceError:
            return False
        return True

    # Read operation: the value of these objects is always the
    # zero-length string (KeyChange TEXTUAL-CONVENTION)

    def readTest(self, varBind, **context):
        name, val = varBind

        if name == self.name:
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        acFun = context.get("acFun")
        if acFun:
            if self.maxAccess not in (
                "read-only",
                "read-write",
                "read-create",
            ) or acFun("read", (name, self.syntax), **context):
                raise error.NoAccessError(name=name, idx=context.get("idx"))

        snmpEngine = context.get("snmpEngine")
        if snmpEngine is not None:
            mibBuilder = snmpEngine.get_mib_builder()
            (usmUserEntry,) = mibBuilder.import_symbols(
                "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
            )
            instId = name[len(self.name) :]
            if not self.__row_exists(usmUserEntry, instId, context):
                raise error.NoSuchInstanceError(name=name, idx=context.get("idx"))

    def readGet(self, varBind, **context):
        name, val = varBind

        snmpEngine = context.get("snmpEngine")
        if snmpEngine is not None:
            mibBuilder = snmpEngine.get_mib_builder()
            (usmUserEntry,) = mibBuilder.import_symbols(
                "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
            )
            instId = name[len(self.name) :]
            if not self.__row_exists(usmUserEntry, instId, context):
                return name, exval.noSuchInstance

        # never reveal anything but the empty string
        return name, self.syntax.clone("")

    # Write operation: two-phase commit

    def writeTest(self, varBind, **context):
        name, val = varBind

        if name == self.name:
            raise error.NoAccessError(name=name, idx=context.get("idx"))

        acFun = context.get("acFun")
        if acFun:
            if self.maxAccess not in ("read-write", "read-create") or acFun(
                "write", (name, self.syntax), **context
            ):
                raise error.NotWritableError(name=name, idx=context.get("idx"))

        instId = name[len(self.name) :]

        snmpEngine, mibBuilder, usmUserEntry = self.__verify_own_user(
            name, instId, context
        )

        # the row must exist and be active for own key change to work
        statusNode = self.__get_row_node(
            usmUserEntry, self.STATUS_COLUMN_ID, instId, context
        )
        if int(statusNode.syntax) != 1:  # active
            raise error.InconsistentValueError(name=name, idx=context.get("idx"))

        # when the associated protocol is not configured, the SET is
        # a successful no-op (RFC 3414)
        protocolNode = self.__get_row_node(
            usmUserEntry, self.PROTOCOL_COLUMN_ID, instId, context
        )
        if tuple(protocolNode.syntax) == self.NO_PROTOCOL_ID:
            return

        # locate the localized key in the LCD
        (pysnmpUsmKeyEntry,) = mibBuilder.import_symbols(
            "PYSNMP-USM-MIB", "pysnmpUsmKeyEntry"
        )
        try:
            keyNode = pysnmpUsmKeyEntry.getNode(
                pysnmpUsmKeyEntry.name + (self.KEY_COLUMN_ID,) + instId, **context
            )
        except error.NoSuchInstanceError:
            raise error.InconsistentNameError(name=name, idx=context.get("idx"))

        oldKey = keyNode.syntax.asOctets()

        # validate the KeyChange value: random || delta, each component
        # as long as the key being changed
        try:
            keyChange = self.syntax.clone(val).asOctets()
        except PyAsn1Error:
            raise error.WrongTypeError(name=name, idx=context.get("idx"))

        if len(keyChange) != 2 * len(oldKey):
            raise error.WrongLengthError(name=name, idx=context.get("idx"))

        # the hash algorithm is the one used by the user's auth protocol
        authProtocolNode = self.__get_row_node(
            usmUserEntry, self.AUTH_PROTOCOL_COLUMN_ID, instId, context
        )
        authProtocol = tuple(authProtocolNode.syntax)
        authServices = snmpEngine.security_models[self.SECURITY_MODEL_USM].AUTH_SERVICES
        if authProtocol == self.NO_AUTH_PROTOCOL or authProtocol not in authServices:
            raise error.InconsistentValueError(name=name, idx=context.get("idx"))

        hashAlgorithm = authServices[authProtocol].hash_algorithm

        # one-way transform: recover the new localized key
        newKey = localkey.resolve_key_change(oldKey, keyChange, hashAlgorithm)

        # stage the new key into the LCD key instance through its own
        # two-phase commit, so a failed commit anywhere in this SET
        # rolls the key back
        stagedContext = context.copy()
        stagedContext.pop("acFun", None)
        keyNode.writeTest((keyNode.name, newKey), **stagedContext)
        self._staged_key_writes[name] = [keyNode, False]

    def writeCommit(self, varBind, **context):
        name, val = varBind

        staged = self._staged_key_writes.get(name)
        if staged is not None:
            keyNode = staged[0]
            keyNode.writeCommit((keyNode.name, None), **context)
            staged[1] = True

    def writeCleanup(self, varBind, **context):
        name, val = varBind

        self.branchVersionId += 1

        staged = self._staged_key_writes.pop(name, None)
        if staged is not None:
            keyNode = staged[0]
            keyNode.writeCleanup((keyNode.name, None), **context)

    def writeUndo(self, varBind, **context):
        name, val = varBind

        staged = self._staged_key_writes.pop(name, None)
        if staged is not None:
            keyNode, committed = staged
            if committed:
                # roll the LCD key back to its previous value
                keyNode.writeUndo((keyNode.name, None), **context)
            else:
                # never committed - just drop the staged value
                keyNode.writeCleanup((keyNode.name, None), **context)


class UsmUserOwnAuthKeyChangeColumn(UsmUserOwnKeyChangeColumn):
    """usmUserOwnAuthKeyChange column instrumentation."""

    KEY_COLUMN_ID = 1  # pysnmpUsmKeyAuthLocalized
    PROTOCOL_COLUMN_ID = 5  # usmUserAuthProtocol
    NO_PROTOCOL_ID = UsmUserOwnKeyChangeColumn.NO_AUTH_PROTOCOL


class UsmUserOwnPrivKeyChangeColumn(UsmUserOwnKeyChangeColumn):
    """usmUserOwnPrivKeyChange column instrumentation."""

    KEY_COLUMN_ID = 2  # pysnmpUsmKeyPrivLocalized
    PROTOCOL_COLUMN_ID = 8  # usmUserPrivProtocol
    NO_PROTOCOL_ID = UsmUserOwnKeyChangeColumn.NO_PRIV_PROTOCOL


# Replace the plain compiled columns with the instrumented ones

__usmUserOwnAuthKeyChange = UsmUserOwnAuthKeyChangeColumn(
    usmUserOwnAuthKeyChange.name, usmUserOwnAuthKeyChange.syntax.clone()
)
__usmUserOwnAuthKeyChange.setMaxAccess(usmUserOwnAuthKeyChange.maxAccess)
__usmUserOwnAuthKeyChange.setLabel("usmUserOwnAuthKeyChange")

__usmUserOwnPrivKeyChange = UsmUserOwnPrivKeyChangeColumn(
    usmUserOwnPrivKeyChange.name, usmUserOwnPrivKeyChange.syntax.clone()
)
__usmUserOwnPrivKeyChange.setMaxAccess(usmUserOwnPrivKeyChange.maxAccess)
__usmUserOwnPrivKeyChange.setLabel("usmUserOwnPrivKeyChange")

mibBuilder.mibSymbols["SNMP-USER-BASED-SM-MIB"][
    "usmUserOwnAuthKeyChange"
] = __usmUserOwnAuthKeyChange
mibBuilder.mibSymbols["SNMP-USER-BASED-SM-MIB"][
    "usmUserOwnPrivKeyChange"
] = __usmUserOwnPrivKeyChange

mibBuilder.export_symbols(
    "__SNMP-USER-BASED-SM-MIB",
    usmStatsUnsupportedSecLevels=__usmStatsUnsupportedSecLevels,
    usmStatsNotInTimeWindows=__usmStatsNotInTimeWindows,
    usmStatsUnknownUserNames=__usmStatsUnknownUserNames,
    usmStatsUnknownEngineIDs=__usmStatsUnknownEngineIDs,
    usmStatsWrongDigests=__usmStatsWrongDigests,
    usmStatsDecryptionErrors=__usmStatsDecryptionErrors,
    usmUserSpinLock=__usmUserSpinLock,
    usmUserOwnAuthKeyChange=__usmUserOwnAuthKeyChange,
    usmUserOwnPrivKeyChange=__usmUserOwnPrivKeyChange,
)
