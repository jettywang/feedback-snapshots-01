#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
import sys


from pysnmp import debug, nextid
from pysnmp.entity.engine import SnmpEngine
from pysnmp.entity.rfc3413 import config
from pysnmp.proto import errind, error, rfc3411
from pysnmp.proto.api import v2c
from pysnmp.proto.proxy import rfc2576
from pysnmp.smi.rfc1902 import ObjectType


getNextHandle = nextid.Integer(0x7FFFFFFF)  # noqa: N816


# Terminal states reported once per management target (RFC 3413 section 3.3).
TARGET_STATE_FILTERED = "filtered"
TARGET_STATE_SENT = "sent"
TARGET_STATE_ACKNOWLEDGED = "acknowledged"
TARGET_STATE_FAILED = "failed"


class NotificationOriginator:
    """Notification originator."""

    ACM_ID = 3  # default MIB access control method to use

    def __init__(self, **options):
        """Create a Notification Originator application."""
        self.__pendingReqs = {}
        self.__pendingNotifications = {}
        self.snmpContext = options.pop("snmpContext", None)  # this is deprecated
        self.__options = options

    def process_response_pdu(
        self,
        snmpEngine: SnmpEngine,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
        contextName,
        pduVersion,
        PDU,
        statusInformation,
        sendPduHandle,
        cbInfo,
    ):
        """Process SNMP PDU response."""
        sendRequestHandle, cbFun, cbCtx = cbInfo

        # 3.3.6d
        if sendPduHandle not in self.__pendingReqs:
            raise error.ProtocolError("Missing sendPduHandle %s" % sendPduHandle)

        (
            origTransportDomain,
            origTransportAddress,
            origMessageProcessingModel,
            origSecurityModel,
            origSecurityName,
            origSecurityLevel,
            origContextEngineId,
            origContextName,
            origPdu,
            origTimeout,
            origRetryCount,
            origRetries,
            origDiscoveryRetries,
        ) = self.__pendingReqs.pop(sendPduHandle)

        snmpEngine.transport_dispatcher.job_finished(id(self))

        if statusInformation:
            debug.logger & debug.FLAG_APP and debug.logger(
                "processResponsePdu: sendRequestHandle {}, sendPduHandle {} statusInformation {}".format(
                    sendRequestHandle, sendPduHandle, statusInformation
                )
            )

            errorIndication = statusInformation["errorIndication"]

            if errorIndication in (errind.notInTimeWindow, errind.unknownEngineID):
                origDiscoveryRetries += 1
                origRetries = 0
            else:
                origDiscoveryRetries = 0
                origRetries += 1

            if (
                origRetries > origRetryCount
                or origDiscoveryRetries > self.__options.get("discoveryRetries", 4)
            ):
                debug.logger & debug.FLAG_APP and debug.logger(
                    "processResponsePdu: sendRequestHandle %s, sendPduHandle %s retry count %d exceeded"
                    % (sendRequestHandle, sendPduHandle, origRetries)
                )
                cbFun(snmpEngine, sendRequestHandle, errorIndication, None, cbCtx)
                return

            # Convert timeout in hundredths of a second into timer ticks
            timeoutInTicks = (
                float(origTimeout)
                * 0.01
                / snmpEngine.transport_dispatcher.get_timer_resolution()
            )

            # User-side API assumes SMIv2
            if messageProcessingModel == 0:
                reqPDU = rfc2576.v2_to_v1(origPdu)
                pduVersion = 0
            else:
                reqPDU = origPdu
                pduVersion = 1

            # 3.3.6a
            try:
                sendPduHandle = snmpEngine.message_dispatcher.send_pdu(
                    snmpEngine,
                    origTransportDomain,
                    origTransportAddress,
                    origMessageProcessingModel,
                    origSecurityModel,
                    origSecurityName,
                    origSecurityLevel,
                    origContextEngineId,
                    origContextName,
                    pduVersion,
                    reqPDU,
                    True,
                    timeoutInTicks,
                    self.process_response_pdu,
                    (sendRequestHandle, cbFun, cbCtx),
                )
            except error.StatusInformation:
                statusInformation = sys.exc_info()[1]
                debug.logger & debug.FLAG_APP and debug.logger(
                    "processResponsePdu: sendRequestHandle {}: sendPdu() failed with {!r} ".format(
                        sendRequestHandle, statusInformation
                    )
                )
                cbFun(
                    snmpEngine,
                    sendRequestHandle,
                    statusInformation["errorIndication"],
                    None,
                    cbCtx,
                )
                return

            snmpEngine.transport_dispatcher.job_started(id(self))

            debug.logger & debug.FLAG_APP and debug.logger(
                "processResponsePdu: sendRequestHandle %s, sendPduHandle %s, timeout %d, retry %d of %d"
                % (
                    sendRequestHandle,
                    sendPduHandle,
                    origTimeout,
                    origRetries,
                    origRetryCount,
                )
            )

            # 3.3.6b
            self.__pendingReqs[sendPduHandle] = (
                origTransportDomain,
                origTransportAddress,
                origMessageProcessingModel,
                origSecurityModel,
                origSecurityName,
                origSecurityLevel,
                origContextEngineId,
                origContextName,
                origPdu,
                origTimeout,
                origRetryCount,
                origRetries,
                origDiscoveryRetries,
            )
            return

        # 3.3.6c
        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            PDU = rfc2576.v1_to_v2(PDU, origPdu)

        cbFun(snmpEngine, sendRequestHandle, None, PDU, cbCtx)

    def send_pdu(
        self,
        snmpEngine: SnmpEngine,
        targetName,
        contextEngineId,
        contextName,
        pdu,
        cbFun=None,
        cbCtx=None,
    ):
        """Send SNMP PDU to a target."""
        (
            transportDomain,
            transportAddress,
            timeout,
            retryCount,
            params,
        ) = config.get_target_address(snmpEngine, targetName)

        (
            messageProcessingModel,
            securityModel,
            securityName,
            securityLevel,
        ) = config.get_target_parameters(snmpEngine, params)

        # User-side API assumes SMIv2
        if messageProcessingModel == 0:
            reqPDU = rfc2576.v2_to_v1(pdu)
            pduVersion = 0
        else:
            reqPDU = pdu
            pduVersion = 1

        # 3.3.5
        if reqPDU.tagSet in rfc3411.CONFIRMED_CLASS_PDUS:
            # Convert timeout in hundredths of a second into timer ticks
            timeoutInTicks = (
                float(timeout)
                * 0.01
                / snmpEngine.transport_dispatcher.get_timer_resolution()
            )

            sendRequestHandle = getNextHandle()

            # 3.3.6a
            sendPduHandle = snmpEngine.message_dispatcher.send_pdu(
                snmpEngine,
                transportDomain,
                transportAddress,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineId,
                contextName,
                pduVersion,
                reqPDU,
                True,
                timeoutInTicks,
                self.process_response_pdu,
                (sendRequestHandle, cbFun, cbCtx),
            )

            debug.logger & debug.FLAG_APP and debug.logger(
                "sendPdu: sendPduHandle %s, timeout %d" % (sendPduHandle, timeout)
            )

            # 3.3.6b
            self.__pendingReqs[sendPduHandle] = (
                transportDomain,
                transportAddress,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineId,
                contextName,
                pdu,
                timeout,
                retryCount,
                0,
                0,
            )
            snmpEngine.transport_dispatcher.job_started(id(self))
        else:
            snmpEngine.message_dispatcher.send_pdu(
                snmpEngine,
                transportDomain,
                transportAddress,
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
                contextEngineId,
                contextName,
                pduVersion,
                reqPDU,
                False,
            )

            sendRequestHandle = None

            debug.logger & debug.FLAG_APP and debug.logger("sendPdu: message sent")

        return sendRequestHandle

    def process_response_varbinds(
        self, snmpEngine: SnmpEngine, sendRequestHandle, errorIndication, pdu, cbCtx
    ):
        """Process SNMP PDU response."""
        (
            notificationHandle,
            targetAddrName,
            targetCbFun,
            targetCbCtx,
            cbFun,
            cbCtx,
        ) = cbCtx

        pendingTargets = self.__pendingNotifications[notificationHandle]

        pendingTargets.pop(sendRequestHandle)

        debug.logger & debug.FLAG_APP and debug.logger(
            "processResponseVarBinds: notificationHandle {}, target {}, sendRequestHandle {}, errorIndication {}, pending requests {}".format(
                notificationHandle,
                targetAddrName,
                sendRequestHandle,
                errorIndication,
                pendingTargets,
            )
        )

        if errorIndication:
            targetState = TARGET_STATE_FAILED
        else:
            targetState = TARGET_STATE_ACKNOWLEDGED

        self._report_target_result(
            snmpEngine,
            notificationHandle,
            targetAddrName,
            targetState,
            errorIndication,
            pdu,
            targetCbFun,
            targetCbCtx,
        )

        if not pendingTargets:
            debug.logger & debug.FLAG_APP and debug.logger(
                "processResponseVarBinds: notificationHandle {}, sendRequestHandle {} -- completed".format(
                    notificationHandle, sendRequestHandle
                )
            )
            del self.__pendingNotifications[notificationHandle]
            if cbFun is not None:
                cbFun(
                    snmpEngine,
                    sendRequestHandle,
                    errorIndication,
                    pdu and v2c.apiPDU.get_error_status(pdu) or 0,
                    pdu and v2c.apiPDU.get_error_index(pdu, muteErrors=True) or 0,
                    pdu and v2c.apiPDU.get_varbinds(pdu) or (),
                    cbCtx,
                )

    @staticmethod
    def _filter_entry_matches(oid, subtree, mask):
        """Return True if OID matches a snmpNotifyFilter entry (RFC 3413 s.6)."""
        if len(oid) < len(subtree):
            return False

        for index, subIdentifier in enumerate(subtree):
            # A zero bit wildcards the corresponding sub-identifier.
            if index // 8 < len(mask) and not (
                mask[index // 8] & (0x80 >> (index % 8))
            ):
                continue
            if oid[index] != subIdentifier:
                return False

        return True

    def _is_allowed_by_filter_profile(self, filterEntries, varBinds, snmpTrapOID):
        """Apply RFC 3413 section 6 snmpNotifyFilterTable rules.

        The NOTIFICATION-TYPE OID (the value of the snmpTrapOID.0 varbind)
        must be specifically included, and none of the object instances may
        be specifically excluded. Matching entries are resolved by the most
        specific subtree, ties broken lexicographically.
        """
        included = 1
        excluded = 2

        def decide(oid):
            matching = [
                entry
                for entry in filterEntries
                if self._filter_entry_matches(oid, entry[0], entry[1])
            ]
            if not matching:
                return None
            # Longest subtree wins; on equal length, the lexicographically
            # largest instance wins (RFC 3413 section 6).
            matching.sort(key=lambda entry: (len(entry[0]), entry[0]))
            return matching[-1][2]

        notificationName = None
        for varName, varVal in varBinds:
            if varName == snmpTrapOID:
                notificationName = tuple(varVal)
                break

        # The notification name must be specifically included.
        if decide(notificationName) != included:
            return False

        for varName, varVal in varBinds:
            if varName == snmpTrapOID:
                continue
            # Object instances are included by default; only an explicit
            # exclusion drops the whole notification for this target.
            if decide(tuple(varName)) == excluded:
                return False

        return True

    def _is_allowed_by_vacm(
        self,
        snmpEngine: SnmpEngine,
        securityModel,
        securityName,
        securityLevel,
        contextName,
        varBinds,
        snmpTrapOID,
    ):
        """Apply the RFC 3413 section 3.3 steps (2) and (3) VACM checks."""
        for varName, varVal in varBinds:
            # Step (3): the NOTIFICATION-TYPE OID is checked separately.
            if varName == snmpTrapOID:
                checkedName = tuple(varVal)
            else:
                checkedName = varName
            try:
                snmpEngine.access_control_model[self.ACM_ID].is_access_allowed(
                    snmpEngine,
                    securityModel,
                    securityName,
                    securityLevel,
                    "notify",
                    contextName,
                    checkedName,
                )
            except error.StatusInformation:
                debug.logger & debug.FLAG_APP and debug.logger(
                    "sendVarBinds: VACM denied access for OID {} securityName {}".format(
                        checkedName, securityName
                    )
                )
                return False

        return True

    def _report_target_result(
        self,
        snmpEngine: SnmpEngine,
        notificationHandle,
        targetAddrName,
        targetState,
        errorIndication,
        pdu,
        targetCbFun,
        targetCbCtx,
    ):
        """Invoke the per-target callback exactly once with a terminal state."""
        if targetCbFun is None:
            return

        targetCbFun(
            snmpEngine,
            notificationHandle,
            targetAddrName,
            targetState,
            errorIndication,
            pdu and v2c.apiPDU.get_varbinds(pdu) or (),
            targetCbCtx,
        )


    #
    # Higher-level API to Notification Originator. Supports multiple
    # targets, automatic var-binding formation and is fully LCD-driven.
    #
    def send_varbinds(
        self,
        snmpEngine: SnmpEngine,
        notificationTarget,
        contextEngineId,
        contextName,
        varBinds: "tuple[ObjectType, ...]" = (),
        cbFun=None,
        cbCtx=None,
        targetCbFun=None,
        targetCbCtx=None,
    ):
        """Send SNMP notification to a target.

        Args:
            snmpEngine (SnmpEngine): SNMP engine that is sending the notification.
            notificationTarget (str): Target name as configured at the SNMP engine.
            contextEngineId (str): SNMP engine ID of the context to send notification in.
            contextName (str): SNMP context name to send notification in.
            varBinds (tuple): SNMP variable bindings to send.
            cbFun (callable): Completion callback invoked once after every
                Confirmed-Class (Inform) target has reached a terminal state.
            cbCtx (object): General-purpose data passed to ``cbFun``.
            targetCbFun (callable): Per-target callback invoked exactly once
                with the target's unique terminal state. Its arguments are
                ``(snmpEngine, notificationHandle, targetAddrName, state,
                errorIndication, varBinds, targetCbCtx)``.
            targetCbCtx (object): General-purpose data passed to ``targetCbFun``.

        Returns:
            int: Notification handle that can be used to cancel the notification.

        Raises:
            PySnmpError: If SNMP notification PDU requires SNMPv2-MIB::snmpTrapOID.0 to be present.
        """
        debug.logger & debug.FLAG_APP and debug.logger(
            'sendVarBinds: notificationTarget {}, contextEngineId {}, contextName "{}", varBinds {}'.format(
                notificationTarget,
                contextEngineId or "<default>",
                contextName,
                varBinds,
            )
        )

        mibBuilder = snmpEngine.get_mib_builder()

        (__SnmpAdminString,) = mibBuilder.import_symbols(
            "SNMP-FRAMEWORK-MIB", "SnmpAdminString"
        )
        # An empty (default) context name is a valid value and must be
        # normalized to SnmpAdminString too, otherwise VACM context lookup
        # fails to match the configured default context.
        if not isinstance(contextName, __SnmpAdminString):
            contextName = __SnmpAdminString(contextName or "")

        # 3.3
        notifyTag, notifyType = config.get_notification_info(
            snmpEngine, notificationTarget
        )

        notificationHandle = getNextHandle()

        debug.logger & debug.FLAG_APP and debug.logger(
            "sendVarBinds: notificationHandle %s, notifyTag %s, "
            "notifyType %s" % (notificationHandle, notifyTag, notifyType)
        )

        inputVarBinds = [(v2c.ObjectIdentifier(x), y) for (x, y) in varBinds]

        # 3.3.2 & 3.3.3
        snmpTrapOID, sysUpTime = mibBuilder.import_symbols(
            "__SNMPv2-MIB", "snmpTrapOID", "sysUpTime"
        )

        snmpTrapOID = snmpTrapOID.getName()
        sysUpTime, uptime = sysUpTime.getName(), sysUpTime.getSyntax()

        # Add sysUpTime if not present already
        if not inputVarBinds or inputVarBinds[0][0] != sysUpTime:
            inputVarBinds.insert(0, (v2c.ObjectIdentifier(sysUpTime), uptime.clone()))

        # Search for and reposition sysUpTime if it's elsewhere
        for idx, varBind in enumerate(inputVarBinds[1:]):
            if varBind[0] == sysUpTime:
                inputVarBinds[0] = varBind
                del inputVarBinds[idx + 1]
                break

        if len(inputVarBinds) < 2:
            raise error.PySnmpError(
                "SNMP notification PDU requires "
                "SNMPv2-MIB::snmpTrapOID.0 to be present"
            )

        # Search for and reposition snmpTrapOID if it's elsewhere
        for idx, varBind in enumerate(inputVarBinds[2:]):
            if varBind[0] == snmpTrapOID:
                del inputVarBinds[idx + 2]
                if inputVarBinds[1][0] == snmpTrapOID:
                    inputVarBinds[1] = varBind
                else:
                    inputVarBinds.insert(1, varBind)
                break

        if inputVarBinds[1][0] != snmpTrapOID:
            raise error.PySnmpError(
                "SNMP notification PDU requires "
                "SNMPv2-MIB::snmpTrapOID.0 to be present"
            )

        debug.logger & debug.FLAG_APP and debug.logger(
            f"sendVarBinds: final varBinds {varBinds}"
        )

        confirmedCount = 0
        firstErrorIndication = None

        # Filtering and authorization are evaluated independently for every
        # target. A rejection for one target never aborts the remaining
        # targets, and a rejected target is never handed to the transport.
        for targetAddrName in config.get_target_names(snmpEngine, notifyTag):
            (
                transportDomain,
                transportAddress,
                timeout,
                retryCount,
                params,
            ) = config.get_target_address(snmpEngine, targetAddrName)
            (
                messageProcessingModel,
                securityModel,
                securityName,
                securityLevel,
            ) = config.get_target_parameters(snmpEngine, params)

            debug.logger & debug.FLAG_APP and debug.logger(
                "sendVarBinds: notificationHandle {}, notifyTag {} yields: transportDomain {}, transportAddress {!r}, securityModel {}, securityName {}, securityLevel {}".format(
                    notificationHandle,
                    notifyTag,
                    transportDomain,
                    transportAddress,
                    securityModel,
                    securityName,
                    securityLevel,
                )
            )

            # 3.3 (1) + RFC 3413 section 6: snmpNotifyFilterTable profile
            # bound to this target's snmpTargetParams entry.
            profileName = config.get_notify_filter_profile_name(
                snmpEngine, params
            )
            if profileName is not None:
                filterEntries = config.get_notify_filters(
                    snmpEngine, profileName
                )
                if filterEntries and not self._is_allowed_by_filter_profile(
                    filterEntries, inputVarBinds, snmpTrapOID
                ):
                    debug.logger & debug.FLAG_APP and debug.logger(
                        "sendVarBinds: notify filter dropped notification for target {} securityName {}".format(
                            targetAddrName, securityName
                        )
                    )
                    self._report_target_result(
                        snmpEngine,
                        notificationHandle,
                        targetAddrName,
                        TARGET_STATE_FILTERED,
                        errind.notificationFiltered,
                        None,
                        targetCbFun,
                        targetCbCtx,
                    )
                    if firstErrorIndication is None:
                        firstErrorIndication = errind.notificationFiltered
                    continue

            # 3.3 (2) and (3): VACM notify view, covering every varbind and
            # the NOTIFICATION-TYPE OID from snmpTrapOID.0.
            if not self._is_allowed_by_vacm(
                snmpEngine,
                securityModel,
                securityName,
                securityLevel,
                contextName,
                inputVarBinds,
                snmpTrapOID,
            ):
                self._report_target_result(
                    snmpEngine,
                    notificationHandle,
                    targetAddrName,
                    TARGET_STATE_FILTERED,
                    errind.notificationFiltered,
                    None,
                    targetCbFun,
                    targetCbCtx,
                )
                if firstErrorIndication is None:
                    firstErrorIndication = errind.notificationFiltered
                continue

            # 3.3 (4): the full, unmodified variable-binding list is used.
            # Sensitive varbinds are never stripped to force a pass.
            if notifyType == 1:
                pdu = v2c.SNMPv2TrapPDU()
            elif notifyType == 2:
                pdu = v2c.InformRequestPDU()
            else:
                raise error.ProtocolError("Unknown notify-type %r", notifyType)

            v2c.apiPDU.set_defaults(pdu)
            v2c.apiPDU.set_varbinds(pdu, inputVarBinds)

            # 3.3 (5)/(6)
            try:
                sendRequestHandle = self.send_pdu(
                    snmpEngine,
                    targetAddrName,
                    contextEngineId,
                    contextName,
                    pdu,
                    self.process_response_varbinds,
                    (
                        notificationHandle,
                        targetAddrName,
                        targetCbFun,
                        targetCbCtx,
                        cbFun,
                        cbCtx,
                    ),
                )

            except error.StatusInformation:
                statusInformation = sys.exc_info()[1]
                debug.logger & debug.FLAG_APP and debug.logger(
                    "sendVarBinds: target {}: sendPdu() failed with {!r}".format(
                        targetAddrName, statusInformation
                    )
                )
                errorIndication = statusInformation["errorIndication"]
                self._report_target_result(
                    snmpEngine,
                    notificationHandle,
                    targetAddrName,
                    TARGET_STATE_FAILED,
                    errorIndication,
                    None,
                    targetCbFun,
                    targetCbCtx,
                )
                if firstErrorIndication is None:
                    firstErrorIndication = errorIndication
                continue

            debug.logger & debug.FLAG_APP and debug.logger(
                "sendVarBinds: notificationHandle %s, target %s, sendRequestHandle %s, timeout %d"
                % (notificationHandle, targetAddrName, sendRequestHandle, timeout)
            )

            if notifyType == 2:
                confirmedCount += 1
                self.__pendingNotifications.setdefault(
                    notificationHandle, {}
                )[sendRequestHandle] = targetAddrName
            else:
                # Unconfirmed-Class PDU: handoff to the transport is the
                # terminal state, distinct from an Inform acknowledgement.
                self._report_target_result(
                    snmpEngine,
                    notificationHandle,
                    targetAddrName,
                    TARGET_STATE_SENT,
                    None,
                    None,
                    targetCbFun,
                    targetCbCtx,
                )

        # All targets were filtered or failed before any Inform could be
        # tracked; resolve the completion callback instead of leaving callers
        # waiting. Trap completions remain driven by the caller, as before.
        if (
            notifyType == 2
            and confirmedCount == 0
            and notificationHandle not in self.__pendingNotifications
            and cbFun is not None
        ):
            cbFun(
                snmpEngine,
                notificationHandle,
                firstErrorIndication or errind.notificationFiltered,
                0,
                0,
                (),
                cbCtx,
            )

        debug.logger & debug.FLAG_APP and debug.logger(
            "sendVarBinds: notificationHandle {}, confirmed targets {}, notification(s) processed".format(
                notificationHandle, confirmedCount
            )
        )

        return notificationHandle


# XXX
# move/group/implement config setting/retrieval at a stand-alone module
