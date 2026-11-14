#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from typing import TYPE_CHECKING

from pysnmp import debug
from pysnmp.proto import errind, error
from pysnmp.proto.acmod.vacm_access import (
    AccessDecision,
    AccessRow,
    RowSelection,
    select_access_row,
)
from pysnmp.smi.error import NoSuchInstanceError

if TYPE_CHECKING:
    from pysnmp.entity.engine import SnmpEngine


def _as_bytes(value):
    """Normalize an SNMP administrative string to bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


# 3.2
class Vacm:
    """View-based Access Control Model."""

    ACCESS_MODEL_ID = 3

    _power_of_two_sequences = (128, 64, 32, 16, 8, 4, 2, 1)

    def __init__(self):
        """Create a VACM instance."""
        self._contextBranchId = None
        self._groupNameBranchId = None
        self._accessBranchId = None
        self._viewTreeBranchId = None

        self._contextMap = {}
        self._groupNameMap = {}
        self._accessRows = {}
        self._viewTreeMap = {}

    def _add_access_entry(
        self,
        groupName,
        contextPrefix,
        securityModel,
        securityLevel,
        prefixMatch,
        readView,
        writeView,
        notifyView,
    ):
        group_name = _as_bytes(groupName) if groupName else b""

        if not group_name:
            return

        row = AccessRow(
            group_name=group_name,
            context_prefix=_as_bytes(contextPrefix),
            security_model=int(securityModel),
            security_level=int(securityLevel),
            context_match=int(prefixMatch),
            read_view=_as_bytes(readView),
            write_view=_as_bytes(writeView),
            notify_view=_as_bytes(notifyView),
        )

        self._accessRows.setdefault(group_name, []).append(row)

    @staticmethod
    def _table_columns(snmpEngine, *symbol_names):
        return snmpEngine.get_mib_builder().import_symbols(
            "SNMP-VIEW-BASED-ACM-MIB", *symbol_names
        )

    def _group_table_version(self, snmpEngine):
        """Return a revision covering every column of the group table.

        Writing a non-index column such as vacmGroupName bumps only that
        column's branch version, so a single column is not a sufficient
        cache key.
        """
        (
            vacmSecurityModel,
            vacmSecurityName,
            vacmGroupName,
            vacmSecurityToGroupStorageType,
            vacmSecurityToGroupStatus,
        ) = self._table_columns(
            snmpEngine,
            "vacmSecurityModel",
            "vacmSecurityName",
            "vacmGroupName",
            "vacmSecurityToGroupStorageType",
            "vacmSecurityToGroupStatus",
        )

        return tuple(
            column.branchVersionId
            for column in (
                vacmSecurityModel,
                vacmSecurityName,
                vacmGroupName,
                vacmSecurityToGroupStorageType,
                vacmSecurityToGroupStatus,
            )
        )

    def _access_table_version(self, snmpEngine):
        """Return a revision covering every column of vacmAccessTable."""
        columns = self._table_columns(
            snmpEngine,
            "vacmAccessContextPrefix",
            "vacmAccessSecurityModel",
            "vacmAccessSecurityLevel",
            "vacmAccessContextMatch",
            "vacmAccessReadViewName",
            "vacmAccessWriteViewName",
            "vacmAccessNotifyViewName",
            "vacmAccessStorageType",
            "vacmAccessStatus",
        )

        return tuple(column.branchVersionId for column in columns)

    def _view_tree_table_version(self, snmpEngine):
        """Return a revision covering every column of the view table."""
        columns = self._table_columns(
            snmpEngine,
            "vacmViewTreeFamilyViewName",
            "vacmViewTreeFamilySubtree",
            "vacmViewTreeFamilyMask",
            "vacmViewTreeFamilyType",
            "vacmViewTreeFamilyStorageType",
            "vacmViewTreeFamilyStatus",
        )

        return tuple(column.branchVersionId for column in columns)

    def _select_access_row(
        self, groupName, contextName, securityModel, securityLevel, viewType
    ) -> RowSelection:
        rows = self._accessRows.get(_as_bytes(groupName), ())

        return select_access_row(
            rows,
            _as_bytes(groupName),
            _as_bytes(contextName),
            int(securityModel),
            int(securityLevel),
            viewType,
        )

    def _is_variable_in_view(self, viewName, variableName) -> bool:
        try:
            entries = self._viewTreeMap[viewName]

        # RFC 3415, 3.2.5a: no view of that name exists.
        except KeyError:
            raise error.StatusInformation(errorIndication=errind.noSuchView)

        # RFC 3415, vacmViewTreeFamilyTable: the matching entry with the
        # most sub-identifiers wins; on equal length the greatest
        # vacmViewTreeFamilyType value (excluded) wins.
        bestKey = None
        accessAllowed = False

        for entry in entries:
            subtree, ignoredSubOids, mode = entry

            if ignoredSubOids:
                subOids = list(variableName)

                for ignoredSubOid in ignoredSubOids:
                    subOids[ignoredSubOid] = 0

                normalizedVariableName = subtree.clone(subOids)

            else:
                normalizedVariableName = variableName

            if subtree.isPrefixOf(normalizedVariableName):
                key = (len(subtree), int(mode))
                if bestKey is None or key >= bestKey:
                    bestKey = key
                    accessAllowed = mode == 1

        return accessAllowed

    def _refresh_contexts(self, snmpEngine):
        (vacmContextName,) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB", "vacmContextName"
        )

        if self._contextBranchId == vacmContextName.branchVersionId:
            return

        self._contextMap.clear()

        nextMibNode = vacmContextName

        while True:
            try:
                nextMibNode = vacmContextName.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            self._contextMap[_as_bytes(nextMibNode.syntax)] = True

        self._contextBranchId = vacmContextName.branchVersionId

    def _refresh_groups(self, snmpEngine):
        (vacmGroupName,) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB", "vacmGroupName"
        )

        version_id = self._group_table_version(snmpEngine)

        if self._groupNameBranchId == version_id:
            return

        (vacmSecurityToGroupEntry,) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB", "vacmSecurityToGroupEntry"
        )

        self._groupNameMap.clear()

        nextMibNode = vacmGroupName

        while True:
            try:
                nextMibNode = vacmGroupName.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            instId = nextMibNode.name[len(vacmGroupName.name) :]

            indices = vacmSecurityToGroupEntry.getIndicesFromInstId(instId)

            key = int(indices[0]), _as_bytes(indices[1])

            self._groupNameMap[key] = nextMibNode.syntax

        self._groupNameBranchId = version_id

    def _refresh_access_rows(self, snmpEngine):
        (vacmAccessStatus,) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB", "vacmAccessStatus"
        )

        version_id = self._access_table_version(snmpEngine)

        if self._accessBranchId == version_id:
            return

        (
            vacmAccessEntry,
            vacmAccessContextPrefix,
            vacmAccessSecurityModel,
            vacmAccessSecurityLevel,
            vacmAccessContextMatch,
            vacmAccessReadViewName,
            vacmAccessWriteViewName,
            vacmAccessNotifyViewName,
        ) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB",
            "vacmAccessEntry",
            "vacmAccessContextPrefix",
            "vacmAccessSecurityModel",
            "vacmAccessSecurityLevel",
            "vacmAccessContextMatch",
            "vacmAccessReadViewName",
            "vacmAccessWriteViewName",
            "vacmAccessNotifyViewName",
        )

        self._accessRows.clear()

        nextMibNode = vacmAccessStatus

        while True:
            try:
                nextMibNode = vacmAccessStatus.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            if nextMibNode.syntax != 1:  # active row
                continue

            instId = nextMibNode.name[len(vacmAccessStatus.name) :]

            indices = vacmAccessEntry.getIndicesFromInstId(instId)

            self._add_access_entry(
                indices[0],
                vacmAccessContextPrefix.getNode(
                    vacmAccessContextPrefix.name + instId
                ).syntax,
                vacmAccessSecurityModel.getNode(
                    vacmAccessSecurityModel.name + instId
                ).syntax,
                vacmAccessSecurityLevel.getNode(
                    vacmAccessSecurityLevel.name + instId
                ).syntax,
                vacmAccessContextMatch.getNode(
                    vacmAccessContextMatch.name + instId
                ).syntax,
                vacmAccessReadViewName.getNode(
                    vacmAccessReadViewName.name + instId
                ).syntax,
                vacmAccessWriteViewName.getNode(
                    vacmAccessWriteViewName.name + instId
                ).syntax,
                vacmAccessNotifyViewName.getNode(
                    vacmAccessNotifyViewName.name + instId
                ).syntax,
            )

        self._accessBranchId = version_id

    def _refresh_view_tree(self, snmpEngine):
        (vacmViewTreeFamilyViewName,) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB", "vacmViewTreeFamilyViewName"
        )

        version_id = self._view_tree_table_version(snmpEngine)

        if self._viewTreeBranchId == version_id:
            return

        (
            vacmViewTreeFamilySubtree,
            vacmViewTreeFamilyMask,
            vacmViewTreeFamilyType,
        ) = snmpEngine.get_mib_builder().import_symbols(  # type: ignore
            "SNMP-VIEW-BASED-ACM-MIB",
            "vacmViewTreeFamilySubtree",
            "vacmViewTreeFamilyMask",
            "vacmViewTreeFamilyType",
        )

        self._viewTreeMap.clear()

        powerOfTwo = [2**exp for exp in range(7, -1, -1)]

        nextMibNode = vacmViewTreeFamilyViewName

        while True:
            try:
                nextMibNode = vacmViewTreeFamilyViewName.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            viewName = _as_bytes(nextMibNode.syntax)

            if viewName not in self._viewTreeMap:
                self._viewTreeMap[viewName] = []

            instId = nextMibNode.name[len(vacmViewTreeFamilyViewName.name) :]

            subtree = vacmViewTreeFamilySubtree.getNode(
                vacmViewTreeFamilySubtree.name + instId
            ).syntax

            mask = vacmViewTreeFamilyMask.getNode(
                vacmViewTreeFamilyMask.name + instId
            ).syntax

            mode = vacmViewTreeFamilyType.getNode(
                vacmViewTreeFamilyType.name + instId
            ).syntax

            mask = mask.asNumbers()
            maskLength = min(len(mask) * 8, len(subtree))

            ignoredSubOids = [
                i * 8 + j
                for i, octet in enumerate(mask)
                for j, bit in enumerate(powerOfTwo)
                if not (bit & octet) and i * 8 + j < maskLength
            ]

            if ignoredSubOids:
                pattern = list(subtree)

                for ignoredSubOid in ignoredSubOids:
                    pattern[ignoredSubOid] = 0

                subtree = subtree.clone(pattern)

            entry = subtree, ignoredSubOids, mode

            self._viewTreeMap[viewName].append(entry)

        for entries in self._viewTreeMap.values():
            entries.sort(key=lambda x: (len(x[0]), x[0]))

        self._viewTreeBranchId = version_id

    def evaluate_access(
        self,
        snmpEngine: "SnmpEngine",
        securityModel,
        securityName,
        securityLevel,
        viewType,
        contextName,
        variableName,
    ) -> AccessDecision:
        """Evaluate VACM access and report how the decision was made.

        Implements the ``isAccessAllowed`` procedure of RFC 3415, 3.2,
        without raising for the normal allow/deny outcomes.  The returned
        :class:`AccessDecision` carries every eligible ``vacmAccessTable``
        candidate, the selected row, the priority that selected it, the
        selected row's view name for the requested view type and whether
        ``variableName`` is covered by that view.
        """
        debug.logger & debug.FLAG_ACL and debug.logger(
            "isAccessAllowed: securityModel %s, securityName %s, "
            "securityLevel %s, viewType %s, contextName %s for "
            "variableName %s"
            % (
                securityModel,
                securityName,
                securityLevel,
                viewType,
                contextName,
                variableName,
            )
        )

        if viewType not in ("read", "write", "notify"):
            raise ValueError(f"Unsupported view type {viewType!r}")

        context_name = _as_bytes(contextName)

        decision_kwargs = dict(
            security_model=int(securityModel),
            security_name=_as_bytes(securityName),
            security_level=int(securityLevel),
            view_type=viewType,
            context_name=context_name,
            variable_name=tuple(variableName),
        )

        def deny(errorIndication, reason, selection=None):
            return AccessDecision(
                **decision_kwargs,
                eligible=selection.eligible if selection else (),
                selected=selection.selected if selection else None,
                basis=selection.basis if selection else None,
                view_name=selection.view_name if selection else None,
                allowed=False,
                error_indication=errorIndication,
                reason=reason,
            )

        # 3.2.1
        self._refresh_contexts(snmpEngine)

        if context_name not in self._contextMap:
            decision = deny(errind.noSuchContext, "unknown-context")
            self._log_decision(decision)
            return decision

        # 3.2.2
        self._refresh_groups(snmpEngine)

        try:
            groupName = self._groupNameMap[
                (int(securityModel), _as_bytes(securityName))
            ]

        except KeyError:
            decision = deny(errind.noGroupName, "unknown-group")
            self._log_decision(decision)
            return decision

        # 3.2.3
        self._refresh_access_rows(snmpEngine)

        selection = self._select_access_row(
            groupName, context_name, securityModel, securityLevel, viewType
        )

        if selection.selected is None:
            decision = deny(errind.noAccessEntry, "no-eligible-row", selection)
            self._log_decision(decision)
            return decision

        # 3.2.4 / 3.2.5a
        if not selection.view_name:
            decision = deny(errind.noSuchView, "empty-view", selection)
            self._log_decision(decision)
            return decision

        self._refresh_view_tree(snmpEngine)

        try:
            allowed = self._is_variable_in_view(
                selection.view_name, tuple(variableName)
            )

        except error.StatusInformation:
            decision = deny(errind.noSuchView, "unknown-view", selection)
            self._log_decision(decision)
            return decision

        if not allowed:
            decision = deny(errind.notInView, "not-in-view", selection)

        else:
            decision = AccessDecision(
                **decision_kwargs,
                eligible=selection.eligible,
                selected=selection.selected,
                basis=selection.basis,
                view_name=selection.view_name,
                allowed=True,
                error_indication=errind.accessAllowed,
                reason="allowed",
            )

        self._log_decision(decision)

        return decision

    @staticmethod
    def _log_decision(decision):
        """Log the candidates, winner, basis and result of a decision."""
        debug.logger & debug.FLAG_ACL and debug.logger(
            "isAccessAllowed: eligible %s, selected %s, basis %s, "
            "view %s, result %s"
            % (
                decision.eligible,
                decision.selected,
                decision.basis.summary() if decision.basis else None,
                decision.view_name,
                decision.reason,
            )
        )

    def is_access_allowed(
        self,
        snmpEngine: "SnmpEngine",
        securityModel,
        securityName,
        securityLevel,
        viewType,
        contextName,
        variableName,
    ):
        """Check if access is allowed to requested MIB variable.

        Implements VACM check as per RFC 3415.

        Args:
            snmpEngine (SnmpEngine): SNMP engine.
            securityModel (int): SNMP security model ID.
            securityName (str): SNMP security name.
            securityLevel (int): SNMP security level.

            viewType (str): SNMP view type ('read', 'write', 'notify').
            contextName (str): SNMP context name.
            variableName (tuple): SNMP variable name.

        Raises:
            StatusInformation: If access is denied.
        """
        decision = self.evaluate_access(
            snmpEngine,
            securityModel,
            securityName,
            securityLevel,
            viewType,
            contextName,
            variableName,
        )

        if not decision.allowed:
            raise error.StatusInformation(errorIndication=decision.error_indication)
