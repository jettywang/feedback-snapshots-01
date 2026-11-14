#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Pre-delivery admission check for RFC 4108 firmware packages.

Given the *authenticated* (signed) CMS attributes of a firmware package,
a device hardware identity and the device's currently installed manifest,
decide whether the package may be delivered to that device.  No firmware
is flashed or executed here; this is a pure applicability check performed
by the release backend before a signed package is pushed to a device.

The caller is responsible for CMS signature verification.  Only signed
attributes participate in decisions: unsigned (sidecar) attributes are
accepted for reporting purposes but can never widen the target scope.
"""

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from pyasn1_modules import rfc4108
from pyasn1_modules import rfc5652

__all__ = [
    'DeviceIdentity', 'InstalledPackage', 'AdmissionDecision',
    'check_package', 'check_batch', 'identifier_key',
    'DECISION_ATTRIBUTE_OIDS',
]

TARGET_HARDWARE_IDS = str(rfc4108.id_aa_targetHardwareIDs)
COMMUNITY_IDENTIFIERS = str(rfc4108.id_aa_communityIdentifiers)
FIRMWARE_PACKAGE_ID = str(rfc4108.id_aa_firmwarePackageID)
FIRMWARE_PACKAGE_INFO = str(rfc4108.id_aa_firmwarePackageInfo)

# Signed attributes that can influence an admission decision, in the
# order they are evaluated.
DECISION_ATTRIBUTE_OIDS = (
    TARGET_HARDWARE_IDS,
    COMMUNITY_IDENTIFIERS,
    FIRMWARE_PACKAGE_ID,
    FIRMWARE_PACKAGE_INFO,
)


class DeviceIdentity(object):
    """Hardware identity of a candidate target device."""

    def __init__(self, hw_type, hw_serial, community_oids=(),
                 supported_fw_pkg_types=None):
        self.hw_type = str(hw_type)
        self.hw_serial = bytes(hw_serial)
        self.community_oids = frozenset(str(oid) for oid in community_oids)
        self.supported_fw_pkg_types = (
            None if supported_fw_pkg_types is None
            else frozenset(int(t) for t in supported_fw_pkg_types)
        )

    def __repr__(self):
        return 'DeviceIdentity(hw_type=%r, hw_serial=%r)' % (
            self.hw_type, self.hw_serial)


class InstalledPackage(object):
    """One entry of a device's current installed-firmware manifest.

    ``dependencies`` mirrors the dependency declarations of the installed
    package; they are needed to detect dependency cycles and packages
    whose installation would break an existing dependent.
    """

    def __init__(self, name, dependencies=()):
        self.name = name
        self.dependencies = tuple(dependencies)

    def __repr__(self):
        return 'InstalledPackage(name=%r)' % (self.name,)


class AdmissionDecision(object):
    """Per-device outcome of an admission check.

    ``reasons`` holds every failure that was found (the check does not
    stop at the first one), so a batch run keeps an independent,
    self-contained justification for each device.
    """

    def __init__(self, device):
        self.device = device
        self.installable = False
        self.error_code = None
        self.reasons = []
        self.notes = []
        self.attributes_used = []
        self.ignored_unsigned = []

    def fail(self, error_code, reason):
        if self.error_code is None:
            self.error_code = error_code
        self.reasons.append('%s: %s' % (error_code, reason))

    def note(self, message):
        self.notes.append(message)

    def __repr__(self):
        return 'AdmissionDecision(installable=%r, error_code=%r, reasons=%r)' % (
            self.installable, self.error_code, self.reasons)


def identifier_key(identifier):
    """Hashable identity of a PreferredOrLegacyPackageIdentifier.

    Returns ``None`` when the CHOICE has no recognized alternative
    selected.  Callers must not fall back to string equality for such
    unknown identifier forms.
    """
    name = identifier.getName()
    if name == 'preferred':
        return 'preferred', str(identifier['preferred']['fwPkgID'])
    elif name == 'legacy':
        return 'legacy', bytes(identifier['legacy'])
    return None


def _preferred_version(identifier):
    if identifier.getName() == 'preferred':
        return int(identifier['preferred']['verNum'])
    return None


class _UndecodableValue(object):
    """A signed attribute value that does not match its known schema.

    Typically a CHOICE extension written by a newer peer.  It must never
    be treated as matchable by string equality.
    """


def _decode_signed_attrs(signed_attrs):
    """Map attribute OID -> list of decoded values for signed attributes."""
    decoded = {}
    for attr in signed_attrs:
        oid = str(attr['attrType'])
        spec = rfc5652.cmsAttributesMap.get(univ.ObjectIdentifier(oid))
        for any_value in attr['attrValues']:
            if spec is not None:
                substrate = der_encode(any_value)
                try:
                    value, _ = der_decode(substrate, asn1Spec=spec)
                except PyAsn1Error:
                    value = _UndecodableValue()
            else:
                value = any_value
            decoded.setdefault(oid, []).append(value)
    return decoded


def _serial_in_entries(hw_serial, entries):
    serial_num = int.from_bytes(hw_serial, 'big')
    for entry in entries:
        name = entry.getName()
        if name == 'all':
            return True
        elif name == 'single':
            if bytes(entry['single']) == hw_serial:
                return True
        elif name == 'block':
            low = int.from_bytes(bytes(entry['block']['low']), 'big')
            high = int.from_bytes(bytes(entry['block']['high']), 'big')
            if low <= serial_num <= high:
                return True
    return False


def _community_match(community_identifier, device):
    name = community_identifier.getName()
    if name == 'communityOID':
        return str(community_identifier['communityOID']) in device.community_oids
    elif name == 'hwModuleList':
        modules = community_identifier['hwModuleList']
        if str(modules['hwType']) != device.hw_type:
            return False
        return _serial_in_entries(device.hw_serial, modules['hwSerialEntries'])
    # Unknown community form: cannot prove membership.
    return False


def _dependency_cycle(own_key, own_dep_keys, manifest):
    """Return a cycle path (list of keys) or None."""
    graph = {own_key: [k for k in own_dep_keys if k is not None]}
    for entry in manifest:
        key = identifier_key(entry.name)
        if key is None:
            continue
        dep_keys = [identifier_key(d) for d in entry.dependencies]
        graph.setdefault(key, []).extend(k for k in dep_keys if k is not None)

    def visit(node, stack):
        if node in stack:
            return list(stack[stack.index(node):]) + [node]
        for nxt in graph.get(node, ()):
            cycle = visit(nxt, stack + (node,))
            if cycle is not None:
                return cycle
        return None

    return visit(own_key, ())


def _check_target_hardware(values, device, decision):
    if isinstance(values[0], _UndecodableValue):
        decision.fail(
            'wrongHardware',
            'targetHardwareIDs cannot be decoded: unrecognized identifier '
            'form; refusing to guess applicability by string equality')
        return
    allowed = [str(oid) for oid in values[0]]
    if device.hw_type not in allowed:
        decision.fail(
            'wrongHardware',
            'device hardware type %s is not in targetHardwareIDs %s'
            % (device.hw_type, allowed))


def _check_communities(values, device, decision):
    if isinstance(values[0], _UndecodableValue):
        decision.fail(
            'notInCommunity',
            'communityIdentifiers cannot be decoded: unrecognized '
            'identifier form; refusing to guess applicability by string '
            'equality')
        return
    if not any(_community_match(ci, device) for ci in values[0]):
        decision.fail(
            'notInCommunity',
            'device %s is not a member of any community in '
            'communityIdentifiers' % (device,))


def _check_package_identity(pkg_id, manifest, decision):
    """Validate the package name, its stale relation and self-conflicts.

    Returns (own_key, own_version); both are None when the identifier
    form is not recognized.
    """
    if isinstance(pkg_id, _UndecodableValue):
        decision.fail(
            'badFirmware',
            'firmwarePackageID cannot be decoded: unrecognized identifier '
            'form; refusing to guess applicability by string equality')
        return None, None
    name = pkg_id['name']
    own_key = identifier_key(name)
    if own_key is None:
        decision.fail(
            'badFirmware',
            'unrecognized firmware package identifier form %r; refusing '
            'to guess applicability by string equality' % (name.getName(),))
        return None, None

    own_version = _preferred_version(name)
    installed_same = [
        entry for entry in manifest
        if identifier_key(entry.name) == own_key
    ]

    if own_key[0] == 'preferred':
        for entry in installed_same:
            installed_ver = _preferred_version(entry.name)
            if installed_ver is not None and installed_ver >= own_version:
                decision.fail(
                    'stalePackage',
                    'installed version %s of %s conflicts with declared '
                    'package version %s (same or newer already installed)'
                    % (installed_ver, own_key[1], own_version))
    else:
        if installed_same:
            decision.fail(
                'stalePackage',
                'identical legacy package %r is already installed'
                % (own_key[1],))

    if pkg_id['stale'].isValue:
        stale = pkg_id['stale']
        stale_name = stale.getName()
        if stale_name == 'preferredStaleVerNum':
            if own_key[0] != 'preferred':
                decision.fail(
                    'badFirmware',
                    'preferred stale version declared for a legacy package '
                    'name: conflicting declaration')
            else:
                stale_ver = int(stale['preferredStaleVerNum'])
                for entry in installed_same:
                    installed_ver = _preferred_version(entry.name)
                    if installed_ver is not None and installed_ver >= stale_ver:
                        decision.fail(
                            'stalePackage',
                            'installed version %s of %s is at or beyond the '
                            'stale threshold %s'
                            % (installed_ver, own_key[1], stale_ver))
        elif stale_name == 'legacyStaleVersion':
            if own_key[0] != 'legacy':
                decision.fail(
                    'badFirmware',
                    'legacy stale version declared for a preferred package '
                    'name: conflicting declaration')
            else:
                stale_bytes = bytes(stale['legacyStaleVersion'])
                for entry in manifest:
                    key = identifier_key(entry.name)
                    if key is not None and key == ('legacy', stale_bytes):
                        decision.fail(
                            'stalePackage',
                            'installed legacy package matches the declared '
                            'stale version')
        else:
            decision.fail(
                'badFirmware',
                'unrecognized stale identifier form %r; freshness cannot '
                'be determined' % (stale_name,))

    return own_key, own_version


def _check_dependencies(own_key, own_version, dependencies, manifest, decision):
    dep_keys = []
    for dep in dependencies:
        dep_key = identifier_key(dep)
        dep_keys.append(dep_key)
        if dep_key is None:
            decision.fail(
                'missingDependency',
                'dependency uses an unrecognized identifier form %r; '
                'refusing to guess by string equality' % (dep.getName(),))
            continue
        candidates = [
            entry for entry in manifest
            if identifier_key(entry.name) == dep_key
        ]
        if dep_key[0] == 'preferred':
            required_ver = _preferred_version(dep)
            if not candidates:
                decision.fail(
                    'missingDependency',
                    'required package %s version >= %s is not installed'
                    % (dep_key[1], required_ver))
            else:
                installed_vers = [
                    _preferred_version(entry.name) for entry in candidates
                ]
                installed_vers = [v for v in installed_vers if v is not None]
                if not installed_vers or max(installed_vers) < required_ver:
                    decision.fail(
                        'wrongDependencyVersion',
                        'installed version of %s is older than the required '
                        'version %s' % (dep_key[1], required_ver))
        else:
            if not candidates:
                decision.fail(
                    'missingDependency',
                    'required legacy package %r is not installed'
                    % (dep_key[1],))

    if own_key is not None:
        cycle = _dependency_cycle(own_key, dep_keys, manifest)
        if cycle is not None:
            decision.fail(
                'badFirmware',
                'dependency cycle detected: %s'
                % ' -> '.join(str(key) for key in cycle))

def _check_breaks_dependency(own_key, own_version, manifest, decision):
    # Installing this package must not break a dependency that an
    # already-installed package declares on it.
    if own_key is None or own_version is None:
        return
    for entry in manifest:
        if identifier_key(entry.name) == own_key:
            continue
        for dep in entry.dependencies:
            if identifier_key(dep) != own_key:
                continue
            required_ver = _preferred_version(dep)
            if required_ver is not None and required_ver > own_version:
                decision.fail(
                    'breaksDependency',
                    'installed package %s requires %s version >= %s, '
                    'which this package (version %s) would violate'
                    % (identifier_key(entry.name), own_key[1],
                       required_ver, own_version))


def check_package(signed_attrs, device, manifest=(), unsigned_attrs=None):
    """Decide whether one firmware package may be delivered to one device.

    ``signed_attrs`` is an iterable of ``rfc5652.Attribute`` whose
    authenticity the caller has already established.  ``manifest`` is an
    iterable of ``InstalledPackage`` describing the device's current
    firmware.  ``unsigned_attrs`` are never consulted for the decision.
    """
    decision = AdmissionDecision(device)
    decoded = _decode_signed_attrs(signed_attrs)
    decision.attributes_used = [
        oid for oid in DECISION_ATTRIBUTE_OIDS if oid in decoded
    ]

    for attr in unsigned_attrs or ():
        oid = str(attr['attrType'])
        if oid in DECISION_ATTRIBUTE_OIDS:
            decision.ignored_unsigned.append(oid)
            decision.note(
                'unsigned attribute %s ignored: unauthenticated metadata '
                'cannot widen the target scope' % oid)

    values = decoded.get(TARGET_HARDWARE_IDS)
    if values:
        _check_target_hardware(values, device, decision)
    else:
        decision.note('targetHardwareIDs absent: no hardware-type constraint')

    values = decoded.get(COMMUNITY_IDENTIFIERS)
    if values:
        _check_communities(values, device, decision)
    else:
        decision.note('communityIdentifiers absent: no community constraint')

    own_key = own_version = None
    values = decoded.get(FIRMWARE_PACKAGE_ID)
    if values:
        own_key, own_version = _check_package_identity(
            values[0], manifest, decision)
    else:
        decision.fail(
            'badSignedAttrs',
            'firmwarePackageID absent: package identity and freshness '
            'cannot be verified')

    _check_breaks_dependency(own_key, own_version, manifest, decision)

    values = decoded.get(FIRMWARE_PACKAGE_INFO)
    if values:
        pkg_info = values[0]
        if isinstance(pkg_info, _UndecodableValue):
            decision.fail(
                'missingDependency',
                'firmwarePackageInfo cannot be decoded: dependencies '
                'cannot be verified')
            decision.installable = not decision.reasons
            return decision
        if (pkg_info['fwPkgType'].isValue
                and device.supported_fw_pkg_types is not None
                and int(pkg_info['fwPkgType'])
                not in device.supported_fw_pkg_types):
            decision.fail(
                'unsupportedPackageType',
                'firmware package type %s is not supported by the device'
                % int(pkg_info['fwPkgType']))
        if pkg_info['dependencies'].isValue:
            _check_dependencies(
                own_key, own_version, pkg_info['dependencies'],
                manifest, decision)
    else:
        decision.note('firmwarePackageInfo absent: no dependencies declared')

    decision.installable = not decision.reasons
    return decision


def check_batch(signed_attrs, devices, manifests=None, unsigned_attrs=None):
    """Check one package against many devices.

    Every device gets its own ``AdmissionDecision`` with its own reasons;
    a match on one device never authorizes the group.  ``manifests`` is
    either a single manifest shared by all devices or a list of
    manifests parallel to ``devices``.
    """
    decisions = []
    for index, device in enumerate(devices):
        if manifests is None:
            manifest = ()
        elif (isinstance(manifests, (list, tuple)) and manifests
                and isinstance(manifests[0], (list, tuple))):
            manifest = manifests[index]
        else:
            manifest = manifests
        decisions.append(
            check_package(signed_attrs, device, manifest, unsigned_attrs))
    return decisions
