#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
# Offline RPKI manifest view checker (RFC 6486).
#
"""Offline completeness checks for one RPKI publication point.

The manifest payload is taken as already authenticated.  This module decides
what may enter the trusted view of a local repository; it does not verify the
CMS signature, fetch anything, or discover files.  The candidate directory is
exactly the mapping supplied by the caller, and a file that is not listed on
the manifest can never enter the trusted view.

A file enters ``ManifestView.files`` only when the manifest lists it, its
content hashes correctly, and the manifest also accounts for every other
candidate file.  Files from two half-finished syncs can therefore each be
individually valid while the merged directory is consumable by neither.
"""

import datetime
import hashlib
import re

from collections.abc import Mapping

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import rfc4055
from pyasn1_modules import rfc6486


SHA256 = rfc4055.id_sha256

# Manifest-level defects make a manifest invalid under RFC 6486 section 4.4
# and section 6.1.  Directory-level defects are completeness problems at
# the publication point and must not cause fallback to an older manifest.
MANIFEST_LEVEL_CODES = frozenset([
    'manifest_version_invalid',
    'manifest_number_too_large',
    'manifest_thisupdate_invalid',
    'manifest_nextupdate_invalid',
    'manifest_interval_inverted',
    'manifest_not_yet_current',
    'manifest_stale',
    'manifest_hash_alg_unsupported',
    'manifest_filelist_empty',
    'manifest_file_name_invalid',
    'manifest_file_name_path',
    'manifest_hash_bitstring_length',
    'manifest_duplicate_file',
    'manifest_duplicate_name_conflict',
    'manifest_number_rollback',
    'manifest_number_conflict',
])

_TIME = re.compile(r'^([0-9]{14})Z$')
_PRINTABLE_ASCII = frozenset(range(0x20, 0x7f))


class ManifestViewError(Exception):
    """An input is unusable, as opposed to a manifest being invalid."""


class Issue(object):
    """One concrete defect.  Issues are never collapsed into a boolean."""

    def __init__(self, code, detail, filename=None):
        self.code = code
        self.detail = detail
        self.filename = filename

    def __eq__(self, other):
        return (isinstance(other, Issue) and
                (self.code, self.detail, self.filename) ==
                (other.code, other.detail, other.filename))

    def __hash__(self):
        return hash((self.code, self.detail, self.filename))

    def as_dict(self):
        return {'code': self.code, 'detail': self.detail,
                'filename': self.filename}

    def __repr__(self):
        return 'Issue(%r, %r, filename=%r)' % (
            self.code, self.detail, self.filename)

    def __str__(self):
        if self.filename is None:
            return '%s: %s' % (self.code, self.detail)
        return '%s: %s: %s' % (self.code, self.filename, self.detail)


class ManifestSnapshot(object):
    """Decoded manifest eContent with the fields used for checking."""

    def __init__(self, manifest):
        self.manifest = manifest
        self.version = int(manifest['version'])
        self.number = int(manifest['manifestNumber'])
        self.this_update = str(manifest['thisUpdate'])
        self.next_update = str(manifest['nextUpdate'])
        self.hash_alg = str(manifest['fileHashAlg'])
        self.entries = []

        for entry in manifest['fileList']:
            name = str(entry['file'])
            bits = entry['hash']
            self.entries.append((name, bits.asOctets(), len(bits)))

    @property
    def file_names(self):
        return [name for name, _, _ in self.entries]

    @property
    def digest(self):
        return hashlib.sha256(der_encoder(self.manifest)).hexdigest()


def decode_manifest(payload):
    """Strictly decode manifest eContent: DER only, nothing trailing."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ManifestViewError('manifest payload must be bytes')

    payload = bytes(payload)

    try:
        manifest, rest = der_decoder(payload, asn1Spec=rfc6486.Manifest())
    except Exception as exc:
        raise ManifestViewError('not valid DER: %s' % exc)

    if rest:
        raise ManifestViewError(
            'trailing octets after manifest: %d' % len(rest))

    if der_encoder(manifest) != payload:
        raise ManifestViewError('manifest encoding is not canonical DER')

    return manifest


def snapshot_manifest(payload):
    return ManifestSnapshot(decode_manifest(payload))


def parse_time(value):
    """Parse a canonical UTC GeneralizedTime as required by RFC 5280.

    Seconds must be present, the zone must be ``Z``, and fractional
    seconds are not allowed.
    """
    if not isinstance(value, str):
        raise ValueError('time must be a string')

    match = _TIME.match(value)
    if match is None:
        raise ValueError(
            'time %r is not the required YYYYMMDDHHMMSSZ form' % value)

    seconds = match.group(1)

    try:
        return datetime.datetime(
            int(seconds[0:4]), int(seconds[4:6]), int(seconds[6:8]),
            int(seconds[8:10]), int(seconds[10:12]), int(seconds[12:14]),
            tzinfo=datetime.timezone.utc)
    except ValueError:
        raise ValueError('time %r is not a valid calendar time' % value)


def format_time(value):
    return value.strftime('%Y%m%d%H%M%SZ')


def _expected_hash_length(hash_alg):
    if hash_alg == str(SHA256):
        return hashlib.sha256().digest_size
    return None


def _check_manifest_fields(snap, checked_at):
    issues = []

    if snap.version != 0:
        issues.append(Issue(
            'manifest_version_invalid',
            'version is %d, RFC 6486 requires 0' % snap.version))

    if (snap.number.bit_length() + 7) // 8 > 20:
        issues.append(Issue(
            'manifest_number_too_large',
            'manifestNumber needs more than the 20 octets allowed by '
            'RFC 6486'))

    try:
        this_update = parse_time(snap.this_update)
    except ValueError as exc:
        issues.append(Issue('manifest_thisupdate_invalid', str(exc)))
        this_update = None

    try:
        next_update = parse_time(snap.next_update)
    except ValueError as exc:
        issues.append(Issue('manifest_nextupdate_invalid', str(exc)))
        next_update = None

    if this_update is not None and next_update is not None:
        if not this_update < next_update:
            issues.append(Issue(
                'manifest_interval_inverted',
                'thisUpdate %s does not precede nextUpdate %s'
                % (snap.this_update, snap.next_update)))

        if checked_at < this_update:
            issues.append(Issue(
                'manifest_not_yet_current',
                'checked_at %s precedes thisUpdate %s'
                % (format_time(checked_at), snap.this_update)))

        if not checked_at < next_update:
            issues.append(Issue(
                'manifest_stale',
                'checked_at %s is not before nextUpdate %s'
                % (format_time(checked_at), snap.next_update)))

    return issues


def _check_hash_algorithm(snap):
    if _expected_hash_length(snap.hash_alg) is None:
        return [Issue(
            'manifest_hash_alg_unsupported',
            'fileHashAlg %s is not a supported RPKI hash algorithm'
            % snap.hash_alg)]
    return []


def _check_file_name(name):
    if not name:
        return [Issue('manifest_file_name_invalid', 'empty file name', name)]

    issues = []
    if not all(ord(ch) in _PRINTABLE_ASCII for ch in name):
        issues.append(Issue(
            'manifest_file_name_invalid',
            'file name contains non-printable or non-IA5 characters', name))

    if '/' in name or '\\' in name:
        issues.append(Issue(
            'manifest_file_name_path',
            'file name contains a path separator', name))
    elif name in ('.', '..'):
        issues.append(Issue(
            'manifest_file_name_path',
            'file name traverses outside the publication point', name))

    return issues


def _check_list_entries(snap):
    issues = []
    expected_length = _expected_hash_length(snap.hash_alg)
    seen = {}

    if not snap.entries:
        issues.append(Issue(
            'manifest_filelist_empty',
            'RFC 6486 requires a manifest to list at least the CRL'))

    for index, (name, digest, bits) in enumerate(snap.entries):
        issues.extend(_check_file_name(name))

        if (expected_length is not None
                and bits != expected_length * 8):
            issues.append(Issue(
                'manifest_hash_bitstring_length',
                'hash BIT STRING is %d bits, expected %d for the declared '
                'algorithm' % (bits, expected_length * 8), name))

        if name in seen:
            first_digest, first_index = seen[name]
            if digest != first_digest:
                issues.append(Issue(
                    'manifest_duplicate_name_conflict',
                    'file name repeated at entries %d and %d with different '
                    'hash content (%s then %s)'
                    % (first_index, index, first_digest.hex(),
                       digest.hex()), name))
            else:
                issues.append(Issue(
                    'manifest_duplicate_file',
                    'file name repeated at entries %d and %d with the same '
                    'hash' % (first_index, index), name))
        else:
            seen[name] = (digest, index)

    return issues


def _check_candidates(snap, candidates):
    issues = []
    listed = {}
    expected_length = _expected_hash_length(snap.hash_alg)

    for name, digest, _ in snap.entries:
        listed.setdefault(name, []).append(digest)

    for name in sorted(candidates):
        content = candidates[name]

        if name not in listed:
            issues.append(Issue(
                'directory_extra_file',
                'file is present in the candidate directory but is not '
                'listed on this manifest', name))
            continue

        if not isinstance(content, (bytes, bytearray)):
            issues.append(Issue(
                'candidate_content_invalid',
                'candidate content must be bytes, got %s'
                % type(content).__name__, name))
            continue

        if expected_length is None:
            continue

        actual = hashlib.sha256(bytes(content)).hexdigest()
        expected = sorted(set(digest.hex() for digest in listed[name]))

        if actual not in expected:
            issues.append(Issue(
                'directory_hash_mismatch',
                'content hashes to %s, manifest requires %s'
                % (actual, ', '.join(expected)), name))

    for name in sorted(listed):
        if name not in candidates:
            issues.append(Issue(
                'directory_missing_file',
                'file is listed on this manifest but is absent from the '
                'candidate directory', name))

    return issues


def _check_previous(previous, snap):
    if previous is None:
        return []

    if isinstance(previous, ManifestSnapshot):
        prev = previous
    else:
        try:
            prev = snapshot_manifest(previous)
        except ManifestViewError as exc:
            raise ManifestViewError('previous manifest is unusable: %s' % exc)

    if prev.number > snap.number:
        return [Issue(
            'manifest_number_rollback',
            'manifestNumber %d is older than the accepted manifestNumber %d'
            % (snap.number, prev.number))]

    if prev.number == snap.number and prev.digest != snap.digest:
        return [Issue(
            'manifest_number_conflict',
            'manifestNumber %d was reused with different content'
            % snap.number)]

    return []


class ManifestView(object):
    """The result for one manifest.

    ``state`` is ``verified``, ``rejected``, ``signature_invalid`` or
    ``undecodable``.  ``files`` is the closed, consumable set and is
    populated only for ``verified``.  ``missing`` and ``extra`` remain
    separate from hash mismatches and from manifest-level defects.
    """

    def __init__(self, snapshot=None, issues=None, candidates=None,
                 state=None):
        self.snapshot = snapshot
        self.issues = list(issues or [])
        self.state = state or ('verified' if not self.issues else 'rejected')
        self.files = {}

        listed = set()
        if snapshot is not None:
            listed = set(snapshot.file_names)

        supplied = set(candidates or ())

        self.listed = listed
        self.present = supplied
        self.missing = sorted(listed - supplied) if snapshot is not None else []
        self.extra = (sorted(supplied - listed)
                      if snapshot is not None else [])

        if self.state == 'verified':
            if self.issues or supplied != listed:
                raise ManifestViewError(
                    'verified views must account for every listed file')
            self.files = dict((name, bytes(candidates[name]))
                              for name in sorted(listed))

    @property
    def manifest_valid(self):
        """True when no defect invalidates the manifest itself.

        Directory completeness is deliberately excluded: an incomplete
        directory is not a reason to treat an otherwise valid manifest as
        absent.
        """
        if self.state in ('signature_invalid', 'undecodable'):
            return False
        return not any(issue.code in MANIFEST_LEVEL_CODES
                       for issue in self.issues)

    @property
    def directory_complete(self):
        return (self.state == 'verified')

    def issues_with(self, code):
        return [issue for issue in self.issues if issue.code == code]

    def as_dict(self):
        return {
            'state': self.state,
            'manifest_number': (None if self.snapshot is None
                                else self.snapshot.number),
            'manifest_digest': (None if self.snapshot is None
                                else self.snapshot.digest),
            'listed': sorted(self.listed),
            'present': sorted(self.present),
            'missing': self.missing,
            'extra': self.extra,
            'manifest_valid': self.manifest_valid,
            'verified_files': sorted(self.files),
            'issues': [issue.as_dict() for issue in self.issues],
        }

    def __repr__(self):
        return ('ManifestView(state=%r, number=%r, missing=%r, extra=%r, '
                'issues=%r)' % (
                    self.state,
                    None if self.snapshot is None else self.snapshot.number,
                    self.missing, self.extra, self.issues))


def evaluate(payload, candidates, previous=None, checked_at=None,
             signature_valid=True):
    """Check one authenticated manifest against a candidate directory.

    :param payload: DER eContent of the manifest.  The caller must already
        have checked the CMS eContentType is ``id-ct-rpkiManifest``; it is
        outside the eContent this function receives.
    :param candidates: mapping of file name to content bytes.  No other
        files exist for this check; there is no filesystem access.
    :param previous: previously accepted manifest payload or snapshot.
    :param checked_at: fixed canonical UTC GeneralizedTime string.
    :param signature_valid: caller-supplied signature result.  Passing
        ``False`` yields a distinct ``signature_invalid`` state and does
        not derive any file-level conclusion from the untrusted payload.
    :returns: :class:`ManifestView`.  Invalid manifests are reported in it
        rather than raised; only unusable arguments raise
        :class:`ManifestViewError`.
    """
    if checked_at is None:
        raise ManifestViewError('checked_at is required')

    try:
        checked = parse_time(checked_at)
    except ValueError as exc:
        raise ManifestViewError('checked_at is unusable: %s' % exc)

    if not isinstance(candidates, Mapping):
        raise ManifestViewError('candidates must be a mapping')

    for name in candidates:
        if not isinstance(name, str):
            raise ManifestViewError('candidate file names must be strings')

    if not isinstance(signature_valid, bool):
        raise ManifestViewError('signature_valid must be True or False')

    if not signature_valid:
        return ManifestView(
            issues=[Issue('manifest_signature_invalid',
                          'the manifest signature did not verify')],
            candidates=candidates, state='signature_invalid')

    try:
        manifest = decode_manifest(payload)
    except ManifestViewError as exc:
        return ManifestView(
            issues=[Issue('manifest_undecodable', str(exc))],
            candidates=candidates, state='undecodable')

    snap = ManifestSnapshot(manifest)
    issues = []
    issues.extend(_check_manifest_fields(snap, checked))
    issues.extend(_check_hash_algorithm(snap))
    issues.extend(_check_list_entries(snap))
    issues.extend(_check_candidates(snap, candidates))
    issues.extend(_check_previous(previous, snap))

    return ManifestView(snap, issues, candidates)


class GenerationView(object):
    """The result for the manifests of one publication point generation.

    ``consumable`` is a single verified :class:`ManifestView`, never a
    union of several manifests.  ``files`` mirrors that view or is empty.
    ``gaps`` preserves the per-manifest ``missing``/``extra`` sets,
    ``complete_numbers`` records which manifests happened to match the
    directory, and ``current_number`` is the manifest RFC 6486 section 6.1
    selects before completeness is considered.
    """

    def __init__(self, views, issues=None, consumable=None,
                 current_number=None, warnings=None):
        self.views = list(views)
        self.issues = list(issues or [])
        self.warnings = list(warnings or [])
        self.consumable = consumable
        self.current_number = current_number
        self.ignored_invalid_numbers = sorted(
            view.snapshot.number for view in self.views
            if view.snapshot is not None and not view.manifest_valid)
        self.state = 'verified' if consumable is not None else 'rejected'
        self.files = dict(consumable.files) if consumable is not None else {}
        self.gaps = dict(
            (view.snapshot.number, {'missing': view.missing,
                                    'extra': view.extra})
            for view in self.views if view.snapshot is not None)
        self.complete_numbers = sorted(
            view.snapshot.number for view in self.views
            if view.directory_complete)

    def view_for(self, manifest_number):
        for view in self.views:
            if (view.snapshot is not None and
                    view.snapshot.number == manifest_number):
                return view
        return None

    def as_dict(self):
        return {
            'state': self.state,
            'current_manifest_number': self.current_number,
            'complete_manifest_numbers': self.complete_numbers,
            'manifest_numbers': [
                None if view.snapshot is None else view.snapshot.number
                for view in self.views],
            'files': sorted(self.files),
            'gaps': self.gaps,
            'ignored_invalid_numbers': self.ignored_invalid_numbers,
            'issues': [issue.as_dict() for issue in self.issues],
            'warnings': [warning.as_dict() for warning in self.warnings],
            'manifests': [view.as_dict() for view in self.views],
        }

    def __repr__(self):
        return ('GenerationView(state=%r, current=%r, complete=%r, '
                'issues=%r)' % (
                    self.state, self.current_number,
                    self.complete_numbers, self.issues))


def evaluate_generation(manifests, candidates, previous=None,
                        checked_at=None, signature_valid=True):
    """Evaluate the manifests presented for one publication point.

    Each manifest is checked independently against the same directory.
    The current manifest is selected by ``manifestNumber`` among
    manifests that are valid at the manifest level, without consulting
    directory completeness.  A consumable view exists only when that
    current manifest matches the whole directory exactly.  An older
    manifest that happens to match is reported in ``complete_numbers``
    but never substituted, so a replayed old manifest cannot mask a
    newer one that fails to account for the directory.

    A directory assembled from pieces of several generations therefore
    produces rejected views and no consumable view.  A file may legitimately
    change content under the same name between generations; that is resolved
    by manifestNumber, not treated as an error.  Reusing one number for
    different content is an error rather than an ordering hint.  Manifests
    that are invalid at the manifest level are reported in ``views`` and
    listed in ``ignored_invalid_numbers``; they never suppress a valid
    current manifest, as required by RFC 6486 section 6.3.

    Do not pass historical manifests here; use ``previous`` for the
    previously accepted one.
    """
    views = [evaluate(payload, candidates, previous, checked_at,
                      signature_valid)
             for payload in manifests]

    valid = [view for view in views if view.manifest_valid]
    warnings = []
    if len(valid) != len(views):
        warnings.append(Issue(
            'generation_ignored_invalid_manifest',
            '%d supplied manifest(s) are invalid at the manifest level and '
            'were not eligible for selection'
            % (len(views) - len(valid))),)
    by_number = {}
    for view in valid:
        by_number.setdefault(view.snapshot.number, []).append(view)

    duplicate_numbers = [
        number for number, group in sorted(by_number.items())
        if len(set(view.snapshot.digest for view in group)) > 1]

    issues = []
    consumable = None
    current = None

    if not views:
        issues.append(Issue(
            'generation_no_manifest', 'no manifest was supplied'))
    elif not valid:
        issues.append(Issue(
            'generation_no_valid_manifest',
            'no supplied manifest is valid at the manifest level'))
    elif duplicate_numbers:
        issues.append(Issue(
            'generation_duplicate_manifest_number',
            'manifestNumber(s) %s are used by manifests with different '
            'content' % ', '.join(str(n) for n in duplicate_numbers)))
    else:
        current = max(valid, key=lambda view: view.snapshot.number)
        if not current.directory_complete:
            issues.append(Issue(
                'generation_current_manifest_incomplete',
                'current manifestNumber %d does not account for the '
                'candidate directory (missing=%s, extra=%s)'
                % (current.snapshot.number, current.missing, current.extra)))
        else:
            consumable = current

    return GenerationView(views, issues, consumable,
                          None if current is None
                          else current.snapshot.number, warnings)
