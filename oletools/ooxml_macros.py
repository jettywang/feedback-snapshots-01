#!/usr/bin/env python3

"""
Identity-preserving discovery of VBA macro projects inside OOXML packages.

The classic macro project in an OOXML (docx/xlsm/pptm/...) package is an OLE
compound file part, usually named ``word/vbaProject.bin``. Two ambiguities
make naive parsers silently pick the wrong bytes:

1. A ZIP archive may contain several *physical members* that claim the same
   part name. :py:meth:`zipfile.ZipFile.open` resolves a name to the last
   matching member, so the first copy is silently replaced. Here every
   physical member keeps its own identity (its :class:`zipfile.ZipInfo`) and
   is read through that identity, never through the possibly ambiguous name.

2. Whether a part is really a macro project is determined by two independent
   sources of truth: the content-type stream (``[Content_Types].xml``) and the
   package relationships (``*.rels``). They can contradict each other, and a
   part can be a perfectly valid OLE file without being referenced at all
   ("orphan"). Candidates are therefore classified separately as *explicit*,
   *conflicting* or *orphan* instead of collapsing onto a single winner.

Name normalisation (backslash to slash, leading slash removal, case folding)
is only used to compare names *inside* the package; it never merges two
physical members and never reaches outside the package. Nothing is ever read
from the host directory or from external relationship targets.
"""

import posixpath
import zipfile

import olefile

from oletools.common.log_helper import log_helper

logger = log_helper.get_or_create_silent_logger('ooxml_macros')

#: content type of a VBA macro project part, as declared in [Content_Types].xml
CTYPE_VBAPROJECT = 'application/vnd.ms-office.vbaProject'

#: relationship types that explicitly point at a VBA macro project part
REL_TYPES_VBAPROJECT = (
    'http://schemas.microsoft.com/office/2006/relationships/vbaProject',
    # Visio uses a versioned variant:
    'http://schemas.microsoft.com/visio/2010/relationships/vbaProject',
)

#: suffix used to recognise the relationship parts themselves
RELS_PART_SUFFIX = '.rels'

#: name of the package relationship part at the package root
ROOT_RELS_PART = '_rels/.rels'

#: name of the content-type stream part
CONTENT_TYPES_PART = '[Content_Types].xml'

# candidate classifications
CATEGORY_EXPLICIT = 'explicit'
CATEGORY_CONFLICT = 'conflict'
CATEGORY_ORPHAN = 'orphan'
CATEGORY_REJECTED = 'rejected'


def normalize_part_name(name):
    """Normalise a part name for comparison *within* a single package.

    The OPC names are case-insensitive and use forward slashes. Real-world
    files sometimes store backslashes or a leading slash. This normalisation is
    purely a comparison key: it never merges physical members and never leaves
    the package namespace.
    """
    if name is None:
        return ''
    normalized = name.replace('\\', '/')
    while normalized.startswith('/'):
        normalized = normalized[1:]
    return normalized.lower()


#: comparison keys, because normalize_part_name lower-cases names
CONTENT_TYPES_KEY = normalize_part_name(CONTENT_TYPES_PART)
ROOT_RELS_KEY = normalize_part_name(ROOT_RELS_PART)
RELS_PART_SUFFIX_KEY = normalize_part_name(RELS_PART_SUFFIX)


def _rel_type_matches(rel_type):
    """Return True if the relationship type denotes a VBA macro project."""
    if not rel_type:
        return False
    rel_type = rel_type.strip().lower()
    for known in REL_TYPES_VBAPROJECT:
        if rel_type == known:
            return True
    # tolerate versioned variants such as .../2007/relationships/vbaProject
    return rel_type.endswith('/relationships/vbaproject')


class MacroProjectCandidate(object):
    """A single physical ZIP member considered as a macro project candidate.

    The identity is the physical member (its :class:`zipfile.ZipInfo` plus its
    position in the archive), not the part name it claims.

    :ivar int member_index: position of the member in ``ZipFile.infolist()``
    :ivar zipfile.ZipInfo zip_info: the physical member descriptor
    :ivar str part_name: raw part name as stored in the archive
    :ivar str normalized_name: comparison key produced by
        :func:`normalize_part_name`
    :ivar str category: one of the ``CATEGORY_*`` constants
    :ivar list[str] reasons: human-readable evidence for the classification,
        one entry per fact (adoption or rejection reason)
    :ivar bool is_ole: whether the member bytes start with the OLE magic
    :ivar bool referenced: whether a relationship points to this member
    :ivar list[str] rel_sources: parts that hold a vbaProject relationship to
        this member
    :ivar list[str] content_type_evidence: how the content-type stream sees it:
        ``"vbaProject"``, ``"other:<type>"`` or ``"unknown"``
    :ivar int file_size: member size in bytes
    :ivar int crc: CRC32 stored in the ZIP header, useful to prove that two
        same-named members carry different bytes
    """

    def __init__(self, member_index, zip_info, is_ole):
        self.member_index = member_index
        self.zip_info = zip_info
        self.part_name = zip_info.filename
        self.normalized_name = normalize_part_name(zip_info.filename)
        self.is_ole = is_ole
        self.category = None
        self.reasons = []
        self.referenced = False
        self.rel_sources = []
        self.content_type_evidence = []
        self.file_size = zip_info.file_size
        self.crc = zip_info.CRC

    def display_name(self, duplicate=False):
        """Name for reports and sub-parser filenames.

        For a unique part name the plain part name is returned, so ordinary
        packages keep their familiar ``word/vbaProject.bin`` output. When
        several physical members claim the same name (``duplicate=True``) an
        unambiguous ``#index`` suffix is appended so no member is confused
        with another.
        """
        if duplicate:
            return '{0}#{1}'.format(self.part_name, self.member_index)
        return self.part_name

    def add_reason(self, reason):
        if reason not in self.reasons:
            self.reasons.append(reason)

    def read_bytes(self, zip_file):
        """Return the exact bytes of *this* physical member.

        The member is opened through its own :class:`zipfile.ZipInfo`, so even
        when several members share a name the returned bytes always come from
        the member this candidate represents.
        """
        return zip_file.open(self.zip_info).read()

    def __repr__(self):
        return 'MacroProjectCandidate({0}, category={1})'.format(
            self.display_name, self.category)


class OOXMLMacroDiscovery(object):
    """Discover and classify VBA macro project candidates in an OOXML package.

    :param zipfile.ZipFile zip_file: an open, readable ZIP archive
    """

    def __init__(self, zip_file):
        self.zip_file = zip_file
        #: physical members keyed by their position in infolist()
        self.candidates = []
        #: normalized part name -> list of member indices claiming that name
        self._name_to_indices = {}
        #: normalized target name -> list of (source part, relationship type)
        self._relationships = {}
        #: normalized part name -> list of declared content types
        self._content_types = {}
        #: normalized extension -> default content type (last wins per OPC rules)
        self._content_defaults = {}
        #: structural anomalies worth reporting (broken rels targets, ...)
        self.anomalies = []
        self._discovered = False
        #: member index -> unambiguous display name within the package
        self._display_names = {}

    # -- public API ---------------------------------------------------------

    def discover(self):
        """Run the full discovery. Idempotent: returns cached result."""
        if self._discovered:
            return self.candidates
        self._enumerate_members()
        self._parse_content_types()
        self._parse_relationships()
        self._classify()
        self._discovered = True
        return self.candidates

    def explicit_candidates(self):
        """Candidates explicitly referenced or declared as vbaProject."""
        return self._by_category(CATEGORY_EXPLICIT)

    def conflict_candidates(self):
        """Candidates whose identity or declaration is ambiguous/contradictory."""
        return self._by_category(CATEGORY_CONFLICT)

    def orphan_candidates(self):
        """OLE members that are neither referenced nor declared vbaProject."""
        return self._by_category(CATEGORY_ORPHAN)

    def rejected_candidates(self):
        """Members that looked like macro projects but cannot be used."""
        return self._by_category(CATEGORY_REJECTED)

    def adopted_candidates(self):
        """All candidates that should be parsed as macro project bytes."""
        return self.explicit_candidates() + self.conflict_candidates() + \
            self.orphan_candidates()

    def read_candidate_bytes(self, candidate):
        """Return the exact member bytes for ``candidate`` (see
        :meth:`MacroProjectCandidate.read_bytes`)."""
        return candidate.read_bytes(self.zip_file)

    def display_name(self, candidate):
        """Return the unambiguous in-package display name for ``candidate``."""
        return self._display_names.get(
            candidate.member_index, candidate.part_name)

    def _name(self, candidate):
        """Display name usable even before classification runs."""
        return self._display_names.get(
            candidate.member_index,
            candidate.display_name(self._is_duplicate(candidate)))

    def _is_duplicate(self, candidate):
        return len(self._name_to_indices.get(
            candidate.normalized_name, [])) > 1

    # -- enumeration --------------------------------------------------------

    def _enumerate_members(self):
        """List every physical member, testing each independently for OLE magic."""
        for index, zip_info in enumerate(self.zip_file.infolist()):
            name = zip_info.filename
            if name.endswith('/'):
                # directory entry, not a part
                continue
            is_ole = self._check_ole_magic(zip_info)
            candidate = MacroProjectCandidate(index, zip_info, is_ole)
            if is_ole:
                candidate.add_reason(
                    'member starts with the OLE compound file magic')
            self.candidates.append(candidate)
            self._name_to_indices.setdefault(
                candidate.normalized_name, []).append(index)

    def _check_ole_magic(self, zip_info):
        try:
            with self.zip_file.open(zip_info) as handle:
                magic = handle.read(len(olefile.MAGIC))
        except (zipfile.BadZipFile, RuntimeError, IOError) as exc:
            self.anomalies.append(
                'cannot read member {0}: {1}'.format(zip_info.filename, exc))
            return False
        return magic == olefile.MAGIC

    # -- content types ------------------------------------------------------

    def _parse_content_types(self):
        """Parse [Content_Types].xml, keeping every declaration even on dupes."""
        matches = [c for c in self.candidates
                   if c.normalized_name == CONTENT_TYPES_KEY]
        if not matches:
            self.anomalies.append(
                'package has no {0} part'.format(CONTENT_TYPES_PART))
            return
        if len(matches) > 1:
            self.anomalies.append(
                'package contains {0} physical {1} members; each is parsed '
                'separately'.format(len(matches), CONTENT_TYPES_PART))
        for candidate in matches:
            self._parse_one_content_types(candidate)

    def _parse_one_content_types(self, candidate):
        import xml.etree.ElementTree as ET
        try:
            data = self.zip_file.open(candidate.zip_info).read()
            root = ET.fromstring(data)
        except (ET.ParseError, ValueError, RuntimeError, IOError) as exc:
            self.anomalies.append(
                'cannot parse content types from member {0}: {1}'
                .format(self._name(candidate), exc))
            return
        for elem in root:
            tag = elem.tag.rsplit('}', 1)[-1]
            if tag == 'Default':
                extension = (elem.attrib.get('Extension') or '').lower()
                if extension.startswith('.'):
                    extension = extension[1:]
                content_type = elem.attrib.get('ContentType')
                if extension and content_type:
                    previous = self._content_defaults.get(extension)
                    if previous is not None and previous != content_type:
                        self.anomalies.append(
                            "conflicting default content types for extension "
                            "'.{0}': {1!r} vs {2!r}"
                            .format(extension, previous, content_type))
                    self._content_defaults[extension] = content_type
            elif tag == 'Override':
                part_name = normalize_part_name(elem.attrib.get('PartName'))
                content_type = elem.attrib.get('ContentType')
                if part_name and content_type:
                    self._content_types.setdefault(part_name, []) \
                        .append(content_type)

    def _content_type_for(self, candidate):
        """All content-type facts available for one physical member."""
        facts = []
        declared = self._content_types.get(candidate.normalized_name, [])
        for content_type in declared:
            facts.append(('vbaProject' if content_type == CTYPE_VBAPROJECT
                          else 'other:' + content_type, content_type))
        if not declared:
            extension = posixpath.splitext(candidate.normalized_name)[1]
            if extension.startswith('.'):
                extension = extension[1:]
            default = self._content_defaults.get(extension)
            if default is not None:
                facts.append(('vbaProject' if default == CTYPE_VBAPROJECT
                              else 'other:' + default, default))
        if not facts:
            facts.append(('unknown', None))
        return facts

    # -- relationships ------------------------------------------------------

    def _parse_relationships(self):
        """Parse every *.rels physical member; external targets are not fetched."""
        rels_members = [c for c in self.candidates
                        if self._is_rels_part(c.normalized_name)]
        for candidate in rels_members:
            self._parse_one_relationships(candidate)
        for normalized_target, references in self._relationships.items():
            for index in self._name_to_indices.get(normalized_target, []):
                target_candidate = self.candidates[index]
                target_candidate.referenced = True
                for source, rel_type in references:
                    if source not in target_candidate.rel_sources:
                        target_candidate.rel_sources.append(source)
            if normalized_target not in self._name_to_indices:
                for source, rel_type in references:
                    self.anomalies.append(
                        "vbaProject relationship from {0} points to missing "
                        "part {1!r}".format(source, normalized_target))

    @staticmethod
    def _is_rels_part(normalized_name):
        if normalized_name == ROOT_RELS_KEY:
            return True
        directory = posixpath.dirname(normalized_name)
        return posixpath.basename(directory) == '_rels' and \
            normalized_name.endswith(RELS_PART_SUFFIX_KEY)

    def _rels_source_directory(self, rels_normalized_name):
        """Directory that owns a relationship part, per OPC rules."""
        if rels_normalized_name == ROOT_RELS_KEY:
            return ''
        # word/_rels/document.xml.rels -> word/
        return posixpath.dirname(posixpath.dirname(rels_normalized_name))

    def _parse_one_relationships(self, candidate):
        import xml.etree.ElementTree as ET
        try:
            data = self.zip_file.open(candidate.zip_info).read()
            root = ET.fromstring(data)
        except (ET.ParseError, ValueError, RuntimeError, IOError) as exc:
            self.anomalies.append(
                'cannot parse relationships from member {0}: {1}'
                .format(self._name(candidate), exc))
            return
        source_directory = self._rels_source_directory(
            candidate.normalized_name)
        for elem in root:
            if elem.tag.rsplit('}', 1)[-1] != 'Relationship':
                continue
            rel_type = elem.attrib.get('Type', '')
            if not _rel_type_matches(rel_type):
                continue
            target_mode = (elem.attrib.get('TargetMode') or '').lower()
            target = elem.attrib.get('Target', '')
            rel_id = elem.attrib.get('Id', '?')
            if target_mode == 'external':
                # external targets live outside the package and must never be
                # fetched from the host or the network
                self.anomalies.append(
                    "external vbaProject relationship {0} in {1} targets "
                    "{2!r} and is not resolved".format(
                        rel_id, self._name(candidate), target))
                continue
            normalized_target = self._resolve_target(source_directory, target)
            if normalized_target is None:
                self.anomalies.append(
                    "vbaProject relationship {0} in {1} has invalid target "
                    "{2!r}".format(rel_id, self._name(candidate), target))
                continue
            self._relationships.setdefault(normalized_target, []).append(
                (self._name(candidate), rel_type))

    @staticmethod
    def _resolve_target(source_directory, target):
        """Resolve a relative relationship target inside the package only."""
        if not target:
            return None
        normalized = normalize_part_name(target)
        if source_directory:
            normalized = posixpath.join(source_directory, normalized)
        # Reject anything trying to leave the package root or address an
        # absolute location *before* normpath hides the traversal, so the host
        # filesystem is never touched to satisfy a relationship.
        segments = normalized.split('/')
        if '..' in segments:
            return None
        normalized = posixpath.normpath(normalized)
        if normalized == '.' or normalized.startswith('/'):
            return None
        return normalized

    # -- classification -----------------------------------------------------

    def _classify(self):
        for indices in self._name_to_indices.values():
            duplicate = len(indices) > 1
            for index in indices:
                self._display_names[index] = \
                    self.candidates[index].display_name(duplicate)
        for candidate in self.candidates:
            facts = self._content_type_for(candidate)
            candidate.content_type_evidence = [fact[0] for fact in facts]
            is_declared_vba = any(
                fact[0] == 'vbaProject' for fact in facts)
            has_other_type = any(
                fact[0].startswith('other:') for fact in facts)
            if candidate.referenced:
                candidate.add_reason(
                    'explicit vbaProject relationship from: '
                    + ', '.join(candidate.rel_sources))
            if is_declared_vba:
                candidate.add_reason(
                    'content type declares ' + CTYPE_VBAPROJECT)
            if has_other_type:
                for label, raw in facts:
                    if label.startswith('other:'):
                        candidate.add_reason(
                            'content type declares non-vbaProject type ' + raw)

            same_name = [self.candidates[i]
                         for i in self._name_to_indices.get(
                             candidate.normalized_name, [])]
            duplicate_name = len(same_name) > 1
            if duplicate_name:
                bytes_label = 'size={0.file_size}, crc32=0x{0.crc:08x}'.format(
                    candidate)
                candidate.add_reason(
                    '{0} physical members claim part name {1!r}; this one has '
                    '{2}'.format(len(same_name), candidate.part_name,
                                 bytes_label))

            # A contradiction is any disagreement about whether this part is a
            # macro project: two content types that disagree, or a macro
            # relationship/declaration facing a non-vbaProject content type.
            macro_claim = candidate.referenced or is_declared_vba
            contradictory_type = (is_declared_vba and has_other_type) or \
                (candidate.referenced and has_other_type)

            if not candidate.is_ole:
                # A member that cannot be an OLE container cannot carry a
                # parseable VBA project, even if relationships claim so.
                if macro_claim:
                    candidate.category = CATEGORY_REJECTED
                    candidate.add_reason(
                        'rejected: member does not start with the OLE '
                        'compound file magic')
                else:
                    # ordinary non-OLE part, not a candidate at all
                    candidate.category = CATEGORY_REJECTED
                continue

            if duplicate_name or contradictory_type:
                candidate.category = CATEGORY_CONFLICT
                if duplicate_name:
                    candidate.add_reason(
                        'conflict: duplicate part name, no member is dropped '
                        'or replaced')
                if contradictory_type:
                    candidate.add_reason(
                        'conflict: relationship/content-type evidence '
                        'disagrees about vbaProject status')
            elif macro_claim:
                candidate.category = CATEGORY_EXPLICIT
                candidate.add_reason('adopted: explicitly identified macro part')
            else:
                candidate.category = CATEGORY_ORPHAN
                candidate.add_reason(
                    'adopted as orphan: OLE member not referenced by any '
                    'relationship and without a vbaProject content type')

    def _by_category(self, category):
        return [c for c in self.candidates if c.category == category]
