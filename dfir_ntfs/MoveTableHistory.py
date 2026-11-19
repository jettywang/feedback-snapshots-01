# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module builds traceable move-history evidence from a MoveTable (tracking.log).

import hashlib
import json
import uuid
from collections import defaultdict, namedtuple
from .MoveTable import LOG_ENTRY_TYPE_MOVE_NOTIFICATION, LogEntry, MoveTableParser

REPORT_VERSION = 1
ENTRY_SIZE = 124
FOOTER_SIZE = 16
WRAP_MARKER = 0xFFFFFFFF

EventRecord = namedtuple('EventRecord', [ 'sector_index', 'sector_offset', 'slot_index', 'entry_offset', 'record', 'machine_id', 'window', 'window_status' ])

def FormatTimestamp(Timestamp):
	"""Format a datetime object as an ISO 8601 UTC string, or return None."""

	if Timestamp is None:
		return None

	return Timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def GuidToDict(Guid):
	"""Return a stable representation of a GUID, including its raw little-endian bytes."""

	version = Guid.version
	if version is None:
		version = 0

	return { 'text': str(Guid), 'version': version, 'bytes_le_hex': Guid.bytes_le.hex() }

def DroidToDict(Droid):
	"""Return a displayable representation of a DROID (volume field, object field)."""

	volume, file_object = Droid
	return { 'volume': GuidToDict(volume), 'object': GuidToDict(file_object) }

def ReadRawEntry(parser, entry_offset):
	"""Read a record again by offset and return raw bytes and their digest."""

	parser.file_object.seek(entry_offset)
	raw = parser.file_object.read(ENTRY_SIZE)

	return raw, { 'offset': entry_offset, 'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'raw_hex': raw.hex() }

def EntryDict(parser, event, Generation = None):
	"""Return every source-visible field of a single notification."""

	entry = event.record
	timestamp_lowest, timestamp_highest = entry.get_timestamp()
	object_id_timestamp, droid_timestamp, birth_droid_timestamp = entry.get_guid_timestamps()
	raw, source = ReadRawEntry(parser, event.entry_offset)

	return {
		'record_id': 'R{}:{}:{}'.format(Generation, entry.get_log_entry_index(), event.entry_offset),
		'index': entry.get_log_entry_index(),
		'previous_index': entry.get_previous_log_entry_index(),
		'next_index': entry.get_next_log_entry_index(),
		'type': entry.get_log_entry_type(),
		'machine_id': entry.get_machine_id(),
		'machine_id_raw_hex': entry.get_machine_id_raw().hex(),
		'object_id': GuidToDict(entry.get_object_id()),
		'droid': DroidToDict(entry.get_droid()),
		'birth_droid': DroidToDict(entry.get_birth_droid()),
		'record_time': {
			'lowest': FormatTimestamp(timestamp_lowest),
			'highest': FormatTimestamp(timestamp_highest),
			'clock': 'FILETIME-derived range from the low 32-bit timestamp field; not a GUID clock'
		},
		'guid_times': {
			'object_id': FormatTimestamp(object_id_timestamp),
			'droid_object': FormatTimestamp(droid_timestamp),
			'birth_droid_object': FormatTimestamp(birth_droid_timestamp),
			'clock': 'GUID v1 embedded time (1582 epoch); creation metadata, not the notification time'
		},
		'location': {
			'sector_index': event.sector_index,
			'sector_offset': event.sector_offset,
			'slot_index': event.slot_index,
			'entry_offset': event.entry_offset,
			'sector_window': event.window,
			'generation': Generation,
			'window_status': event.window_status
		},
		'source': source
	}

def BuildSectorWindows(parser):
	"""Read each sector footer and build its declared index window.
	The normal window is [lowest_present, next_index), where next_index is the
	next index to allocate. A value of 0xFFFFFFFF is a wrap marker, not an index."""

	windows = {}
	for sector_index, sector in enumerate(parser.log_sectors(), start = 1):
		footer = sector.get_footer()
		lowest = footer.get_lowest_log_entry_index_present()
		next_index = footer.get_next_log_entry_index()
		start = None if lowest == WRAP_MARKER else lowest
		end = None if next_index == WRAP_MARKER else next_index
		windows[sector_index] = {
			'lowest_present': lowest,
			'next_index': next_index,
			'start': start,
			'end_exclusive': end,
			'end_inclusive': None if end is None else end - 1,
			'has_wrap_marker': lowest == WRAP_MARKER or next_index == WRAP_MARKER,
			'inverted': start is not None and end is not None and start > end,
			'footer_offset': sector_index * parser.sector_size + parser.sector_size - FOOTER_SIZE
		}

	return windows

def WindowStatus(Index, Window):
	"""Classify an index against its sector's declared valid window."""

	if Window['has_wrap_marker']:
		return 'wrap-marker-boundary'

	start, end = Window['start'], Window['end_exclusive']
	if Window['inverted']:
		return 'inverted-window'
	if start is None or end is None:
		return 'unknown-window'
	if Index < start:
		return 'below-window'
	if Index >= end:
		return 'above-window'
	return 'inside-window'

def InputSize(file_object):
	"""Return the input size without relying on a mutable position."""

	current = file_object.tell()
	file_object.seek(0, 2)
	size = file_object.tell()
	file_object.seek(current)
	return size

def AnalyzeMoveTable(file_object, sector_size = None):
	"""Analyze a MoveTable and return a JSON-serializable evidence report.
	The report keeps direct notification edges separate from inferred continuity
	candidates and from records excluded by a sector's validity window."""

	parser = MoveTableParser(file_object, sector_size)
	header = parser.get_header()
	extended_header = header.get_extended_header()
	expansion_data = header.get_expansion_data()
	windows = BuildSectorWindows(parser)

	all_events = []
	sector_slots = defaultdict(list)

	unreadable_slots = []
	for sector_index, sector in enumerate(parser.log_sectors(), start = 1):
		window = windows[sector_index]
		pos = 0
		while pos + ENTRY_SIZE <= parser.sector_size - FOOTER_SIZE:
			slot_index = pos // ENTRY_SIZE
			entry_offset = sector_index * parser.sector_size + pos
			try:
				entry = LogEntry(sector.buf[pos : pos + ENTRY_SIZE])
			except Exception as exception:
				unreadable_slots.append({ 'sector_index': sector_index, 'slot_index': slot_index, 'entry_offset': entry_offset, 'error': str(exception) })
				sector_slots[sector_index].append({ 'slot_index': slot_index, 'offset': entry_offset, 'type': None, 'index': None, 'window_status': 'unreadable' })
				pos += ENTRY_SIZE
				continue

			entry_type = entry.get_log_entry_type()
			slot = { 'slot_index': slot_index, 'offset': entry_offset, 'type': entry_type, 'index': None, 'window_status': None }
			if entry_type == LOG_ENTRY_TYPE_MOVE_NOTIFICATION:
				slot['index'] = entry.get_log_entry_index()
				slot['window_status'] = WindowStatus(slot['index'], window)
				all_events.append(EventRecord(sector_index, sector_index * parser.sector_size, slot_index, entry_offset, entry, entry.get_machine_id(), window, slot['window_status']))
			sector_slots[sector_index].append(slot)
			pos += ENTRY_SIZE

	notifications = sorted(all_events, key = lambda event: event.entry_offset)
	in_window = [ event for event in notifications if event.window_status == 'inside-window' ]
	excluded = [ event for event in notifications if event.window_status != 'inside-window' ]

	# Repeated notifications are detected by their complete content, not by a
	# shared object ID alone. The first physical occurrence is retained.
	content_groups = defaultdict(list)
	for event in in_window:
		entry = event.record
		timestamps = entry.get_timestamp()
		key = (
			entry.get_log_entry_index(), entry.get_previous_log_entry_index(), entry.get_next_log_entry_index(),
			entry.get_machine_id(), str(entry.get_object_id()),
			str(entry.get_birth_droid()[0]), str(entry.get_birth_droid()[1]),
			str(entry.get_droid()[0]), str(entry.get_droid()[1]),
			timestamps[0], timestamps[1]
		)
		content_groups[key].append(event)

	duplicate_groups = []
	duplicate_offsets = set()
	for group in content_groups.values():
		if len(group) < 2:
			continue
		duplicate_groups.append({
			'representative_offset': group[0].entry_offset,
			'representative_index': group[0].record.get_log_entry_index(),
			'sources': [ event.entry_offset for event in group ],
			'indexes': [ event.record.get_log_entry_index() for event in group ]
		})
		duplicate_offsets.update(event.entry_offset for event in group[1:])

	# Keep physical order. After a wrap, a lower index is a new generation, not
	# an earlier record; sorting by index would silently reorder generations.
	physical = [ event for event in in_window if event.entry_offset not in duplicate_offsets ]

	issues = []
	for group in duplicate_groups:
		issues.append({ 'kind': 'duplicate-notification', 'index': group['representative_index'], 'sources': group['sources'], 'indexes': group['indexes'] })
	for slot in unreadable_slots:
		issues.append({ 'kind': 'unreadable-slot', 'sector_index': slot['sector_index'], 'slot_index': slot['slot_index'], 'source': slot['entry_offset'], 'error': slot['error'] })

	# A generation begins at 0 and increments whenever the physical sequence
	# steps backwards in index. Identifiers are (generation, index), never index
	# alone, so a post-wrap index 0 is distinct from the original index 0.
	generation_by_offset = {}
	wrap_events = []
	generation = 0
	previous = None
	for event in physical:
		if previous is not None:
			previous_index = previous.record.get_log_entry_index()
			current_index = event.record.get_log_entry_index()
			if current_index < previous_index:
				generation += 1
				wrap_events.append({
					'kind': 'logical-index-reset',
					'from_generation': generation - 1,
					'to_generation': generation,
					'from_index': previous_index,
					'to_index': current_index,
					'from_offset': previous.entry_offset,
					'to_offset': event.entry_offset
				})
		generation_by_offset[event.entry_offset] = generation
		previous = event

	ident_counts = defaultdict(list)
	for event in physical:
		ident_counts[(generation_by_offset[event.entry_offset], event.record.get_log_entry_index())].append(event)

	ambiguous_offsets = set()
	for ident, group in sorted(ident_counts.items()):
		if len(group) > 1:
			ambiguous_offsets.update(event.entry_offset for event in group)
			issues.append({ 'kind': 'duplicate-index', 'generation': ident[0], 'index': ident[1], 'sources': [ event.entry_offset for event in group ] })

	unique = [ event for event in physical if event.entry_offset not in ambiguous_offsets ]
	ambiguous_events = [ event for event in physical if event.entry_offset in ambiguous_offsets ]
	for event in ambiguous_events:
		issues.append({ 'kind': 'excluded-ambiguous-index', 'generation': generation_by_offset[event.entry_offset], 'index': event.record.get_log_entry_index(), 'source': event.entry_offset })

	ident_counts = defaultdict(list)
	for event in unique:
		ident_counts[(generation_by_offset[event.entry_offset], event.record.get_log_entry_index())].append(event)

	for event in unique:
		entry = event.record
		generation = generation_by_offset[event.entry_offset]
		index = entry.get_log_entry_index()
		previous_index = entry.get_previous_log_entry_index()
		next_index = entry.get_next_log_entry_index()
		generation_indexes = set(ident[1] for ident in ident_counts if ident[0] == generation)

		if previous_index not in generation_indexes:
			if previous_index != WRAP_MARKER and previous_index <= index:
				issues.append({ 'kind': 'missing-previous-record', 'generation': generation, 'index': index, 'previous_index': previous_index, 'source': event.entry_offset })

		if next_index not in generation_indexes:
			if next_index > index and next_index <= max(generation_indexes) + 1:
				issues.append({ 'kind': 'missing-next-record', 'generation': generation, 'index': index, 'next_index': next_index, 'source': event.entry_offset })

	for first, second in zip(unique, unique[1:]):
		first_generation = generation_by_offset[first.entry_offset]
		second_generation = generation_by_offset[second.entry_offset]
		if first_generation != second_generation:
			continue
		first_index = first.record.get_log_entry_index()
		second_index = second.record.get_log_entry_index()
		if second_index - first_index > 1:
			issues.append({ 'kind': 'index-gap', 'generation': first_generation, 'from_index': first_index, 'to_index': second_index, 'missing_indexes': second_index - first_index - 1, 'sources': [ first.entry_offset, second.entry_offset ] })
		if first.record.get_next_log_entry_index() != second_index:
			issues.append({ 'kind': 'link-mismatch', 'generation': first_generation, 'index': first_index, 'stored_next_index': first.record.get_next_log_entry_index(), 'next_present_index': second_index, 'source': first.entry_offset })

	# A stale slot is an in-file notification outside the window declared by its
	# own sector. Sector reuse is the direct evidence of a wrap/recycle boundary.
	stale_events = []
	for event in excluded:
		stale_events.append({ 'index': event.record.get_log_entry_index(), 'sector_index': event.sector_index, 'slot_index': event.slot_index, 'entry_offset': event.entry_offset, 'status': event.window_status })
		issues.append({ 'kind': 'excluded-slot', 'index': event.record.get_log_entry_index(), 'source': event.entry_offset, 'sector_index': event.sector_index, 'slot_index': event.slot_index, 'status': event.window_status })
	for event in ambiguous_events:
		stale_events.append({ 'index': event.record.get_log_entry_index(), 'sector_index': event.sector_index, 'slot_index': event.slot_index, 'entry_offset': event.entry_offset, 'status': 'ambiguous-index' })

	recycled_sectors = []
	for sector_index, slots in sorted(sector_slots.items()):
		stale = [ slot for slot in slots if slot['type'] == LOG_ENTRY_TYPE_MOVE_NOTIFICATION and slot['window_status'] != 'inside-window' ]
		if stale:
			recycled_sectors.append({
				'kind': 'sector-slot-reuse',
				'sector_index': sector_index,
				'valid_indexes': [ slot['index'] for slot in slots if slot['window_status'] == 'inside-window' ],
				'stale_indexes': [ slot['index'] for slot in stale ],
				'footer': windows[sector_index]
			})

	# One explicit notification is one observed edge: birth DROID -> current DROID.
	edges = []
	edge_by_offset = {}
	for event in unique:
		entry = event.record
		birth_volume, birth_object = entry.get_birth_droid()
		current_volume, current_object = entry.get_droid()
		object_id_timestamp, droid_timestamp, birth_timestamp = entry.get_guid_timestamps()
		caveats = []
		if birth_object == uuid.UUID(int = 0) or current_object == uuid.UUID(int = 0):
			caveats.append('nil DROID object field; identity is incomplete')
		if birth_object == current_object:
			caveats.append('DROID object fields are equal; only the volume field distinguishes this edge')
		if object_id_timestamp is not None and birth_timestamp is not None and object_id_timestamp != birth_timestamp:
			caveats.append('object-ID and birth-DROID GUID times differ; they are independent embedded identities')
		if entry.get_machine_id() != extended_header.machine_id:
			caveats.append('record machine differs from the header machine')

		edge = {
			'edge_id': 'E{}'.format(len(edges) + 1),
			'status': 'observed',
			'from': { 'droid': DroidToDict((birth_volume, birth_object)), 'record_index': entry.get_log_entry_index(), 'record_id': 'R{}:{}:{}'.format(generation_by_offset[event.entry_offset], entry.get_log_entry_index(), event.entry_offset), 'source': event.entry_offset },
			'to': { 'droid': DroidToDict((current_volume, current_object)), 'record_index': entry.get_log_entry_index(), 'record_id': 'R{}:{}:{}'.format(generation_by_offset[event.entry_offset], entry.get_log_entry_index(), event.entry_offset), 'source': event.entry_offset },
			'object_id': GuidToDict(entry.get_object_id()),
			'machine_id': entry.get_machine_id(),
			'cross_volume': birth_volume != current_volume,
			'caveats': caveats,
			'evidence_offset': event.entry_offset,
			'generation': generation_by_offset[event.entry_offset],
			'sector_index': event.sector_index,
			'slot_index': event.slot_index
		}
		edges.append(edge)
		edge_by_offset[event.entry_offset] = edge

	# Chains use observed edges. Two strengths are kept apart:
	# - exact: the successor's birth DROID equals the predecessor's current DROID;
	# - object-field: only the DROID object field matches, so the volume transition
	#   is inferred rather than observed.
	edge_order = sorted(edges, key = lambda edge: edge['evidence_offset'])
	chains = []
	chain_breaks = []
	candidates = []

	def BuildChains(ExactOnly):
		Built = []
		LastBreak = None
		Current = []
		for edge in edge_order:
			BreakReason = None
			if Current:
				PreviousEdge = Current[-1]
				PreviousIndex = PreviousEdge['from']['record_index']
				CurrentIndex = edge['from']['record_index']
				PreviousTo = PreviousEdge['to']['droid']
				CurrentFrom = edge['from']['droid']
				if PreviousEdge['generation'] != edge['generation']:
					BreakReason = 'generation-change'
				elif CurrentIndex < PreviousIndex:
					BreakReason = 'index-reset'
				elif CurrentIndex == PreviousIndex:
					BreakReason = 'duplicate-index'
				elif CurrentIndex - PreviousIndex > 1:
					BreakReason = 'missing-index'
				elif PreviousEdge['machine_id'] != edge['machine_id']:
					BreakReason = 'machine-change'
				elif ExactOnly and PreviousTo != CurrentFrom:
					BreakReason = 'unobserved-transition'
				elif not ExactOnly and PreviousTo['object']['text'] != CurrentFrom['object']['text']:
					BreakReason = 'unobserved-transition'

			if BreakReason is not None:
				Built.append(Current)
				if ExactOnly and BreakReason != 'generation-change':
					LastBreak = {
						'id': 'B{}'.format(len(chain_breaks) + 1),
						'reason': BreakReason,
						'from_index': Current[-1]['from']['record_index'],
						'to_index': edge['from']['record_index'],
						'from_edge': Current[-1]['edge_id'],
						'to_edge': edge['edge_id'],
						'from_offset': Current[-1]['evidence_offset'],
						'to_offset': edge['evidence_offset']
					}
					chain_breaks.append(LastBreak)
					candidates.append({
						'candidate_id': 'C{}'.format(len(candidates) + 1),
						'status': 'inferred',
						'kind': 'chain-continuation',
						'object_id': edge['object_id']['text'],
						'from_edge': Current[-1]['edge_id'],
						'to_edge': edge['edge_id'],
						'from_index': Current[-1]['from']['record_index'],
						'to_index': edge['from']['record_index'],
						'from_offset': Current[-1]['evidence_offset'],
						'to_offset': edge['evidence_offset'],
						'reasons': [ BreakReason, 'same object ID alone cannot prove a complete migration chain' ],
						'caveat': 'not an observed move; intermediate records may be missing or the records may be unrelated'
					})
				Current = []
			Current.append(edge)
		if Current:
			Built.append(Current)
		return Built

	exact_chains = BuildChains(True)
	object_chains = BuildChains(False)
	exact_chain_keys = set(tuple(edge['edge_id'] for edge in chain) for chain in exact_chains)
	chains = []
	for chain in object_chains:
		key = tuple(edge['edge_id'] for edge in chain)
		strength = 'exact' if key in exact_chain_keys else 'object-field'
		chains.append((chain, strength))

	# Shared-object-ID candidates are useful when DROID endpoints do not connect.
	# They are deliberately weak and never contribute edges to a chain.
	shared_object_groups = defaultdict(list)
	for edge in edge_order:
		shared_object_groups[edge['object_id']['text']].append(edge)
	for object_id, group in sorted(shared_object_groups.items()):
		for first, second in zip(group, group[1:]):
			if first['to']['droid'] == second['from']['droid']:
				continue
			if second['from']['record_index'] - first['from']['record_index'] == 1:
				continue
			candidates.append({
				'candidate_id': 'C{}'.format(len(candidates) + 1),
				'status': 'inferred',
				'kind': 'shared-object-id',
				'object_id': object_id,
				'from_edge': first['edge_id'],
				'to_edge': second['edge_id'],
				'from_index': first['from']['record_index'],
				'to_index': second['from']['record_index'],
				'from_offset': first['evidence_offset'],
				'to_offset': second['evidence_offset'],
				'reasons': [ 'same object ID is present on both records', 'DROID endpoints do not connect' ],
				'caveat': 'same object ID alone cannot prove a complete migration chain'
			})

	chain_fragments = []
	for chain_edges, strength in chains:
		chain_fragments.append({
			'chain_id': 'H{}'.format(len(chain_fragments) + 1),
			'status': 'fragment',
			'strength': strength,
			'from_record_id': chain_edges[0]['from']['record_id'],
			'to_record_id': chain_edges[-1]['to']['record_id'],
			'object_id': chain_edges[0]['object_id']['text'],
			'generation': chain_edges[0]['generation'],
			'from_index': chain_edges[0]['from']['record_index'],
			'to_index': chain_edges[-1]['to']['record_index'],
			'machines': sorted(set(edge['machine_id'] for edge in chain_edges)),
			'observed_edge_ids': [ edge['edge_id'] for edge in chain_edges ],
			'evidence_offsets': [ edge['evidence_offset'] for edge in chain_edges ],
			'caveat': 'fragment contains observed edges only; it is not a complete migration history' + ('' if strength == 'exact' else '; volume transitions are inferred from matching object fields')
		})

	machines = {}
	for event in unique:
		machine = event.machine_id
		if machine not in machines:
			machines[machine] = { 'machine_id': machine, 'machine_id_raw_hex': event.record.get_machine_id_raw().hex(), 'first_offset': event.entry_offset, 'records': 0, 'indexes': [] }
		machines[machine]['records'] += 1
		machines[machine]['indexes'].append(event.record.get_log_entry_index())

	report = {
		'report_version': REPORT_VERSION,
		'input': {
			'size': InputSize(file_object),
			'sector_size': parser.sector_size,
			'notification_size': ENTRY_SIZE,
			'sha256_note': 'each record source digest covers exactly its 124-byte notification slot'
		},
		'header': {
			'machine_id': extended_header.machine_id,
			'machine_id_raw_hex': header.buf[40:56].split(b'\x00', 1)[0].hex(),
			'volume_object_id': GuidToDict(extended_header.volume_object_id),
			'log_is_flushed': header.is_log_flushed(),
			'expansion': {
				'lowest_log_entry_index_present': expansion_data.lowest_log_entry_index_present,
				'highest_log_entry_index_present': expansion_data.highest_log_entry_index_present,
				'file_size': expansion_data.file_size
			}
		},
		'summary': {
			'machine_count': len(machines),
			'machines': sorted(machines.values(), key = lambda machine: machine['machine_id']),
			'notifications_in_file': len(notifications),
			'accepted_records': len(unique),
			'duplicate_notifications': sum(len(group['sources']) - 1 for group in duplicate_groups),
			'excluded_records': len(excluded),
			'observed_edges': len(edges),
			'inferred_candidates': len(candidates),
			'chain_fragments': len(chain_fragments),
			'chain_breaks': len(chain_breaks),
			'wrap_events': len(wrap_events),
			'recycled_sectors': len(recycled_sectors),
			'issue_count': len(issues)
		},
		'record_count_including_stale': len(notifications),
		'records': [ EntryDict(parser, event, generation_by_offset.get(event.entry_offset)) for event in unique ],
		'accepted_records': [ EntryDict(parser, event, generation_by_offset.get(event.entry_offset)) for event in unique ],
		'excluded_records': [ EntryDict(parser, event, 'excluded-stale') for event in excluded ] + [
			EntryDict(parser, event._replace(window_status = 'ambiguous-index'), generation_by_offset.get(event.entry_offset)) for event in ambiguous_events
		],
		'duplicate_notifications': [
			{ 'representative': EntryDict(parser, next(event for event in unique if event.entry_offset == group['representative_offset']), generation_by_offset.get(group['representative_offset'])), 'sources': [ EntryDict(parser, next(event for event in notifications if event.entry_offset == offset), generation_by_offset.get(offset)) for offset in group['sources'] ] }
			for group in duplicate_groups
		],
		'observed_edges': edges,
		'inferred_candidates': candidates,
		'chain_fragments': chain_fragments,
		'chain_breaks': chain_breaks,
		'wrap_events': wrap_events,
		'recycled_sectors': recycled_sectors,
		'excluded_slots': stale_events,
		'issues': issues,
		'sectors': [
			{ 'sector_index': sector_index, 'window': windows[sector_index], 'slots': sector_slots[sector_index] }
			for sector_index in sorted(windows)
		],
		'evidence_rules': [
			'An observed edge is exactly one notification birth-DROID -> current-DROID pair.',
			'An inferred candidate connects surviving records; it is not a move.',
			'GUID embedded time and record FILETIME range are separate clocks.',
			'A shared object ID or DROID alone does not prove a complete migration chain.',
			'Only notifications inside their own sector footer window enter the current history.',
			'Repeated notifications are collapsed by identical record content (index, links, machine, DROIDs, timestamps), retaining the first physical source.'
		]
	}

	return report

def RenderText(Report):
	"""Render a human-readable report with IDs and offsets for every statement."""

	lines = []
	lines.append('MoveTable migration evidence (report v{})'.format(Report['report_version']))
	lines.append('')
	lines.append('Header machine: {}'.format(Report['header']['machine_id']))
	lines.append('Header volume object ID: {}'.format(Report['header']['volume_object_id']['text']))
	lines.append('Sector size: {}; flushed: {}'.format(Report['input']['sector_size'], Report['header']['log_is_flushed']))
	lines.append('')
	def Plural(Count):
		return '' if Count == 1 else 's'

	lines.append('Summary: {} accepted, {} excluded, {} duplicate{}, {} observed edge{}, {} inferred candidate{}, {} chain fragment{}, {} break{}, {} wrap event{}, {} issue{}'.format(
		Report['summary']['accepted_records'], Report['summary']['excluded_records'],
		Report['summary']['duplicate_notifications'], Plural(Report['summary']['duplicate_notifications']),
		Report['summary']['observed_edges'], Plural(Report['summary']['observed_edges']),
		Report['summary']['inferred_candidates'], Plural(Report['summary']['inferred_candidates']),
		Report['summary']['chain_fragments'], Plural(Report['summary']['chain_fragments']),
		Report['summary']['chain_breaks'], Plural(Report['summary']['chain_breaks']),
		Report['summary']['wrap_events'], Plural(Report['summary']['wrap_events']),
		Report['summary']['issue_count'], Plural(Report['summary']['issue_count'])))
	lines.append('')

	lines.append('Machines:')
	for machine in Report['summary']['machines']:
		lines.append('  {} (raw {}): {} records at indexes {}; first offset {}'.format(
			machine['machine_id'], machine['machine_id_raw_hex'], machine['records'], machine['indexes'], machine['first_offset']))
	lines.append('')

	lines.append('Observed edges (birth DROID -> current DROID):')
	if not Report['observed_edges']:
		lines.append('  none')
	for edge in Report['observed_edges']:
		lines.append('  {} [observed] {} (volume {}) -> {} (volume {}), machine {}, record #{}, offset {}, sector {}/slot {}'.format(
			edge['edge_id'], edge['from']['droid']['object']['text'], edge['from']['droid']['volume']['text'],
			edge['to']['droid']['object']['text'], edge['to']['droid']['volume']['text'], edge['machine_id'],
			edge['from']['record_index'], edge['evidence_offset'], edge['sector_index'], edge['slot_index']))
		lines.append('    caveats: {}'.format('; '.join(edge['caveats']) if edge['caveats'] else 'none'))
	lines.append('')

	lines.append('Inferred candidates (not observed moves):')
	if not Report['inferred_candidates']:
		lines.append('  none')
	for candidate in Report['inferred_candidates']:
		lines.append('  {} [inferred] {} edges {} -> {}, records {} -> {}, offsets {} -> {}'.format(
			candidate['candidate_id'], candidate['kind'], candidate['from_edge'], candidate['to_edge'],
			candidate['from_index'], candidate['to_index'], candidate['from_offset'], candidate['to_offset']))
		lines.append('    reasons: {}'.format('; '.join(candidate['reasons'])))
	lines.append('')

	lines.append('Chain fragments:')
	for chain in Report['chain_fragments']:
		lines.append('  {} object {}, generation {}, indexes {} -> {}, machines {}, edges {}'.format(
			chain['chain_id'], chain['object_id'], chain['generation'], chain['from_index'], chain['to_index'],
			','.join(chain['machines']), ','.join(chain['observed_edge_ids'])))
	lines.append('')

	lines.append('Chain breaks:')
	if not Report['chain_breaks']:
		lines.append('  none')
	for chain_break in Report['chain_breaks']:
		lines.append('  {} {}: {} -> {} (edges {} -> {}) at offsets {} -> {}'.format(
			chain_break['id'], chain_break['reason'], chain_break['from_index'], chain_break['to_index'],
			chain_break['from_edge'], chain_break['to_edge'], chain_break['from_offset'], chain_break['to_offset']))
	lines.append('')

	lines.append('Wrap / recycle evidence:')
	if not Report['wrap_events']:
		lines.append('  none')
	for wrap in Report['wrap_events']:
		lines.append('  logical index reset generation {} -> {}: {} -> {} at offsets {} -> {}'.format(
			wrap['from_generation'], wrap['to_generation'], wrap['from_index'], wrap['to_index'],
			wrap['from_offset'], wrap['to_offset']))

	lines.append('')
	lines.append('Recycled sectors (stale slots excluded):')
	if not Report['recycled_sectors']:
		lines.append('  none')
	for recycled in Report['recycled_sectors']:
		lines.append('  sector {}: valid indexes {}, stale indexes {} (footer window [{}, {}))'.format(
			recycled['sector_index'], recycled['valid_indexes'], recycled['stale_indexes'],
			recycled['footer']['start'], recycled['footer']['end_exclusive']))
	lines.append('')

	lines.append('Excluded stale slots (never added to current history):')
	if not Report['excluded_records']:
		lines.append('  none')
	for record in Report['excluded_records']:
		location = record['location']
		lines.append('  record #{} generation {} offset {} sector {}/slot {}: {} (window [{}, {}))'.format(
			record['index'], location['generation'], location['entry_offset'], location['sector_index'], location['slot_index'],
			location['window_status'], location['sector_window']['start'], location['sector_window']['end_exclusive']))
	lines.append('')

	lines.append('Issues:')
	if not Report['issues']:
		lines.append('  none')
	for issue in Report['issues']:
		lines.append('  {}: {}'.format(issue['kind'], issue))
	lines.append('')

	lines.append('Per-record evidence:')
	for record in Report['records']:
		location = record['location']
		lines.append('  record #{} generation {} offset {} sector {}/slot {}: machine {}'.format(
			record['index'], location['generation'], location['entry_offset'], location['sector_index'], location['slot_index'], record['machine_id']))
		lines.append('    object ID: {}'.format(record['object_id']['text']))
		lines.append('    birth DROID: volume {} object {}'.format(record['birth_droid']['volume']['text'], record['birth_droid']['object']['text']))
		lines.append('    current DROID: volume {} object {}'.format(record['droid']['volume']['text'], record['droid']['object']['text']))
		lines.append('    links: previous {} next {}; record time {} - {}'.format(record['previous_index'], record['next_index'], record['record_time']['lowest'], record['record_time']['highest']))
		lines.append('    GUID times (separate clock): object {} droid {} birth {}'.format(record['guid_times']['object_id'], record['guid_times']['droid_object'], record['guid_times']['birth_droid_object']))
		lines.append('    source SHA-256: {}'.format(record['source']['sha256']))

	return '\n'.join(lines) + '\n'

def WriteJson(Report, output_file):
	"""Write a deterministic JSON report."""

	json.dump(Report, output_file, indent = 2, sort_keys = True)
	output_file.write('\n')
