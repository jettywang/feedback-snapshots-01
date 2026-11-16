# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module performs structure-aware mutation and validation of NTFS log
# record operation payloads (the client data decoded by LogFile.NTFSLogRecord).

import struct
import random

from dfir_ntfs import LogFile

# Size of the fixed part of an NTFS log record (all fields up to the LCN array).
NTFS_LOG_RECORD_FIXED_SIZE = 32

# Size of a single logical cluster number (LCN) entry in the trailing array.
LCN_ENTRY_SIZE = 8

# Operations capable of carrying a file name (and therefore a path change).
FILENAME_BEARING_OPERATIONS = [
	LogFile.UpdateFileNameRoot,
	LogFile.UpdateFileNameAllocation,
	LogFile.UpdateRecordDataRoot,
	LogFile.UpdateRecordDataAllocation
]

class LogMutationException(LogFile.LogFileException):
	"""This exception is raised when a structure-aware operation cannot be performed."""

	pass

class RangeOverlap(object):
	"""Relationship between two payload ranges."""

	NONE = 'none' # The ranges do not intersect.
	EMPTY = 'empty' # At least one of the ranges is empty.
	SHARED = 'shared' # Both ranges are non-empty and span exactly the same bytes.
	PARTIAL = 'partial' # The ranges are non-empty, intersect, but are not identical.

def align_up(value, alignment):
	"""Round an integer up to the nearest multiple of 'alignment'."""

	return (value + alignment - 1) // alignment * alignment

class PayloadRange(object):
	"""A redo or undo byte range described by an offset relative to the record start and a length."""

	def __init__(self, offset, length):
		if offset < 0 or length < 0:
			raise LogMutationException('Invalid payload range: {}, {}'.format(offset, length))

		self.offset = offset
		self.length = length

	def is_empty(self):
		return self.length == 0

	def end(self):
		return self.offset + self.length

	def overlaps(self, other):
		if self.is_empty() or other.is_empty():
			return RangeOverlap.EMPTY

		if self.offset == other.offset and self.length == other.length:
			return RangeOverlap.SHARED

		if self.end() <= other.offset or other.end() <= self.offset:
			return RangeOverlap.NONE

		return RangeOverlap.PARTIAL

	def as_tuple(self):
		return (self.offset, self.length)

	def __eq__(self, other):
		return self.offset == other.offset and self.length == other.length

	def __repr__(self):
		return 'PayloadRange(offset={}, length={})'.format(self.offset, self.length)

class VersionLayout(object):
	"""Version-specific layout of the log file surrounding an NTFS log record."""

	def __init__(self, major_version, minor_version, record_header_length, log_page_data_offset, sequence_number_bits):
		self.major_version = major_version
		self.minor_version = minor_version
		self.record_header_length = record_header_length
		self.log_page_data_offset = log_page_data_offset
		self.sequence_number_bits = sequence_number_bits

	def as_tuple(self):
		return (self.major_version, self.minor_version)

LAYOUT_V1_1 = VersionLayout(1, 1, LogFile.LogRecordHeader.sizeof, 64, 42)
LAYOUT_V2_0 = VersionLayout(2, 0, LogFile.LogRecordHeader.sizeof, 64, 43)

VERSION_LAYOUTS = {
	(1, 1): LAYOUT_V1_1,
	(2, 0): LAYOUT_V2_0,
	(3, 0): LAYOUT_V2_0
}

def get_version_layout(version_tuple):
	"""Return a VersionLayout object for a (major, minor) version tuple."""

	if version_tuple in VERSION_LAYOUTS.keys():
		return VERSION_LAYOUTS[version_tuple]

	raise LogMutationException('Unsupported log file version: {}'.format(version_tuple))

def lcn_data_base(lcns_to_follow):
	"""Return the first offset usable by redo/undo payload data for a given LCN array size."""

	return NTFS_LOG_RECORD_FIXED_SIZE + lcns_to_follow * LCN_ENTRY_SIZE

class RangeProblem(object):
	"""A single structural problem found while validating redo/undo ranges."""

	def __init__(self, kind, detail):
		self.kind = kind
		self.detail = detail

	def __eq__(self, other):
		return self.kind == other.kind and self.detail == other.detail

	def __repr__(self):
		return 'RangeProblem(kind={}, detail={!r})'.format(self.kind, self.detail)

class RangeValidationReport(object):
	"""Result of validating the redo/undo ranges of an NTFS log record payload."""

	def __init__(self, redo_range, undo_range, payload_length, lcns_to_follow, problems):
		self.redo_range = redo_range
		self.undo_range = undo_range
		self.payload_length = payload_length
		self.lcns_to_follow = lcns_to_follow
		self.problems = problems

	def is_valid(self):
		return len(self.problems) == 0

	def overlap(self):
		return self.redo_range.overlaps(self.undo_range)

def validate_ranges(payload, lcns_to_follow = None, redo_offset = None, redo_length = None, undo_offset = None, undo_length = None):
	"""Validate redo/undo ranges of an NTFS log record payload in a structure-aware way.

	Every non-empty range must start at an 8-byte-aligned offset at or beyond the LCN data
	region base and must end within the payload. Empty ranges are legal, and so are shared
	or partially overlapping ranges: overlap alone never invalidates a record.
	Return a RangeValidationReport object (it never raises for ordinary structural problems).
	"""

	if not isinstance(payload, (bytes, bytearray)):
		raise LogMutationException('Invalid payload type: {}'.format(type(payload)))

	if lcns_to_follow is None:
		lcns_to_follow = struct.unpack('<H', payload[14 : 16])[0]

	if redo_offset is None:
		redo_offset = struct.unpack('<H', payload[4 : 6])[0]

	if redo_length is None:
		redo_length = struct.unpack('<H', payload[6 : 8])[0]

	if undo_offset is None:
		undo_offset = struct.unpack('<H', payload[8 : 10])[0]

	if undo_length is None:
		undo_length = struct.unpack('<H', payload[10 : 12])[0]

	problems = []
	payload_length = len(payload)
	base = lcn_data_base(lcns_to_follow)

	if payload_length < base:
		problems.append(RangeProblem('truncated_payload', 'payload length {} is below the LCN data region base {}'.format(payload_length, base)))

	redo_range = PayloadRange(redo_offset, redo_length)
	undo_range = PayloadRange(undo_offset, undo_length)

	for name, payload_range in (('redo', redo_range), ('undo', undo_range)):
		if payload_range.is_empty():
			continue # An empty range never touches any bytes, its offset field is meaningless.

		if payload_length < base:
			continue

		if payload_range.offset < base:
			problems.append(RangeProblem('range_inside_header', '{} offset {} is below the data region base {}'.format(name, payload_range.offset, base)))
		elif payload_range.offset % 8 != 0:
			problems.append(RangeProblem('misaligned_offset', '{} offset {} is not aligned to 8 bytes'.format(name, payload_range.offset)))

		if payload_range.end() > payload_length:
			problems.append(RangeProblem('range_out_of_bounds', '{} range [{}:{}] exceeds the payload length {}'.format(name, payload_range.offset, payload_range.end(), payload_length)))

	return RangeValidationReport(redo_range, undo_range, payload_length, lcns_to_follow, problems)

def _pack_header(redo_operation, undo_operation, redo_offset, redo_length, undo_offset, undo_length,
	target_attribute, lcns_to_follow, record_offset, attribute_offset, cluster_block_offset,
	target_block_size, target_vcn):
	return struct.pack('<HHHHHHHHHHHHq',
		redo_operation & 0xFFFF,
		undo_operation & 0xFFFF,
		redo_offset & 0xFFFF,
		redo_length & 0xFFFF,
		undo_offset & 0xFFFF,
		undo_length & 0xFFFF,
		target_attribute & 0xFFFF,
		lcns_to_follow & 0xFFFF,
		record_offset & 0xFFFF,
		attribute_offset & 0xFFFF,
		cluster_block_offset & 0xFFFF,
		target_block_size & 0xFFFF,
		target_vcn)[: 32]

class MutatedRecord(object):
	"""A structure-aware mutation result: a new payload and the client data length wrapping it."""

	def __init__(self, payload, client_data_length, layout, strategy):
		self.payload = bytes(payload)
		self.client_data_length = client_data_length
		self.layout = layout
		self.strategy = strategy

	def validation_report(self):
		return validate_ranges(self.payload)

	def decode(self, lsn = 0, transaction_id = 0, cluster_size = LogFile.CLUSTER_SIZE_DEFAULT):
		"""Parse this mutation result back into a LogFile.NTFSLogRecord object."""

		return LogFile.NTFSLogRecord(self.payload, lsn, transaction_id, cluster_size)

class StructureAwareMutator(object):
	"""Build and mutate NTFS log record operation payloads while keeping every linked field coherent."""

	def __init__(self, layout = LAYOUT_V2_0, seed = None):
		if type(layout) is not VersionLayout:
			raise LogMutationException('Invalid version layout object')

		self.layout = layout
		self.random = random.Random(seed)

	@classmethod
	def from_record(cls, ntfs_log_record, layout = LAYOUT_V2_0, seed = None):
		"""Create a mutator seeded from a fully decodable LogFile.NTFSLogRecord object."""

		mutator = cls(layout, seed)
		mutator.original_payload = bytes(ntfs_log_record.buf)
		return mutator

	def build(self, redo_operation, undo_operation, redo_data, undo_data, lcns = None,
		target_attribute = 0, record_offset = 0, attribute_offset = 0, cluster_block_offset = 0,
		target_block_size = 0, target_vcn = 0, overlap = RangeOverlap.NONE):
		"""Build a coherent payload: header, LCN array and both ranges are laid out together."""

		if lcns is None:
			lcns = []

		if not isinstance(redo_data, (bytes, bytearray)) or not isinstance(undo_data, (bytes, bytearray)):
			raise LogMutationException('Redo and undo data must be byte strings')

		lcns_to_follow = len(lcns)
		base = lcn_data_base(lcns_to_follow)

		redo_length = len(redo_data)
		undo_length = len(undo_data)

		if redo_length == 0:
			redo_offset = 0
		else:
			redo_offset = base

		if undo_length == 0:
			undo_offset = 0
		elif overlap == RangeOverlap.SHARED and redo_length == undo_length and redo_length > 0:
			undo_offset = redo_offset
		elif overlap == RangeOverlap.PARTIAL and redo_length > 0 and undo_length > 0:
			undo_offset = align_up(max(base, redo_offset + redo_length // 2), 8)
		else:
			if undo_length > 0:
				undo_offset = align_up(redo_offset + redo_length, 8) if redo_length > 0 else base

		payload = bytearray()
		payload += _pack_header(redo_operation, undo_operation, redo_offset, redo_length, undo_offset, undo_length,
			target_attribute, lcns_to_follow, record_offset, attribute_offset, cluster_block_offset,
			target_block_size, target_vcn)

		for lcn in lcns:
			payload += struct.pack('<q', lcn)

		if redo_length > 0:
			if len(payload) != redo_offset:
				raise LogMutationException('Internal layout error at the redo range')

			payload += bytes(redo_data)

		if undo_length > 0:
			if overlap == RangeOverlap.SHARED and undo_offset == redo_offset:
				pass # The undo range shares the redo bytes.
			else:
				if undo_offset < len(payload):
					if overlap != RangeOverlap.PARTIAL:
						raise LogMutationException('Internal layout error at the undo range')

				if len(payload) < undo_offset:
					payload += b'\x00' * (undo_offset - len(payload))

				payload += bytes(undo_data)

		client_data_length = align_up(len(payload), 8)
		if len(payload) < client_data_length:
			payload += b'\x00' * (client_data_length - len(payload))

		report = validate_ranges(payload, lcns_to_follow, redo_offset, redo_length, undo_offset, undo_length)
		if not report.is_valid():
			raise LogMutationException('Built a payload failing its own validation: {}'.format([str(p) for p in report.problems]))

		return MutatedRecord(payload, client_data_length, self.layout, 'build')

	def _read_header(self, payload):
		fields = struct.unpack('<HHHHHHHHHHHH', payload[: 24])
		(target_vcn, ) = struct.unpack('<q', payload[24 : 32])
		return {
			'redo_operation': fields[0],
			'undo_operation': fields[1],
			'redo_offset': fields[2],
			'redo_length': fields[3],
			'undo_offset': fields[4],
			'undo_length': fields[5],
			'target_attribute': fields[6],
			'lcns_to_follow': fields[7],
			'record_offset': fields[8],
			'attribute_offset': fields[9],
			'cluster_block_offset': fields[10],
			'target_block_size': fields[11],
			'target_vcn': target_vcn
		}

	def _write_header(self, payload, header):
		payload[0 : 32] = _pack_header(header['redo_operation'], header['undo_operation'],
			header['redo_offset'], header['redo_length'], header['undo_offset'], header['undo_length'],
			header['target_attribute'], header['lcns_to_follow'], header['record_offset'],
			header['attribute_offset'], header['cluster_block_offset'], header['target_block_size'],
			header['target_vcn'])

	def resize_lcn_array(self, mutated_or_payload, new_lcns_to_follow, filler_lcn = -1):
		"""Grow or shrink the LCN array, moving every payload range and updating the total length."""

		payload = bytearray(self._as_payload(mutated_or_payload))
		header = self._read_header(payload)

		old_base = lcn_data_base(header['lcns_to_follow'])
		new_base = lcn_data_base(new_lcns_to_follow)
		delta = new_base - old_base

		if new_lcns_to_follow < 0:
			raise LogMutationException('Invalid LCN count: {}'.format(new_lcns_to_follow))

		old_lcns = self._extract_lcns(payload, header['lcns_to_follow'])
		redo = PayloadRange(header['redo_offset'], header['redo_length'])
		undo = PayloadRange(header['undo_offset'], header['undo_length'])

		data_region = bytes(payload[old_base : ])
		payload = payload[: NTFS_LOG_RECORD_FIXED_SIZE]

		for index in range(new_lcns_to_follow):
			lcn_value = old_lcns[index] if index < len(old_lcns) else filler_lcn
			payload += struct.pack('<q', lcn_value)

		payload += data_region

		header['lcns_to_follow'] = new_lcns_to_follow

		for name, payload_range in (('redo', redo), ('undo', undo)):
			if payload_range.is_empty():
				continue

			new_offset = payload_range.offset + delta
			if new_offset < new_base or new_offset % 8 != 0:
				raise LogMutationException('Cannot move the {} range coherently'.format(name))

			if name == 'redo':
				header['redo_offset'] = new_offset
			else:
				header['undo_offset'] = new_offset

		self._write_header(payload, header)

		client_data_length = align_up(len(payload), 8)
		if len(payload) < client_data_length:
			payload += b'\x00' * (client_data_length - len(payload))

		report = validate_ranges(payload)
		if not report.is_valid():
			raise LogMutationException('Mutation produced an invalid payload: {}'.format([str(p) for p in report.problems]))

		return MutatedRecord(payload, client_data_length, self.layout, 'resize_lcn_array')

	def relayout_ranges(self, mutated_or_payload, overlap):
		"""Re-pack redo/undo data with a requested overlap relationship, updating offsets and length."""

		payload = bytearray(self._as_payload(mutated_or_payload))
		header = self._read_header(payload)

		redo_data = self._extract_range(payload, header['redo_offset'], header['redo_length'])
		undo_data = self._extract_range(payload, header['undo_offset'], header['undo_length'])

		return self.build(header['redo_operation'], header['undo_operation'], redo_data, undo_data,
			lcns = self._extract_lcns(payload, header['lcns_to_follow']),
			target_attribute = header['target_attribute'],
			record_offset = header['record_offset'],
			attribute_offset = header['attribute_offset'],
			cluster_block_offset = header['cluster_block_offset'],
			target_block_size = header['target_block_size'],
			target_vcn = header['target_vcn'],
			overlap = overlap)

	def resize_range(self, mutated_or_payload, name, new_length):
		"""Change one range length while keeping its relative base (offset) and the total length coherent."""

		if name not in ('redo', 'undo'):
			raise LogMutationException('Invalid range name: {}'.format(name))

		payload = bytearray(self._as_payload(mutated_or_payload))
		header = self._read_header(payload)

		offset_key = name + '_offset'
		length_key = name + '_length'
		other_name = 'undo' if name == 'redo' else 'redo'
		other_offset_key = other_name + '_offset'
		other_length_key = other_name + '_length'

		old_length = header[length_key]
		offset = header[offset_key]

		if new_length < 0:
			raise LogMutationException('Invalid range length: {}'.format(new_length))

		if new_length == old_length:
			return MutatedRecord(payload, align_up(len(payload), 8), self.layout, 'resize_range')

		if new_length == 0:
			header[offset_key] = 0
			header[length_key] = 0
			self._write_header(payload, header)
			return MutatedRecord(payload, align_up(len(payload), 8), self.layout, 'resize_range')

		if offset == 0:
			raise LogMutationException('Cannot resize an empty range')

		delta = new_length - old_length
		old_end = offset + old_length
		new_end = offset + new_length

		other_range = PayloadRange(header[other_offset_key], header[other_length_key])
		shared = (not other_range.is_empty()) and other_range.offset == offset and other_range.length == old_length

		if delta > 0:
			payload[old_end : old_end] = b'\x00' * delta
			if not other_range.is_empty() and other_range.offset >= old_end:
				header[other_offset_key] = other_range.offset + delta
		else:
			del payload[new_end : old_end]
			if not other_range.is_empty() and other_range.offset >= old_end:
				header[other_offset_key] = max(lcn_data_base(header['lcns_to_follow']), other_range.offset + delta)

		header[length_key] = new_length

		if shared:
			header[other_length_key] = new_length

		self._write_header(payload, header)

		client_data_length = align_up(len(payload), 8)
		if len(payload) < client_data_length:
			payload += b'\x00' * (client_data_length - len(payload))

		report = validate_ranges(payload)
		if not report.is_valid():
			raise LogMutationException('Mutation produced an invalid payload: {}'.format([str(p) for p in report.problems]))

		return MutatedRecord(payload, client_data_length, self.layout, 'resize_range')

	def corrupt(self, mutated_or_payload, corruption):
		"""Deliberately break one linked field without repairing the others (negative testing)."""

		payload = bytearray(self._as_payload(mutated_or_payload))

		if corruption == 'redo_length_overflow':
			struct.pack_into('<H', payload, 6, struct.unpack('<H', payload[6 : 8])[0] + 64)
		elif corruption == 'undo_length_overflow':
			struct.pack_into('<H', payload, 10, struct.unpack('<H', payload[10 : 12])[0] + 64)
		elif corruption == 'redo_offset_into_header':
			struct.pack_into('<H', payload, 4, 16)
		elif corruption == 'undo_offset_into_header':
			struct.pack_into('<H', payload, 8, 24)
		elif corruption == 'redo_misaligned':
			struct.pack_into('<H', payload, 4, lcn_data_base(struct.unpack('<H', payload[14 : 16])[0]) + 2)
		elif corruption == 'truncate':
			payload = payload[: max(NTFS_LOG_RECORD_FIXED_SIZE, len(payload) // 2)]
		elif corruption == 'lcn_count_overflow':
			struct.pack_into('<H', payload, 14, struct.unpack('<H', payload[14 : 16])[0] + 4)
		else:
			raise LogMutationException('Unknown corruption: {}'.format(corruption))

		return MutatedRecord(payload, align_up(len(payload), 8), self.layout, 'corrupt:' + corruption)

	def _as_payload(self, mutated_or_payload):
		if type(mutated_or_payload) is MutatedRecord:
			return mutated_or_payload.payload

		if isinstance(mutated_or_payload, (bytes, bytearray)):
			return bytes(mutated_or_payload)

		if type(mutated_or_payload) is LogFile.NTFSLogRecord:
			return bytes(mutated_or_payload.buf)

		raise LogMutationException('Unsupported mutation source: {}'.format(type(mutated_or_payload)))

	def _extract_range(self, payload, offset, length):
		if length == 0:
			return b''

		return bytes(payload[offset : offset + length])

	def _extract_lcns(self, payload, lcns_to_follow):
		lcns = []
		for index in range(lcns_to_follow):
			start = NTFS_LOG_RECORD_FIXED_SIZE + index * LCN_ENTRY_SIZE
			lcns.append(struct.unpack('<q', payload[start : start + LCN_ENTRY_SIZE])[0])

		return lcns

class OperationExplanation(object):
	"""Explainability of a single redo or undo operation."""

	def __init__(self, code, name, known):
		self.code = code
		self.name = name
		self.known = known

	def __repr__(self):
		return 'OperationExplanation(code=0x{:02x}, name={}, known={})'.format(self.code, self.name, self.known)

class ExplainedRecord(object):
	"""Structure-aware explanation of an NTFS log record payload."""

	def __init__(self, payload, report):
		self.payload = bytes(payload)
		self.report = report

		redo_code = struct.unpack('<H', payload[0 : 2])[0]
		undo_code = struct.unpack('<H', payload[2 : 4])[0]

		self.redo = OperationExplanation(redo_code, LogFile.ResolveNTFSOperation(redo_code), redo_code in LogFile.NTFSOperations.keys())
		self.undo = OperationExplanation(undo_code, LogFile.ResolveNTFSOperation(undo_code), undo_code in LogFile.NTFSOperations.keys())

	def is_structurally_valid(self):
		return self.report.is_valid()

	def fully_explained(self):
		"""A record is fully explained only when it is valid and both operations are known."""

		return self.is_structurally_valid() and self.redo.known and self.undo.known

	def explainability(self):
		if not self.is_structurally_valid():
			return 'rejected'

		if self.redo.known and self.undo.known:
			return 'full'

		if self.redo.known or self.undo.known:
			return 'partial'

		return 'unknown'

class PathChangeEvent(object):
	"""A high-level path change event extracted only from a structurally valid, name-bearing record."""

	def __init__(self, lsn, operation_explanation, target_range, name_text, raw_name, transaction_id):
		self.lsn = lsn
		self.operation = operation_explanation
		self.target_range = target_range
		self.name_text = name_text
		self.raw_name = raw_name
		self.transaction_id = transaction_id

	def __repr__(self):
		return 'PathChangeEvent(lsn={}, operation={}, range={}, name={!r})'.format(self.lsn, self.operation.name, self.target_range, self.name_text)

def explain_record(ntfs_log_record_or_payload):
	"""Explain an NTFS log record: structure validation plus separate known/unknown operation handling."""

	payload = _as_payload(ntfs_log_record_or_payload)
	report = validate_ranges(payload)
	return ExplainedRecord(payload, report)

def extract_path_change_events(ntfs_log_record, min_chars = 1):
	"""Extract path change events without ever trusting malformed or out-of-bounds ranges.

	A malformed record yields an empty list: it can never produce a seemingly valid event.
	"""

	if type(ntfs_log_record) is not LogFile.NTFSLogRecord:
		raise LogMutationException('Expected an NTFSLogRecord object')

	payload = bytes(ntfs_log_record.buf)
	report = validate_ranges(payload)
	if not report.is_valid():
		return []

	explanation = ExplainedRecord(payload, report)
	if not explanation.redo.known:
		return []

	if explanation.redo.code not in FILENAME_BEARING_OPERATIONS:
		return []

	redo_bytes = bytes(payload[report.redo_range.offset : report.redo_range.end()])
	if len(redo_bytes) < 2 or len(redo_bytes) % 2 != 0:
		return []

	try:
		name_text = redo_bytes.decode('utf-16le', errors = 'strict')
	except UnicodeDecodeError:
		return []

	if len(name_text.strip('\x00')) < min_chars or '\x00' in name_text.rstrip('\x00'):
		return []

	event = PathChangeEvent(ntfs_log_record.lsn, explanation.redo, report.redo_range, name_text, redo_bytes, ntfs_log_record.transaction_id)
	return [ event ]

def _as_payload(ntfs_log_record_or_payload):
	if type(ntfs_log_record_or_payload) is LogFile.NTFSLogRecord:
		return bytes(ntfs_log_record_or_payload.buf)

	if isinstance(ntfs_log_record_or_payload, (bytes, bytearray)):
		return bytes(ntfs_log_record_or_payload)

	raise LogMutationException('Unsupported record source: {}'.format(type(ntfs_log_record_or_payload)))
