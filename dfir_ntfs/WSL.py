# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements an interface to work with some extended metadata set by the Windows Subsystem for Linux (WSL).

import struct
import datetime

from . import Attributes

def _SafeDecodedEA(attribute):
	try:
		value = attribute.value_decoded()
	except Exception:
		value = None

	if value is not None and type(value).__name__ == 'EA':
		return value

	return Attributes.EA(attribute.value)

def DecodeUnixtime(TimestampSeconds, TimestampNanoseconds):
	"""Decode the Unixtime timestamp and return the datetime object."""

	return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds = TimestampSeconds) + datetime.timedelta(microseconds = TimestampNanoseconds / 1000)

class LXXATTR(object):
	"""This class is used to access Linux extended attributes stored in the LXXATTR extended attribute."""

	def __init__(self, value):
		self.value = value
		if not self.validate_header():
			raise ValueError('Invalid version and/or format of the LXXATTR header')

	def validate_header(self):
		"""Validate the header of the LXXATTR extended attribute."""

		if len(self.value) < 12:
			return False

		version = struct.unpack('<H', self.value[2 : 4])[0]
		format_ = struct.unpack('<H', self.value[0 : 2])[0]
		if version != 1 or format_ != 0:
			return False

		return True

	def extended_attributes(self):
		"""This method yields (name, value) tuples for each Linux extended attribute."""

		pos_block = 4
		while pos_block < len(self.value):
			next_block_pos_relative_raw = self.value[pos_block : pos_block + 4]
			if len(next_block_pos_relative_raw) != 4:
				break

			next_block_pos_relative = struct.unpack('<L', next_block_pos_relative_raw)[0]
			if next_block_pos_relative > 0:
				block_raw = self.value[pos_block : pos_block + next_block_pos_relative]
			else:
				block_raw = self.value[pos_block : ]

			if len(block_raw) < 9:
				break

			name_length = struct.unpack('B', block_raw[6 : 7])[0]
			if name_length == 0:
				break

			value_length = struct.unpack('<H', block_raw[4 : 6])[0]

			name = block_raw[7 : 7 + name_length]
			value = block_raw[7 + name_length : 7 + name_length + value_length]

			yield (name, value)

			if next_block_pos_relative > 0:
				pos_block += next_block_pos_relative
			else:
				break

class LXATTRB(object):
	"""This class is used to access Linux metadata stored in the LXATTRB extended attribute."""

	def __init__(self, value):
		self.value = value
		if not self.validate_header():
			raise ValueError('Invalid version and/or format of the LXATTRB header')

	def validate_header(self):
		"""Validate the header of the LXATTR extended attribute."""

		if len(self.value) != 56:
			return False

		version = struct.unpack('<H', self.value[2 : 4])[0]
		format_ = struct.unpack('<H', self.value[0 : 2])[0]
		if version != 1 or format_ != 0:
			return False

		return True

	def get_mode(self):
		"""Get and return the mode (as an integer)."""

		return struct.unpack('<L', self.value[4 : 8])[0]

	def get_uid(self):
		"""Get and return the user ID."""

		return struct.unpack('<L', self.value[8 : 12])[0]

	def get_gid(self):
		"""Get and return the group ID."""

		return struct.unpack('<L', self.value[12 : 16])[0]

	def get_rdev(self):
		"""Get and return the device ID (as one integer)."""

		return struct.unpack('<L', self.value[16 : 20])[0]

	def get_atime(self):
		"""Get, decode and return the A (last accessed) timestamp."""

		ns_a = struct.unpack('<L', self.value[20 : 24])[0]
		s_a = struct.unpack('<Q', self.value[32 : 40])[0]

		return DecodeUnixtime(s_a, ns_a)

	def get_mtime(self):
		"""Get, decode and return the M (modified) timestamp."""

		ns_m = struct.unpack('<L', self.value[24 : 28])[0]
		s_m = struct.unpack('<Q', self.value[40 : 48])[0]

		return DecodeUnixtime(s_m, ns_m)

	def get_chtime(self):
		"""Get, decode and return the CH (inode changed) timestamp."""

		ns_ch = struct.unpack('<L', self.value[28 : 32])[0]
		s_ch = struct.unpack('<Q', self.value[48 : 56])[0]

		return DecodeUnixtime(s_ch, ns_ch)

	def print_information(self):
		"""Print all information in a human-readable form."""

		print('WSL metadata:')
		print(' Mode: {}'.format(hex(self.get_mode())))
		print(' UID/GID: {}/{}'.format(self.get_uid(), self.get_gid()))
		print(' Device ID: {}'.format(hex(self.get_rdev())))
		print(' File last accessed: {}'.format(self.get_atime()))
		print(' File modified: {}'.format(self.get_mtime()))
		print(' Inode changed: {}'.format(self.get_chtime()))

# --- Traceable WSL metadata view. ---
#
# The classes below do not replace the convenience classes above. They keep every candidate value attached to the
# exact file record segment (FRS) byte range it was decoded from, so that a caller can audit which evidence was used.

LXATTRB_FIELD_OFFSETS = {
	'mode': (4, 4),
	'uid': (8, 4),
	'gid': (12, 4),
	'rdev': (16, 4),
	'atime_nanoseconds': (20, 4),
	'mtime_nanoseconds': (24, 4),
	'chtime_nanoseconds': (28, 4),
	'atime_seconds': (32, 8),
	'mtime_seconds': (40, 8),
	'chtime_seconds': (48, 8),
}

STANDARD_INFORMATION_FIELD_OFFSETS = {
	'ctime': (0, 8),
	'mtime': (8, 8),
	'etime': (16, 8),
	'atime': (24, 8),
}

def _Hex(Value):
	if Value is None:
		return

	return Value.hex()

def _DecodeText(Value):
	if Value is None:
		return

	return Value.decode('utf-8', errors = 'replace')

def _MFTNumber(FRS):
	try:
		return FRS.get_master_file_table_number()
	except Exception:
		return

class WSLSource(object):
	"""An exact location of one piece of WSL-related evidence inside a file record segment (FRS)."""

	def __init__(self, kind, frs = None, frs_index = None, is_base_frs = None, mft_number = None, attribute_type = None, attribute_name = None, attribute_offset = None, value_offset = None, ea_entry_index = None, ea_entry_offset = None, payload_offset = None, payload_length = None, field = None, field_offset = None, field_length = None, declared_length = None, ea_name = None, raw = None):
		self.kind = kind
		self.frs = frs
		self.frs_index = frs_index
		self.is_base_frs = is_base_frs
		self.mft_number = mft_number
		self.attribute_type = attribute_type
		self.attribute_name = attribute_name
		self.attribute_offset = attribute_offset
		self.value_offset = value_offset
		self.ea_entry_index = ea_entry_index
		self.ea_entry_offset = ea_entry_offset
		self.payload_offset = payload_offset
		self.payload_length = payload_length
		self.field = field
		self.field_offset = field_offset
		self.field_length = field_length
		self.declared_length = declared_length
		self.ea_name = ea_name
		self.raw = raw

	def describe(self):
		"""Return a compact description with absolute FRS offsets."""

		parts = []
		if self.mft_number is not None:
			parts.append('$MFT {}'.format(self.mft_number))

		if self.frs_index is not None:
			parts.append('FRS #{}'.format(self.frs_index))

		if self.attribute_offset is not None:
			parts.append('attribute @ {}'.format(self.attribute_offset))

		if self.value_offset is not None:
			parts.append('value @ {}'.format(self.value_offset))

		if self.ea_entry_index is not None:
			parts.append('EA #{} @ {}'.format(self.ea_entry_index, self.ea_entry_offset))

		if self.payload_offset is not None:
			parts.append('payload @ {} ({})'.format(self.payload_offset, self.payload_length))

		if self.field is not None:
			parts.append('{} @ {}+{}'.format(self.field, self.field_offset, self.field_length))

		if len(parts) == 0:
			return self.kind

		return '{}: {}'.format(self.kind, ', '.join(parts))

	def to_dict(self):
		return {
			'kind': self.kind,
			'mft_number': self.mft_number,
			'frs_index': self.frs_index,
			'is_base_frs': self.is_base_frs,
			'attribute_type': self.attribute_type,
			'attribute_name': self.attribute_name,
			'attribute_offset': self.attribute_offset,
			'value_offset': self.value_offset,
			'ea_entry_index': self.ea_entry_index,
			'ea_entry_offset': self.ea_entry_offset,
			'payload_offset': self.payload_offset,
			'payload_length': self.payload_length,
			'field': self.field,
			'field_offset': self.field_offset,
			'field_length': self.field_length,
			'declared_length': self.declared_length,
			'ea_name': _Hex(self.ea_name),
			'raw': _Hex(self.raw),
		}

	def __str__(self):
		return self.describe()

class WSLIssue(object):
	"""A byte range that cannot be interpreted without guessing."""

	def __init__(self, kind, reason, source, field = None, raw = None):
		self.kind = kind
		self.reason = reason
		self.source = source
		self.field = field
		self.raw = raw

	def to_dict(self):
		return {
			'kind': self.kind,
			'field': self.field,
			'reason': self.reason,
			'raw': _Hex(self.raw),
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def __str__(self):
		field_str = ''
		if self.field is not None:
			field_str = ' [{}]'.format(self.field)

		return '{}: {}{} ({})'.format(self.kind, self.reason, field_str, self.source.describe() if self.source is not None else 'no source')

class WSLTimestamp(object):
	"""A Linux timestamp, preserving both seconds and nanoseconds."""

	def __init__(self, seconds, nanoseconds, source = None, raw = None):
		self.seconds = seconds
		self.nanoseconds = nanoseconds
		self.source = source
		self.raw = raw

		self.is_valid = 0 <= nanoseconds < 1000000000
		self.error = None
		if not self.is_valid:
			self.error = 'Invalid nanosecond component: {} (must be less than 1000000000)'.format(nanoseconds)

		self.datetime = None
		try:
			self.datetime = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds = seconds, microseconds = nanoseconds // 1000)
		except Exception as e:
			self.error = 'Cannot decode timestamp: {}'.format(e)

	def to_nanoseconds(self):
		return self.seconds * 1000000000 + self.nanoseconds

	def to_dict(self):
		return {
			'seconds': self.seconds,
			'nanoseconds': self.nanoseconds,
			'datetime': self.datetime.isoformat() if self.datetime is not None else None,
			'is_valid': self.is_valid,
			'error': self.error,
			'raw': _Hex(self.raw),
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def __eq__(self, Other):
		if not isinstance(Other, WSLTimestamp):
			return NotImplemented

		return self.seconds == Other.seconds and self.nanoseconds == Other.nanoseconds

	def __str__(self):
		if self.datetime is None:
			return '{}.{:09d} (undecodable)'.format(self.seconds, self.nanoseconds)

		return '{}.{:09d} ({})'.format(self.datetime.strftime('%Y-%m-%d %H:%M:%S'), self.nanoseconds % 1000000000, self.seconds)

class WSLFieldCandidate(object):
	"""One candidate value for a WSL field and the bytes it occupies."""

	def __init__(self, field, value, source, raw, relative_offset = None, relative_length = None, absolute_offset = None, raw_ranges = None, record = None):
		self.field = field
		self.value = value
		self.source = source
		self.raw = raw
		self.relative_offset = relative_offset
		self.relative_length = relative_length
		self.absolute_offset = absolute_offset
		self.raw_ranges = raw_ranges
		self.record = record

	def to_dict(self):
		value = self.value
		if isinstance(value, WSLTimestamp):
			value = value.to_dict()

		return {
			'field': self.field,
			'value': value,
			'relative_offset': self.relative_offset,
			'relative_length': self.relative_length,
			'absolute_offset': self.absolute_offset,
			'raw': _Hex(self.raw),
			'raw_ranges': [ (offset, length, _Hex(raw)) for offset, length, raw in self.raw_ranges ] if self.raw_ranges is not None else None,
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def __str__(self):
		return '{} = {} @ {}'.format(self.field, self.value, self.absolute_offset)

class WSLConflict(object):
	"""Different evidence supplying different values for one field or extended attribute name."""

	def __init__(self, field, candidates, kind = 'field'):
		self.field = field
		self.candidates = candidates
		self.kind = kind

		self.values = []
		for candidate in candidates:
			value = candidate.value
			if isinstance(value, WSLTimestamp):
				value = (value.seconds, value.nanoseconds)

			if value not in self.values:
				self.values.append(value)

	def to_dict(self):
		values = []
		for value in self.values:
			if isinstance(value, tuple):
				values.append(list(value))
			else:
				values.append(value)

		return {
			'field': self.field,
			'kind': self.kind,
			'values': values,
			'candidates': [ candidate.to_dict() for candidate in self.candidates ],
		}

	def __str__(self):
		return 'conflict for {}: {} candidate(s), {} distinct value(s)'.format(self.field, len(self.candidates), len(self.values))

class WSLTimeComparison(object):
	"""A comparison between a Linux timestamp and an NTFS timestamp; neither replaces the other."""

	def __init__(self, linux_field, linux_timestamp, linux_source, ntfs_field, ntfs_timestamp, ntfs_ticks, ntfs_source, note = None, extra = None):
		self.linux_field = linux_field
		self.linux_timestamp = linux_timestamp
		self.linux_source = linux_source
		self.ntfs_field = ntfs_field
		self.ntfs_timestamp = ntfs_timestamp
		self.ntfs_ticks = ntfs_ticks
		self.ntfs_source = ntfs_source
		self.note = note
		self.extra = extra

		self.ntfs_nanoseconds = ntfs_ticks * 100 - 11644473600 * 1000000000
		self.delta_nanoseconds = linux_timestamp.to_nanoseconds() - self.ntfs_nanoseconds
		self.diverged = self.delta_nanoseconds != 0

	def to_dict(self):
		return {
			'linux_field': self.linux_field,
			'linux_timestamp': self.linux_timestamp.to_dict(),
			'linux_source': self.linux_source.to_dict() if self.linux_source is not None else None,
			'ntfs_field': self.ntfs_field,
			'ntfs_timestamp': self.ntfs_timestamp.isoformat() if self.ntfs_timestamp is not None else None,
			'ntfs_ticks': self.ntfs_ticks,
			'ntfs_nanoseconds': self.ntfs_nanoseconds,
			'ntfs_source': self.ntfs_source.to_dict() if self.ntfs_source is not None else None,
			'delta_nanoseconds': self.delta_nanoseconds,
			'diverged': self.diverged,
			'note': self.note,
		}

	def __str__(self):
		return '{} (Linux) vs {} (NTFS): delta {} ns ({})'.format(self.linux_timestamp, self.ntfs_field, self.delta_nanoseconds, 'diverged' if self.diverged else 'equal')

class LXATTRBView(object):
	"""One LXATTRB extended attribute, including its version, field offsets, and uninterpretable spans."""

	def __init__(self, value, source = None):
		self.value = value
		self.source = source

		self.format = None
		self.version = None
		self.is_interpretable = False
		self.is_complete = False
		self.error = None
		self.fields = {}
		self.issues = []
		self.trailing = None

		if len(value) < 4:
			self.error = 'Truncated LXATTRB header: {} byte(s) available, 4 required'.format(len(value))
			self.issues.append(WSLIssue('LXATTRB', self.error, source, raw = value))
			return

		self.format, self.version = struct.unpack('<HH', value[: 4])

		if self.format != 0 or self.version != 1:
			self.error = 'Unknown LXATTRB version/format: {}/{}'.format(self.version, self.format)
			self.issues.append(WSLIssue('LXATTRB', self.error, source, raw = value))
			return

		self.is_interpretable = True
		self.is_complete = len(value) == 56

		if len(value) < 56:
			self.error = 'Truncated LXATTRB: {} byte(s) available, 56 required'.format(len(value))
			self.issues.append(WSLIssue('LXATTRB', self.error, source, raw = value))

		if len(value) > 56:
			trailing_raw = value[56 : ]
			trailing_source = self._Source(56, len(trailing_raw))
			self.trailing = WSLIssue('LXATTRB', 'Trailing bytes after the 56-byte LXATTRB structure', trailing_source, raw = trailing_raw)
			self.issues.append(self.trailing)

		for field in [ 'mode', 'uid', 'gid', 'rdev' ]:
			candidate = self._ReadInteger(field)
			if candidate is not None:
				self.fields[field] = candidate

		for field in [ 'atime', 'mtime', 'chtime' ]:
			candidate = self._ReadTimestamp(field)
			if candidate is not None:
				self.fields[field] = candidate

	def _Source(self, relative_offset, length, field = None, declared_length = None):
		if self.source is None:
			return

		payload_offset = self.source.payload_offset
		field_offset = None
		if payload_offset is not None:
			field_offset = payload_offset + relative_offset

		raw = self.value[relative_offset : relative_offset + length]
		return WSLSource(self.source.kind, frs = self.source.frs, frs_index = self.source.frs_index, is_base_frs = self.source.is_base_frs, mft_number = self.source.mft_number, attribute_type = self.source.attribute_type, attribute_name = self.source.attribute_name, attribute_offset = self.source.attribute_offset, value_offset = self.source.value_offset, ea_entry_index = self.source.ea_entry_index, ea_entry_offset = self.source.ea_entry_offset, payload_offset = payload_offset, payload_length = len(self.value), field = field, field_offset = field_offset, field_length = length, declared_length = declared_length, ea_name = self.source.ea_name, raw = raw)

	def _ReadInteger(self, field):
		relative_offset, relative_length = LXATTRB_FIELD_OFFSETS[field]
		if relative_offset + relative_length > len(self.value):
			source = self._Source(relative_offset, max(0, len(self.value) - relative_offset), field = field)
			self.issues.append(WSLIssue('LXATTRB', 'Truncated field: {} byte(s) available, {} required'.format(max(0, len(self.value) - relative_offset), relative_length), source, field = field))
			return

		raw = self.value[relative_offset : relative_offset + relative_length]
		value = struct.unpack('<L', raw)[0]
		source = self._Source(relative_offset, relative_length, field = field)
		return WSLFieldCandidate(field, value, source, raw, relative_offset, relative_length, source.field_offset if source is not None else None, [ (source.field_offset if source is not None else None, relative_length, raw) ], self)

	def _ReadTimestamp(self, field):
		nanoseconds_field = field + '_nanoseconds'
		seconds_field = field + '_seconds'
		nanoseconds_offset, nanoseconds_length = LXATTRB_FIELD_OFFSETS[nanoseconds_field]
		seconds_offset, seconds_length = LXATTRB_FIELD_OFFSETS[seconds_field]

		if seconds_offset + seconds_length > len(self.value):
			available = max(0, len(self.value) - nanoseconds_offset)
			source = self._Source(nanoseconds_offset, available, field = field)
			self.issues.append(WSLIssue('LXATTRB', 'Truncated timestamp: {} byte(s) available, {} required'.format(available, (seconds_offset + seconds_length) - nanoseconds_offset), source, field = field))
			return

		nanoseconds_raw = self.value[nanoseconds_offset : nanoseconds_offset + nanoseconds_length]
		seconds_raw = self.value[seconds_offset : seconds_offset + seconds_length]
		nanoseconds = struct.unpack('<L', nanoseconds_raw)[0]
		seconds = struct.unpack('<Q', seconds_raw)[0]

		span_length = (seconds_offset + seconds_length) - nanoseconds_offset
		source = self._Source(nanoseconds_offset, span_length, field = field)
		timestamp = WSLTimestamp(seconds, nanoseconds, source, nanoseconds_raw + seconds_raw)
		raw_ranges = []
		for relative_offset, relative_length, raw in [ (nanoseconds_offset, nanoseconds_length, nanoseconds_raw), (seconds_offset, seconds_length, seconds_raw) ]:
			absolute_offset = None
			if source is not None and source.payload_offset is not None:
				absolute_offset = source.payload_offset + relative_offset

			raw_ranges.append((absolute_offset, relative_length, raw))

		candidate = WSLFieldCandidate(field, timestamp, source, nanoseconds_raw + seconds_raw, nanoseconds_offset, span_length, source.field_offset if source is not None else None, raw_ranges, self)

		if not timestamp.is_valid:
			self.issues.append(WSLIssue('LXATTRB', timestamp.error, source, field = field, raw = nanoseconds_raw))
			return

		return candidate

	def get_field(self, field):
		candidate = self.fields.get(field)
		if candidate is None:
			return

		return candidate.value

	def get_mode(self):
		return self.get_field('mode')

	def get_uid(self):
		return self.get_field('uid')

	def get_gid(self):
		return self.get_field('gid')

	def get_rdev(self):
		return self.get_field('rdev')

	def get_atime(self):
		value = self.get_field('atime')
		if value is not None:
			return value.datetime

	def get_mtime(self):
		value = self.get_field('mtime')
		if value is not None:
			return value.datetime

	def get_chtime(self):
		value = self.get_field('chtime')
		if value is not None:
			return value.datetime

	def to_dict(self):
		return {
			'format': self.format,
			'version': self.version,
			'is_interpretable': self.is_interpretable,
			'error': self.error,
			'fields': { field: candidate.to_dict() for field, candidate in self.fields.items() },
			'issues': [ issue.to_dict() for issue in self.issues ],
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def print_information(self):
		print('LXATTRB:')
		print(' Source: {}'.format(self.source.describe() if self.source is not None else 'unknown'))
		print(' Version/format: {}/{}'.format(self.version, self.format))

		if not self.is_interpretable:
			print(' Not interpretable: {}'.format(self.error))

		for field in [ 'mode', 'uid', 'gid', 'rdev', 'atime', 'mtime', 'chtime' ]:
			candidate = self.fields.get(field)
			if candidate is None:
				print(' {}: unavailable'.format(field))
			else:
				print(' {}: {} @ byte {} ({} byte(s))'.format(field, candidate.value, candidate.absolute_offset, candidate.source.field_length if candidate.source is not None else '?'))

		for issue in self.issues:
			print(' Issue: {}'.format(issue))

class WSLXAttr(object):
	"""One Linux extended attribute from a LXXATTR payload, preserving raw name and value."""

	def __init__(self, name, value, source, block_offset, name_offset, value_offset, block_length, padding = b'', is_valid = True, error = None, raw = None, record = None):
		self.name = name
		self.value = value
		self.source = source
		self.block_offset = block_offset
		self.name_offset = name_offset
		self.value_offset = value_offset
		self.block_length = block_length
		self.padding = padding
		self.is_valid = is_valid
		self.error = error
		self.raw = raw
		self.record = record

	@property
	def name_text(self):
		return _DecodeText(self.name)

	@property
	def value_text(self):
		return _DecodeText(self.value)

	def value_absolute_offset(self):
		"""Return an absolute offset of the value inside the FRS, when known."""

		if self.source is None or self.source.payload_offset is None:
			return

		return self.source.payload_offset + self.value_offset

	def to_dict(self):
		return {
			'name': _Hex(self.name),
			'name_text': self.name_text,
			'value': _Hex(self.value),
			'value_text': self.value_text,
			'block_offset': self.block_offset,
			'name_offset': self.name_offset,
			'value_offset': self.value_offset,
			'value_absolute_offset': self.value_absolute_offset(),
			'block_length': self.block_length,
			'padding': _Hex(self.padding),
			'is_valid': self.is_valid,
			'error': self.error,
			'raw': _Hex(self.raw),
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def __str__(self):
		if not self.is_valid:
			return '{} = {} (invalid: {})'.format(self.name_text, _Hex(self.value), self.error)

		return '{} = {}'.format(self.name_text, self.value_text)

class LXXATTRView(object):
	"""One LXXATTR extended attribute, keeping duplicate Linux extended attribute names."""

	def __init__(self, value, source = None):
		self.value = value
		self.source = source

		self.format = None
		self.version = None
		self.is_interpretable = False
		self.is_complete = True
		self.error = None
		self.extended_attributes = []
		self.issues = []

		if len(value) < 4:
			self.error = 'Truncated LXXATTR header: {} byte(s) available, 4 required'.format(len(value))
			self.issues.append(WSLIssue('LXXATTR', self.error, source, raw = value))
			return

		self.format, self.version = struct.unpack('<HH', value[: 4])

		if self.format != 0 or self.version != 1:
			self.error = 'Unknown LXXATTR version/format: {}/{}'.format(self.version, self.format)
			self.issues.append(WSLIssue('LXXATTR', self.error, source, raw = value))
			return

		self.is_interpretable = True
		self._ParseBlocks()

	def _Source(self, relative_offset, length, declared_length = None):
		if self.source is None:
			return

		absolute_offset = None
		if self.source.payload_offset is not None:
			absolute_offset = self.source.payload_offset + relative_offset

		raw = self.value[relative_offset : relative_offset + length]
		return WSLSource(self.source.kind, frs = self.source.frs, frs_index = self.source.frs_index, is_base_frs = self.source.is_base_frs, mft_number = self.source.mft_number, attribute_type = self.source.attribute_type, attribute_name = self.source.attribute_name, attribute_offset = self.source.attribute_offset, value_offset = self.source.value_offset, ea_entry_index = self.source.ea_entry_index, ea_entry_offset = self.source.ea_entry_offset, payload_offset = absolute_offset, payload_length = len(raw), declared_length = declared_length, ea_name = self.source.ea_name, raw = raw)

	def _ParseBlocks(self):
		pos_block = 4
		while pos_block < len(self.value):
			remaining = len(self.value) - pos_block
			if remaining < 7:
				if any(self.value[pos_block : ]):
					source = self._Source(pos_block, remaining)
					self.issues.append(WSLIssue('LXXATTR', 'Truncated block header: {} byte(s) available, 7 required'.format(remaining), source, raw = self.value[pos_block : ]))
				break

			next_block_pos_relative = struct.unpack('<L', self.value[pos_block : pos_block + 4])[0]

			if next_block_pos_relative > 0:
				block_end = pos_block + next_block_pos_relative
				if next_block_pos_relative < 7 or block_end > len(self.value):
					source = self._Source(pos_block, remaining)
					self.issues.append(WSLIssue('LXXATTR', 'Invalid next block offset: {}'.format(next_block_pos_relative), source))
					break
			else:
				block_end = len(self.value)

			block_length = block_end - pos_block
			value_length = struct.unpack('<H', self.value[pos_block + 4 : pos_block + 6])[0]
			name_length = struct.unpack('B', self.value[pos_block + 6 : pos_block + 7])[0]

			name_start = pos_block + 7
			name_end = name_start + name_length
			value_start = name_end
			value_end = value_start + value_length

			if name_end > block_end or value_end > block_end:
				available_name = bytes(self.value[name_start : min(name_end, block_end)])
				available_value = bytes(self.value[value_start : min(value_end, block_end)]) if value_start <= block_end else b''
				source = self._Source(pos_block, block_length, value_length)
				entry = WSLXAttr(available_name, available_value, source, pos_block, name_start - pos_block, value_start - pos_block, block_length, is_valid = False, error = 'Block value exceeds the block boundary: value end {}, block end {}'.format(value_end, block_end), raw = bytes(self.value[pos_block : block_end]), record = self)
				self.extended_attributes.append(entry)
				self.issues.append(WSLIssue('LXXATTR', entry.error, source, raw = bytes(self.value[pos_block : block_end])))
				break

			name = bytes(self.value[name_start : name_end])
			xattr_value = bytes(self.value[value_start : value_end])
			padding = bytes(self.value[value_end : block_end])

			source = self._Source(pos_block, block_length, value_length)
			entry = WSLXAttr(name, xattr_value, source, pos_block, name_start - pos_block, value_start - pos_block, block_length, padding, True, None, bytes(self.value[pos_block : block_end]), self)
			self.extended_attributes.append(entry)

			if next_block_pos_relative == 0:
				break

			pos_block = block_end

	def to_dict(self):
		return {
			'format': self.format,
			'version': self.version,
			'is_interpretable': self.is_interpretable,
			'error': self.error,
			'extended_attributes': [ entry.to_dict() for entry in self.extended_attributes ],
			'issues': [ issue.to_dict() for issue in self.issues ],
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def print_information(self):
		print('LXXATTR:')
		print(' Source: {}'.format(self.source.describe() if self.source is not None else 'unknown'))
		print(' Version/format: {}/{}'.format(self.version, self.format))

		if not self.is_interpretable:
			print(' Not interpretable: {}'.format(self.error))

		for entry in self.extended_attributes:
			print(' {} @ byte {}'.format(entry, entry.source.payload_offset if entry.source is not None else '?'))

		for issue in self.issues:
			print(' Issue: {}'.format(issue))

class WSLNTFSTimestamp(object):
	"""An NTFS FILETIME timestamp tied to the exact $STANDARD_INFORMATION bytes."""

	def __init__(self, field, ticks, source, raw, datetime_value = None):
		self.field = field
		self.ticks = ticks
		self.source = source
		self.raw = raw
		self.datetime = datetime_value

		self.nanoseconds = ticks * 100 - 11644473600 * 1000000000

	def to_dict(self):
		return {
			'field': self.field,
			'ticks': self.ticks,
			'datetime': self.datetime.isoformat() if self.datetime is not None else None,
			'nanoseconds': self.nanoseconds,
			'raw': _Hex(self.raw),
			'source': self.source.to_dict() if self.source is not None else None,
		}

	def __str__(self):
		if self.datetime is None:
			return '{}: {} ticks'.format(self.field, self.ticks)

		return '{}: {} ({} ticks)'.format(self.field, self.datetime, self.ticks)

class WSLMetadataView(object):
	"""A traceable Linux metadata view for one NTFS file record.

	The effective LXATTRB is the first interpretable LXATTRB in file record order (the base FRS first, then child
	FRS objects, and $EA entries in their on-disk order). Its field values are exposed together with their exact
	source spans. Every other candidate, duplicate, conflict, unknown version, truncated value, and missing item is
	reported separately; a missing UID/GID/mode is never replaced with zero.
	"""

	def __init__(self, file_record):
		self.file_record = file_record

		self.sources = []
		self.ea_entries = []
		self.unknown_ea_names = []
		self.lxattrb_records = []
		self.lxxattr_records = []
		self.ntfs_timestamps = []
		self.issues = []
		self.conflicts = []
		self.time_comparisons = []
		self.missing = []
		self.duplicate_ea_names = []
		self.duplicate_xattr_names = []

		self._ea_name_sources = {}
		self._xattrs_by_name = {}

		self._Parse()
		self._SelectEffectiveLXATTRB()
		self._FindDuplicatesAndConflicts()
		self._CompareTimestamps()
		self._FindMissingEvidence()

	def _IterFRS(self):
		if hasattr(self.file_record, 'base_frs') and hasattr(self.file_record, 'child_frs_list'):
			yield (0, True, self.file_record.base_frs)
			for index, child_frs in enumerate(self.file_record.child_frs_list, 1):
				yield (index, False, child_frs)
		else:
			yield (0, True, self.file_record)

	def _Parse(self):
		for frs_index, is_base_frs, frs in self._IterFRS():
			mft_number = _MFTNumber(frs)

			for attribute in frs.attributes():
				if type(attribute).__name__ != 'AttributeRecordResident':
					continue

				if attribute.type_code == 0x10: # $STANDARD_INFORMATION
					self._ParseStandardInformation(frs, frs_index, is_base_frs, mft_number, attribute)
				elif attribute.type_code == 0xE0: # $EA
					self._ParseEA(frs, frs_index, is_base_frs, mft_number, attribute)

	def _AttributeSource(self, kind, frs, frs_index, is_base_frs, mft_number, attribute, raw = None):
		payload_offset = attribute.value_offset
		return WSLSource(kind, frs = frs, frs_index = frs_index, is_base_frs = is_base_frs, mft_number = mft_number, attribute_type = attribute.type_code, attribute_name = attribute.name, attribute_offset = attribute.record_offset, value_offset = attribute.value_offset, payload_offset = payload_offset, payload_length = len(attribute.value), raw = raw if raw is not None else attribute.value)

	def _ParseStandardInformation(self, frs, frs_index, is_base_frs, mft_number, attribute):
		value = attribute.value
		base_source = self._AttributeSource('$STANDARD_INFORMATION', frs, frs_index, is_base_frs, mft_number, attribute)
		self.sources.append(base_source)

		for field, (relative_offset, relative_length) in STANDARD_INFORMATION_FIELD_OFFSETS.items():
			if relative_offset + relative_length > len(value):
				source = WSLSource('$STANDARD_INFORMATION', frs = frs, frs_index = frs_index, is_base_frs = is_base_frs, mft_number = mft_number, attribute_type = attribute.type_code, attribute_name = attribute.name, attribute_offset = attribute.record_offset, value_offset = attribute.value_offset, payload_offset = base_source.payload_offset, payload_length = len(value), field = field, field_offset = attribute.value_offset + relative_offset if attribute.value_offset is not None else None, field_length = relative_length)
				self.issues.append(WSLIssue('$STANDARD_INFORMATION', 'Truncated timestamp field: {} byte(s) available, {} required'.format(max(0, len(value) - relative_offset), relative_length), source, field = field))
				continue

			raw = value[relative_offset : relative_offset + relative_length]
			ticks = struct.unpack('<Q', raw)[0]
			absolute_offset = attribute.value_offset + relative_offset if attribute.value_offset is not None else None
			source = WSLSource('$STANDARD_INFORMATION', frs = frs, frs_index = frs_index, is_base_frs = is_base_frs, mft_number = mft_number, attribute_type = attribute.type_code, attribute_name = attribute.name, attribute_offset = attribute.record_offset, value_offset = attribute.value_offset, payload_offset = absolute_offset, payload_length = relative_length, field = field, field_offset = absolute_offset, field_length = relative_length, raw = raw)

			datetime_value = None
			try:
				datetime_value = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds = ticks // 10)
			except Exception:
				pass

			self.ntfs_timestamps.append(WSLNTFSTimestamp(field, ticks, source, raw, datetime_value))

	def _ParseEA(self, frs, frs_index, is_base_frs, mft_number, attribute):
		ea = _SafeDecodedEA(attribute)

		for entry in ea.entries_all():
			payload_offset = None
			if attribute.value_offset is not None:
				payload_offset = attribute.value_offset + entry.value_offset

			source = WSLSource('$EA', frs = frs, frs_index = frs_index, is_base_frs = is_base_frs, mft_number = mft_number, attribute_type = attribute.type_code, attribute_name = attribute.name, attribute_offset = attribute.record_offset, value_offset = attribute.value_offset, ea_entry_index = entry.index, ea_entry_offset = entry.entry_offset, payload_offset = payload_offset, payload_length = entry.actual_value_length, declared_length = entry.declared_value_length, ea_name = entry.name, raw = entry.value)

			self.ea_entries.append((entry, source))
			self.sources.append(source)

			if entry.name is not None:
				self._ea_name_sources.setdefault(entry.name, []).append(source)

			if not entry.is_valid:
				self.issues.append(WSLIssue('$EA', entry.error, source, raw = entry.raw))

				# A truncated entry value can still contain a complete WSL structure prefix. Decode that prefix and
				# report the missing tail, instead of discarding the evidence entirely.
				if entry.name is None or entry.actual_value_length == 0:
					continue

			if entry.name == b'LXATTRB\x00':
				record = LXATTRBView(entry.value, source)
				self.lxattrb_records.append(record)
				self.issues.extend(record.issues)
			elif entry.name == b'LXXATTR\x00':
				record = LXXATTRView(entry.value, source)
				self.lxxattr_records.append(record)
				self.issues.extend(record.issues)
				for xattr in record.extended_attributes:
					if xattr.is_valid:
						self._xattrs_by_name.setdefault(xattr.name, []).append(xattr)
			else:
				self.unknown_ea_names.append(entry.name)

	def _SelectEffectiveLXATTRB(self):
		self.effective_lxattrb = None
		self.effective_fields = {}

		for field in [ 'mode', 'uid', 'gid', 'rdev', 'atime', 'mtime', 'chtime' ]:
			for record in self.lxattrb_records:
				if not record.is_interpretable:
					continue

				candidate = record.fields.get(field)
				if candidate is not None:
					self.effective_fields[field] = candidate
					if self.effective_lxattrb is None:
						self.effective_lxattrb = record

					break

	def _FindDuplicatesAndConflicts(self):
		for name, sources in self._ea_name_sources.items():
			if len(sources) > 1:
				self.duplicate_ea_names.append(name)

		for name, entries in self._xattrs_by_name.items():
			if len(entries) > 1:
				self.duplicate_xattr_names.append(name)

		field_candidates = {}
		for record in self.lxattrb_records:
			for field, candidate in record.fields.items():
				field_candidates.setdefault(field, []).append(candidate)

		for field, candidates in field_candidates.items():
			if len(candidates) < 2:
				continue

			values = []
			for candidate in candidates:
				value = candidate.value
				if isinstance(value, WSLTimestamp):
					value = (value.seconds, value.nanoseconds)

				if value not in values:
					values.append(value)

			if len(values) > 1:
				self.conflicts.append(WSLConflict(field, candidates))

		for name, entries in self._xattrs_by_name.items():
			if len(entries) < 2:
				continue

			values = []
			for entry in entries:
				if entry.value not in values:
					values.append(entry.value)

			if len(values) > 1:
				self.conflicts.append(WSLConflict(name, entries, 'xattr'))

	def _CompareTimestamps(self):
		ntfs_by_field = {}
		for timestamp in self.ntfs_timestamps:
			ntfs_by_field.setdefault(timestamp.field, []).append(timestamp)

		comparisons = [
			('atime', 'atime', None),
			('mtime', 'mtime', None),
			('chtime', 'etime', 'WSL chtime is the inode change time; NTFS E is the $MFT entry modification time, so this comparison is informational.'),
		]

		for record in self.lxattrb_records:
			if not record.is_interpretable:
				continue

			for linux_field, ntfs_field, note in comparisons:
				linux_candidate = record.fields.get(linux_field)
				if linux_candidate is None:
					continue

				for ntfs_timestamp in ntfs_by_field.get(ntfs_field, []):
					self.time_comparisons.append(WSLTimeComparison(linux_field, linux_candidate.value, linux_candidate.source, ntfs_field, ntfs_timestamp.datetime, ntfs_timestamp.ticks, ntfs_timestamp.source, note))

	def _FindMissingEvidence(self):
		# These are informational absence markers, not zero values. They are kept separately from conflicts.
		if len(self.lxattrb_records) == 0:
			self.missing.append('LXATTRB')
		elif self.effective_lxattrb is None:
			self.missing.append('interpretable LXATTRB')

		if len(self.lxxattr_records) == 0:
			self.missing.append('LXXATTR')

		if len(self.ntfs_timestamps) == 0:
			self.missing.append('$STANDARD_INFORMATION timestamps')

	def get_effective_field(self, field):
		"""Return the effective WSLFieldCandidate for a field, or None if no interpretable evidence exists."""

		return self.effective_fields.get(field)

	def get_field_candidates(self, field):
		"""Return all WSLFieldCandidate objects for a field, including conflicting ones."""

		candidates = []
		for record in self.lxattrb_records:
			candidate = record.fields.get(field)
			if candidate is not None:
				candidates.append(candidate)

		return candidates

	def get_evidence_for(self, field):
		"""Return the WSLSource selected as the effective evidence for a field."""

		candidate = self.get_effective_field(field)
		if candidate is None:
			return

		return candidate.source

	def get_uid(self):
		return self._EffectiveValue('uid')

	def get_gid(self):
		return self._EffectiveValue('gid')

	def get_mode(self):
		return self._EffectiveValue('mode')

	def get_rdev(self):
		return self._EffectiveValue('rdev')

	def get_atime(self):
		return self._EffectiveTimestamp('atime')

	def get_mtime(self):
		return self._EffectiveTimestamp('mtime')

	def get_chtime(self):
		return self._EffectiveTimestamp('chtime')

	def _EffectiveValue(self, field):
		candidate = self.get_effective_field(field)
		if candidate is None:
			return

		return candidate.value

	def _EffectiveTimestamp(self, field):
		value = self._EffectiveValue(field)
		if value is None:
			return

		return value.datetime

	def get_xattrs(self, name = None):
		"""Return all Linux extended attributes from interpretable LXXATTR records (optionally matching a raw name)."""

		result = []
		for record in self.lxxattr_records:
			if not record.is_interpretable:
				continue

			for entry in record.extended_attributes:
				if name is None or entry.name == name:
					result.append(entry)

		return result

	def to_dict(self):
		return {
			'sources': [ source.to_dict() for source in self.sources ],
			'ea_entries': [ { 'index': entry.index, 'name': _Hex(entry.name), 'flags': entry.flags, 'is_valid': entry.is_valid, 'error': entry.error, 'declared_value_length': entry.declared_value_length, 'actual_value_length': entry.actual_value_length, 'entry_offset': entry.entry_offset, 'value_offset': entry.value_offset, 'source': source.to_dict() } for entry, source in self.ea_entries ],
			'unknown_ea_names': [ _Hex(name) for name in self.unknown_ea_names ],
			'lxattrb_records': [ record.to_dict() for record in self.lxattrb_records ],
			'lxxattr_records': [ record.to_dict() for record in self.lxxattr_records ],
			'effective_lxattrb': self.effective_lxattrb.to_dict() if self.effective_lxattrb is not None else None,
			'effective_fields': { field: candidate.to_dict() for field, candidate in self.effective_fields.items() },
			'effective_field_sources': { field: candidate.source.to_dict() for field, candidate in self.effective_fields.items() if candidate.source is not None },
			'conflicts': [ conflict.to_dict() for conflict in self.conflicts ],
			'issues': [ issue.to_dict() for issue in self.issues ],
			'duplicate_ea_names': [ _Hex(name) for name in self.duplicate_ea_names ],
			'duplicate_xattr_names': [ _Hex(name) for name in self.duplicate_xattr_names ],
			'ntfs_timestamps': [ timestamp.to_dict() for timestamp in self.ntfs_timestamps ],
			'time_comparisons': [ comparison.to_dict() for comparison in self.time_comparisons ],
			'missing': list(self.missing),
		}

	def print_information(self):
		"""Print all effective values, conflicts, and uninterpretable spans with their FRS byte offsets."""

		print('WSL metadata view:')
		print(' Sources:')
		for source in self.sources:
			print('  {}'.format(source.describe()))

		print(' Effective LXATTRB fields (first interpretable value per field, in record order):')
		if self.effective_lxattrb is None:
			print('  unavailable (no interpretable LXATTRB)')
		else:
			for field in [ 'mode', 'uid', 'gid', 'rdev', 'atime', 'mtime', 'chtime' ]:
				candidate = self.effective_fields.get(field)
				if candidate is None:
					print('  {}: unavailable (no default)'.format(field))
				else:
					print('  {}: {} @ byte {}+{} ({})'.format(field, candidate.value, candidate.absolute_offset, candidate.source.field_length if candidate.source is not None else '?', candidate.source.describe() if candidate.source is not None else 'unknown'))

		print(' Linux extended attributes:')
		for entry in self.get_xattrs():
			print('  {} @ byte {}'.format(entry, entry.source.payload_offset if entry.source is not None else '?'))

		print(' Duplicate names:')
		if len(self.duplicate_ea_names) == 0 and len(self.duplicate_xattr_names) == 0:
			print('  none')
		for name in self.duplicate_ea_names:
			print('  EA name: {}'.format(_DecodeText(name)))
		for name in self.duplicate_xattr_names:
			print('  xattr name: {}'.format(_DecodeText(name)))

		print(' Uninterpretable fields/values:')
		if len(self.issues) == 0:
			print('  none')
		for issue in self.issues:
			print('  {}'.format(issue))

		print(' Conflicts:')
		if len(self.conflicts) == 0:
			print('  none')
		for conflict in self.conflicts:
			print('  {}'.format(conflict))
			for candidate in conflict.candidates:
				source = candidate.source
				if hasattr(candidate, 'absolute_offset'):
					print('   {} @ byte {} ({})'.format(candidate.value, candidate.absolute_offset, source.describe() if source is not None else 'unknown'))
				else:
					print('   {} @ byte {} ({})'.format(candidate.value_text, source.payload_offset if source is not None else '?', source.describe() if source is not None else 'unknown'))

		print(' NTFS timestamps (kept separately):')
		for timestamp in self.ntfs_timestamps:
			print('  {} @ byte {}'.format(timestamp, timestamp.source.payload_offset if timestamp.source is not None else '?'))

		print(' NTFS/Linux timestamp comparisons:')
		if len(self.time_comparisons) == 0:
			print('  none')
		for comparison in self.time_comparisons:
			print('  {}'.format(comparison))

		print(' Missing evidence (not interpreted as zero):')
		if len(self.missing) == 0:
			print('  none')
		for item in self.missing:
			print('  {}'.format(item))

	def __str__(self):
		return 'WSLMetadataView, {} source(s), {} conflict(s), {} issue(s)'.format(len(self.sources), len(self.conflicts), len(self.issues))

def BuildWSLMetadataView(file_record):
	"""Build and return a WSLMetadataView for an MFT.FileRecord or MFT.FileRecordSegment object."""

	return WSLMetadataView(file_record)

def build_wsl_metadata_view(file_record):
	"""Build and return a WSLMetadataView for an MFT.FileRecord or MFT.FileRecordSegment object."""

	return WSLMetadataView(file_record)

# Compatibility aliases for callers which used the initial draft names.
SourceLocation = WSLSource
UninterpretableEvidence = WSLIssue
FieldCandidate = WSLFieldCandidate
Conflict = WSLConflict
TimeComparison = WSLTimeComparison
LXATTRBRecord = LXATTRBView
LXXATTRRecord = LXXATTRView
