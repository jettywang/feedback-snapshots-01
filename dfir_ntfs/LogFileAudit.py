# dfir_ntfs: an NTFS parser for digital forensics & incident response
#
# Read-only restart-page consistency audit for $LogFile.
#
# This module deliberately does not repair, rewrite, or silently choose a
# recovery state. It answers a narrower question: under each restart page's
# own geometry, which log records are actually reachable, which required
# references resolve, and what (if anything) that state can support.

import io

from . import LogFile

MAX_CHAIN_RECORDS = 2000000

RESTART_SIGNATURE = b'RSTR'
CHKDSK_SIGNATURE = b'CHKD'
BAD_SIGNATURE = b'BAAD'

EXPECTED_TABLE_OPERATIONS = {
	'open_attribute_table': { LogFile.OpenAttributeTableDump },
	'attribute_names': { LogFile.AttributeNamesDump },
	'dirty_page_table': { LogFile.DirtyPageTableDump },
	'transaction_table': { LogFile.TransactionTableDump },
}


class AuditError(Exception):
	"""Raised when an audit cannot be performed safely."""


class PageGeometry(object):
	"""Geometry taken from one restart page, never from the parser's selected page."""

	def __init__(self, restart_page):
		restart_area = restart_page.get_restart_area()

		self.log_page_size = restart_page.get_log_page_size()
		self.system_page_size = restart_page.get_system_page_size()
		self.version = (restart_page.get_major_version(), restart_page.get_minor_version())
		self.record_header_length = restart_area.get_record_header_length()
		self.log_page_data_offset = restart_area.get_log_page_data_offset()
		self.sequence_number_bits = restart_area.get_sequence_number_bits()
		self.declared_file_size = restart_area.get_file_size()

		if self.log_page_size <= 0 or self.log_page_size % 512 != 0:
			raise AuditError('Invalid log page size: {}'.format(self.log_page_size))

		if self.record_header_length < LogFile.LogRecordHeader.sizeof:
			raise AuditError('Invalid record header length: {}'.format(self.record_header_length))

		if self.log_page_data_offset < 8 or self.log_page_data_offset % 8 != 0:
			raise AuditError('Invalid log page data offset: {}'.format(self.log_page_data_offset))

		if not 3 <= self.sequence_number_bits < 64:
			raise AuditError('Invalid sequence number bits: {}'.format(self.sequence_number_bits))

	def lsn_to_offset(self, lsn):
		absolute_offset = ((lsn << self.sequence_number_bits) & 0xFFFFFFFFFFFFFFFF) >> (self.sequence_number_bits - 3)

		return (absolute_offset // self.log_page_size, absolute_offset % self.log_page_size)

	def offset_to_lsn(self, log_page_number, offset_in_page, sequence_number):
		absolute_offset = log_page_number * self.log_page_size + offset_in_page

		return (absolute_offset >> 3) | (sequence_number << (64 - self.sequence_number_bits))

	def lsn_to_seqnum(self, lsn):
		return lsn >> (64 - self.sequence_number_bits)

	def wrapped_page_number(self):
		if self.version == (1, 1):
			return 4

		if self.version[0] >= 2:
			return 34

		raise AuditError('Unknown "infinite" area location for version {}'.format(self.version))


class LogRecord(object):
	"""A validated log record header and its location."""

	def __init__(self, page_number, offset_in_page, header, header_length):
		self.page_number = page_number
		self.offset_in_page = offset_in_page
		self.lsn = header.get_this_lsn()
		self.previous_lsn = header.get_client_previous_lsn()
		self.undo_next_lsn = header.get_client_undo_next_lsn()
		self.client_data_length = header.get_client_data_length()
		self.client_id = header.get_client_id()
		self.record_type = header.get_record_type()
		self.transaction_id = header.get_transaction_id()
		self.flags = header.get_flags()
		self.header_length = header_length
		self.buf = header.buf


class PageAudit(object):
	"""Audit of one restart page and the records reachable under its own geometry."""

	def __init__(self, restart_page, file_object, actual_size, label):
		self.label = label
		self.restart_page = restart_page
		self.file_object = file_object
		self.actual_size = actual_size

		self.geometry = PageGeometry(restart_page)
		self.restart_area = restart_page.get_restart_area()
		self.clients = list(self.restart_area.clients())

		self._record_cache = {}
		self._page_cache = {}

	def _read_page(self, page_number):
		if page_number in self._page_cache:
			return self._page_cache[page_number]

		if page_number < 0:
			self._page_cache[page_number] = None
			return None

		offset = page_number * self.geometry.log_page_size
		if offset + self.geometry.log_page_size > self.actual_size:
			self._page_cache[page_number] = None
			return None

		self.file_object.seek(offset)
		buf = self.file_object.read(self.geometry.log_page_size)
		if len(buf) != self.geometry.log_page_size:
			self._page_cache[page_number] = None
			return None

		try:
			page = LogFile.LogRecordPage(buf, page_number, self.geometry.log_page_data_offset)
		except (LogFile.LogFileException, NotImplementedError):
			page = None

		self._page_cache[page_number] = page
		return page

	def resolve_record(self, lsn):
		"""Return a LogRecord only if the LSN maps to a header with a matching this-LSN."""

		if lsn in self._record_cache:
			return self._record_cache[lsn]

		result = None
		page_number, offset_in_page = self.geometry.lsn_to_offset(lsn)

		if offset_in_page < self.geometry.log_page_data_offset:
			self._record_cache[lsn] = None
			return None

		page = self._read_page(page_number)
		if page is not None:
			try:
				header = page.get_log_record_at_offset(offset_in_page, self.geometry.record_header_length)
			except LogFile.LogFileException:
				header = None

			if header is not None:
				client_data_length = header.get_client_data_length()
				if 8 <= client_data_length and client_data_length % 8 == 0:
					if header.get_this_lsn() == lsn:
						result = LogRecord(page_number, offset_in_page, header, self.geometry.record_header_length)

		self._record_cache[lsn] = result
		return result

	def resolve_client_data(self, lsn):
		"""Return (record, ClientData) only if the full client data is present in the file."""

		record = self.resolve_record(lsn)
		if record is None:
			return (None, None)

		total = record.header_length + record.client_data_length
		if record.offset_in_page + total > self.geometry.log_page_size:
			client_buf = record.buf[record.header_length : ]
			left = record.client_data_length - len(client_buf)
			page_number = record.page_number

			while left > 0:
				page_number += 1
				if page_number * self.geometry.log_page_size >= self.actual_size:
					return (record, None)

				page = self._read_page(page_number)
				if page is None:
					return (record, None)

				capacity = self.geometry.log_page_size - self.geometry.log_page_data_offset
				take = min(left, capacity)
				client_buf += page.buf[self.geometry.log_page_data_offset : self.geometry.log_page_data_offset + take]
				left -= take
		else:
			client_buf = record.buf[record.header_length : record.header_length + record.client_data_length]

		if len(client_buf) != record.client_data_length:
			return (record, None)

		try:
			client_data = LogFile.ClientData(client_buf, record.record_type, lsn, record.transaction_id, LogFile.CLUSTER_SIZE_DEFAULT)
		except Exception:
			return (record, None)

		return (record, client_data)

	def next_record(self, record):
		"""Find the next record in file order, including page wrap, or None if it cannot be validated."""

		if record.client_data_length < 8 or record.client_data_length % 8 != 0:
			return None

		page_number = record.page_number
		offset_in_page = record.offset_in_page
		seqnum = self.geometry.lsn_to_seqnum(record.lsn)
		page_size = self.geometry.log_page_size
		header_length = self.geometry.record_header_length
		data_offset = self.geometry.log_page_data_offset

		if record.client_data_length <= page_size - offset_in_page - header_length:
			candidate_offset = offset_in_page + header_length + record.client_data_length
			candidate = self.geometry.offset_to_lsn(page_number, candidate_offset, seqnum)
			if self.resolve_record(candidate) is not None:
				return candidate

			next_page = page_number + 1
			if next_page * page_size >= self.actual_size:
				next_page = self.geometry.wrapped_page_number()
				seqnum += 1

			candidate = self.geometry.offset_to_lsn(next_page, data_offset, seqnum)
			if self.resolve_record(candidate) is not None:
				return candidate

			return None

		left = record.client_data_length - (page_size - offset_in_page - header_length)
		pages_to_skip = 1 + left // (page_size - data_offset)

		next_page = page_number + pages_to_skip
		candidate_offset = data_offset + left - (pages_to_skip - 1) * (page_size - data_offset)
		candidate = self.geometry.offset_to_lsn(next_page, candidate_offset, seqnum)

		if next_page * page_size >= self.actual_size:
			pages_left = (self.actual_size // page_size) - (page_number + 1)
			next_page = self.geometry.wrapped_page_number() + (pages_to_skip - 1) - pages_left
			seqnum += 1
			candidate = self.geometry.offset_to_lsn(next_page, candidate_offset, seqnum)

		if self.resolve_record(candidate) is not None:
			return candidate

		candidate = self.geometry.offset_to_lsn(next_page + 1, data_offset, seqnum)
		if self.resolve_record(candidate) is not None:
			return candidate

		return None

	def walk_forward(self, start_lsn, stop_lsn):
		"""Walk next-record links; return a dict describing coverage and the stop reason."""

		visited = []
		seen = set()
		current = start_lsn
		stop_reached = False

		while current:
			if current in seen:
				return self._walk_result(visited, 'loop at {:#x}'.format(current), stop_reached)
			if current == stop_lsn:
				stop_reached = True
			record = self.resolve_record(current)
			if record is None:
				return self._walk_result(visited, 'missing or invalid record at {:#x}'.format(current), stop_reached)

			seen.add(current)
			visited.append(current)

			if stop_reached:
				return self._walk_result(visited, 'stop LSN reached', True)
			if len(visited) >= MAX_CHAIN_RECORDS:
				return self._walk_result(visited, 'record limit reached', stop_reached)

			current = self.next_record(record)

		return self._walk_result(visited, 'no next record', stop_reached)

	def _walk_result(self, visited, reason, reached):
		return {
			'visited': len(visited),
			'reason': reason,
			'reached_stop': reached,
			'first_lsns': visited[:4],
			'last_lsn': visited[-1] if visited else None,
			'visited_set': set(visited),
		}

	def page_extent(self):
		page_size = self.geometry.log_page_size
		return (self.geometry.wrapped_page_number() * page_size, (self.actual_size // page_size) * page_size)

	def audit(self):
		page_size = self.geometry.log_page_size
		pages_in_file = self.actual_size // page_size if page_size else 0
		declared_size = self.geometry.declared_file_size

		signature = bytes(self.restart_page.buf[:4])
		extent_start, extent_end = self.page_extent()

		result = {
			'label': self.label,
			'version': self.geometry.version,
			'current_lsn': self.restart_area.get_current_lsn(),
			'signature': signature,
			'signature_authority': self._signature_authority(signature),
			'sequence_number_bits': self.geometry.sequence_number_bits,
			'file_size_declared': declared_size,
			'file_size_actual': self.actual_size,
			'pages_in_file': pages_in_file,
			'page_extent': (extent_start, extent_end),
			'checks': [],
			'clients': [],
			'verdict': None,
		}

		def add_check(name, ok, detail, kind):
			result['checks'].append({'name': name, 'ok': ok, 'detail': detail, 'kind': kind})

		add_check('signature_is_clean_restart', signature == RESTART_SIGNATURE, 'signature={}'.format(signature), 'gate')
		add_check('declared_file_size_not_zero', declared_size > 0, 'declared={}'.format(declared_size), 'gate')

		declared_covered = declared_size > 0 and self.actual_size >= declared_size
		result['declared_extent_covered'] = declared_covered
		add_check('declared_extent_covered', declared_covered, 'declared={} actual={}'.format(declared_size, self.actual_size), 'limit')
		add_check('record_area_present', extent_start < extent_end, 'record area=[{}, {})'.format(extent_start, extent_end), 'gate')

		for index, client in enumerate(self.clients):
			result['clients'].append(self._audit_client(index, client))

		result['verdict'] = self._classify(result)
		result['state_completeness_claim'] = self._state_completeness_claim(result)
		return result

	def _audit_client(self, index, client):
		info = {
			'index': index,
			'name': client.get_client_name(),
			'oldest_lsn': client.get_oldest_lsn(),
			'restart_lsn': client.get_client_restart_lsn(),
			'oldest_record': False,
			'restart_record': False,
			'restart_decoded': None,
			'checkpoint': None,
			'tables': {},
			'forward': None,
			'errors': [],
		}

		oldest_lsn = client.get_oldest_lsn()
		restart_lsn = client.get_client_restart_lsn()
		current_lsn = self.restart_area.get_current_lsn()

		oldest_record = self.resolve_record(oldest_lsn)
		restart_record = self.resolve_record(restart_lsn)

		info['oldest_record'] = oldest_record is not None
		info['restart_record'] = restart_record is not None

		if oldest_record is None:
			info['errors'].append('oldest LSN {:#x} does not resolve to a valid record'.format(oldest_lsn))
		elif oldest_record.client_id != index:
			info['errors'].append('oldest LSN belongs to client {}, expected {}'.format(oldest_record.client_id, index))

		if restart_record is None:
			info['errors'].append('client restart LSN {:#x} does not resolve to a valid record'.format(restart_lsn))
		elif restart_record.client_id != index:
			info['errors'].append('restart LSN belongs to client {}, expected {}'.format(restart_record.client_id, index))
		elif restart_record.record_type != LogFile.LfsClientRestart:
			info['errors'].append('restart LSN has record type {}, expected client restart'.format(restart_record.record_type))
		else:
			_, client_data = self.resolve_client_data(restart_lsn)
			if client_data is None:
				info['errors'].append('client restart record is truncated across pages')
			else:
				try:
					decoded = client_data.data_decoded()
				except (LogFile.ClientException, NotImplementedError) as e:
					info['errors'].append('cannot decode client restart area: {}'.format(e))
				else:
					info['restart_decoded'] = decoded
					info['checkpoint'] = self._describe_reference(decoded.get_start_of_checkpoint_lsn(), index)
					for name, getter in [
						('open_attribute_table', decoded.get_open_attribute_table_lsn),
						('attribute_names', decoded.get_attribute_names_lsn),
						('dirty_page_table', decoded.get_dirty_page_table_lsn),
						('transaction_table', decoded.get_transaction_table_lsn),
					]:
						lsn = getter()
						info['tables'][name] = self._describe_reference(lsn, index, EXPECTED_TABLE_OPERATIONS[name])

		if oldest_record is not None and restart_record is not None and current_lsn:
			forward = self.walk_forward(oldest_lsn, current_lsn)
			forward.pop('visited_set', None)
			info['forward'] = forward

		return info

	def _describe_reference(self, lsn, expected_client_id, expected_operations = None):
		if lsn == 0:
			return {'lsn': 0, 'status': 'not_referenced'}

		record = self.resolve_record(lsn)
		if record is None:
			return {'lsn': lsn, 'status': 'missing', 'page': self.geometry.lsn_to_offset(lsn)[0]}

		info = {
			'lsn': lsn,
			'status': 'present',
			'page': record.page_number,
			'client_id': record.client_id,
			'record_type': record.record_type,
		}

		if record.client_id != expected_client_id:
			info['status'] = 'wrong_client'
			return info

		_, client_data = self.resolve_client_data(lsn)
		if client_data is None:
			info['status'] = 'truncated'
			return info

		if client_data.record_type == LogFile.LfsClientRestart:
			try:
				decoded = client_data.data_decoded()
			except (LogFile.ClientException, NotImplementedError):
				info['status'] = 'undecodable'
			else:
				info['ntfs_version'] = (decoded.get_major_version(), decoded.get_minor_version())
		elif client_data.record_type == LogFile.LfsClientRecord:
			try:
				decoded = client_data.data_decoded()
			except (LogFile.ClientException, NotImplementedError):
				info['status'] = 'undecodable'
			else:
				operation = decoded.get_redo_operation()
				info['operation'] = LogFile.ResolveNTFSOperation(operation)
				if expected_operations is not None and operation not in expected_operations:
					info['status'] = 'wrong_operation'

		return info

	def _state_completeness_claim(self, result):
		"""Return whether this page can support a statement that the log is complete."""

		reasons = []

		if result['signature'] != RESTART_SIGNATURE:
			reasons.append('restart page signature is {}, not RSTR'.format(result['signature']))

		if not result.get('declared_extent_covered', False):
			reasons.append('image is smaller than the declared log file size; the capture cannot prove the tail is absent')
		elif result['file_size_actual'] > result['file_size_declared']:
			reasons.append('image is larger than the declared log file size; extra pages are not covered by this restart state')

		if result['verdict'] != 'supported_for_reachable_range':
			reasons.append('not all required records and references resolve')

		for client in result['clients']:
			if client['oldest_lsn'] == 0 or client['restart_lsn'] == 0:
				reasons.append('client has a zero oldest or restart LSN')

		return {
			'allowed': len(reasons) == 0,
			'reasons': reasons,
		}

	def _signature_authority(self, signature):
		if signature == RESTART_SIGNATURE:
			return 'normal'
		if signature == CHKDSK_SIGNATURE:
			return 'chkdsk_repair'
		if signature == BAD_SIGNATURE:
			return 'marked_bad'
		return 'unknown'

	def _client_supported(self, client):
		if not client['restart_record'] or not client['oldest_record']:
			return False
		if client['restart_decoded'] is None:
			return False
		if client['forward'] is None or not client['forward']['reached_stop']:
			return False

		references = [client['checkpoint']]
		references.extend(client['tables'].values())

		for reference in references:
			if reference is None:
				continue
			if reference['status'] == 'not_referenced':
				continue
			if reference['status'] != 'present':
				return False

		return True

	def _classify(self, result):
		for check in result['checks']:
			if check['kind'] == 'gate' and not check['ok']:
				return 'unsupported'

		if not result['clients']:
			return 'unsupported'

		supported = 0
		for client in result['clients']:
			if self._client_supported(client):
				supported += 1

		if supported == len(result['clients']):
			return 'supported_for_reachable_range'

		if supported > 0 or any(client['restart_record'] or client['oldest_record'] for client in result['clients']):
			return 'partially_supported'

		return 'unsupported'


def compare_restart_states(results, loader):
	"""Compare restart-page candidates without choosing one.

	Returns a dict with:
	  selection: one of 'single_candidate', 'multiple_candidates', 'no_trustworthy_candidate'
	  max_lsn_choice_safe: whether the page with the highest current LSN is itself supportable
	  reasons: human-readable reasons
	"""

	reasons = []
	candidates = []

	for result in results:
		client = result['clients'][0] if result['clients'] else None
		candidates.append({
			'label': result['label'],
			'current_lsn': result.get('current_lsn'),
			'oldest_lsn': client['oldest_lsn'] if client else None,
			'restart_lsn': client['restart_lsn'] if client else None,
			'verdict': result['verdict'],
			'claim': result['state_completeness_claim']['allowed'],
			'signature': result['signature'],
			'geometry': (result['version'], result['sequence_number_bits']),
		})

	if not candidates:
		return {
			'selection': 'no_trustworthy_candidate',
			'candidates': candidates,
			'max_lsn_choice_safe': False,
			'reasons': ['no restart page could be audited'],
		}

	current_values = [result.get('current_lsn', 0) for result in results]

	highest_index = max(range(len(results)), key=lambda index: current_values[index])
	highest_result = results[highest_index]

	highest_supported = (highest_result['verdict'] == 'supported_for_reachable_range')

	usable = [result for result in results if result['verdict'] == 'supported_for_reachable_range']
	distinct = set()
	for result in usable:
		client = result['clients'][0]
		distinct.add((client['oldest_lsn'], client['restart_lsn'], result['signature'], result['version'], result['sequence_number_bits']))

	if len(usable) == 0:
		selection = 'no_trustworthy_candidate'
		reasons.append('no restart page has a fully supported reachable range')
	elif len(usable) == 1:
		selection = 'single_candidate'
		reasons.append('only {} has a fully supported reachable range'.format(usable[0]['label']))
	else:
		if len(distinct) > 1:
			selection = 'multiple_candidates'
			reasons.append('{} restart pages are each internally supportable but describe different states; keep both candidates'.format(len(usable)))
		else:
			selection = 'single_candidate'
			reasons.append('{} restart pages are equivalent for the audited range'.format(len(usable)))

	if len(results) == 1:
		reasons.append('only one restart page is parseable; there is no competing candidate to choose between')
		max_safe = highest_supported
	elif not highest_supported:
		reasons.append('the page with the highest restart LSN ({}) is not fully supportable, so "higher LSN wins" would overstate completeness'.format(highest_result['label']))
		max_safe = False
	else:
		max_safe = True

	if len(usable) > 1 and len(distinct) > 1:
		max_safe = False
		reasons.append('even if the highest-LSN page is supportable, the other page is also supportable and differs; selection needs an independent oracle')

	return {
		'selection': selection,
		'candidates': candidates,
		'max_lsn_choice_safe': max_safe,
		'reasons': reasons,
	}


def audit_file(file_object, labels = ('page 1', 'page 2'), recover = False):
	"""Audit both restart pages under their own geometry.

	If recover is True, work on an in-memory copy and apply the parser's tail/fast
	pages first. The original file object is never written.
	"""

	file_object.seek(0, 2)
	actual_size = file_object.tell()

	file_object.seek(0)
	work_file = io.BytesIO(file_object.read(actual_size))

	notes = []

	if recover:
		parser = LogFile.LogFileParser(work_file)
		parser.prepare_for_writes()

		if parser.log_version == (1, 1):
			parser.apply_tail_page()
		elif parser.log_version[0] >= 2:
			parser.apply_fast_pages()

		work_file = parser.file_object
		work_file.seek(0, 2)
		actual_size = work_file.tell()
		notes.append('recovery view uses the loader-selected geometry; it is not a neutral reconstruction')

	work_file.seek(0)
	raw_pages = [work_file.read(LogFile.PAGE_SIZE), work_file.read(LogFile.PAGE_SIZE)]

	results = []

	if len(raw_pages[0]) != LogFile.PAGE_SIZE or len(raw_pages[1]) != LogFile.PAGE_SIZE:
		raise AuditError('Truncated log file: fewer than two restart pages')

	if raw_pages[0] == raw_pages[1] == b'\xFF' * LogFile.PAGE_SIZE:
		raise AuditError('Empty log file')

	for index, raw in enumerate(raw_pages):
		try:
			restart_page = LogFile.RestartPage(raw)
		except (LogFile.LogFileException, NotImplementedError) as e:
			notes.append('{} is not parseable: {}'.format(labels[index], e))
			continue

		try:
			page_audit = PageAudit(restart_page, work_file, actual_size, labels[index])
			results.append(page_audit.audit())
		except (AuditError, LogFile.LogFileException) as e:
			notes.append('{} cannot be audited: {}'.format(labels[index], e))

	return results, notes


def loader_view(file_object, recover = False):
	"""Describe what LogFileParser selects and what its combined LSN set contains."""

	file_object.seek(0, 2)
	actual_size = file_object.tell()

	file_object.seek(0)
	work_file = io.BytesIO(file_object.read(actual_size))

	parser = LogFile.LogFileParser(work_file)

	if recover:
		parser.prepare_for_writes()
		if parser.log_version == (1, 1):
			parser.apply_tail_page()
		elif parser.log_version[0] >= 2:
			parser.apply_fast_pages()
		parser.file_object.seek(0, 2)
		actual_size = parser.file_object.tell()

	view = {
		'selected': None,
		'page_1_parseable': parser.restart_page_1 is not None,
		'page_2_parseable': parser.restart_page_2 is not None,
		'page_1_signature': bytes(parser.restart_page_1.buf[:4]) if parser.restart_page_1 is not None else None,
		'page_2_signature': bytes(parser.restart_page_2.buf[:4]) if parser.restart_page_2 is not None else None,
		'version': parser.log_version,
		'sequence_number_bits': parser.sequence_number_bits,
		'record_header_length': parser.record_header_length,
		'log_page_data_offset': parser.log_page_data_offset,
		'actual_file_size': actual_size,
		'geometry_conflicts': [],
		'notes': [],
		'checks': [],
	}

	if parser.restart_page_1 is not None and parser.restart_page_2 is not None:
		view['selected'] = 'page 1 (hard-coded preference; LSNs are not compared)'
	elif parser.restart_page_1 is not None:
		view['selected'] = 'page 1 (only parseable page)'
	else:
		view['selected'] = 'page 2 (only parseable page)'

	selected_page = parser.restart_page_1 if parser.restart_page_1 is not None else parser.restart_page_2
	other_page = parser.restart_page_2 if parser.restart_page_1 is not None else None

	selected_area = selected_page.get_restart_area()
	selected_clients = list(selected_area.clients())
	selected_client = selected_clients[0] if selected_clients else None

	view['selected_current_lsn'] = selected_area.get_current_lsn()
	view['selected_oldest_lsn'] = selected_client.get_oldest_lsn() if selected_client else None
	view['selected_restart_lsn'] = selected_client.get_client_restart_lsn() if selected_client else None

	if other_page is not None:
		other_area = other_page.get_restart_area()
		other_clients = list(other_area.clients())
		other_client = other_clients[0] if other_clients else None

		selected_geometry = PageGeometry(selected_page)
		other_geometry = PageGeometry(other_page)

		for name, left, right in [
			('sequence number bits', selected_geometry.sequence_number_bits, other_geometry.sequence_number_bits),
			('record header length', selected_geometry.record_header_length, other_geometry.record_header_length),
			('log page data offset', selected_geometry.log_page_data_offset, other_geometry.log_page_data_offset),
			('log page size', selected_geometry.log_page_size, other_geometry.log_page_size),
			('log version', selected_geometry.version, other_geometry.version),
		]:
			if left != right:
				view['geometry_conflicts'].append('{}: page 1={}, page 2={}'.format(name, left, right))

		if view['geometry_conflicts']:
			view['notes'].append('loader kept page 1 geometry and did not reject the conflicting page 2 geometry')

		if bytes(selected_page.buf[:4]) != RESTART_SIGNATURE:
			view['notes'].append('selected page signature is {}, not a clean RSTR page'.format(bytes(selected_page.buf[:4])))

		if other_client is not None:
			view['page_2_current_lsn'] = other_area.get_current_lsn()
			view['page_2_oldest_lsn'] = other_client.get_oldest_lsn()
			view['page_2_restart_lsn'] = other_client.get_client_restart_lsn()

			view['notes'].append('page 1 current={:#x}, page 2 current={:#x}'.format(selected_area.get_current_lsn(), other_area.get_current_lsn()))
			if other_area.get_current_lsn() > selected_area.get_current_lsn():
				view['notes'].append('page 2 claims a newer current LSN but is not selected')

	if other_page is not None:
		other_bits = other_page.get_restart_area().get_sequence_number_bits()
		if selected_area.get_sequence_number_bits() != other_bits:
			view['notes'].append('restart pages disagree on sequence number bits: {} vs {}'.format(
				selected_area.get_sequence_number_bits(), other_bits))

	parser.collect_lsns()
	view['collected_lsn_count'] = len(parser.lsns)
	view['collected_min_lsn'] = parser.lsns[0] if parser.lsns else None
	view['collected_max_lsn'] = parser.lsns[-1] if parser.lsns else None

	if other_page is not None:
		other_area = other_page.get_restart_area()
		other_clients = list(other_area.clients())
		other_client = other_clients[0] if other_clients else None

		if other_client is not None:
			restart_lsn = other_client.get_client_restart_lsn()
			view['page_2_restart_in_collected_set'] = restart_lsn in parser.lsns
			page_number, _ = parser.lsn_to_offset(restart_lsn)
			view['page_2_restart_page_number'] = page_number
			view['page_2_restart_page_inside_file'] = page_number < actual_size // parser.log_page_size

	return view
