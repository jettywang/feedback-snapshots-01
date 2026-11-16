#!/usr/bin/env python3
# coding: utf-8

# dfir_ntfs: an NTFS parser for digital forensics & incident response
#
# Read-only comparison of NTFS $LogFile restart pages.
#
# This tool never repairs, rewrites, or "blesses" a log file. It reports:
#   * which restart pages are parseable and which one the loader actually uses;
#   * which required LSNs resolve to records under each page's own geometry;
#   * which recovery ranges are actually covered versus merely parseable;
#   * why a single "highest LSN wins" answer is unsupportable.

import argparse
import io
import struct
import sys

from dfir_ntfs import LogFile, LogFileAudit

PAGE_SIZE = LogFile.PAGE_SIZE
HEADER_LENGTH = 48
DATA_OFFSET = 64
SEQUENCE_NUMBER_BITS = 43
USA_SIZE = 9


class SyntheticLog(object):
	"""Builder for short, self-contained $LogFile samples (in memory only)."""

	LOG_RECORD_SIZE = HEADER_LENGTH + 64
	CLIENT_RESTART_SIZE = HEADER_LENGTH + 112

	def __init__(self, page_count = 48):
		self.pages = [bytearray(b'\xFF' * PAGE_SIZE) for _ in range(page_count)]
		self.version = (2, 0)

	def lsn(self, page_number, offset_in_page, sequence_number = 0):
		absolute_offset = page_number * PAGE_SIZE + offset_in_page
		return (absolute_offset >> 3) | (sequence_number << (64 - SEQUENCE_NUMBER_BITS))

	def offset(self, lsn):
		absolute_offset = ((lsn << SEQUENCE_NUMBER_BITS) & 0xFFFFFFFFFFFFFFFF) >> (SEQUENCE_NUMBER_BITS - 3)
		return (absolute_offset // PAGE_SIZE, absolute_offset % PAGE_SIZE)

	def _protect(self, page, usa_offset):
		page = bytearray(page)
		sequence_number = b'\x01\x00'
		usa = bytearray(USA_SIZE * 2)
		usa[0:2] = sequence_number

		for index in range(1, USA_SIZE):
			position = index * 512 - 2
			usa[index * 2 : index * 2 + 2] = page[position : position + 2]
			page[position : position + 2] = sequence_number

		struct.pack_into('<H', page, 4, usa_offset)
		struct.pack_into('<H', page, 6, USA_SIZE)
		page[usa_offset : usa_offset + USA_SIZE * 2] = usa

		return bytes(page)

	def restart_page(self, signature, current_lsn, oldest_lsn, restart_lsn, declared_file_size, sequence_number_bits = SEQUENCE_NUMBER_BITS):
		page = bytearray(PAGE_SIZE)
		page[0:4] = signature
		struct.pack_into('<Q', page, 8, 0)
		struct.pack_into('<L', page, 16, PAGE_SIZE)
		struct.pack_into('<L', page, 20, PAGE_SIZE)
		struct.pack_into('<H', page, 24, 48)
		struct.pack_into('<H', page, 26, self.version[1])
		struct.pack_into('<H', page, 28, self.version[0])

		restart_area = 48
		struct.pack_into('<Q', page, restart_area + 0, current_lsn)
		struct.pack_into('<H', page, restart_area + 8, 1)
		struct.pack_into('<H', page, restart_area + 10, 0xFFFF)
		struct.pack_into('<H', page, restart_area + 12, 0)
		struct.pack_into('<H', page, restart_area + 14, 0)
		struct.pack_into('<L', page, restart_area + 16, sequence_number_bits)
		struct.pack_into('<H', page, restart_area + 20, 224)
		struct.pack_into('<H', page, restart_area + 22, 64)
		struct.pack_into('<q', page, restart_area + 24, declared_file_size)
		struct.pack_into('<L', page, restart_area + 32, 112)
		struct.pack_into('<H', page, restart_area + 36, HEADER_LENGTH)
		struct.pack_into('<H', page, restart_area + 38, DATA_OFFSET)

		client = restart_area + 64
		struct.pack_into('<Q', page, client + 0, oldest_lsn)
		struct.pack_into('<Q', page, client + 8, restart_lsn)
		struct.pack_into('<H', page, client + 16, 0xFFFF)
		struct.pack_into('<H', page, client + 18, 0xFFFF)
		struct.pack_into('<H', page, client + 20, 0)
		struct.pack_into('<L', page, client + 28, 8)
		page[client + 32 : client + 40] = 'NTFS'.encode('utf-16le')

		return self._protect(page, 30)

	def _record(self, this_lsn, previous_lsn, record_type, client_data, transaction_id = 0):
		header = bytearray(HEADER_LENGTH)
		struct.pack_into('<Q', header, 0, this_lsn)
		struct.pack_into('<Q', header, 8, previous_lsn)
		struct.pack_into('<Q', header, 16, 0)
		struct.pack_into('<L', header, 24, len(client_data))
		struct.pack_into('<L', header, 28, 0)
		struct.pack_into('<L', header, 32, record_type)
		struct.pack_into('<L', header, 36, transaction_id)
		return bytes(header) + client_data

	def _log_record_data(self, operation):
		client_data = bytearray(64)
		struct.pack_into('<H', client_data, 0, operation)
		struct.pack_into('<H', client_data, 4, 32)
		struct.pack_into('<H', client_data, 6, 32)
		return bytes(client_data)

	def client_restart_data(self, checkpoint_lsn, open_attribute_table_lsn):
		client_data = bytearray(112)
		struct.pack_into('<L', client_data, 0, 1)
		struct.pack_into('<L', client_data, 4, 0)
		struct.pack_into('<Q', client_data, 8, checkpoint_lsn)
		struct.pack_into('<Q', client_data, 16, open_attribute_table_lsn)
		struct.pack_into('<Q', client_data, 24, 0)
		struct.pack_into('<Q', client_data, 32, 0)
		struct.pack_into('<Q', client_data, 40, 0)
		struct.pack_into('<Q', client_data, 72, checkpoint_lsn)
		struct.pack_into('<L', client_data, 80, 4096)
		struct.pack_into('<Q', client_data, 104, checkpoint_lsn)
		return bytes(client_data)

	def log_record_page(self, page_number, records):
		page = bytearray(b'\x00' * PAGE_SIZE)
		page[0:4] = b'RCRD'
		struct.pack_into('<L', page, 16, 0)
		struct.pack_into('<H', page, 20, 1)
		struct.pack_into('<H', page, 22, 0)

		offset = DATA_OFFSET
		last_lsn = 0

		for record in records:
			if offset + len(record) > PAGE_SIZE:
				raise ValueError('Synthetic log record page overflows')

			page[offset : offset + len(record)] = record
			last_lsn = struct.unpack('<Q', record[0:8])[0]
			offset += len(record)

		struct.pack_into('<Q', page, 8, last_lsn)
		struct.pack_into('<H', page, 24, offset)
		struct.pack_into('<Q', page, 32, last_lsn)

		return self._protect(page, 40)

	def write_state(self, page_number, with_table_reference = True, table_lsn = None):
		"""Create a consistent state: checkpoint record, optional table dump, then client restart."""

		checkpoint_offset = DATA_OFFSET
		second_offset = checkpoint_offset + self.LOG_RECORD_SIZE
		third_offset = second_offset + self.LOG_RECORD_SIZE

		checkpoint = self.lsn(page_number, checkpoint_offset)
		second = self.lsn(page_number, second_offset)
		third = self.lsn(page_number, third_offset)

		if table_lsn is None:
			table_lsn = second if with_table_reference else 0

		records = [
			self._record(checkpoint, 0, LogFile.LfsClientRecord, self._log_record_data(LogFile.ForgetTransaction)),
			self._record(second, checkpoint, LogFile.LfsClientRecord, self._log_record_data(LogFile.OpenAttributeTableDump)),
			self._record(third, 0, LogFile.LfsClientRestart, self.client_restart_data(checkpoint, table_lsn)),
		]

		self.pages[page_number] = self.log_record_page(page_number, records)

		return (checkpoint, third, second)

	def build(self, page_1, page_2):
		self.pages[0] = page_1
		self.pages[1] = page_2

		return b''.join(bytes(page) for page in self.pages)


def build_two_valid_states(declared_file_size):
	builder = SyntheticLog()
	oldest_1, restart_1, _ = builder.write_state(36)
	oldest_2, restart_2, _ = builder.write_state(40)

	page_1 = builder.restart_page(b'RSTR', restart_1, oldest_1, restart_1, declared_file_size)
	page_2 = builder.restart_page(b'RSTR', restart_2, oldest_2, restart_2, declared_file_size)

	return (builder.build(page_1, page_2), oldest_1, restart_1, oldest_2, restart_2)


def build_newer_missing(declared_file_size):
	builder = SyntheticLog()
	oldest_1, restart_1, _ = builder.write_state(36)

	missing_page = 60
	missing_lsn = builder.lsn(missing_page, DATA_OFFSET)

	page_1 = builder.restart_page(b'RSTR', restart_1, oldest_1, restart_1, declared_file_size)
	page_2 = builder.restart_page(b'RSTR', missing_lsn, oldest_1, missing_lsn, declared_file_size)

	return (builder.build(page_1, page_2), oldest_1, restart_1, missing_lsn)


def build_newer_corrupt_page(declared_file_size):
	builder = SyntheticLog()
	oldest_1, restart_1, _ = builder.write_state(36)

	missing_page = 60
	missing_lsn = builder.lsn(missing_page, DATA_OFFSET)

	page_1 = builder.restart_page(b'RSTR', restart_1, oldest_1, restart_1, declared_file_size)
	page_2 = bytearray(builder.restart_page(b'RSTR', missing_lsn, oldest_1, missing_lsn, declared_file_size))
	page_2[1022:1024] = b'\xDE\xAD'
	page_2 = bytes(page_2)

	return (builder.build(page_1, page_2), oldest_1, restart_1, missing_lsn)


def build_chain_complete_table_missing(declared_file_size):
	builder = SyntheticLog()
	oldest_1, restart_1, _ = builder.write_state(36)

	missing_table_lsn = builder.lsn(60, DATA_OFFSET)
	oldest_2, restart_2, _ = builder.write_state(40, table_lsn = missing_table_lsn)

	page_1 = builder.restart_page(b'RSTR', restart_1, oldest_1, restart_1, declared_file_size)
	page_2 = builder.restart_page(b'RSTR', restart_2, oldest_2, restart_2, declared_file_size)

	return (builder.build(page_1, page_2), oldest_2, restart_2, missing_table_lsn)


def build_geometry_conflict(declared_file_size):
	builder = SyntheticLog()
	oldest_1, restart_1, _ = builder.write_state(36)
	oldest_2, restart_2, _ = builder.write_state(40)

	page_1 = builder.restart_page(b'RSTR', restart_1, oldest_1, restart_1, declared_file_size, sequence_number_bits = 43)
	page_2 = builder.restart_page(b'RSTR', restart_2, oldest_2, restart_2, declared_file_size, sequence_number_bits = 42)

	return (builder.build(page_1, page_2), oldest_1, restart_1, oldest_2, restart_2)


def describe_audit(result):
	lines = []
	lines.append('  {}: signature={} ({}), version={}'.format(
		result['label'], result['signature'].decode('latin-1', errors='replace'), result['signature_authority'], result['version']))
	lines.append('    declared file size: {}, actual file size: {}, record area: [{}, {})'.format(
		result['file_size_declared'], result['file_size_actual'], result['page_extent'][0], result['page_extent'][1]))

	for check in result['checks']:
		lines.append('    {} {:<38} {}  ({})'.format('gate ' if check['kind'] == 'gate' else 'limit', check['name'], 'PASS' if check['ok'] else 'FAIL', check['detail']))

	for client in result['clients']:
		lines.append('    client {}: oldest={:#x} resolved={} restart={:#x} resolved={}'.format(
			client['name'], client['oldest_lsn'], client['oldest_record'], client['restart_lsn'], client['restart_record']))

		if client['forward'] is not None:
			lines.append('      forward walk: {} record(s), reached current: {} ({})'.format(
				client['forward']['visited'], client['forward']['reached_stop'], client['forward']['reason']))

		if client['checkpoint'] is not None:
			lines.append('      checkpoint: {:#x} -> {}'.format(client['checkpoint']['lsn'], client['checkpoint']['status']))

		for name, reference in client['tables'].items():
			if reference['status'] != 'not_referenced':
				lines.append('      {}: {:#x} -> {}'.format(name, reference['lsn'], reference['status']))

		for error in client['errors']:
			lines.append('      error: {}'.format(error))

	lines.append('    page verdict: {}'.format(result['verdict']))
	claim = result['state_completeness_claim']
	lines.append('    completeness claim: {}'.format('allowed' if claim['allowed'] else 'withheld'))
	for reason in claim['reasons']:
		lines.append('      withheld because: {}'.format(reason))
	return lines


def describe_loader(view):
	lines = []
	lines.append('  loader selected: {}'.format(view['selected']))
	lines.append('  loader geometry: version={}, seq bits={}, header={}, data offset={}'.format(
		view['version'], view['sequence_number_bits'], view['record_header_length'], view['log_page_data_offset']))

	for conflict in view['geometry_conflicts']:
		lines.append('  geometry conflict (not rejected): {}'.format(conflict))

	for note in view['notes']:
		lines.append('  note: {}'.format(note))

	lines.append('  collected LSNs: {} (min {:#x}, max {:#x})'.format(
		view['collected_lsn_count'], view['collected_min_lsn'], view['collected_max_lsn']))

	if 'page_2_restart_in_collected_set' in view:
		lines.append('  page 2 restart LSN in collected set: {} (page {}, inside file: {})'.format(
			view['page_2_restart_in_collected_set'], view['page_2_restart_page_number'], view['page_2_restart_page_inside_file']))

	return lines


def run_sample(name, data, expectation = None):
	print('\n=== {} ==='.format(name))

	file_object = io.BytesIO(data)
	try:
		results, notes = LogFileAudit.audit_file(file_object, recover=False)
	except LogFileAudit.AuditError as e:
		print('  audit error: {}'.format(e))
		return False

	for note in notes:
		print('  note: {}'.format(note))

	for result in results:
		for line in describe_audit(result):
			print(line)

	file_object.seek(0)
	view = LogFileAudit.loader_view(file_object, recover=False)
	for line in describe_loader(view):
		print(line)

	comparison = LogFileAudit.compare_restart_states(results, view)
	print('  comparison: {}'.format(comparison['selection']))
	print('  "highest LSN wins" safe: {}'.format(comparison['max_lsn_choice_safe']))
	for reason in comparison['reasons']:
		print('    {}'.format(reason))

	if expectation is not None:
		ok = expectation(results, view)
		print('  EXPECTATION: {}'.format('PASS' if ok else 'FAIL'))
		return ok

	return True


def expectation_two_valid(results, view):
	if len(results) != 2:
		return False
	if any(result['verdict'] != 'supported_for_reachable_range' for result in results):
		return False
	# Each page is internally consistent, but the loader can only emit one geometry and mixes both LSN sets.
	return view['selected'].startswith('page 1') and view['collected_lsn_count'] > 0


def expectation_newer_missing(results, view):
	if len(results) != 2:
		return False
	newer = results[1]
	return newer['signature'] == b'RSTR' and newer['verdict'] == 'partially_supported' and not view['page_2_restart_in_collected_set']


def expectation_newer_corrupt_page(results, view):
	# A corrupted USA on the newer page must make it unparseable rather than silently accepted.
	return len(results) == 1 and results[0]['label'] == 'page 1' and view['page_2_parseable'] is False


def expectation_chain_complete_table_missing(results, view):
	if len(results) != 2:
		return False

	page_2 = results[1]
	client = page_2['clients'][0]
	if not client['restart_record'] or client['forward'] is None or not client['forward']['reached_stop']:
		return False

	table = client['tables']['open_attribute_table']
	return page_2['verdict'] == 'partially_supported' and table['status'] == 'missing'


def expectation_geometry_conflict(results, view):
	return len(view['geometry_conflicts']) > 0 and view['selected'].startswith('page 1')


def self_check():
	declared = 48 * PAGE_SIZE
	ok = True

	data, oldest_1, restart_1, oldest_2, restart_2 = build_two_valid_states(declared)
	ok &= run_sample('synthetic: two valid restart states', data, expectation_two_valid)

	data, oldest_1, restart_1, missing_lsn = build_newer_missing(declared)
	ok &= run_sample('synthetic: newer page 2 points outside the file', data, expectation_newer_missing)

	data, oldest_1, restart_1, missing_lsn = build_newer_corrupt_page(declared)
	ok &= run_sample('synthetic: newer page 2 fails USA validation', data, expectation_newer_corrupt_page)

	data, oldest_2, restart_2, missing_table_lsn = build_chain_complete_table_missing(declared)
	ok &= run_sample('synthetic: record chain complete but required table dump missing', data, expectation_chain_complete_table_missing)

	data, oldest_1, restart_1, oldest_2, restart_2 = build_geometry_conflict(declared)
	ok &= run_sample('synthetic: restart pages disagree on sequence number bits', data, expectation_geometry_conflict)

	return ok


def main():
	parser = argparse.ArgumentParser(description='Read-only NTFS $LogFile restart-page consistency audit')
	parser.add_argument('logfile', nargs='?', help='path to a $LogFile image')
	parser.add_argument('--self-check', action='store_true', help='run bundled short synthetic cases (no files written)')
	parser.add_argument('--recover', action='store_true', help='also audit an in-memory recovery view (tail/fast pages)')

	args = parser.parse_args()

	if args.self_check:
		if not self_check():
			return 1

		return 0

	if not args.logfile:
		parser.error('either --self-check or a $LogFile path is required')

	with open(args.logfile, 'rb') as file_object:
		data = file_object.read()

	ok = run_sample(args.logfile, data)

	if args.recover:
		print('\n=== {} (in-memory recovery view; original untouched) ==='.format(args.logfile))
		file_object = io.BytesIO(data)
		results, notes = LogFileAudit.audit_file(file_object, recover=True)

		for note in notes:
			print('  note: {}'.format(note))

		for result in results:
			for line in describe_audit(result):
				print(line)

		file_object.seek(0)
		for line in describe_loader(LogFileAudit.loader_view(file_object, recover=True)):
			print(line)

	return 0 if ok else 1


if __name__ == '__main__':
	sys.exit(main())
