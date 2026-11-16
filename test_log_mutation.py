# coding: utf-8

# Tests for structure-aware mutation and validation of NTFS log record operation payloads.

import os
import io
import struct

import pytest

from dfir_ntfs import LogFile, LogMutation as LM

TEST_DATA_DIR = 'test_data'
LOGFILE_7 = os.path.join(TEST_DATA_DIR, 'LogFile_7.bin')
LOGFILE_10 = os.path.join(TEST_DATA_DIR, 'LogFile_10.bin')
LOGFILE_10_4K = os.path.join(TEST_DATA_DIR, 'LogFile_10_large.bin')
ALL_LOGFILES = [ LOGFILE_7, LOGFILE_10, LOGFILE_10_4K ]


def make_mutator(layout):
	return LM.StructureAwareMutator(layout = layout, seed = 42)


def test_payload_range_overlap_semantics():
	# Empty ranges never overlap anything, even when an offset is present.
	assert LM.PayloadRange(40, 0).overlaps(LM.PayloadRange(40, 8)) == LM.RangeOverlap.EMPTY

	# Identical non-empty ranges are a legal shared range, not a rejection.
	assert LM.PayloadRange(40, 8).overlaps(LM.PayloadRange(40, 8)) == LM.RangeOverlap.SHARED

	# Distinct, touching and partially intersecting ranges are classified explicitly.
	assert LM.PayloadRange(40, 8).overlaps(LM.PayloadRange(48, 8)) == LM.RangeOverlap.NONE
	assert LM.PayloadRange(40, 16).overlaps(LM.PayloadRange(48, 8)) == LM.RangeOverlap.PARTIAL


def test_build_links_header_lcn_ranges_and_total_length():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	redo_bytes = b'REDO' * 6   # 24 bytes
	undo_bytes = b'UNDO' * 4   # 16 bytes, non-overlapping

	mutated = mutator.build(LogFile.UpdateResidentValue, LogFile.UpdateResidentValue,
		redo_bytes, undo_bytes, lcns = [ 11, 22, 33 ], target_attribute = 7, target_vcn = 9)

	# Total length covers header (32) + three LCNs (24) + both 8-aligned ranges.
	assert mutated.client_data_length == len(mutated.payload)
	assert mutated.client_data_length % 8 == 0
	assert mutated.client_data_length == 32 + 24 + 24 + 16

	report = mutated.validation_report()
	assert report.is_valid()
	assert report.overlap() == LM.RangeOverlap.NONE

	record = mutated.decode(lsn = 1234, transaction_id = 56)
	assert record.get_lcns_to_follow() == 3
	assert record.get_lcns_for_page() == [ 11, 22, 33 ]
	assert record.get_target_attribute() == 7
	assert record.get_target_vcn() == 9

	# Ranges begin right after the LCN data region base and point at the exact operation bytes.
	expected_redo_offset = LM.lcn_data_base(3)
	assert record.get_redo_offset() == expected_redo_offset
	assert record.get_redo_length() == 24
	assert mutated.payload[expected_redo_offset : expected_redo_offset + 24] == redo_bytes
	assert record.get_redo_data() == redo_bytes

	expected_undo_offset = expected_redo_offset + 24
	assert record.get_undo_offset() == expected_undo_offset
	assert record.get_undo_length() == 16
	assert mutated.payload[expected_undo_offset : expected_undo_offset + 16] == undo_bytes
	assert record.get_undo_data() == undo_bytes


def test_shared_and_empty_ranges_are_accepted():
	mutator = make_mutator(LM.LAYOUT_V1_1)
	payload_bytes = b'SHARED' * 4

	shared = mutator.build(LogFile.UpdateNonresidentValue, LogFile.UpdateNonresidentValue,
		payload_bytes, payload_bytes, lcns = [ 5 ], overlap = LM.RangeOverlap.SHARED)
	shared_report = shared.validation_report()
	assert shared_report.is_valid()
	assert shared_report.overlap() == LM.RangeOverlap.SHARED
	decoded = shared.decode()
	assert decoded.get_redo_offset() == decoded.get_undo_offset()
	assert decoded.get_redo_data() == decoded.get_undo_data() == payload_bytes

	empty_undo = mutator.build(LogFile.CreateAttribute, LogFile.DeleteAttribute,
		b'X' * 16, b'', lcns = [ 5 ])
	empty_report = empty_undo.validation_report()
	assert empty_report.is_valid()
	assert empty_report.overlap() == LM.RangeOverlap.EMPTY
	assert empty_undo.decode().get_undo_data() == b''


def test_lcn_array_resize_moves_ranges_and_keeps_bytes():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	original = mutator.build(LogFile.UpdateMappingPairs, LogFile.UpdateMappingPairs,
		b'A' * 32, b'B' * 16, lcns = [ 100 ])

	original_redo_offset = original.decode().get_redo_offset()
	assert original_redo_offset == LM.lcn_data_base(1)

	grown = mutator.resize_lcn_array(original, 4, filler_lcn = -1)
	grown_record = grown.decode()
	assert grown.validation_report().is_valid()
	assert grown_record.get_lcns_for_page() == [ 100, -1, -1, -1 ]
	# Every non-empty range shifts by exactly the LCN array growth (3 * 8 bytes).
	assert grown_record.get_redo_offset() == original_redo_offset + 24
	assert grown_record.get_redo_data() == b'A' * 32
	assert grown_record.get_undo_data() == b'B' * 16
	assert grown.client_data_length == original.client_data_length + 24

	shrunk = mutator.resize_lcn_array(grown, 1)
	shrunk_record = shrunk.decode()
	assert shrunk.validation_report().is_valid()
	assert shrunk_record.get_lcns_for_page() == [ 100 ]
	assert shrunk_record.get_redo_offset() == original_redo_offset
	assert shrunk_record.get_redo_data() == b'A' * 32


def test_range_resize_preserves_relative_base_and_relinks_neighbour():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	original = mutator.build(LogFile.UpdateResidentValue, LogFile.UpdateResidentValue,
		b'A' * 32, b'B' * 16, lcns = [ 7 ])
	redo_base = original.decode().get_redo_offset()
	undo_base = original.decode().get_undo_offset()

	grown = mutator.resize_range(original, 'redo', 40)
	grown_record = grown.decode()
	assert grown.validation_report().is_valid()
	assert grown_record.get_redo_offset() == redo_base           # Relative base is preserved.
	assert grown_record.get_redo_length() == 40
	assert grown_record.get_undo_offset() == undo_base + 8       # Neighbour range is relinked.
	assert grown_record.get_undo_data() == b'B' * 16

	emptied = mutator.resize_range(original, 'undo', 0)
	emptied_record = emptied.decode()
	assert emptied.validation_report().is_valid()
	assert emptied_record.get_undo_length() == 0
	assert emptied_record.get_undo_data() == b''


def test_relayout_changes_overlap_without_rejecting_shared_bytes():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	redo_bytes = b'R' * 32
	undo_bytes = b'U' * 32

	separate = mutator.build(LogFile.UpdateNonresidentValue, LogFile.UpdateNonresidentValue,
		redo_bytes, undo_bytes, lcns = [ 9 ])
	assert separate.validation_report().overlap() == LM.RangeOverlap.NONE

	shared = mutator.relayout_ranges(separate, LM.RangeOverlap.SHARED)
	shared_report = shared.validation_report()
	assert shared_report.is_valid()
	assert shared_report.overlap() == LM.RangeOverlap.SHARED
	shared_record = shared.decode()
	assert shared_record.get_redo_data() == redo_bytes
	assert shared_record.get_undo_data() == redo_bytes  # Shared bytes are not rejected.

	partial = mutator.relayout_ranges(separate, LM.RangeOverlap.PARTIAL)
	partial_report = partial.validation_report()
	assert partial_report.is_valid()
	assert partial_report.overlap() == LM.RangeOverlap.PARTIAL
	partial_record = partial.decode()
	assert partial_record.get_redo_data() == redo_bytes
	# The undo range starts inside the redo range, so only its non-overlapping tail is undo-only.
	overlap_start = partial_report.undo_range.offset - partial_report.redo_range.offset
	assert partial_record.get_undo_data()[overlap_start : ] == undo_bytes[overlap_start : ]


def test_specific_operation_bytes_stay_inside_their_own_range():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	redo_bytes = bytes(range(16))
	undo_bytes = bytes(range(0x80, 0x90))
	mutated = mutator.build(LogFile.SetNewAttributeSizes, LogFile.SetNewAttributeSizes,
		redo_bytes, undo_bytes, lcns = [ 1 ])

	report = mutated.validation_report()
	redo_slice = mutated.payload[report.redo_range.offset : report.redo_range.end()]
	undo_slice = mutated.payload[report.undo_range.offset : report.undo_range.end()]

	assert redo_slice == redo_bytes
	assert undo_slice == undo_bytes
	# A byte belonging to redo must never be presented as undo evidence.
	assert redo_slice != undo_slice
	assert report.redo_range.end() <= report.undo_range.offset


def test_validator_catches_length_overflow_that_slicing_silently_accepts():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	mutated = mutator.build(LogFile.UpdateResidentValue, LogFile.UpdateResidentValue,
		b'A' * 16, b'B' * 16, lcns = [ 1 ])

	corrupted = mutator.corrupt(mutated, 'redo_length_overflow')
	report = LM.validate_ranges(corrupted.payload)
	assert not report.is_valid()
	assert any(problem.kind == 'range_out_of_bounds' for problem in report.problems)

	# The deliberately defective validator ignores the declared length and only checks the offset:
	# it must fail to catch this record, proving why length cannot be ignored.
	def defective_length_validator(payload):
		redo_offset = struct.unpack('<H', payload[4 : 6])[0]
		return LM.lcn_data_base(struct.unpack('<H', payload[14 : 16])[0]) <= redo_offset < len(payload)

	assert defective_length_validator(corrupted.payload) is True
	assert report.is_valid() is False


def test_validator_catches_relative_base_violation_into_lcn_and_header():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	mutated = mutator.build(LogFile.UpdateResidentValue, LogFile.UpdateResidentValue,
		b'A' * 16, b'B' * 16, lcns = [ 2, 4 ])
	base = LM.lcn_data_base(2)

	corrupted = mutator.corrupt(mutated, 'redo_offset_into_header')
	report = LM.validate_ranges(corrupted.payload)
	assert not report.is_valid()
	assert any(problem.kind == 'range_inside_header' for problem in report.problems)

	# A defective validator that ignores the relative base accepts any in-buffer offset,
	# including one landing inside the LCN array / fixed header.
	def defective_base_validator(payload):
		redo_offset, redo_length = struct.unpack('<HH', payload[4 : 8])
		return redo_offset + redo_length <= len(payload)

	assert defective_base_validator(corrupted.payload) is True
	assert report.is_valid() is False
	assert base == 48

	misaligned = mutator.corrupt(mutated, 'redo_misaligned')
	misaligned_report = LM.validate_ranges(misaligned.payload)
	assert any(problem.kind == 'misaligned_offset' for problem in misaligned_report.problems)


def test_intentionally_defective_validators_are_demonstrably_caught():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	valid = mutator.build(LogFile.UpdateResidentValue, LogFile.UpdateResidentValue,
		b'A' * 24, b'B' * 16, lcns = [ 1, 2 ])

	# Correct, structure-aware validation accepts the coherent record.
	assert LM.validate_ranges(valid.payload).is_valid() is True

	# Defect 1: a validator which ignores the declared length and trusts slicing.
	def validator_ignoring_length(payload):
		redo_offset = struct.unpack('<H', payload[4 : 6])[0]
		redo_length = struct.unpack('<H', payload[6 : 8])[0]
		sliced = payload[redo_offset : redo_offset + redo_length]
		return len(sliced) > 0  # Slicing never raises, it silently truncates.

	length_corruption = mutator.corrupt(valid, 'redo_length_overflow')
	assert validator_ignoring_length(length_corruption.payload) is True
	assert LM.validate_ranges(length_corruption.payload).is_valid() is False

	# Defect 2: a validator which ignores the relative base (LCN/header region).
	def validator_ignoring_relative_base(payload):
		redo_offset, redo_length = struct.unpack('<HH', payload[4 : 8])
		return redo_offset + redo_length <= len(payload)

	base_corruption = mutator.corrupt(valid, 'redo_offset_into_header')
	assert validator_ignoring_relative_base(base_corruption.payload) is True
	assert LM.validate_ranges(base_corruption.payload).is_valid() is False

	# Each defective validator misses exactly the defect it was designed to ignore,
	# while the structure-aware validator rejects both corruptions.
	assert validator_ignoring_length(length_corruption.payload) is True
	assert validator_ignoring_relative_base(base_corruption.payload) is True
	assert LM.validate_ranges(length_corruption.payload).is_valid() is False
	assert LM.validate_ranges(base_corruption.payload).is_valid() is False


def test_malformed_records_never_emit_path_change_events():
	mutator = make_mutator(LM.LAYOUT_V2_0)
	name = 'find_me.txt'.encode('utf-16le')
	valid = mutator.build(LogFile.UpdateFileNameRoot, 0x77, name, b'', lcns = [ 3 ])

	events = LM.extract_path_change_events(valid.decode(lsn = 99))
	assert len(events) == 1
	assert events[0].lsn == 99
	assert events[0].name_text == 'find_me.txt'
	assert events[0].operation.known is True
	assert events[0].target_range == LM.PayloadRange(valid.decode().get_redo_offset(), len(name))

	for corruption in [ 'redo_length_overflow', 'redo_offset_into_header', 'truncate', 'lcn_count_overflow' ]:
		corrupted = mutator.corrupt(valid, corruption)
		assert LM.validate_ranges(corrupted.payload).is_valid() is False
		assert LM.extract_path_change_events(corrupted.decode(lsn = 99)) == []

	# A structurally valid record carrying no name-bearing operation yields no path event.
	non_name = mutator.build(LogFile.CommitTransaction, LogFile.Noop, b'C' * 8, b'')
	assert LM.extract_path_change_events(non_name.decode()) == []

	# A valid range containing bytes that are not decodable as a file name yields no event either.
	undecodable = mutator.build(LogFile.UpdateFileNameRoot, LogFile.Noop, b'\x00\xd8', b'') # Lone UTF-16 surrogate U+D800.
	assert undecodable.validation_report().is_valid()
	assert LM.extract_path_change_events(undecodable.decode()) == []


def test_known_and_unknown_operations_are_explained_separately():
	mutator = make_mutator(LM.LAYOUT_V2_0)

	known = mutator.build(LogFile.UpdateFileNameAllocation, LogFile.UpdateFileNameAllocation,
		b'N' * 16, b'N' * 16, overlap = LM.RangeOverlap.SHARED)
	known_explanation = LM.explain_record(known.decode())
	assert known_explanation.fully_explained() is True
	assert known_explanation.explainability() == 'full'
	assert known_explanation.redo.known and known_explanation.undo.known

	partial = mutator.build(LogFile.UpdateFileNameRoot, 0x77, b'N' * 16, b'')
	partial_explanation = LM.explain_record(partial.decode())
	assert partial_explanation.explainability() == 'partial'
	assert partial_explanation.redo.known is True
	assert partial_explanation.undo.known is False
	assert partial_explanation.undo.name == '0x77'

	unknown = mutator.build(0x99, 0x88, b'Q' * 8, b'Q' * 8, overlap = LM.RangeOverlap.SHARED)
	unknown_explanation = LM.explain_record(unknown.decode())
	assert unknown_explanation.explainability() == 'unknown'
	assert unknown_explanation.redo.known is False and unknown_explanation.undo.known is False
	assert unknown_explanation.redo.name == '0x99' and unknown_explanation.undo.name == '0x88'

	rejected = mutator.corrupt(known, 'undo_length_overflow')
	assert LM.explain_record(rejected.decode()).explainability() == 'rejected'


def test_version_layouts_are_distinct_and_recorded():
	assert LM.LAYOUT_V1_1.as_tuple() == (1, 1)
	assert LM.LAYOUT_V2_0.as_tuple() == (2, 0)
	assert LM.LAYOUT_V1_1.sequence_number_bits != LM.LAYOUT_V2_0.sequence_number_bits

	mutator_v1 = make_mutator(LM.LAYOUT_V1_1)
	mutated_v1 = mutator_v1.build(LogFile.Noop, LogFile.Noop, b'V' * 8, b'')
	assert mutated_v1.layout is LM.LAYOUT_V1_1
	# Version 3.0 reuses the 2.x page/record layout.
	assert LM.get_version_layout((3, 0)).record_header_length == LM.LAYOUT_V2_0.record_header_length
	with pytest.raises(LM.LogMutationException):
		LM.get_version_layout((9, 9))


def test_real_records_validate_and_roundtrip_through_mutation():
	for path in ALL_LOGFILES:
		with open(path, 'rb') as file_object:
			parser = LogFile.LogFileParser(file_object)
			layout = LM.get_version_layout(parser.log_version)
			mutator = LM.StructureAwareMutator(layout = layout, seed = 1)

			seen_ntfs_records = 0
			seen_shared = 0
			seen_empty = 0

			for record in parser.parse_ntfs_records(False):
				if type(record) is not LogFile.NTFSLogRecord:
					continue

				seen_ntfs_records += 1
				explanation = LM.explain_record(record)

				if explanation.report.overlap() == LM.RangeOverlap.SHARED:
					seen_shared += 1
				if explanation.report.overlap() == LM.RangeOverlap.EMPTY:
					seen_empty += 1

				if not explanation.is_structurally_valid():
					# Only the truncated tail records (multi-page payload missing its continuation).
					continue

				# A valid real record must survive a structure-preserving LCN mutation.
				lcns = record.get_lcns_for_page()
				mutated = mutator.resize_lcn_array(record, len(lcns) + 1, filler_lcn = -1)
				assert mutated.validation_report().is_valid()
				regrown_record = mutated.decode(record.lsn, record.transaction_id, record.cluster_size)
				assert regrown_record.get_lcns_for_page()[: len(lcns)] == lcns
				assert regrown_record.get_redo_operation() == record.get_redo_operation()
				assert regrown_record.get_undo_operation() == record.get_undo_operation()
				assert regrown_record.get_redo_data() == record.get_redo_data()
				assert regrown_record.get_undo_data() == record.get_undo_data()

			assert seen_ntfs_records > 0
			assert seen_shared > 0
			assert seen_empty > 0


def test_real_truncated_tail_records_are_flagged_not_sliced():
	truncated_total = 0
	for path in ALL_LOGFILES:
		with open(path, 'rb') as file_object:
			parser = LogFile.LogFileParser(file_object)
			for record in parser.parse_ntfs_records(False):
				if type(record) is not LogFile.NTFSLogRecord:
					continue

				report = LM.validate_ranges(record.buf)
				if not report.is_valid():
					truncated_total += 1
					assert any(problem.kind == 'range_out_of_bounds' for problem in report.problems)
					# The old lenient slicing returns a shortened, seemingly valid byte string.
					assert len(record.get_redo_data()) != record.get_redo_length() or \
						len(record.get_undo_data()) != record.get_undo_length()
					# Such a record must never surface as a path change event.
					assert LM.extract_path_change_events(record) == []

	assert truncated_total > 0


def test_full_logfile_decoding_still_succeeds_after_changes():
	# End-to-end sanity: the parser pipeline and all yielded records remain consumable.
	for path in ALL_LOGFILES:
		with open(path, 'rb') as file_object:
			parser = LogFile.LogFileParser(file_object)
			count = 0
			for decoded in parser.parse_ntfs_records(True):
				if type(decoded) is LogFile.NTFSLogRecord:
					LM.explain_record(decoded)
					count += 1
			assert count > 0
