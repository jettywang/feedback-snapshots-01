# coding: utf-8

# dfir_ntfs: an NTFS parser for digital forensics & incident response

import io
import os

from dfir_ntfs import LogFile, LogFileAudit
import logfile_restart_audit as audit_script

TEST_DATA_DIR = 'test_data'

LOGFILE_10 = os.path.join(TEST_DATA_DIR, 'LogFile_10.bin')
LOGFILE_10_LARGE = os.path.join(TEST_DATA_DIR, 'LogFile_10_large.bin')
LOGFILE_7 = os.path.join(TEST_DATA_DIR, 'LogFile_7.bin')

DECLARED_SIZE = 48 * audit_script.PAGE_SIZE


def test_audit_counts_parseability_separately_from_coverage():
	data, oldest_1, restart_1, oldest_2, restart_2 = audit_script.build_two_valid_states(DECLARED_SIZE)
	results, notes = LogFileAudit.audit_file(io.BytesIO(data))

	assert len(results) == 2
	assert notes == []
	assert results[0]['verdict'] == 'supported_for_reachable_range'
	assert results[1]['verdict'] == 'supported_for_reachable_range'

	for result in results:
		client = result['clients'][0]
		assert client['restart_record'] is True
		assert client['oldest_record'] is True
		assert client['forward']['reached_stop'] is True


def test_loader_prefers_page_1_and_merges_both_states():
	data, oldest_1, restart_1, oldest_2, restart_2 = audit_script.build_two_valid_states(DECLARED_SIZE)
	file_object = io.BytesIO(data)

	view = LogFileAudit.loader_view(file_object)
	assert view['selected'].startswith('page 1')
	assert restart_2 > restart_1
	assert view['page_2_restart_in_collected_set'] is True

	parser = LogFile.LogFileParser(io.BytesIO(data))
	restart_areas = []
	for item in parser.parse_ntfs_records(False):
		if type(item) is LogFile.NTFSRestartArea:
			restart_areas.append(item.lsn)

	assert restart_1 in restart_areas
	assert restart_2 in restart_areas
	assert len(restart_areas) == 2


def test_newer_restart_lsn_outside_file_is_rejected_by_audit():
	data, oldest_1, restart_1, missing_lsn = audit_script.build_newer_missing(DECLARED_SIZE)
	results, notes = LogFileAudit.audit_file(io.BytesIO(data))

	assert len(results) == 2
	assert results[0]['verdict'] == 'supported_for_reachable_range'

	newer = results[1]
	assert newer['verdict'] == 'partially_supported'
	assert newer['clients'][0]['restart_record'] is False

	view = LogFileAudit.loader_view(io.BytesIO(data))
	assert view['page_2_restart_in_collected_set'] is False
	assert view['page_2_restart_page_inside_file'] is False
	assert missing_lsn > restart_1


def test_corrupt_usa_on_newer_page_makes_it_unparseable():
	data, oldest_1, restart_1, missing_lsn = audit_script.build_newer_corrupt_page(DECLARED_SIZE)
	results, notes = LogFileAudit.audit_file(io.BytesIO(data))

	assert len(results) == 1
	assert results[0]['label'] == 'page 1'
	assert any('page 2 is not parseable' in note for note in notes)

	view = LogFileAudit.loader_view(io.BytesIO(data))
	assert view['page_2_parseable'] is False
	assert view['selected'].startswith('page 1')


def test_complete_chain_does_not_imply_required_tables_are_present():
	data, oldest_2, restart_2, missing_table_lsn = audit_script.build_chain_complete_table_missing(DECLARED_SIZE)
	results, notes = LogFileAudit.audit_file(io.BytesIO(data))

	page_2 = results[1]
	client = page_2['clients'][0]

	assert client['restart_record'] is True
	assert client['forward']['reached_stop'] is True
	assert client['tables']['open_attribute_table']['status'] == 'missing'
	assert page_2['verdict'] == 'partially_supported'


def test_geometry_conflict_is_reported_not_silently_resolved():
	data, oldest_1, restart_1, oldest_2, restart_2 = audit_script.build_geometry_conflict(DECLARED_SIZE)
	view = LogFileAudit.loader_view(io.BytesIO(data))

	assert view['selected'].startswith('page 1')
	assert len(view['geometry_conflicts']) == 1
	assert 'sequence number bits' in view['geometry_conflicts'][0]


def test_real_sample_page_2_claims_newer_but_is_not_selected():
	with open(LOGFILE_10_LARGE, 'rb') as file_object:
		view = LogFileAudit.loader_view(file_object)
		assert view['selected'].startswith('page 1')
		assert view['page_2_current_lsn'] > view['selected_current_lsn']
		assert view['page_2_restart_in_collected_set'] is False
		assert view['page_2_restart_page_inside_file'] is False

	with open(LOGFILE_10_LARGE, 'rb') as file_object:
		results, notes = LogFileAudit.audit_file(file_object)
		assert results[0]['verdict'] == 'supported_for_reachable_range'
		assert results[1]['verdict'] == 'partially_supported'


def test_real_sample_needs_recovery_view_before_coverage_checks():
	with open(LOGFILE_10, 'rb') as file_object:
		raw_results, notes = LogFileAudit.audit_file(file_object, recover=False)
		assert raw_results[0]['verdict'] == 'unsupported'

		recovered_results, notes = LogFileAudit.audit_file(file_object, recover=True)
		assert notes[0].startswith('recovery view')
		assert recovered_results[0]['verdict'] == 'supported_for_reachable_range'


def test_audit_never_writes_to_the_input_file():
	with open(LOGFILE_7, 'rb') as file_object:
		before = file_object.read()

	file_object = io.BytesIO(before)
	LogFileAudit.audit_file(file_object, recover=True)
	LogFileAudit.loader_view(file_object, recover=True)
	file_object.seek(0)

	assert file_object.read() == before


def test_two_valid_states_cannot_be_reduced_to_one_candidate():
	data, oldest_1, restart_1, oldest_2, restart_2 = audit_script.build_two_valid_states(DECLARED_SIZE)
	file_object = io.BytesIO(data)

	results, notes = LogFileAudit.audit_file(file_object)
	file_object.seek(0)
	view = LogFileAudit.loader_view(file_object)

	comparison = LogFileAudit.compare_restart_states(results, view)

	assert comparison['selection'] == 'multiple_candidates'
	assert comparison['max_lsn_choice_safe'] is False
	assert comparison['candidates'][0]['restart_lsn'] == restart_1
	assert comparison['candidates'][1]['restart_lsn'] == restart_2


def test_newer_but_unsupported_page_is_not_selected_by_audit():
	data, oldest_1, restart_1, missing_lsn = audit_script.build_newer_missing(DECLARED_SIZE)
	file_object = io.BytesIO(data)

	results, notes = LogFileAudit.audit_file(file_object)
	file_object.seek(0)
	view = LogFileAudit.loader_view(file_object)

	comparison = LogFileAudit.compare_restart_states(results, view)

	assert comparison['selection'] == 'single_candidate'
	assert comparison['max_lsn_choice_safe'] is False
	assert any('overstate completeness' in reason for reason in comparison['reasons'])
