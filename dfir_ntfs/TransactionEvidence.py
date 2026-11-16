# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# This module implements a read-only transaction evidence view for the $LogFile journal.
# It correlates log records belonging to the same client into transaction instances by
# following client previous-LSN (predecessor) and client undo-next-LSN chains.
#
# Important interpretation rules (see module-level constants and the 'TransactionEvidenceAnalyzer' class):
# - a transaction ID may be reused, therefore it never identifies a transaction instance on its own;
# - the physical position of a record is not the global order of events, therefore LSN order is used;
# - a missing chain segment is reported as missing evidence, never assumed to be a successful commit;
# - a compensation log record (CLR) describes rollback of another record, it is not counted again as
#   a separate user operation.

from . import LogFile

# Outcome states assigned to a transaction instance.
STATE_COMMITTED = 'committed'
"""A commit record (CommitTransaction) is present in the (complete) predecessor chain of this instance."""

STATE_ROLLED_BACK = 'rolled_back'
"""Compensation log records prove that changes of this instance were undone."""

STATE_OPEN_UNKNOWN = 'open_unknown'
"""Neither a commit nor sufficient rollback evidence is present; the outcome cannot be confirmed."""

STATE_MISSING_LINK = 'missing_link'
"""The predecessor chain leaves this log file towards a record that is absent, so the outcome cannot be confirmed."""

STATE_INDETERMINATE = 'indeterminate'
"""The available evidence is contradictory or insufficient to select any of the states above."""

# Kinds assigned to an individual evidence record.
KIND_USER_OPERATION = 'user_operation'
"""A normal redo/undo record that describes one file system operation."""

KIND_COMPENSATION = 'compensation'
"""A compensation log record (CLR): it undoes a previously logged operation, it is not a new user operation."""

KIND_COMMIT = 'commit'
"""A commit record: it marks a transaction as committed, it is not itself a file system operation."""

KIND_PREPARE = 'prepare'
"""A prepare record: part of the two-phase commit protocol, not a file system operation by itself."""

KIND_FORGET = 'forget'
"""A forget record: the client releases its transaction state, it does not prove either commit or rollback."""

KIND_OTHER = 'other'
"""Anything else (for example, table dumps and Noop records without a compensation action)."""


class TransactionEvidenceException(LogFile.LogFileException):
	"""This exception is raised when transaction evidence cannot be built."""

	pass


class EvidenceRecord(object):
	"""One log record treated as a piece of transaction evidence.

	Every field is sourced from the log file itself and the physical location of this record is retained,
	so that each conclusion drawn later can be traced back to an original record.
	"""

	lsn = None
	"""The log sequence number (LSN) of this record (a globally unique identity within this log file)."""

	sequence_number = None
	"""The LSN sequence number (the log file generation, incremented when the circular log wraps)."""

	client_id = None
	"""The log client ID (for NTFS, this is typically 0)."""

	transaction_id = None
	"""The transaction ID as stored in the record header (this value may be reused)."""

	record_type = None
	"""The record type from the log record header (for example, LfsClientRecord)."""

	previous_lsn = None
	"""The client previous LSN: predecessor of this record in the per-client forward chain."""

	undo_next_lsn = None
	"""The client undo-next LSN: the next record to undo when rolling back (0 if none)."""

	log_page_number = None
	"""The physical log record page number holding this record."""

	offset_in_page = None
	"""The physical offset of this record within its log record page."""

	file_offset = None
	"""The physical byte offset of this record in the $LogFile file."""

	redo_operation = None
	"""The redo operation code (or None for non-NTFS client data)."""

	undo_operation = None
	"""The undo operation code (or None for non-NTFS client data)."""

	header_flags = None
	"""The flags field of the log record header."""

	kind = None
	"""The evidence kind, one of the KIND_* constants."""

	is_clr = False
	"""True if this record is a compensation log record (its undo operation is CompensationLogRecord)."""

	is_chain_root = False
	"""True if the client previous LSN of this record is zero (a root of a per-client chain)."""

	predecessor_present = None
	"""True if the predecessor (client previous LSN) resolves to a record present in this log file,
	False if it points to an absent record, None if there is no predecessor (previous LSN is zero)."""

	undo_target_present = None
	"""True if the undo-next LSN resolves to a record present in this log file,
	False if it points to an absent record, None if there is no undo-next LSN (it is zero)."""

	def location(self):
		"""Return a human-readable, stable physical location string for this record."""

		return 'page {} offset {} (file offset {})'.format(self.log_page_number, self.offset_in_page, self.file_offset)

	def __str__(self):
		redo = LogFile.ResolveNTFSOperation(self.redo_operation) if self.redo_operation is not None else 'n/a'
		undo = LogFile.ResolveNTFSOperation(self.undo_operation) if self.undo_operation is not None else 'n/a'

		return 'EvidenceRecord, LSN: {}, seqnum: {}, client: {}, transaction ID: {}, kind: {}, redo: {}, undo: {}, location: {}'.format(
			self.lsn, self.sequence_number, self.client_id, self.transaction_id, self.kind, redo, undo, self.location())


class TransactionInstance(object):
	"""One transaction instance reconstructed from evidence.

	An instance is a connected component of the per-client predecessor (client previous LSN) chain.
	The transaction ID is kept only as a label, because the same ID may identify more than one instance.
	"""

	instance_id = None
	"""A stable identifier of this instance within an analysis result (for example, 'T01')."""

	client_id = None
	"""The log client ID shared by every record of this instance."""

	transaction_id = None
	"""The transaction ID label stored in the records of this instance."""

	sequence_numbers = None
	"""The set of LSN sequence numbers (log generations) covered by this instance."""

	records = None
	"""All EvidenceRecord objects of this instance, ordered by LSN."""

	state = None
	"""The outcome state, one of the STATE_* constants."""

	state_reasons = None
	"""A list of human-readable reasons (each citing an LSN and a location) supporting the state."""

	missing_predecessor_lsns = None
	"""LSNs referenced by client previous-LSN fields of this instance but absent from the log file."""

	missing_undo_target_lsns = None
	"""LSNs referenced by client undo-next-LSN fields of this instance but absent from the log file."""

	def user_operations(self):
		"""Yield evidence records that describe user (file system) operations.

		Compensation, commit, prepare and forget records are excluded so that rollback bookkeeping is
		never counted again as a separate user operation.
		"""

		for record in self.records:
			if record.kind == KIND_USER_OPERATION:
				yield record

	def compensation_records(self):
		"""Yield the compensation log records (CLRs) of this instance."""

		for record in self.records:
			if record.kind == KIND_COMPENSATION:
				yield record

	def boundary_records(self):
		"""Yield commit, prepare and forget records of this instance."""

		for record in self.records:
			if record.kind in (KIND_COMMIT, KIND_PREPARE, KIND_FORGET):
				yield record

	def first_lsn(self):
		"""Return the lowest LSN of this instance."""

		return self.records[0].lsn

	def last_lsn(self):
		"""Return the highest LSN of this instance."""

		return self.records[-1].lsn

	def __str__(self):
		return 'TransactionInstance {}, client: {}, transaction ID: {}, state: {}, records: {}, LSN range: {} - {}'.format(
			self.instance_id, self.client_id, self.transaction_id, self.state, len(self.records), self.first_lsn(), self.last_lsn())


class TransactionEvidenceAnalyzer(object):
	"""Build a read-only transaction evidence view from a LogFileParser object.

	This analyzer never writes to the parsed $LogFile: it only reads log record pages and headers.
	In particular, tail/fast pages are not applied and no disk recovery action is performed.
	"""

	parser = None
	"""The LogFileParser object used as a read-only data source."""

	records = None
	"""All collected transaction EvidenceRecord objects (LfsClientRecord), keyed by their LSN."""

	restart_records = None
	"""NTFS client restart (checkpoint) records; these are not part of any transaction instance."""

	instances = None
	"""The reconstructed TransactionInstance objects, ordered by their first LSN."""

	def __init__(self, log_file_parser):
		self.parser = log_file_parser
		self.records = dict()
		self.restart_records = []
		self.instances = []

	def _classify_record(self, redo_operation, undo_operation):
		"""Classify a decoded NTFS log record and return its evidence kind and whether it is a CLR."""

		is_clr = undo_operation == LogFile.CompensationLogRecord or redo_operation == LogFile.CompensationLogRecord

		if redo_operation == LogFile.CommitTransaction:
			return KIND_COMMIT, is_clr

		if redo_operation == LogFile.PrepareTransaction:
			return KIND_PREPARE, is_clr

		if redo_operation == LogFile.ForgetTransaction:
			return KIND_FORGET, is_clr

		if is_clr:
			return KIND_COMPENSATION, True

		if redo_operation in (LogFile.OpenAttributeTableDump, LogFile.AttributeNamesDump,
			LogFile.DirtyPageTableDump, LogFile.TransactionTableDump, LogFile.Noop):
			return KIND_OTHER, False

		return KIND_USER_OPERATION, False

	def collect_evidence(self):
		"""Read every reachable client record and build EvidenceRecord objects.

		The parser's own LSN discovery (collect_lsns and sort_lsns) is used, therefore records that
		cannot be validated against their page/offset are excluded exactly as in the rest of this tool.
		"""

		if self.parser.lsns is None:
			self.parser.collect_lsns()

		if self.parser.lsns_sorted is None:
			self.parser.sort_lsns()

		self.records = dict()
		self.restart_records = []

		for client_id, lsn_list in self.parser.lsns_sorted.items():
			for lsn in lsn_list:
				log_page_number, offset_in_page = self.parser.lsn_to_offset(lsn)
				log_record_page = self.parser.get_log_record_page_by_number(log_page_number)
				if log_record_page is None:
					continue

				try:
					log_record_header = log_record_page.get_log_record_at_offset(offset_in_page, self.parser.record_header_length)
				except LogFile.LogFileException:
					continue

				if lsn != log_record_header.get_this_lsn():
					continue

				record = EvidenceRecord()
				record.lsn = lsn
				record.sequence_number = self.parser.lsn_to_seqnum(lsn)
				record.client_id = log_record_header.get_client_id()
				record.transaction_id = log_record_header.get_transaction_id()
				record.record_type = log_record_header.get_record_type()
				record.previous_lsn = log_record_header.get_client_previous_lsn()
				record.undo_next_lsn = log_record_header.get_client_undo_next_lsn()
				record.log_page_number = log_page_number
				record.offset_in_page = offset_in_page
				record.file_offset = log_page_number * self.parser.log_page_size + offset_in_page
				record.header_flags = log_record_header.get_flags()
				record.is_chain_root = record.previous_lsn == 0

				record.redo_operation = None
				record.undo_operation = None
				record.kind = KIND_OTHER
				record.is_clr = False

				# NTFS client restart (checkpoint) records anchor the log but are not transactions:
				# keep them as separate evidence instead of building a transaction instance.
				if record.record_type == LogFile.LfsClientRestart:
					self.restart_records.append(record)
					continue

				if record.record_type == LogFile.LfsClientRecord:
					try:
						client_data = self.parser.get_client_data(lsn)
						decoded = client_data.data_decoded()
					except (LogFile.ClientException, NotImplementedError, LogFile.LogFileException):
						decoded = None

					if type(decoded) is LogFile.NTFSLogRecord:
						record.redo_operation = decoded.get_redo_operation()
						record.undo_operation = decoded.get_undo_operation()
						record.kind, record.is_clr = self._classify_record(record.redo_operation, record.undo_operation)

				self.records[lsn] = record

		# Resolve predecessor and undo-next references against the records actually present.
		for record in self.records.values():
			if record.previous_lsn == 0:
				record.predecessor_present = None
			else:
				record.predecessor_present = record.previous_lsn in self.records

			if record.undo_next_lsn == 0:
				record.undo_target_present = None
			else:
				record.undo_target_present = record.undo_next_lsn in self.records

	def _build_instances(self):
		"""Group records into transaction instances along per-client predecessor chains."""

		# Map every LSN to the root LSN of its predecessor component.
		root_of = dict()
		missing_predecessors = dict() # root LSN -> set of missing predecessor LSNs

		def resolve_root(lsn):
			path = []
			current = lsn

			while True:
				if current in root_of:
					resolved_root = root_of[current]
					for seen_lsn in path:
						root_of[seen_lsn] = resolved_root
					return resolved_root

				record = self.records.get(current)
				if record is None or record.previous_lsn == 0:
					resolved_root = current
					for seen_lsn in path:
						root_of[seen_lsn] = resolved_root
					return resolved_root

				if record.previous_lsn not in self.records:
					# A predecessor is referenced but absent: this component is a broken fragment.
					resolved_root = current
					missing_predecessors.setdefault(resolved_root, set()).add(record.previous_lsn)
					for seen_lsn in path:
						root_of[seen_lsn] = resolved_root
					return resolved_root

				if current in path: # Defensive guard against a malformed cyclic reference.
					resolved_root = current
					for seen_lsn in path:
						root_of[seen_lsn] = resolved_root
					return resolved_root

				path.append(current)
				current = record.previous_lsn

		components = dict()
		for lsn in self.records:
			root_lsn = resolve_root(lsn)
			components.setdefault(root_lsn, []).append(lsn)

		instances = []
		instance_counter = 0

		for root_lsn in sorted(components.keys(), key = lambda value: min(components[value])):
			instance_counter += 1
			instance = TransactionInstance()
			instance.instance_id = 'T{:02d}'.format(instance_counter)
			instance.records = sorted((self.records[lsn] for lsn in components[root_lsn]), key = lambda item: item.lsn)
			instance.client_id = instance.records[0].client_id
			instance.transaction_id = instance.records[0].transaction_id
			instance.sequence_numbers = set(record.sequence_number for record in instance.records)
			instance.missing_predecessor_lsns = sorted(missing_predecessors.get(root_lsn, set()))
			instance.missing_undo_target_lsns = sorted(
				record.undo_next_lsn for record in instance.records
				if record.undo_target_present is False
			)
			instance.state_reasons = []
			instance.state = self._determine_state(instance)
			instances.append(instance)

		self.instances = instances

	def _determine_state(self, instance):
		"""Determine and justify the outcome state of a transaction instance.

		The state is conservative: whenever an essential chain segment is missing, the instance is
		never reported as committed, because the absent segment could have carried (or been pointed to
		by) a rollback or a commit record that is no longer in the log.
		"""

		commit_records = [record for record in instance.records if record.kind == KIND_COMMIT]
		clr_records = list(instance.compensation_records())
		forget_records = [record for record in instance.records if record.kind == KIND_FORGET]

		for record in commit_records:
			instance.state_reasons.append(
				'CommitTransaction record at LSN {} ({})'.format(record.lsn, record.location()))

		for record in clr_records:
			target_note = ''
			if record.undo_next_lsn != 0:
				if record.undo_target_present:
					target_note = ' undo-next LSN {} present'.format(record.undo_next_lsn)
				else:
					target_note = ' undo-next LSN {} ABSENT'.format(record.undo_next_lsn)

			instance.state_reasons.append(
				'Compensation log record at LSN {} ({}) undoes earlier work;{}'.format(record.lsn, record.location(), target_note))

		for record in forget_records:
			instance.state_reasons.append(
				'ForgetTransaction record at LSN {} ({}) releases client state and proves neither commit nor rollback'.format(
					record.lsn, record.location()))

		for missing_lsn in instance.missing_predecessor_lsns:
			instance.state_reasons.append(
				'Predecessor LSN {} is referenced but absent from this log file (broken chain)'.format(missing_lsn))

		for missing_lsn in instance.missing_undo_target_lsns:
			instance.state_reasons.append(
				'Undo-next target LSN {} is referenced but absent from this log file (incomplete rollback trail)'.format(missing_lsn))

		has_broken_chain = len(instance.missing_predecessor_lsns) > 0 or len(instance.missing_undo_target_lsns) > 0
		has_commit = len(commit_records) > 0
		has_clr = len(clr_records) > 0

		if has_broken_chain and not has_commit:
			return STATE_MISSING_LINK

		if has_broken_chain and has_commit:
			# A commit is visible, but part of the chain cannot be inspected: keep both facts explicit.
			instance.state_reasons.append('Commit evidence exists while the chain is incomplete; the commit scope cannot be fully verified')
			return STATE_INDETERMINATE

		if has_commit:
			return STATE_COMMITTED

		if has_clr:
			return STATE_ROLLED_BACK

		return STATE_OPEN_UNKNOWN

	def analyze(self):
		"""Collect evidence, build instances and return the list of TransactionInstance objects."""

		self.collect_evidence()
		self._build_instances()
		return self.instances

	def render_report(self):
		"""Render a plain-text, human-readable evidence report (as a string)."""

		if not self.instances:
			self.analyze()

		lines = []
		lines.append('NTFS $LogFile transaction evidence view (read-only analysis; no disk recovery performed)')
		lines.append('Log clients present: {}'.format(
			sorted(set(record.client_id for record in self.records.values()) |
				set(record.client_id for record in self.restart_records))))
		lines.append('Transaction evidence records: {}'.format(len(self.records)))
		lines.append('NTFS client restart (checkpoint) records (not transactions): {}'.format(len(self.restart_records)))
		for record in sorted(self.restart_records, key = lambda item: item.lsn):
			lines.append(' * checkpoint LSN {} ({})'.format(record.lsn, record.location()))
		lines.append('Transaction instances: {}'.format(len(self.instances)))

		reused_ids = self._reused_transaction_ids()
		if reused_ids:
			lines.append('Reused transaction IDs (same ID, distinct instances): {}'.format(
				', '.join('{} ({} instances)'.format(tid, count) for tid, count in sorted(reused_ids.items()))))

		lines.append('')
		lines.append('State legend:')
		lines.append(' * {} - a commit record is present in a complete chain'.format(STATE_COMMITTED))
		lines.append(' * {} - compensation log records prove rollback'.format(STATE_ROLLED_BACK))
		lines.append(' * {} - neither commit nor sufficient rollback evidence is present'.format(STATE_OPEN_UNKNOWN))
		lines.append(' * {} - a referenced chain segment is absent; success cannot be assumed'.format(STATE_MISSING_LINK))
		lines.append(' * {} - evidence is contradictory or incomplete'.format(STATE_INDETERMINATE))

		for instance in self.instances:
			lines.append('')
			lines.append('=== {} ==='.format(instance.instance_id))
			lines.append('Client ID: {}'.format(instance.client_id))
			lines.append('Transaction ID (label, may be reused): {}'.format(instance.transaction_id))
			lines.append('LSN sequence number(s) (log generation): {}'.format(
				', '.join(str(value) for value in sorted(instance.sequence_numbers))))
			lines.append('LSN range: {} - {}'.format(instance.first_lsn(), instance.last_lsn()))
			lines.append('State: {}'.format(instance.state))
			lines.append('Evidence records: {} (user operations: {}, compensation: {}, boundary: {})'.format(
				len(instance.records),
				len(list(instance.user_operations())),
				len(list(instance.compensation_records())),
				len(list(instance.boundary_records()))))

			lines.append('Reasons:')
			for reason in instance.state_reasons:
				lines.append(' * {}'.format(reason))
			if not instance.state_reasons:
				lines.append(' * no commit, prepare or compensation record found in the available chain')

			lines.append('Record chain (ordered by LSN; physical location retained for each record):')
			for record in instance.records:
				lines.append(self._render_record_line(record))

		lines.append('')
		lines.append('Causal graph:')
		lines.append(self.render_graph())

		return '\n'.join(lines)

	def _render_record_line(self, record):
		"""Render one evidence record line for the report."""

		redo = LogFile.ResolveNTFSOperation(record.redo_operation) if record.redo_operation is not None else 'n/a'
		undo = LogFile.ResolveNTFSOperation(record.undo_operation) if record.undo_operation is not None else 'n/a'

		notes = []
		if record.is_chain_root:
			notes.append('chain root (prev LSN 0)')
		if record.predecessor_present is False:
			notes.append('prev LSN {} ABSENT'.format(record.previous_lsn))
		if record.undo_target_present is False:
			notes.append('undo-next LSN {} ABSENT'.format(record.undo_next_lsn))
		notes_text = '; '.join(notes)

		line = ' [{}] LSN {} seqnum {} [{}] redo={} undo={} prev={} undo_next={} | {}'.format(
			record.kind, record.lsn, record.sequence_number, record.location(), redo, undo,
			record.previous_lsn, record.undo_next_lsn, notes_text)

		return line

	def render_graph(self):
		"""Render an ASCII causal graph covering every transaction instance.

		Edges:
		- 'prev' edges follow the client previous-LSN (forward) chain;
		- 'undo' edges follow client undo-next-LSN links from compensation records to the records they undo;
		- missing links are rendered explicitly as '[ABSENT]' nodes.
		"""

		if not self.instances:
			self.analyze()

		lines = []

		for instance in self.instances:
			lines.append('{} (transaction ID label {}, state: {}):'.format(
				instance.instance_id, instance.transaction_id, instance.state))

			missing_nodes = set(instance.missing_predecessor_lsns) | set(instance.missing_undo_target_lsns)
			for missing_lsn in sorted(missing_nodes):
				lines.append('  [ABSENT LSN {}] (referenced but not present in this log file)'.format(missing_lsn))

			for record in instance.records:
				node = '  LSN {} [{}]{}'.format(record.lsn, record.kind,
					' CLR' if record.is_clr else '')

				edges = []
				if record.previous_lsn != 0:
					target = str(record.previous_lsn) if record.predecessor_present else 'ABSENT {}'.format(record.previous_lsn)
					edges.append('prev->{}'.format(target))
				if record.kind == KIND_COMPENSATION and record.undo_next_lsn != 0:
					target = str(record.undo_next_lsn) if record.undo_target_present else 'ABSENT {}'.format(record.undo_next_lsn)
					edges.append('undo->{}'.format(target))

				if edges:
					lines.append('{} -- {}'.format(node, ', '.join(edges)))
				else:
					lines.append(node)

			lines.append('')

		return '\n'.join(lines).rstrip()

	def _reused_transaction_ids(self):
		"""Return a dictionary of transaction IDs shared by more than one instance."""

		id_to_instances = dict()
		for instance in self.instances:
			id_to_instances.setdefault(instance.transaction_id, set()).add(instance.instance_id)

		return {tid: len(instance_set) for tid, instance_set in id_to_instances.items() if len(instance_set) > 1}
