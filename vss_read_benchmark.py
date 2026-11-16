#!/usr/bin/env python3

# dfir_ntfs: an NTFS parser for digital forensics & incident response
# (c) Maxim Suhanov
#
# A benchmark and an equivalence checker for sequential reads of shadow copies.
# It uses a counting file object (not wall-clock time) and an independent reference reader
# to prove that the optimized path returns the same bytes, truncation points and provenance.

import io
import os
import sys
import tarfile

from dfir_ntfs import ShadowCopy

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_data')


class CountingFile(io.RawIOBase):
	"""Wrap a binary file object and count physical read calls, seek calls and bytes read."""

	def __init__(self, file_object):
		self._file_object = file_object
		self.read_calls = 0
		self.seek_calls = 0
		self.bytes_read = 0

	def seek(self, offset, whence = 0):
		self.seek_calls += 1
		return self._file_object.seek(offset, whence)

	def read(self, size = -1):
		self.read_calls += 1
		if size is None or size < 0:
			data = self._file_object.read()
		else:
			data = self._file_object.read(size)

		self.bytes_read += len(data)
		return data

	def tell(self):
		return self._file_object.tell()

	def close(self):
		return self._file_object.close()

	def readable(self):
		return True

	def seekable(self):
		return True


def open_member(archive, member):
	tar = tarfile.open(archive, 'r')
	return CountingFile(tar.extractfile(member)), tar


def reference_read(parser, size):
	"""Independent model: resolve every 512-byte sub-block on its own and read it individually.

	Returns (data, provenance); provenance records, for every 16 KiB block, the exact translation
	list (an offset, a (source, offset) tuple or a null marker) as produced by translate_exact_offset.
	"""

	start_offset = parser.tell()
	data = bytearray()
	provenance = []

	remaining = size
	offset = start_offset

	while remaining > 0:
		block_offset = offset // 0x4000 * 0x4000
		offset_in_block = offset % 0x4000

		translations = parser.translate_exact_offset(block_offset)
		if len(translations) == 0:
			break

		block = bytearray()
		for item in translations:
			if isinstance(item, tuple): # The two-volume parser.
				use_storage, sub_offset = item
				if sub_offset is None:
					block += b'\x00' * 512
					continue

				if use_storage:
					file_object = parser.volume_storage_object
					base = parser.volume_storage_offset
				else:
					file_object = parser.volume_object
					base = parser.volume_offset

				file_object.seek(base + sub_offset)
				block += file_object.read(512)

			elif item is None: # The single-volume parser: a null block.
				block += b'\x00' * 512

			else: # The single-volume parser.
				parser.volume_object.seek(parser.volume_offset + item)
				block += parser.volume_object.read(512)

		take = min(len(block) - offset_in_block, remaining)
		data += block[offset_in_block : offset_in_block + take]
		provenance.append((block_offset, tuple(translations)))

		offset += take
		remaining -= take

	parser.seek(start_offset + len(data))
	return bytes(data), provenance


def optimized_read(parser, size):
	"""Drive the optimized sequential path and capture the same provenance."""

	start_offset = parser.tell()
	data = parser.read(size)

	provenance = []
	covered = 0
	block = start_offset // 0x4000 * 0x4000
	first_in_block = start_offset % 0x4000

	while covered < len(data):
		translations = parser.translate_exact_offset(block)
		provenance.append((block, tuple(translations)))

		step = 0x4000 - first_in_block if len(provenance) == 1 else 0x4000
		covered += min(step, len(data) - covered)
		block += 0x4000
		first_in_block = 0

	parser.seek(start_offset + len(data))
	return bytes(data), provenance


def aggregate_stats(parser):
	stats = dict(translate_requests = 0, translate_cache_hits = 0, store_chain_steps = 0,
	             diff_entry_inspections = 0, coalesced_read_runs = 0, physical_read_calls = 0)

	current = parser
	while current is not None:
		for key in stats:
			stats[key] += current.stats.get(key, 0)

		current = current.current_next_parser

	return stats


def check_equivalence(label, parser_factory, positions, region_blocks = 64):
	"""Compare the independent model against the optimized path on fresh parsers."""

	for position in positions:
		ref_file, ref_tar = parser_factory()
		ref_parser = ref_file.parser
		ref_storage_file = getattr(ref_parser, 'volume_storage_object', None)
		ref_parser.select_shadow(position)
		ref_parser.seek(0)
		ref_data, ref_provenance = reference_read(ref_parser, region_blocks * 0x4000)
		ref_io = (ref_file.read_calls, ref_file.seek_calls)
		if ref_storage_file is not None:
			ref_io = (ref_io[0] + ref_storage_file.read_calls, ref_io[1] + ref_storage_file.seek_calls)

		ref_file.close()
		ref_tar.close()

		opt_file, opt_tar = parser_factory()
		opt_parser = opt_file.parser
		opt_storage_file = getattr(opt_parser, 'volume_storage_object', None)
		opt_parser.select_shadow(position)
		opt_parser.seek(0)
		opt_data, opt_provenance = optimized_read(opt_parser, region_blocks * 0x4000)
		opt_io = (opt_file.read_calls, opt_file.seek_calls)
		if opt_storage_file is not None:
			opt_io = (opt_io[0] + opt_storage_file.read_calls, opt_io[1] + opt_storage_file.seek_calls)

		stats = aggregate_stats(opt_parser)
		opt_file.close()
		opt_tar.close()

		assert opt_data == ref_data, 'byte mismatch for {} position {}'.format(label, position)
		assert opt_provenance == ref_provenance, 'provenance mismatch for {} position {}'.format(label, position)
		assert len(opt_data) == len(ref_data)

		print('{:>10} store {}: OK  bytes={:>8}  physical reads {:>5} -> {:>5} ({:4.1f}x fewer), seeks {:>5} -> {:>5}, runs/block={:.2f}, translate hits={}'.format(
			label, position, len(opt_data), ref_io[0], opt_io[0], ref_io[0] / max(1, opt_io[0]),
			ref_io[1], opt_io[1], stats['coalesced_read_runs'] / max(1, region_blocks), stats['translate_cache_hits']))


class _Factory:
	def __init__(self, archive, member, volume_offset, two_volume = False, storage_archive = None, storage_member = None, storage_offset = 0):
		self.archive = archive
		self.member = member
		self.volume_offset = volume_offset
		self.two_volume = two_volume
		self.storage_archive = storage_archive
		self.storage_member = storage_member
		self.storage_offset = storage_offset

	def __call__(self):
		volume_file, volume_tar = open_member(self.archive, self.member)

		if not self.two_volume:
			parser = ShadowCopy.ShadowParser(volume_file, self.volume_offset)
			volume_file.parser = parser
			return volume_file, volume_tar

		storage_file, storage_tar = open_member(self.storage_archive, self.storage_member)
		parser = ShadowCopy.ShadowParserTwoVolumes(volume_file, storage_file, self.volume_offset, None, self.storage_offset)
		volume_file.parser = parser
		storage_file.parser = parser
		volume_file.storage_tar = storage_tar
		volume_file.storage_file = storage_file
		return volume_file, volume_tar


def main():
	cases = [
		('vss_2003', _Factory(os.path.join(DATA_DIR, 'vss_2003.tgz'), 'vss_2003.raw', 63 * 512), [ 1, 2, 3, 5 ]),
		('vss_10', _Factory(os.path.join(DATA_DIR, 'vss_10.tgz'), 'vss_10.raw', 2048 * 512), [ 1, 2, 3 ]),
		('two-vol', _Factory(os.path.join(DATA_DIR, 'vss_1_vol.tar.gz'), 'vss_1_vol.raw', 67584 * 512,
		                     True, os.path.join(DATA_DIR, 'vss_2_stor.tar.gz'), 'vss_2_stor.raw', 67584 * 512), [ 1, 2 ]),
	]

	for label, factory, positions in cases:
		check_equivalence(label, factory, positions)

	print('')
	print('All optimized reads match the independent model (bytes, truncation points and provenance).')


if __name__ == '__main__':
	main()
