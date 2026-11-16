# coding: utf-8

# Per-sector source regression tests for VSS (Volume Shadow Copy Service) overlay reads.
#
# A 16 KiB VSS data block is made of 32 sectors of 512 bytes. An overlay diff entry
# (the 0x2 flag plus an allocation bitmap) replaces only the sectors whose bitmap bit
# is set; every other sector keeps coming from the base block, a regular (full) entry
# or a later store in the stack. These tests build small, fully synthetic VSS images and
# define the expected source of every sector independently, so an implementation that
# treats an overlay as a whole-block replacement, inverts the bitmap or reads from the
# wrong store fails on the precise offending sector instead of being hidden by an
# accidentally equal whole block.

import io
import struct
import uuid

import pytest

from dfir_ntfs import ShadowCopy

BLOCK = 0x4000          # A VSS data block: 16 KiB.
SECTOR = 512            # A VSS sector.
SECTORS_PER_BLOCK = BLOCK // SECTOR  # 32 sectors in one data block.

OVERLAY_FLAG = ShadowCopy.DIFF_AREA_TABLE_ENTRY_UNKNOWN_NAME_2
REGULAR_FLAGS = 0
NULL_BLOCK_STORE_FLAG = ShadowCopy.STORE_FLAG_UNKNOWN_NAME_400

GUID = ShadowCopy.VSP_DIFF_AREA_FILE_GUID


def _shadow_header(block_type, offset_1=0, offset_2=0, offset_3=0):
	return GUID + struct.pack('<LL', 1, block_type) + \
		struct.pack('<QQQ', offset_1, offset_2, offset_3)


def _start_block(first_control_block_offset):
	buf = bytearray(8192)
	buf[3:7] = b'NTFS'
	buf[7680:7680 + 48] = _shadow_header(
		ShadowCopy.SHADOW_BLOCK_TYPE_UNKNOWN_NAME_1, 7680, 7680, 0)
	struct.pack_into('<Q', buf, 7728, first_control_block_offset)

	volume_guid = uuid.uuid4().bytes_le
	buf[7744:7760] = volume_guid
	buf[7760:7776] = volume_guid  # Storage is local to the volume.
	return bytes(buf)


def _control_block_item_2(store_guid, stack_position, volume_size, store_flags):
	buf = bytearray(0x80)
	struct.pack_into('<L', buf, 0, ShadowCopy.CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_2)
	struct.pack_into('<Q', buf, 8, volume_size)
	buf[16:32] = store_guid
	struct.pack_into('<Q', buf, 32, stack_position)
	struct.pack_into('<Q', buf, 40, store_flags)
	return bytes(buf)


def _control_block_item_3(store_guid, diff_area_offset, bitmap_offset, previous_bitmap_offset=0):
	buf = bytearray(0x80)
	struct.pack_into('<L', buf, 0, ShadowCopy.CONTROL_BLOCK_ITEM_TYPE_UNKNOWN_NAME_3)
	struct.pack_into('<Q', buf, 8, diff_area_offset)
	buf[16:32] = store_guid
	struct.pack_into('<Q', buf, 48, bitmap_offset)
	struct.pack_into('<Q', buf, 72, previous_bitmap_offset)
	return bytes(buf)


def _control_block(volume_offset, next_offset, items):
	buf = bytearray(BLOCK)
	buf[0:48] = _shadow_header(
		ShadowCopy.SHADOW_BLOCK_TYPE_UNKNOWN_NAME_2, 0, volume_offset, next_offset)

	position = 0x80
	for item in items:
		buf[position:position + len(item)] = item
		position += len(item)
	return bytes(buf)


def _bitmap_block(volume_offset, next_offset, bitmap_bytes):
	buf = bytearray(BLOCK)
	buf[0:48] = _shadow_header(
		ShadowCopy.SHADOW_BLOCK_TYPE_UNKNOWN_NAME_6, 0, volume_offset, next_offset)
	buf[0x80:0x80 + len(bitmap_bytes)] = bitmap_bytes
	return bytes(buf)


def _diff_area_block(volume_offset, next_offset, entries):
	buf = bytearray(BLOCK)
	buf[0:48] = _shadow_header(
		ShadowCopy.SHADOW_BLOCK_TYPE_UNKNOWN_NAME_3, 0, volume_offset, next_offset)

	position = 0x80
	for original_offset, _store_offset, data_offset, flags, allocation_bitmap in entries:
		struct.pack_into('<QQQLL', buf, position, original_offset, _store_offset,
		                 data_offset, flags, allocation_bitmap)
		position += 32
	return bytes(buf)


def _sector_pattern(tag, sector_index):
	"""Return a unique 512-byte pattern for a (tag, sector) pair."""
	return bytes([tag & 0xFF, sector_index & 0xFF]) + \
		struct.pack('<H', sector_index) * 255


class SyntheticVssImage(object):
	"""A small in-memory VSS volume with several stores in one stack.

	Metadata blocks live at the low block indices. Data blocks (base volume content and
	per-store copy-on-write blocks) live in a dedicated region and are filled with unique
	per-sector patterns so that the source of any individual sector is unambiguous.
	"""

	def __init__(self, block_count, store_count, base_tag=0x10):
		self.block_count = block_count
		self.store_count = store_count
		self.volume_size = block_count * BLOCK
		self.base_tag = base_tag

		self.control_block_index = 1
		self.bitmap_block_indices = list(range(2, 2 + store_count))
		self.diff_block_indices = list(range(2 + store_count, 2 + 2 * store_count))
		self.first_data_block = 2 + 2 * store_count

		self.store_guids = [uuid.uuid4().bytes_le for _ in range(store_count)]
		self.data_block_counter = self.first_data_block
		self.data_tags = {}

		# Per-store configuration, filled in by the test through add_*() helpers.
		self.entries = {i: [] for i in range(store_count)}
		self.bitmap_bits = {i: bytearray(self._bitmap_length()) for i in range(store_count)}
		self.previous_bitmap_bits = {i: bytearray(self._bitmap_length())
		                             for i in range(store_count)}
		self.store_flags = {i: NULL_BLOCK_STORE_FLAG for i in range(store_count)}

		self.image = bytearray(self.volume_size)
		for block_index in range(block_count):
			self._fill_block(block_index, base_tag + block_index)

	def _bitmap_length(self):
		bits = self.block_count
		if bits % 8 != 0:
			bits += 8 - bits % 8
		return bits // 8

	def _fill_block(self, block_index, tag):
		self.data_tags[block_index] = tag
		for sector_index in range(SECTORS_PER_BLOCK):
			offset = block_index * BLOCK + sector_index * SECTOR
			self.image[offset:offset + SECTOR] = _sector_pattern(tag, sector_index)

	def allocate_data_block(self, tag):
		block_index = self.data_block_counter
		if block_index >= self.block_count:
			raise RuntimeError('Out of data blocks in the synthetic image')
		self.data_block_counter += 1
		self._fill_block(block_index, tag)
		return block_index

	def add_regular_entry(self, store_index, original_block, data_block):
		self.entries[store_index].append(
			(original_block * BLOCK, 0, data_block * BLOCK, REGULAR_FLAGS, 0))

	def add_overlay_entry(self, store_index, original_block, data_block, sector_set):
		allocation_bitmap = 0
		for sector_index in sector_set:
			allocation_bitmap |= 1 << sector_index
		self.entries[store_index].append(
			(original_block * BLOCK, 0, data_block * BLOCK, OVERLAY_FLAG,
			 allocation_bitmap))

	def set_bitmap_bit(self, store_index, block_index, previous=False):
		byte_index = block_index // 8
		bit_shift = block_index % 8
		target = self.previous_bitmap_bits[store_index] if previous \
			else self.bitmap_bits[store_index]
		target[byte_index] |= 1 << bit_shift

	def build(self):
		# The start block occupies the first 8192 bytes of the volume.
		self.image[0:8192] = _start_block(self.control_block_index * BLOCK)

		items = []
		for store_index in range(self.store_count):
			items.append(_control_block_item_2(
				self.store_guids[store_index], store_index, self.volume_size,
				self.store_flags[store_index]))
			items.append(_control_block_item_3(
				self.store_guids[store_index],
				self.diff_block_indices[store_index] * BLOCK,
				self.bitmap_block_indices[store_index] * BLOCK))

		control_offset = self.control_block_index * BLOCK
		self.image[control_offset:control_offset + BLOCK] = _control_block(
			control_offset, 0, items)

		for store_index in range(self.store_count):
			bitmap_offset = self.bitmap_block_indices[store_index] * BLOCK
			self.image[bitmap_offset:bitmap_offset + BLOCK] = _bitmap_block(
				bitmap_offset, 0, bytes(self.bitmap_bits[store_index]))

			diff_offset = self.diff_block_indices[store_index] * BLOCK
			self.image[diff_offset:diff_offset + BLOCK] = _diff_area_block(
				diff_offset, 0, self.entries[store_index])

		return io.BytesIO(bytes(self.image))

	def parser(self):
		shadow = ShadowCopy.ShadowParser(self.build(), 0, self.volume_size)
		return shadow


def _assert_sector_offsets(shadow, block_index, expected_blocks):
	"""Compare translate_exact_offset() sector by sector against expected blocks.

	'expected_blocks' maps each of the 32 sector indices to either a source block
	index (an offset into the volume) or None (a null sector). A failure names the
	sector, the offset produced and the offset expected.
	"""
	offsets = shadow.translate_exact_offset(block_index * BLOCK)
	assert len(offsets) == SECTORS_PER_BLOCK

	for sector_index in range(SECTORS_PER_BLOCK):
		expected_block = expected_blocks[sector_index]
		if expected_block is None:
			expected_offset = None
		else:
			expected_offset = expected_block * BLOCK + sector_index * SECTOR

		assert offsets[sector_index] == expected_offset, (
			'block {} sector {}: translate returned {} but expected {}'.format(
				block_index, sector_index, offsets[sector_index], expected_offset))


def _assert_sector_data(shadow, block_index, expected_tags):
	"""Read a whole block and verify each 512-byte sector's content independently."""
	data = shadow.read_at_exact_offset(block_index * BLOCK)
	assert len(data) == BLOCK

	for sector_index in range(SECTORS_PER_BLOCK):
		start = sector_index * SECTOR
		sector_data = data[start:start + SECTOR]
		expected_tag = expected_tags[sector_index]

		if expected_tag is None:
			expected_data = b'\x00' * SECTOR
		else:
			expected_data = _sector_pattern(expected_tag, sector_index)

		assert sector_data == expected_data, (
			'block {} sector {}: data tag 0x{:02X} but expected 0x{:02X}'.format(
				block_index, sector_index, sector_data[0],
				0 if expected_tag is None else expected_tag))


def _read_at(shadow, offset, size):
	shadow.seek(offset)
	return shadow.read(size)


def test_overlay_replaces_only_bitmap_sectors():
	# One overlay on top of a regular full block: only two sectors come from the
	# overlay, the other thirty still come from the regular (base replacement) block.
	image = SyntheticVssImage(block_count=10, store_count=2)
	target_block = 8

	regular_block = image.allocate_data_block(tag=0xD1)
	overlay_block = image.allocate_data_block(tag=0xD0)

	image.add_regular_entry(store_index=1, original_block=target_block,
	                        data_block=regular_block)
	overlay_sectors = {1, 3}
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=overlay_block, sector_set=overlay_sectors)

	shadow = image.parser()
	shadow.select_shadow(0)

	expected_blocks = {}
	expected_tags = {}
	for sector_index in range(SECTORS_PER_BLOCK):
		if sector_index in overlay_sectors:
			expected_blocks[sector_index] = overlay_block
			expected_tags[sector_index] = image.data_tags[overlay_block]
		else:
			expected_blocks[sector_index] = regular_block
			expected_tags[sector_index] = image.data_tags[regular_block]

	_assert_sector_offsets(shadow, target_block, expected_blocks)
	_assert_sector_data(shadow, target_block, expected_tags)


def test_multiple_overlays_apply_in_diff_area_order():
	# Two overlapping overlay entries in the same store: later entries overwrite the
	# sectors they claim (repeated coverage), sectors never claimed fall through to the
	# regular block underneath.
	image = SyntheticVssImage(block_count=11, store_count=2)
	target_block = 9

	regular_block = image.allocate_data_block(tag=0xD2)
	first_overlay_block = image.allocate_data_block(tag=0xDA)
	second_overlay_block = image.allocate_data_block(tag=0xDB)

	image.add_regular_entry(store_index=1, original_block=target_block,
	                        data_block=regular_block)
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=first_overlay_block, sector_set={2, 4, 6})
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=second_overlay_block, sector_set={4, 8})

	shadow = image.parser()
	shadow.select_shadow(0)

	first_only = {2, 6}
	second_wins = {4, 8}  # Sector 4 is covered twice: the last overlay must win.

	expected_blocks = {}
	expected_tags = {}
	for sector_index in range(SECTORS_PER_BLOCK):
		if sector_index in second_wins:
			source_block = second_overlay_block
		elif sector_index in first_only:
			source_block = first_overlay_block
		else:
			source_block = regular_block
		expected_blocks[sector_index] = source_block
		expected_tags[sector_index] = image.data_tags[source_block]

	_assert_sector_offsets(shadow, target_block, expected_blocks)
	_assert_sector_data(shadow, target_block, expected_tags)


def test_overlay_and_regular_entry_merge_in_one_store():
	# An overlay entry and a regular entry for the same target in one store: the regular
	# entry fills every sector first, then the overlay claims only its bitmap sectors. The
	# overlay sectors must come from the overlay block and the remaining sectors from the
	# regular block, in both possible on-disk orders.
	overlay_sectors = {2, 5}

	for overlay_first in (True, False):
		image = SyntheticVssImage(block_count=10, store_count=1)
		target_block = 8

		regular_block = image.allocate_data_block(tag=0xAA)
		overlay_block = image.allocate_data_block(tag=0xBB)

		if overlay_first:
			image.add_overlay_entry(store_index=0, original_block=target_block,
			                        data_block=overlay_block, sector_set=overlay_sectors)
			image.add_regular_entry(store_index=0, original_block=target_block,
			                        data_block=regular_block)
		else:
			image.add_regular_entry(store_index=0, original_block=target_block,
			                        data_block=regular_block)
			image.add_overlay_entry(store_index=0, original_block=target_block,
			                        data_block=overlay_block, sector_set=overlay_sectors)

		shadow = image.parser()
		shadow.select_shadow(0)

		expected_blocks = {}
		expected_tags = {}
		for sector_index in range(SECTORS_PER_BLOCK):
			if sector_index in overlay_sectors:
				source_block = overlay_block
			else:
				source_block = regular_block
			expected_blocks[sector_index] = source_block
			expected_tags[sector_index] = image.data_tags[source_block]

		_assert_sector_offsets(shadow, target_block, expected_blocks)
		_assert_sector_data(shadow, target_block, expected_tags)


def test_overlay_falls_back_to_base_volume_without_store_entry():
	# No base (regular) data block exists for this target: overlay sectors come from the
	# overlay block while every unclaimed sector keeps its original base-volume content.
	image = SyntheticVssImage(block_count=10, store_count=1, base_tag=0x20)
	target_block = 8

	overlay_block = image.allocate_data_block(tag=0xE0)
	overlay_sectors = {0, 15, 31}
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=overlay_block, sector_set=overlay_sectors)

	shadow = image.parser()
	shadow.select_shadow(0)

	expected_blocks = {}
	expected_tags = {}
	for sector_index in range(SECTORS_PER_BLOCK):
		if sector_index in overlay_sectors:
			expected_blocks[sector_index] = overlay_block
			expected_tags[sector_index] = image.data_tags[overlay_block]
		else:
			expected_blocks[sector_index] = target_block  # Original base volume.
			expected_tags[sector_index] = image.base_tag + target_block

	_assert_sector_offsets(shadow, target_block, expected_blocks)
	_assert_sector_data(shadow, target_block, expected_tags)


def test_overlay_ignored_when_redirected_from_another_store():
	# Store 0 has only an overlay. Reading it fills unclaimed sectors by redirecting to
	# the next store, and redirection passes ignore_overlay_entries=True, so store 1's
	# own overlay must be skipped in favour of store 2's regular block.
	image = SyntheticVssImage(block_count=12, store_count=3)
	target_block = 11

	deep_regular_block = image.allocate_data_block(tag=0xD2)
	middle_overlay_block = image.allocate_data_block(tag=0xD1)
	near_overlay_block = image.allocate_data_block(tag=0xD0)

	image.add_regular_entry(store_index=2, original_block=target_block,
	                        data_block=deep_regular_block)
	image.add_overlay_entry(store_index=1, original_block=target_block,
	                        data_block=middle_overlay_block, sector_set={5, 6})
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=near_overlay_block, sector_set={0, 6, 31})

	# Selecting store 0: its overlay wins sectors 0, 6 and 31; everything else is
	# redirected down the stack and store 1's overlay is skipped, so it lands on store 2.
	shadow = image.parser()
	shadow.select_shadow(0)

	near_sectors = {0, 6, 31}
	expected_blocks = {}
	for sector_index in range(SECTORS_PER_BLOCK):
		if sector_index in near_sectors:
			expected_blocks[sector_index] = near_overlay_block
		else:
			expected_blocks[sector_index] = deep_regular_block
	_assert_sector_offsets(shadow, target_block, expected_blocks)

	# Selecting store 1 directly applies its own overlay (no redirection flag), proving
	# the skip above is specifically a consequence of cross-store redirection.
	shadow_direct = image.parser()
	shadow_direct.select_shadow(1)
	expected_direct = {}
	for sector_index in range(SECTORS_PER_BLOCK):
		if sector_index in {5, 6}:
			expected_direct[sector_index] = middle_overlay_block
		else:
			expected_direct[sector_index] = deep_regular_block
	_assert_sector_offsets(shadow_direct, target_block, expected_direct)


def test_unclaimed_bitmap_block_without_entry_is_null():
	# A block marked in both current and previous bitmaps but absent from the diff area
	# has no source data: with the null-block store flag it resolves to zeroed sectors.
	image = SyntheticVssImage(block_count=10, store_count=1)
	target_block = 8
	image.set_bitmap_bit(0, target_block)
	image.set_bitmap_bit(0, target_block, previous=True)

	shadow = image.parser()
	shadow.select_shadow(0)

	offsets = shadow.translate_exact_offset(target_block * BLOCK)
	assert offsets == [None] * SECTORS_PER_BLOCK

	data = shadow.read_at_exact_offset(target_block * BLOCK)
	assert data == b'\x00' * BLOCK


def test_unaligned_and_cross_block_reads_keep_sector_sources():
	# Reads that start mid-block and span a block boundary must still assemble each
	# sector from its own source; check both offset translation and returned bytes.
	image = SyntheticVssImage(block_count=11, store_count=2)
	target_block = 8  # Blocks 9 and 10 stay untouched base data for the cross-block tail.

	regular_block = image.allocate_data_block(tag=0xC1)
	overlay_block = image.allocate_data_block(tag=0xC0)
	overlay_sectors = {1, 3}

	image.add_regular_entry(store_index=1, original_block=target_block,
	                        data_block=regular_block)
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=overlay_block, sector_set=overlay_sectors)

	shadow = image.parser()
	shadow.select_shadow(0)

	# Independently define the tag of every sector of the target block and the two
	# following base blocks. This stays a per-sector model rather than a whole-block copy.
	def expected_tag_at(block_index, sector_index):
		if block_index == target_block:
			if sector_index in overlay_sectors:
				return image.data_tags[overlay_block]
			return image.data_tags[regular_block]
		return image.base_tag + block_index  # Untouched base-volume block.

	# Unaligned start at sector 1 of the target, spanning all of block 9 and into block 10.
	start_offset = target_block * BLOCK + SECTOR
	read_size = BLOCK + 3 * SECTOR

	expected = bytearray()
	for absolute_offset in range(start_offset, start_offset + read_size, SECTOR):
		block_index = absolute_offset // BLOCK
		sector_index = (absolute_offset % BLOCK) // SECTOR
		expected += _sector_pattern(expected_tag_at(block_index, sector_index),
		                            sector_index)

	result = _read_at(shadow, start_offset, read_size)
	assert len(result) == read_size
	assert bytes(result) == bytes(expected)

	# A small unaligned read entirely inside one overlay sector.
	inside = _read_at(shadow, target_block * BLOCK + SECTOR + 17, 200)
	expected_inside = _sector_pattern(
		image.data_tags[overlay_block], 1)[17:217]
	assert inside == expected_inside


def test_whole_block_and_partial_blocks_coexist():
	# A plain full (regular) block and a partial (overlay) block on different targets in
	# the same store must not interfere with each other's sector sources.
	image = SyntheticVssImage(block_count=12, store_count=1)
	full_target = 9
	partial_target = 10

	full_block = image.allocate_data_block(tag=0xF0)
	partial_data_block = image.allocate_data_block(tag=0xF1)

	image.add_regular_entry(store_index=0, original_block=full_target,
	                        data_block=full_block)
	partial_sectors = {7, 23}
	image.add_overlay_entry(store_index=0, original_block=partial_target,
	                        data_block=partial_data_block, sector_set=partial_sectors)

	shadow = image.parser()
	shadow.select_shadow(0)

	full_offsets = shadow.translate_exact_offset(full_target * BLOCK)
	for sector_index in range(SECTORS_PER_BLOCK):
		assert full_offsets[sector_index] == full_block * BLOCK + sector_index * SECTOR

	partial_offsets = shadow.translate_exact_offset(partial_target * BLOCK)
	for sector_index in range(SECTORS_PER_BLOCK):
		if sector_index in partial_sectors:
			expected = partial_data_block * BLOCK + sector_index * SECTOR
		else:
			expected = partial_target * BLOCK + sector_index * SECTOR
		assert partial_offsets[sector_index] == expected


def test_failures_are_localized_to_the_offending_sector():
	# Meta-test: feed deliberately wrong expectations and confirm the assertion names the
	# exact sector, which is what makes these regressions debuggable.
	image = SyntheticVssImage(block_count=10, store_count=2)
	target_block = 8
	regular_block = image.allocate_data_block(tag=0xD1)
	overlay_block = image.allocate_data_block(tag=0xD0)
	overlay_sectors = {1, 3}

	image.add_regular_entry(store_index=1, original_block=target_block,
	                        data_block=regular_block)
	image.add_overlay_entry(store_index=0, original_block=target_block,
	                        data_block=overlay_block, sector_set=overlay_sectors)

	shadow = image.parser()
	shadow.select_shadow(0)
	correct = shadow.translate_exact_offset(target_block * BLOCK)

	# Whole-block replacement bug: pretend every sector came from the overlay block.
	whole_block_wrong = [overlay_block * BLOCK + i * SECTOR
	                     for i in range(SECTORS_PER_BLOCK)]
	caught = [i for i in range(SECTORS_PER_BLOCK) if whole_block_wrong[i] != correct[i]]
	assert caught == [i for i in range(SECTORS_PER_BLOCK) if i not in overlay_sectors]

	# Inverted bitmap bug: overlay applied to every sector except 1 and 3.
	inverted = []
	for i in range(SECTORS_PER_BLOCK):
		if i not in overlay_sectors:
			inverted.append(overlay_block * BLOCK + i * SECTOR)
		else:
			inverted.append(regular_block * BLOCK + i * SECTOR)
	caught_inverted = [i for i in range(SECTORS_PER_BLOCK) if inverted[i] != correct[i]]
	assert set(caught_inverted) == set(range(SECTORS_PER_BLOCK))

	# Wrong-store bug: overlay sectors mistakenly read from the regular block.
	wrong_store = list(correct)
	for i in overlay_sectors:
		wrong_store[i] = regular_block * BLOCK + i * SECTOR
	caught_store = [i for i in range(SECTORS_PER_BLOCK) if wrong_store[i] != correct[i]]
	assert caught_store == sorted(overlay_sectors)
