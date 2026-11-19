#!/usr/bin/env python3

"""Generate a small deterministic MoveTable fixture for the history analyzer."""

import datetime
import os
import struct
import sys
import uuid

HEADER_SIGNATURE = b'\xEC\xA7\x43\x66\xFE\xEF\xD1\x11\xB2\xAE\x00\xC0\x4F\xB9\x38\x6D'
SECTOR_SIZE = 512
ENTRY_SIZE = 124
FOOTER_SIZE = 16
SLOTS_PER_SECTOR = (SECTOR_SIZE - FOOTER_SIZE) // ENTRY_SIZE

MACHINE_A = b'LAB-A'
MACHINE_B = b'LAB-B'
VOLUME_A = uuid.UUID('11111111-1111-4111-8111-111111111111')
VOLUME_B = uuid.UUID('22222222-2222-4222-8222-222222222222')
VOLUME_C = uuid.UUID('33333333-3333-4333-8333-333333333333')

# GUID v1 values encode identity and a creation time. They are deliberately
# earlier than the notification time; the analyzer must keep both clocks.
GUID_EPOCH = datetime.datetime(1582, 10, 15)
FIXTURE_NODE = b'\x52\x54\x00\x12\x34\x56'

def GuidV1(Label, Created):
	intervals = int((Created - GUID_EPOCH).total_seconds() * 10000000)
	time_low = intervals & 0xFFFFFFFF
	time_mid = (intervals >> 32) & 0xFFFF
	time_hi = ((intervals >> 48) & 0x0FFF) | 0x1000
	sequence = (sum(Label.encode('ascii')) & 0x3FFF) | 0x8000
	return uuid.UUID(fields = (time_low, time_mid, time_hi, sequence >> 8, sequence & 0xFF, int.from_bytes(FIXTURE_NODE, 'big')))

CREATED = datetime.datetime(2024, 1, 2, 3, 4, 5)

OBJECT_IDS = {
	'alpha': GuidV1('alpha-object', CREATED + datetime.timedelta(days = 1)),
	'beta': GuidV1('beta-object', CREATED + datetime.timedelta(days = 2)),
	'stale': GuidV1('stale-object', CREATED + datetime.timedelta(days = 4)),
}

DROID_OBJECTS = {
	'alpha-birth': GuidV1('alpha-birth', CREATED + datetime.timedelta(hours = 1)),
	'alpha-mid': GuidV1('alpha-mid', CREATED + datetime.timedelta(hours = 2)),
	'alpha-end': GuidV1('alpha-end', CREATED + datetime.timedelta(hours = 3)),
	'beta-birth': GuidV1('beta-birth', CREATED + datetime.timedelta(hours = 4)),
	'beta-end': GuidV1('beta-end', CREATED + datetime.timedelta(hours = 5)),
}

def Filetime(Value):
	return int((Value - datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)

def Entry(Index, Previous, NextIndex, Machine, ObjectId, BirthVolume, BirthObject, CurrentVolume, CurrentObject, Timestamp):
	# The low 32 bits of the FILETIME give the advertised [low, high] bracket.
	timestamp_high = (Filetime(Timestamp) >> 32) & 0xFFFFFFFF
	return struct.pack(
		'<LLLLL16s16s16s16s16s16sL',
		NextIndex, Previous, 2, Index, 0,
		ObjectId.bytes_le, CurrentVolume.bytes_le, CurrentObject.bytes_le,
		Machine.ljust(16, b'\x00'), BirthVolume.bytes_le, BirthObject.bytes_le,
		timestamp_high
	) + struct.pack('<L', 0)

def EmptySlot():
	return struct.pack('<LLLLL16s16s16s16s16s16sL', 0, 0, 1, 0, 0, b'\x00' * 16, b'\x00' * 16, b'\x00' * 16, b'\x00' * 16, b'\x00' * 16, b'\x00' * 16, 0) + struct.pack('<L', 0)

def BuildSector(Entries, Lowest, NextIndex):
	body = b''.join(Entries)
	body += EmptySlot() * (SLOTS_PER_SECTOR - len(Entries))
	assert len(body) == SECTOR_SIZE - FOOTER_SIZE
	return body + struct.pack('<LL8s', Lowest, NextIndex, b'\x00' * 8)

def BuildHeader(Machine):
	sector = bytearray(SECTOR_SIZE)
	sector[0:16] = HEADER_SIGNATURE
	struct.pack_into('<LLL', sector, 16, 65536, 1, 0)
	struct.pack_into('<LLL', sector, 28, 0, 0, 0)
	struct.pack_into('<16s16sQQQLLLLLLLLL', sector, 40, Machine.ljust(16, b'\x00'), VOLUME_A.bytes_le, 0, 0, 0, 0, 1, 0, 15, 0, 0, 15, 0, 0xFFFFFFFF)
	return bytes(sector)

def main(Path):
	base = datetime.datetime(2026, 3, 4, 5, 6, 7)
	minutes = lambda value: base + datetime.timedelta(minutes = value)
	records = [
		# Generation 0: a cross-volume notification, then a gap at index 2.
		(0, 0xFFFFFFFF, 1, MACHINE_A, OBJECT_IDS['alpha'], VOLUME_A, DROID_OBJECTS['alpha-birth'], VOLUME_A, DROID_OBJECTS['alpha-mid'], minutes(1)),
		(1, 0, 2, MACHINE_A, OBJECT_IDS['alpha'], VOLUME_A, DROID_OBJECTS['alpha-mid'], VOLUME_B, DROID_OBJECTS['alpha-end'], minutes(2)),
		# Index 2 is intentionally absent between the two surviving chain pieces.
		(3, 2, 4, MACHINE_A, OBJECT_IDS['alpha'], VOLUME_B, DROID_OBJECTS['alpha-end'], VOLUME_B, DROID_OBJECTS['alpha-end'], minutes(4)),
		# Duplicate of record 3 in another sector, later collapsed by content.
		(3, 2, 4, MACHINE_A, OBJECT_IDS['alpha'], VOLUME_B, DROID_OBJECTS['alpha-end'], VOLUME_B, DROID_OBJECTS['alpha-end'], minutes(4)),
		# A second machine begins a new generation with index 0.
		(0, 0xFFFFFFFF, 1, MACHINE_B, OBJECT_IDS['beta'], VOLUME_C, DROID_OBJECTS['beta-birth'], VOLUME_C, DROID_OBJECTS['beta-end'], minutes(5)),
	]

	sectors = []
	sectors.append(BuildSector([ Entry(*records[0]) ], 0, 1))
	sectors.append(BuildSector([ Entry(*records[1]) ], 1, 2))
	sectors.append(BuildSector([ Entry(*records[2]) ], 3, 4))
	sectors.append(BuildSector([ Entry(*records[3]) ], 3, 4))
	sectors.append(BuildSector([ Entry(*records[4]) ], 0, 1))

	# Sector 6 has been recycled: its footer declares an empty current window,
	# while an older notification still occupies the slot. Its DROID would look
	# like a plausible continuation, which is exactly why it must be excluded.
	stale = Entry(3, 2, 4, MACHINE_A, OBJECT_IDS['alpha'], VOLUME_B, DROID_OBJECTS['alpha-end'], VOLUME_C, DROID_OBJECTS['beta-birth'], minutes(30))
	sectors.append(BuildSector([ stale ], 0, 0))

	# Remaining sector is empty with a wrap marker in its footer.
	sectors.append(BuildSector([], 0xFFFFFFFF, 0xFFFFFFFF))

	data = BuildHeader(MACHINE_A) + b''.join(sectors)
	with open(Path, 'wb') as f:
		f.write(data)

if __name__ == '__main__':
	main(sys.argv[1] if len(sys.argv) > 1 else 'test_data/tracking_migration_small.log')
