from __future__ import annotations

from dissect.cstruct import cstruct

# References:
#   - https://veracrypt.jp/en/Encryption%20Scheme.html
#   - https://veracrypt.jp/en/VeraCrypt%20Volume%20Format%20Specification.html
#   - https://github.com/veracrypt/VeraCrypt/blob/master/src/Volume/VolumeHeader.h
veracrypt_def = """
struct VolumeHeader {
    // char     salt[64];
    char        magic[4];           // b"VERA"
    uint16      version;
    uint16      client_version;
    char        crc32[4];           // CRC32 checksum of bytes 256-511
    char        reserved_1[16];     // 16 * 0x00
    uint64      hidden_volume_size;
    uint64      volume_size;
    uint64      mk_scope_offset;    // offset in bytes of master key scope
    uint64      mk_scope_size;
    uint32      flags;              // bit 0 = system_encryption
                                    // bit 1 = non-system in-place encrypted/decrypted volume
                                    // bit 2-31 = reserved
    uint32      sector_size;
    char        reserved_2[120];    // 120 * 0x00
    char        crc32_decrypted[4]; // CRC32 checksum of decrypted bytes 64-251
    char        master_keys[256];   // concatenated primary and secondary master keys
};
"""

c_veracrypt = cstruct(endian=">").load(veracrypt_def)

TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET = (63 - 1) * 512  # 31744

# Ranges within the 512-byte decrypted header (which directly follows the 64-byte salt).
HEADER_CRC32_RANGE = slice(0, 188)  # absolute bytes 64-251: the header fields
KEY_AREA_CRC32_RANGE = slice(192, 448)  # absolute bytes 256-511: the master key area

# Supported VolumeHeader.version range (VeraCrypt 1.x writes version 5).
VOLUME_HEADER_VERSION_MIN = 1
VOLUME_HEADER_VERSION_MAX = 5

# Sector size must be a power of two within this range.
SECTOR_SIZE_MIN = 512
SECTOR_SIZE_MAX = 8192
