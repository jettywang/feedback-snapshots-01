Coverage-analysis fixtures
==========================

These are synthetic, self-signed PE32+ files generated solely for
``tests/authenticode/test_pe_coverage.py``. They are not malware and are not
executed. The signing key was generated temporarily for this fixture set; the
matching self-signed certificate is ``selfsigned.pem`` and is used as the local
trust anchor.

All files share the same header, one ``.text`` section at file offset ``0x200``
and a certificate table at ``0x400``.

==========================================  ============================================
File                                        Layout
==========================================  ============================================
``minimal_signed.exe``                      certificate table ends exactly at EOF
``minimal_signed_slack.exe``                0x20 bytes of declared table slack at EOF
``minimal_signed_table_extended.exe``       0x40 bytes of appended data absorbed as
                                            declared table slack; a further 0x40 bytes
                                            are appended after the declared table
``minimal_signed_post_table_overlay.exe``   0x40 bytes after the declared table, thus
                                            inside Signify's hashed tail range
``minimal_signed_extra_entry.exe``          a second, non-PKCS#7 WIN_CERTIFICATE entry
                                            inside the declared certificate table
``minimal_signed_section_gap.exe``          two sections with a 0x200-byte gap between
                                            them; the gap is inside the digest
==========================================  ============================================

The certificate table starts at ``0x400`` in most files (``0xA00`` in the
section-gap fixture); each file's declared size is recorded in the data-directory
entry at ``0xE8``. The four-byte optional-header checksum field is at ``0x98``.
Section raw data starts at ``0x200`` in the single-section fixtures, and at ``0x400``
in the section-gap fixture.
