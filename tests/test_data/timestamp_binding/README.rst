Timestamp binding test material
===============================

The three ``*.pem`` files are throw-away RSA private keys generated for the tests in
``tests/test_timestamp_binding.py``. They are not used by the library, not part of the
trust store, and only exist so that the tests can build independently valid
Authenticode signatures and RFC 3161 timestamp tokens without network access.
