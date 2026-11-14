Changelog
=========

Unreleased
~~~~~~~~~~

* Added a single startup configuration lifecycle for ``NoiseConnection``.
  After ``start_handshake()`` the protocol name, prologue, role, PSKs and
  pre-message keypairs are frozen; further attempts raise
  ``NoiseConfigurationFrozenError``.
* Added ``NoiseConnection.validate()``, ``startup_configuration``,
  ``startup_digest`` and ``audit_configuration()``.
* Added ``noise.negotiation.NegotiationRecord`` and ``negotiate()``. Records
  encode both parties' choices and offer lists with unambiguous length-prefixed
  fields and are bound into the effective prologue.
* Failed startup validation no longer consumes PSKs and leaves the connection
  retryable. Caller-owned PSK lists and byte strings are copied.

.. _v0-3-1:

0.3.1 - 2020-03-03
~~~~~~~~~~~~~~~~~~

* Fixed deprecation warnings and/or breakage for 448/25519 due to Cryptography changes - contributed by @warner
* Bumped required Cryptography to 2.8
* CI/CD testing added for Python 3.8
      
.. _v0-3-0:

0.3.0 - 2019-02-24 
~~~~~~~~~~~~~~~~~~

* Added support for non-default crypto backends
* Loosened restriction on Cryptography version in requirements.txt and bumped version to 2.5
* Moved away from custom x448 implementation in favor of OpenSSL implementation (for default backend)   

.. _v0-2-2:

0.2.2 - 2018-03-21
~~~~~~~~~~~~~~~~~~

* Loosened restrictions on Python and Cryptography in setup.py - contributed by @warner
* Cryptography version required bumped to 2.1.4


.. _v0-2-1:

0.2.1 - 2017-11-04
~~~~~~~~~~~~~~~~~~

* Cryptography updated to 2.1.3 due to OpenSSL vulnerability fix


.. _v0-2-0:

0.2.0 - 2017-11-01
~~~~~~~~~~~~~~~~~~

* Compatible with revision 33 (doesn't break compatibility with revision 32).
* Cryptography requirement updated to the newest version (2.1.2) - **Python 3.5** is supported again.
* Adding sphinx documentation for Read the Docs publication and README update
* Renamed NoiseBuilder to NoiseConnection
* Minor fixes for better performance.


.. _v0-1-0:

0.1.1 - 2017-09-12
~~~~~~~~~~~~~~~~~~

Initial release.
