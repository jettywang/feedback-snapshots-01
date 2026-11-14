.. noiseprotocol documentation master file, created by
   sphinx-quickstart on Sun Oct  8 01:15:26 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to noiseprotocol's documentation!
=========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:


Documentation for the Code
**************************

Configuration lifecycle
=======================

A :class:`noise.connection.NoiseConnection` has one startup configuration per
connection. All setup happens before ``start_handshake()``:

* ``NoiseConnection.from_name()`` fixes the protocol name and its pattern and
  crypto functions. The name cannot be replaced later.
* ``set_prologue()``, ``set_psks()``, ``set_as_initiator()`` /
  ``set_as_responder()`` and the keypair setters may be called any number of
  times before startup. The last value wins.
* ``validate()`` performs the same checks as ``start_handshake()`` without
  consuming PSKs or changing any state.
* ``start_handshake()`` validates, snapshots, freezes and then initialises the
  handshake. It may succeed once. A validation failure leaves the connection
  usable, unchanged and retryable. A failure after freezing rolls the
  configuration back.

After startup the effective protocol name, prologue, role, PSKs and
pre-message keypairs cannot be changed, either through ``NoiseConnection``
setters or directly through ``NoiseConnection.noise_protocol``. Attempts raise
:class:`noise.exceptions.NoiseConfigurationFrozenError`.

Caller-owned inputs retain independent ownership. PSK lists and byte strings
are copied by the setters, and the startup snapshot keeps its own copies.

Auditable startup configuration
-------------------------------

``start_handshake()`` returns a
:class:`noise.configuration.StartupConfiguration` snapshot, also available as
``connection.startup_configuration``. It records the protocol name, role,
application prologue, the effective prologue that entered the handshake hash,
PSKs, public pre-message keys, and the pre-handshake negotiation record.

``connection.audit_configuration()`` renders that snapshot as a dictionary.
PSKs appear as SHA-256 digests, not raw bytes. The record remains available
after ``handshake_done()`` and its ``configuration_digest`` does not change
during the handshake.

Negotiation records
-------------------

When a protocol is chosen from prior negotiation, build a
:class:`noise.negotiation.NegotiationRecord` and pass it to
``set_negotiation_record()`` before ``start_handshake()``. Use
``noise.negotiation.negotiate()`` on both peers with the same role-labelled
offer lists to derive byte-identical records.

The record encodes, with explicit length prefixes, both parties' choices and
both parties' complete offer lists. It is bound into the effective prologue
before the application prologue, so both endpoints confirm the same
negotiation transcript. If one side uses a different record, the prologues
differ and the real handshake fails authentication.

.. automodule:: noise.state
   :members:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
