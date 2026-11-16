beacon-guardrails
=================

The command ``beacon-guardrails`` correlates Beacon Guardrails candidates in a payload with
the Beacon configuration they protect. It is intended for analysis and triage: it reports
every candidate it can find, the patch size used for each, the decoding material and the
checksum evidence, instead of accepting the first magic-value hit.

.. code-block:: bash

   $ beacon-guardrails <beacon-file>

If the command is not in your path, you can also run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.guardrails --help

Candidate model
---------------

A Guardrails block is located by its masked signature. For each hit, the supported Beacon
configuration patch sizes (``0x1800`` since Cobalt Strike 4.9 and ``0x1000`` before that) are
tried independently. Every ``(guard_config_offset, patch_size)`` pair is a separate candidate,
so a single Guardrails block can produce more than one candidate. The patch size determines
which raw bytes are treated as the guarded Beacon configuration.

For each candidate the tool reports:

 - the Guardrails signature offset, guard configuration offset, derived Beacon offset and patch size
 - the single-byte Guardrails and Beacon XOR keys used for decoding
 - the parsed Guardrails settings, including a declared ``GUARD_PAYLOAD_CHECKSUM``
 - SHA-256 digests and short hex previews of the masked and unmasked buffers

Correlation
-----------

The Guardrails checksum is recomputed from the raw Beacon patch using the candidate's payload
XOR key. A candidate is only reported as ``confirmed`` when a key reproduces the declared
checksum exactly. Note that the checksum can be reproduced by a repeated form of a short key;
the tool groups keys that yield identical plaintext and records the shortest equivalent key,
so key enumeration order does not affect the result.

Candidates are sorted by offset and patch size before correlation. Reordering the input
candidates therefore does not change the reported evidence or the confirmed association.
When more than one distinct interval confirms, or when more than one distinct plaintext
reproduces the same checksum, the report is marked ``ambiguous`` and no single candidate is
reported as resolved.

Status values
-------------

 - ``confirmed``: the declared checksum was reproduced from the raw interval.
 - ``checksum_mismatch``: the settings parsed, but no payload key reproduced the checksum.
 - ``no_checksum``: the Guardrails block parsed but declares no ``GUARD_PAYLOAD_CHECKSUM``.
 - ``parse_error``: the unmasked Guardrails block could not be parsed as settings.
 - ``missing_interval``: the Beacon patch interval lies outside the payload.
 - ``truncated_adjacent_block``: the Beacon patch is present but the adjacent Guardrails patch is truncated.

Guardrail options such as the computer name or domain are sample declarations only. The
report deliberately does not assert that a victim host satisfies them.

.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.guardrails
  :func: build_parser
  :prog: beacon-guardrails
