beacon-dump
===========

You can use the command ``beacon-dump`` to dump configuration from Cobalt Strike beacon paylaods.

If the command is not in your path, you can also use run the command using the following Python module:

.. code-block:: bash

   $ python -m dissect.cobaltstrike.beacon --help

XOR keys
--------
The beacon configuration is usually obfuscated using a single-byte XOR key. ``beacon-dump`` automatically tries all the default xor keys (``0x69`` and ``0x2e``).

In case a beacon uses a non default XOR key you can specify the ``-a`` or ``--all-xor-keys`` argument to check all possible single byte XOR keys.
Note that this option is not recommended for large payloads such as memory dumps.

You can also use the ``-x`` or ``--xorkey`` option to specify a known XOR key or a set of keys by repeating the argument:

.. code-block:: bash

   $ beacon-dump -x 0xAC -x 0xCE -x 0x55 -x 0xED <beacon-file>

Output format
-------------

The output format can be specified using the ``-f`` or ``--format`` option. The following formats are supported:

   - ``normal``: output the beacon configuration in a human readable format of key value pairs (default)
   - ``dumpstruct``: output the beacon settings using ``cstruct.dumpstruct``
   - ``c2profile``: output the beacon configuration as a malleable C2 profile
   - ``raw``: output the raw beacon configuration

Configuration normalization
----------------------------

Some beacons are built with a modified ``SettingsType`` enum so that the type numbers stored in the
configuration no longer match the stock values (``TYPE_SHORT=1``, ``TYPE_INT=2``, ``TYPE_PTR=3``).
``beacon-dump`` normalizes these blocks before parsing. Normalization never mutates the observed input;
use ``--normalize-report`` to print an auditable, reproducible account of every decision:

.. code-block:: bash

   $ beacon-dump --normalize-report <beacon-file>

Each reported line identifies the setting header offset, the type number the sample *actually declared*,
the normalized type number (never presented as the originally declared number), the evidence class and the
normalizer that made the decision. Three evidence classes are used:

   - ``stock``: a known beacon setting and its stock setting type support the mapping,
   - ``length``: only the value-length heuristic (2, 4 or more than 4 bytes) supports the mapping,
   - ``unknown``: the observed type number cannot be confirmed. Its original bytes are retained and the
     field is listed under unconfirmed types instead of being guessed.

When more than one normalizer proposes a different type for the same field, the contradiction is reported
as a conflict and the original bytes are kept. The report also contains the SHA-256 hash of the original
input block, so two samples that differ only in their type enum mapping can be compared: their normalized
blocks and semantic values are equal while their original hashes remain distinct.

The same information is available from the API on
:attr:`BeaconConfig.modifications <dissect.cobaltstrike.beacon.BeaconConfig.modifications>`, see
:class:`BeaconModifications <dissect.cobaltstrike.beacon.BeaconModifications>` and
:meth:`BeaconModifications.explain() <dissect.cobaltstrike.beacon.BeaconModifications.explain>`.

.. sphinx_argparse_cli::
  :module: dissect.cobaltstrike.beacon
  :func: build_parser
  :prog: beacon-dump
