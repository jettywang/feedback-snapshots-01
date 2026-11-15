
.. _type.schema:

Schema ambiguity precheck
-------------------------

Before feeding untrusted network input to a decoder, it is worth knowing
whether the schema itself lets one wire tag map to more than one field. The
:ref:`SchemaPrecheck <schema.SchemaPrecheck>` walks an already-constructed
schema graph and reports those ambiguities without decoding any bytes and
without instantiating a value.

Two kinds of findings are produced:

* a :ref:`TagConflict <schema.TagConflict>` marks a *deterministic* collision,
  where two concrete fields accept the same on-the-wire tag in the same
  decoding window. SEQUENCE optional/default windows, SET, nested untagged
  CHOICE and explicit/implicit tagging are all taken into account;
* an :ref:`OpenTypeFinding <schema.OpenTypeFinding>` marks an open type
  (ANY / ANY DEFINED BY) whose concrete type is chosen from runtime context.
  Such a field is never judged statically safe.

Recursive references terminate the walk, while a type legitimately shared by
several parents is reported at every parent path rather than mistaken for a
cycle.

.. code-block:: python

   from pyasn1.type import univ, namedtype
   from pyasn1.type.schema import precheck

   class Ambiguous(univ.Sequence):
       componentType = namedtype.NamedTypes(
           namedtype.OptionalNamedType('first', univ.Integer()),
           namedtype.NamedType('second', univ.Integer()))

   for finding in precheck.precheck(Ambiguous()):
       print(finding.severity, finding.path, finding.rationale)

Each deterministic conflict can be turned into concrete evidence.
:ref:`build_evidence <schema.build_evidence>` returns the smallest BER
substrate the conflicting fields both claim, together with a control encoding
in which one field is given a distinct legal tag so the same payload routes
deterministically. The evidence is built on cloned schemas; the original
schema is never modified.

.. code-block:: python

   from pyasn1.type.schema import precheck_evidence

   schema = Ambiguous()
   for conflict in precheck.SchemaPrecheck(schema).conflicts:
       evidence = precheck_evidence.build_evidence(schema, conflict)
       print(evidence.ambiguousHex, evidence.controlHex)

.. toctree::
   :maxdepth: 2

   /pyasn1/type/schema/precheck
   /pyasn1/type/schema/precheck_evidence
