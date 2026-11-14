# API

The in-toto API provides various functions and {doc}`classes <model>` that you
can use to generate, consume, modify and verify in-toto metadata, as a more
feature-rich, programmable alternative to the {doc}`command line tools
<command-line-tools/index>`.

```{admonition} Cryptographic Signatures
:class: tip

in-toto metadata is signed with cryptographic keys via the *Signer API*
in [securesystemslib](https://github.com/secure-systems-lab/securesystemslib)
Please refer to its [documentation](https://python-securesystemslib.readthedocs.io/en/latest/signer.html)
for details about loading a `Signer` for "Evidence Generation".

Loading verification keys for "Supply Chain Verification" is
documented [in-toto#663](https://github.com/in-toto/in-toto/issues/663).
```

## Evidence Generation

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_run
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_start
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_stop
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_match_products

```

## Supply Chain Verification

```{eval-rst}
.. autofunction:: in_toto.verifylib.in_toto_verify
```

### Evidence Index

An optional evidence index locates link metadata and sublayout evidence by
step name and full functionary keyid. It is useful when authorized
functionaries share the eight character keyid prefix used by traditional
filenames. An index is a location hint only: it does not authorize keys, and
payload, signature and step bindings are still verified.

```{eval-rst}
.. autoclass:: in_toto.evidence_index.EvidenceIndex
  :members: load, from_dict, entries_for_step, entry_for, link_path, sublayout_path, validate_for_layout
```

```{eval-rst}
.. autoexception:: in_toto.exceptions.EvidenceIndexError
```
