Add :ref:`reuse_built_package`, :ref:`build_approvals_file`, and :ref:`build_provenance_dir` to PEP-517 packaging
environments, so a package built from the same source for the same target can be reused only while its build dependency
versions and approval records still match. Every build leaves a provenance document with the resolved build dependency
versions and approvals beside each artifact and in the ``--result-json`` journal.
