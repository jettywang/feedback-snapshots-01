=============================
oslopolicy-check-rule-sources
=============================

.. program:: oslopolicy-check-rule-sources

Synopsis
--------

::

  oslopolicy-check-rule-sources [-h] [--config-dir DIR] [--config-file PATH]
                                [--output-file OUTPUT_FILE]
                                [--exclude-deprecated [EXCLUDE_DEPRECATED]]
                                [--namespace NAMESPACE]
                                [--approved-overrides APPROVED_OVERRIDES]

Description
-----------

The ``oslopolicy-check-rule-sources`` tool audits the policy rules registered
by each plugin namespace before a generated configuration is handed to
operators for approval. It is a read-only check: it never writes a policy
file and never modifies an enforcer, so generating the report cannot apply
unapproved configuration.

The report lists:

* the registration sources, in the precedence order used to resolve
  duplicates (the first source registering a rule wins),
* the site-approved overrides, each traced back to the actual registrations
  for that rule,
* rules registered identically by more than one source, along with the
  adopted registration,
* rules registered with conflicting definitions (for example different
  check strings or different intended scopes), showing the differences, the
  adopted registration, the shadowed ones, and whether a site-approved
  override covers the conflict.

The tool exits with a non-zero status if a conflict has no site-approved
override or if an approved override refers to a rule that no source
registers, so it can gate configuration generation in CI.

Options
-------

.. include:: common/default-opts.rst

.. include:: common/generator-opts.rst

.. include:: common/rule-opts.rst

.. option:: --approved-overrides APPROVED_OVERRIDES

    Path to a YAML file listing the rule overrides approved by the site. The
    file must contain a top-level ``overrides`` mapping of rule name to
    either a plain check string or a mapping with ``check_str`` and,
    optionally, ``scope_types`` keys. Every entry is checked against the
    actual rule registrations and listed explicitly in the report.

Examples
--------

To check the rules registered by two plugins against the site-approved
overrides:

.. code-block:: bash

   oslopolicy-check-rule-sources --namespace plugin-a --namespace plugin-b \
       --approved-overrides /etc/mysite/approved-overrides.yaml

An approved overrides file looks like:

.. code-block:: yaml

   overrides:
     "compute:delete":
       check_str: "role:admin and project_id:%(project_id)s"
       scope_types: ["project"]
     "network:get_all": "role:reader"

For more information regarding the options supported by this tool:

.. code-block:: bash

   oslopolicy-check-rule-sources --help

See Also
--------

:program:`oslopolicy-sample-generator`, :program:`oslopolicy-policy-generator`,
:program:`oslopolicy-validator`
