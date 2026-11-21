======================
oslopolicy-reachability
======================

.. program:: oslopolicy-reachability

Synopsis
--------

::

  oslopolicy-reachability --policy-file <policy.yaml>
  oslopolicy-reachability --namespace <namespace>

Description
-----------

The ``oslopolicy-reachability`` tool performs a read-only reachability check of
the policy graph. Starting from the policies that back API actions (the
*registered* rules), it follows every ``rule:`` reference and reports:

* which rules are actually reachable from a registered action;
* reachable actions that are explicitly disabled with the ``!`` check;
* historical names kept as deprecated aliases;
* rules that are defined but not referenced by any action (advisory only);
* blocking problems: references to undefined rules and cyclical references.

The check is read-only. It never evaluates credentials, loads additional
files, or mutates the enforcer, so it is safe to run before publishing an
authorization configuration.

Two kinds of problems are treated as release blockers and make the tool exit
with a non-zero status, because they break policy evaluation at runtime:

* a ``rule:`` reference to a rule that is not defined (not registered, not in
  the policy file, and not kept as a deprecated alias);
* a chain of ``rule:`` references that forms a cycle.

For each blocking problem the full action chain that introduces it is printed,
for example ``service:action -> service:helper -> rule:missing``. Rules that
are merely unreachable are never a failure; historical names retained for
backwards compatibility commonly fall into that group.

Options
-------

.. option:: --policy-file POLICY_FILE

    Path to a standalone YAML policy file to analyze. Every policy in the file
    is treated as a registered action (a traversal root).

.. option:: --namespace NAMESPACE

    Option namespace under ``oslo.policy.enforcer`` in which to look for a
    ``policy.Enforcer``. When used, roots are the policies the service
    actually registers in code, including deprecated aliases.

.. option:: --quiet

    Only print blocking issues, suppressing the reachable and unreachable
    advisory sections.

.. option:: -h, --help

    Show help message and exit.

Examples
--------

Check a policy file before publishing it:

.. code-block:: bash

   oslopolicy-reachability --policy-file /etc/myapp/policy.yaml

Output when a broken and a cyclical reference are present::

   Blocking issues found: 2
     [undefined] action "service:broken": service:broken -> rule:does_not_exist
     [cycle] action "service:loop_a": service:loop_a -> service:loop_b -> rule:service:loop_a

   Reachable from 4 registered action(s): 4 rule(s).
   ...

A clean configuration exits ``0`` and reports no undefined or cyclical
references; any unreachable rules are listed as advisory information only.

See Also
--------

:program:`oslopolicy-validator`
