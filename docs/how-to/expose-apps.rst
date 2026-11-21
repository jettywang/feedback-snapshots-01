############
 Expose apps
############

Control which apps, manual pages, and shell completions an environment links onto your ``PATH``, without rebuilding
it.

************
 Hide an app
************

Use ``unexpose`` when another command with the same name should win, but you want to keep the environment:

.. code-block:: console

    $ pipx unexpose ansible

pipx removes the apps, manual pages, and shell completions recorded for that environment from its global directories.
Upgrade and reinstall keep it hidden, and injected apps stay hidden too.

***************
 Restore an app
***************

.. code-block:: console

    $ pipx expose ansible

pipx links each recorded app, manual page, and shell completion that is missing from its target directory, without
rebuilding the environment. Run it on an exposed environment to restore a link you deleted. When a file pipx does not
own already sits at a target path, pipx leaves it in place, links the rest, and exits with ``1``. Move that file away
and run ``pipx expose`` again to link the skipped resource.

*****************************
 Publish only selected entries
*****************************

A toolkit can add management or documentation commands in a new release, while ordinary users should see only the
commands in the configuration. ``--only-apps`` installs the package and all its dependencies as usual, then links only
the named entry points:

.. code-block:: console

    $ pipx install "toolbox==2.0" --only-apps toolbox

The environment still holds every entry point the package ships, so a later release can add one without changing what
your users can run. An entry that the package or a dependency ships under another selected name stays hidden, and the
selection also limits the manual pages and shell completions pipx links. pipx records the selection, so ``upgrade``,
``reinstall``, ``expose``, and ``pipx manifest sync`` keep publishing the same entries.

The install fails and rolls back when a selected app is missing. A failed upgrade, including one that only adds entry
points, leaves the existing environment and the commands users run in place. The list of installed files in the
environment and the commands on ``PATH`` stay separate, so ``pipx list`` shows the published entries rather than every
installed one.

``--only-apps`` applies one package spec at a time and cannot be combined with ``--include-deps`` or
``--include-resources-from``, because it already restricts those dependency resources. The manifest accepts the same
selection as ``only-apps = ["toolbox"]``.

***************************
 Expose a dependency's apps
***************************

pipx does not expose a dependency's apps by default; select them at install time.

``--include-deps`` exposes apps and manual pages from every dependency:

.. code-block:: console

    $ pipx install nox --include-deps

``--include-resources-from PACKAGE`` exposes resources from one dependency; repeat it to select more:

.. code-block:: console

    $ pipx install "nox[tox_to_nox]" --include-resources-from tox

pipx records the selection so upgrade and reinstall preserve it. The install fails and rolls back when a selected
package is not a dependency that ships apps, manual pages, or shell completions. Both options also work on
``pipx inject``; see :doc:`inject-packages`.

.. note::

    pipx renamed ``--include-apps-from`` to ``--include-resources-from``, and still reads the old name from metadata
    written by earlier versions.

**********
 Verify it
**********

.. code-block:: console

    $ pipx list

The exposed apps appear under their environment. Run one to confirm it resolves on your ``PATH``.
