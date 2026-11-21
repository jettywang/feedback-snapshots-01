######################
 Manage installed apps
######################

List, upgrade, and remove the apps pipx manages, then confirm each change.

**********
 List apps
**********

.. code-block:: console

    $ pipx list

The output shows each package version, its apps, and the environment paths. Narrow or reshape it:

- ``pipx list --short`` prints package names and versions only.
- ``pipx list --include-injected`` also lists packages injected into each environment.
- ``pipx list --outdated`` lists environments with an available upgrade.
- ``pipx list --pinned`` lists pinned environments only.

************
 Upgrade one
************

.. code-block:: console

    $ pipx upgrade black

Add ``--include-injected`` to upgrade injected packages alongside the main app. Pass ``--install`` to install the
package spec when it is missing rather than error.

pipx exposes any apps, manual pages, and shell completions the new version adds, and removes the ones it no longer
ships, so ``pipx list`` and ``PIPX_BIN_DIR`` match the upgraded package. ``upgrade-all`` and ``pipx install --upgrade``
do the same.

Verify:

.. code-block:: console

    $ pipx list --short

************
 Upgrade all
************

.. code-block:: console

    $ pipx upgrade-all

Use ``--skip PKG ...`` to leave named environments untouched, and ``--include-injected`` to include injected packages.
pipx skips pinned environments; see :doc:`pin-packages`.

pipx upgrades up to eight environments at once and prints their output in environment order, as a one-at-a-time run
would. An app, manual page, or completion that several environments expose ends up with the same environment as in a
one-at-a-time run. A failed environment does not stop the others. `pip <https://pip.pypa.io/>`__ and `uv
<https://github.com/astral-sh/uv>`__ cannot prompt for input, such as index credentials, during any pipx command other
than ``pipx runpip``. Pass ``--verbose`` to upgrade them one at a time.

Ctrl-C, ``SIGTERM`` or ``SIGHUP`` stops pipx from starting more upgrades, and pipx finishes the ones already in progress
before it exits, since an upgrade cut short leaves an environment with a mix of old and new files. Press Ctrl-C again to
stop those too. pipx then reports each environment it stopped mid-upgrade, ``pipx list`` flags it, and the next ``pipx
upgrade-all``, ``pipx upgrade`` or ``pipx reinstall`` of it reinstalls it from its metadata. With ``--verbose`` the
first Ctrl-C already stops the running upgrade.

Verify:

.. code-block:: console

    $ pipx list --outdated

**************
 Uninstall one
**************

.. code-block:: console

    $ pipx uninstall black

pipx deletes the environment and unlinks its apps, manual pages, and shell completions. It only reclaims an exposed
entry it can still prove the environment owns: a link that resolves into the environment, a dangling link that names
it, or a copy whose shebang or bytes match the recorded file. An entry an operator repointed to another environment, a
file replaced by hand, and a copy another environment's metadata claims are left in place, because deleting them would
take away something this uninstall no longer owns.

Preview the decision first with ``--dry-run``:

.. code-block:: console

    $ pipx uninstall black --dry-run

The preview prints one line per exposed entry with the evidence pipx found and whether it would remove or keep the
entry, without changing anything. ``--output json`` reports the same evidence in the ``evidence`` list, with
``would_remove`` and ``retained`` naming the paths either way. The real uninstall re-checks each entry immediately
before unlinking it, so an entry repointed to another environment after the preview is kept.

Verify:

.. code-block:: console

    $ pipx list --short

**************
 Uninstall all
**************

.. code-block:: console

    $ pipx uninstall-all

Record what you have first with ``pipx list --short`` if you plan to reinstall later.

Verify:

.. code-block:: console

    $ pipx list

**************
 Reinstall one
**************

Rebuild an environment from its recorded metadata, keeping the same options as the original install. Reach for it after
a Python upgrade or to repair a broken environment.

.. code-block:: console

    $ pipx reinstall black

Pass ``--python`` to rebuild under another interpreter. ``pipx install --force`` keeps the environment's interpreter
and ignores ``--python``.

Verify:

.. code-block:: console

    $ pipx list --short

**************
 Reinstall all
**************

.. code-block:: console

    $ pipx reinstall-all

Run it after installing a new Python version so every app moves to it. Use ``--python`` to target a specific
interpreter and ``--skip PKG ...`` to exclude environments.

pipx rebuilds up to eight environments at once (fewer on machines with fewer CPUs) and holds back the output of each
until the ones before it finish, so it reads the same as a one-at-a-time run. Resources that several environments
expose, failed environments and credential prompts work as described for ``upgrade-all`` above. Pass ``--verbose`` to
rebuild them one at a time and watch the pip or uv output as it happens.

Ctrl-C, ``SIGTERM`` or ``SIGHUP`` stops the rebuilds in progress and restores each of those environments from its
backup; the environments already rebuilt keep their new build.

Verify:

.. code-block:: console

    $ pipx list

.. tip::

    To check environments without changing them, or to repair only the broken ones, see :ref:`repair-environments`.
