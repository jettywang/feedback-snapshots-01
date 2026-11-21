##############
 Tool manifest
##############

Declare a set of pipx tools in one file and install, upgrade, or prune them as a unit with ``pipx manifest``.

*******************
 Write the manifest
*******************

The manifest is a ``pipx.toml`` file. Each dependency group holds one `PEP 508 <https://peps.python.org/pep-0508/>`__
package requirement and names its pipx environment. ``project.dependencies`` must be an empty list so each group
resolves on its own; pipx rejects the manifest otherwise:

.. code-block:: toml

    [project]
    name = "pipx-tools"
    version = "1"
    dependencies = []
    requires-python = ">=3.10"

    [dependency-groups]
    black = ["black>=25,<26"]
    httpie = ["httpie"]

    [tool.pipx]
    version = "1.0"

    [tool.pipx.tools.black]
    apps = ["black"]
    lock = "pylock.black.toml"

    [tool.pipx.tools.httpie]
    apps = ["http", "https"]

Add a ``tool.pipx.tools`` table only when a tool needs policy beyond its package requirement. A tool table may set
``suffix``, ``apps``, ``include-dependencies``, ``include-resources-from``, ``expose``, or ``lock``. Use
``include-resources-from = ["PACKAGE"]`` to select dependency resources; do not combine it with
``include-dependencies``. Relative ``lock`` paths start from the manifest directory. Put `nab
<https://pypi.org/project/nab/>`__ settings in ``tool.nab``.

Use the normalized package name plus its suffix as the environment name when a tool sets a suffix:

.. code-block:: toml

    [dependency-groups]
    black-24 = ["black==24.10.0"]

    [tool.pipx.tools.black-24]
    suffix = "-24"
    apps = ["black"]

Package requirements use PEP 508 syntax without environment markers.

******************
 Lock the manifest
******************

``nab`` resolves each locked dependency group into a `PEP 751 <https://peps.python.org/pep-0751/>`__ lock file.
Install it, then generate the declared locks:

.. code-block:: console

    $ pipx install nab
    $ pipx manifest lock ./pipx.toml

``pipx manifest lock`` passes the manifest to ``nab`` once per locked dependency group, and records that group as the
lock's default so installers select it. Existing locks seed their replacements, and pipx overwrites the declared files
only after every resolution succeeds. Entries without ``lock`` stay unlocked. ``pipx manifest lock`` refuses to run
when a ``lock`` path resolves outside the manifest directory, through ``..``, ``~``, an absolute path, or a symlink;
``pipx manifest sync`` still reads locks kept elsewhere.

*******************
 Apply the manifest
*******************

.. code-block:: console

    $ pipx manifest sync ./pipx.toml

``sync`` installs, upgrades, or downgrades each declared tool. The backend resolves unlocked specs on each run; locked
entries install from the artifacts in their named PEP 751 files. Under the `pip <https://pip.pypa.io/>`__ backend, a
locked entry needs pip 26.1 or newer; run ``pipx upgrade-shared`` when pipx reports an older one.

pipx restores an existing environment and its exposed resources when a tool fails to install, lacks a required app, or
the sync is interrupted. For an environment that already exists, ``sync`` keeps the installer and venv options recorded
at install time, such as ``--index-url`` or ``--system-site-packages``, the same way ``pipx reinstall`` does, and keeps
the apps, manual pages, and completions of its injected packages exposed.

Pass ``--prune`` to uninstall environments absent from the manifest. pipx skips pruning when any declared tool fails
to sync:

.. code-block:: console

    $ pipx manifest sync ./pipx.toml --prune

Without ``--prune``, sync leaves your other pipx environments alone. Pass ``--global`` (not available on Windows) or
``--backend`` after ``sync`` to select the pipx store or the installation backend. pipx reads only the manifest path you
supply on the command line.

*****************************
 Check locks against a policy
*****************************

An operator who installs tools for other people can require that every submitted lock be checked against a local
approval policy before pipx installs anything. Write the policy in a file the operator controls and pass it explicitly;
pipx never searches for one:

.. code-block:: toml

    # policy.toml
    version = "1"

    [[intent]]
    id = "ops-review-42"
    environment = "black"
    lock = "pylock.black.toml"
    approval = "review:ops-2026-11-19"
    packages = ["black==25.1.0", "click==8.3.2", "packaging==26.3", "pathspec==1.0.3", "platformdirs==4.5.1"]

Each ``intent`` is one approval: the manifest tool it covers (``environment``), the lock name it is bound to (optional
``lock``), the provenance a matching lock must declare (``approval``), and the exact package pins it approves. A lock
declares its provenance in a ``[tool.pipx]`` table with an ``approval`` key. A lock may also report ``created-by``, but
only ``[tool.pipx].approval`` can satisfy an intent, so a lock that names only its generator fails verification. Every
policy pin is an exact ``==`` version. A ``hashes`` table may pin the SHA-256 of an approved artifact per package.

Run the read-only stage first. It parses the manifest and every declared lock, names the intent each lock matched, and
lists any dependency left for a person to review without installing, unlocking, or exposing anything:

.. code-block:: console

    $ pipx manifest sync ./pipx.toml --policy ./policy.toml --verify

Passing ``--policy`` to a normal ``sync`` runs the same checks first and stops before the first lock, environment, or app
link is touched when any tool fails. The command exits ``1``, and with ``--output json`` reports the same envelope as a
failed sync. The verification holds every tool to the policy, so a tool that declares no lock fails rather than
bypassing the gate.

The check fails when a lock declares no approval source, declares a different source than its intent, is not a
lock format version 1 file, omits an approved package, names a version the intent or the manifest requirement does not
accept, references a package the lock does not contain, or selects a dependency absent from the intent. A marker on a
package that only involves the Python version is treated as selected, because the check runs on pipx's own
interpreter rather than the one the environment will use. A lock that is
otherwise approved but carries an extra dependency is reported as ``needs_review`` and names that dependency in both
``data.tools[].pending_review`` and the error message, so the reviewer sees exactly what to look at next. The
same JSON entry reports the lock's own ``approval`` and the ``source`` it names as its generator, so a reviewer can
tell an approved lock from one that only says what produced it.

A lock file whose ``[tool.pipx]`` table or policy is missing is not trusted by default: name the approval source in the
policy and in the lock, and keep both files where only the operator can write them.

**********
 Verify it
**********

.. code-block:: console

    $ pipx list --short

Each declared tool appears at the version its group resolved to.
