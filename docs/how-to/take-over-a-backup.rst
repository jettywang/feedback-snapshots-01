##############################
 Take over a venv from a backup
##############################

Adopt a virtual environment directory that pipx did not install, such as one restored after a disaster, without
trusting its contents. ``pipx takeover`` first copies the backup into a quarantine outside the managed environments,
reads it without running its interpreter, and exposes nothing. Only ``pipx takeover approve`` moves it into
``$PIPX_HOME/venvs`` and links the commands that verified.

.. warning::

    Treat a backup as untrusted input. ``pipx takeover`` never runs the backup's interpreter, never replays its
    ``pipx_metadata.json``, and never writes into ``$PIPX_BIN_DIR`` before approval. Run ``check`` and read its output
    before you approve.

**********
 Workflow
**********

.. code-block:: console

    $ pipx takeover stage /media/usb/demo-venv --source "tape 2026-11-18, host db01"
    demo: staged in quarantine at /home/me/.local/share/pipx/quarantine/demo from tape 2026-11-18, host db01
    demo: would expose demo
    demo: review it with 'pipx takeover check demo', then approve it

    $ pipx takeover list
    demo (demo 1.0): 1 verified app(s), 0 man page(s) from tape 2026-11-18, host db01

    $ pipx takeover check demo
    demo (demo 1.0): 1 verified app(s), 0 man page(s) from tape 2026-11-18, host db01
    demo: would expose demo
    demo: ready; approve it with 'pipx takeover approve demo'

    $ pipx takeover approve demo
    demo: taken over from quarantine
    demo: exposed demo

``stage`` copies the directory (the original backup is left untouched) and records who supplied it. ``--name`` picks
the environment name when the backup cannot supply one. ``list`` shows every staged environment with its provenance.
``check`` re-reads the staged copy and reports exactly which apps and man pages approval would link. ``approve``
re-verifies, moves the environment into the managed store, rewrites a launcher's ``#!`` line to the adopted
environment's interpreter, and writes fresh pipx metadata. ``remove`` deletes a staged copy without exposing anything.

************************
 What verification means
************************

The preflight is static: it reads distribution metadata, ``entry_points.txt`` and launcher bytes, and never starts the
backup's Python. An app verifies when its distribution declares a console or GUI entry point **and** its launcher is a
regular file inside the environment. A launcher whose ``#!`` line names a Python interpreter outside the environment is
accepted as a launcher to repair, because the original machine's path is expected in a portable backup; one that names
a non-Python program outside the environment is refused. A man page verifies when it is a regular file under a
``share/man/manN`` section.

Approval refuses an environment that:

- lacks ``pyvenv.cfg`` or its interpreter, so it is not a virtual environment;
- records no package name, or names a package that does not match the environment name;
- declares none of its apps, so approving it would expose nothing.

A digest of the staged tree is recorded at staging time. Editing the staged copy afterwards makes ``check`` and
``approve`` fail until you remove it and stage the backup again, so approval always applies to what you reviewed.

**************************
 Unverified and missing content
**************************

The check output distinguishes three cases:

- **Declared but missing** — an entry point names an app whose launcher is gone. It is reported as not exposed.
- **Unowned** — a file in the environment's ``bin`` directory that no distribution claims. It is never exposed.
- **Unreadable metadata** — with the record gone, pipx infers the package only when the environment holds exactly one
  distribution; otherwise pass ``--name``.

Both cases leave the environment approvable: only the verified entry points become commands. A name that already
exists in ``$PIPX_BIN_DIR`` under an unowned file stays in place, ``approve`` reports the collision as a partial
result, and exits ``1``.

************************
 The backup's own record
************************

``pipx_metadata.json`` in the backup is treated as a claim, not as instructions. pipx reads only the package name,
version and Python version from it; it does not replay recorded ``pip_args``, exposure settings, suffixes, or
injected-package records. The adopted environment gets a fresh record listing only what verification confirmed. A
backup without the file is still staged when its distribution metadata or ``--name`` names the package.

*********
 Cleanup
*********

``pipx takeover remove NAME`` deletes a staged environment. A backup that fails verification stays in quarantine until
it is removed, so a rejected transfer is never silently adopted. ``pipx environment --value PIPX_QUARANTINE_DIR``
prints the quarantine location.
