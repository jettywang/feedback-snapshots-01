******************************************
 Keep services on different pip versions
******************************************

A pip-backed environment borrows ``pip`` from a shared libraries environment instead of shipping its own. When several
services must stay on different approved ``pip`` versions, give each service its own **shared profile**: a small,
separately upgraded environment with a written compatibility declaration. Upgrading one profile never touches another,
and an older environment keeps running the profile it recorded until you move it deliberately.

.. note::

    The uv backend needs no shared environment, so profiles apply only to pip-backed environments.

Declare a profile
=================

A declaration states the ``pip`` requirement the profile installs and, optionally, the Python it promises. Declaring
does not touch any environment, so existing services keep the ``pip`` they already run:

.. code-block:: console

    $ pipx profile declare legacy --requires 'pip>=26.1,<26.2' --python-requires '>=3.11'

Apply the declaration to create or upgrade the profile's environment. Only that profile changes:

.. code-block:: console

    $ pipx profile upgrade legacy

An upgrade whose ``pip`` pin falls outside the declaration is refused, so a single global fix cannot drag every service
forward. To cross the declaration on purpose, add ``--force``; pipx warns and records the override on the profile.

Link an environment to a profile
================================

Pass ``--profile`` when installing. The new environment records the profile and its ``pipx_shared.pth`` points at the
profile's site-packages:

.. code-block:: console

    $ pipx install --profile legacy my-service

An existing environment keeps the profile it recorded. ``pipx reinstall`` rebuilds it on the same profile; a
``--force`` install or an upgrade never switches it.

Review and reclaim
==================

List every profile with its declaration, recorded ``pip`` version, revision and the environments that reference it:

.. code-block:: console

    $ pipx profile list

When nothing references a profile any more, reclaim it. preview first with ``--dry-run``:

.. code-block:: console

    $ pipx profile reclaim legacy --dry-run
    $ pipx profile reclaim legacy

``pipx profile gc`` reclaims every unused non-default profile at once. The default profile is never reclaimed; use
``pipx reset`` to remove all of pipx's state.

Check
=====

``pipx profile list`` shows the profile with its requirement and ``used by`` entries. After you move every
environment off a profile, ``pipx profile gc --dry-run`` lists it and a real ``pipx profile gc`` removes its directory.

Profiles live beside the shared libraries, under ``$PIPX_HOME/shared.profiles/<name>``; each holds a
``shared_profile.json`` declaration. ``pipx environment --value PIPX_SHARED_PROFILES`` prints the directory.
