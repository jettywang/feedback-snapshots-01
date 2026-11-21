Memory: restore semantics for a managed recovery service
=========================================================

This note documents where py7zr restores archive permissions, what it asks the
kernel to apply, and where a managed recovery service should override that
behaviour.  Everything below was measured against this checkout on macOS
(``darwin``, CPython 3.12.11, APFS) with ``utils/perm_restore_probe.py``; the
probe prints the same facts on any POSIX host.  Section "Platform-dependent
conclusions" lists what must be re-measured elsewhere.

Where restoration happens
-------------------------

Permissions are restored in exactly one place: the post-processing loop at the
end of ``SevenZipFile._extract()`` in ``py7zr/py7zr.py``.

* The loop runs only for members that reached ``target_files``.  Regular files
  are added at ``py7zr/py7zr.py:773``; directories are added only when the
  destination path did not already exist (``py7zr/py7zr.py:762``).  Links,
  junctions and sockets are never added, so they are never chmod'ed.
* ``mtime`` is applied first with ``os.utime`` (``py7zr/py7zr.py:810``).
* On POSIX hosts, if the member carries the Unix extension, the archived mode
  is applied verbatim with ``Path.chmod(st_mode)`` (``py7zr/py7zr.py:811-815``).
  ``st_mode`` is ``stat.S_IMODE(a)`` of the raw extension
  (``py7zr/py7zr.py:259-267``), so it includes setuid, setgid and sticky bits.
* Otherwise, a Windows-only fallback clears the write bits when
  ``FILE_ATTRIBUTE_READONLY`` is set, and only for non-directories
  (``py7zr/py7zr.py:816-819``).
* When a ``WriterFactory`` is passed, the function returns before this loop
  (``py7zr/py7zr.py:802``), so nothing is chmod'ed and nothing is written to
  disk.

The Unix mode itself is encoded by ``MemberType.unix_extension_bits()``
(``py7zr/member.py:47-55``): bit 15 of ``attributes`` is the marker, bits 16+
carry ``S_IFMT|S_IMODE``.  Materialising in-memory members or members with no
``stat`` result gets ``0o600``, not the process umask
(``py7zr/member.py:14``, ``py7zr/member.py:65-69``).

Member classification, which decides whether a mode is applied at all, is
attribute-driven: ``is_directory`` and ``readonly`` only look at Windows bits
(``py7zr/py7zr.py:192-211``), while ``is_symlink`` and ``is_socket`` prefer the
Unix type bits (``py7zr/py7zr.py:226-251``).  ``is_file`` is the Unix regular
bit when the extension exists, otherwise "none of the above"
(``py7zr/py7zr.py:199-204``).

Boundary map
------------

Regular files
~~~~~~~~~~~~~

* POSIX + Unix extension: exact ``S_IMODE`` is requested, including special
  bits.  A pre-existing destination file is overwritten in place and then
  chmod'ed; there is no "create new inode" step.
* POSIX + Windows-only attributes: mode is whatever ``open(..., "wb")`` and
  ``Path.touch()`` produce under the process umask, then the read-only fallback
  may clear ``u+w,g+w,o+w``.
* A member with a Unix *directory* type bit but no Windows DIRECTORY bit is
  treated as a regular file and receives the directory's permission bits.
* A FIFO or character device type bit is likewise materialised as a regular
  file with those permission bits.  Sockets are skipped entirely
  (``py7zr/py7zr.py:767-768``).

Directories
~~~~~~~~~~~

* A directory member is created with ``mkdir(parents=True)`` at
  ``py7zr/py7zr.py:774-783``; its mode is applied later, in the post-processing
  loop.  Children are therefore created while the directory still has the
  umask-derived mode.
* If the directory path already exists, it is *not* added to ``target_files``
  and its mode is never touched (measured: pre-created ``0o700`` stays
  ``0o700``).  Its children are still chmod'ed.
* Implicit parents (directories implied by a member path but never stored as
  members) are created by ``Path.parent.mkdir()`` in the worker
  (``py7zr/py7zr.py:1745``) and follow the process umask.  With umask ``0o077``
  they came out as ``0o700``, and the leaf file as ``0o600``.
* A restrictive directory mode is applied before the next member's
  post-processing, so archive order matters.  ``d`` (``0000``) stored before
  ``d/f`` made ``os.utime`` fail with ``PermissionError`` at
  ``py7zr/py7zr.py:810``; the same two members in the reverse order extracted
  successfully and left ``d`` at ``0000``.  The tree is left unreadable either
  way.

Links
~~~~~

* POSIX symlinks are created with ``Path.symlink_to(target)``
  (``py7zr/py7zr.py:1759-1770``) after containment checks, and never chmod'ed.
  The link's own mode is the platform default (``lrwxr-xr-x`` = ``0o755`` under
  this host's umask), regardless of the mode stored in the archive.
* Windows junctions are handled separately, only on ``win32``
  (``py7zr/py7zr.py:1747-1758``) with ``_winapi.CreateJunction``.  On POSIX a
  junction-flagged member falls into the directory branch and becomes an empty
  directory; its target payload is not written.
* A pre-existing symlink at a member path is a real hazard: containment is
  checked against the resolved path, so an in-root link is followed.  The probe
  shows a pre-existing ``dest/f -> victim`` link being written *through* and
  then chmod'ed, changing ``victim`` to the archived mode.  A link pointing
  outside the root is rejected with ``Bad7zFile``
  (``py7zr/helpers.py:446-459``).

Custom output (``WriterFactory``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Directories and sockets are skipped; regular files, symlinks, FIFOs and
  character devices are all handed to ``factory.create()`` as byte streams
  (``py7zr/py7zr.py:754-760``).
* The factory sees the link target bytes, not a link.  The probe's factory
  received ``b"d/f"`` for a symlink member.
* No ``chmod``, ``utime`` or directory creation happens.  The probe recorded
  zero ``os.chmod`` calls and an empty destination tree.

Reference matrix (measured)
---------------------------

========================= ============== ============= ============================= ==========================
Member                    Archive mode   Requested     Result on this host           Note
========================= ============== ============= ============================= ==========================
regular file              ``0640``       ``0640``      ``0640``                      exact
regular file              ``0600``       ``0600``      ``0600``                      exact
directory                 ``0750``       ``0750``      ``0750``                      exact
setuid file               ``4755``       ``4755``      ``0755``                      kernel drops setuid
setgid directory          ``2775``       ``2775``      ``0775`` (probe)              kernel drops setgid
sticky directory          ``1777``       ``1777``      ``1777``                      preserved without privilege
symlink                   ``0711``       none          ``0755`` (lrwxr-xr-x)          link mode ignored
pre-existing directory    ``0755``       none          unchanged                     not in ``target_files``
pre-existing symlink      ``0600``       ``0600``      target ``0600`` + new data    link followed in-root
``FILE_ATTRIBUTE_READONLY`` only ``-``      ``0444``/``0644``                        umask-derived, write bits cleared
integrity-stream bit only ``-``       ``0000``      ``0000``                      bit 15 collides with Unix marker
socket                    ``0600``       none          no output                     skipped
FIFO / char device        ``0644``       ``0644``      regular file ``0644``          degraded
========================= ============== ============= ============================= ==========================

The integrity-stream row is a format collision worth calling out: on Windows,
``0x8000`` means ``FILE_ATTRIBUTE_INTEGRITY_STREAM``; py7zr reads the same bit
as the Unix-extension marker.  A Windows-produced archive that sets it without
a meaningful upper half produces ``posix_mode == 0`` and an extracted file with
mode ``0000``.  Treat "Unix extension present" as untrusted input.

What is safe to apply, and what to trim
---------------------------------------

Apply directly:

* Owner read/write bits and owner execute on directories.
* Group/other read and execute on data and directories when the site's tenant
  model matches the archived one.
* The read-only fallback for Windows-only archives, as a starting point.

Trim or rewrite by policy:

* setuid/setgid on files: never apply during unattended recovery.
* setgid on directories: it changes group inheritance for everything created
  beneath it, which is a site decision, not an archive decision.
* sticky on world-writable directories: only meaningful if the service also
  accepts world-writable directories, which it usually should not.
* group/other write: an upload channel should not be able to make recovered
  content mutably shared.
* modes that leave a directory unreadable or unsearchable by the service
  account (``0000``, ``0400``, ``0100`` on a directory): these break the
  service's own post-processing and later auditing.
* anything that is not a regular file, directory or symlink: skip rather than
  materialise.

Predictable restoration
-----------------------

The example in ``utils/restore_policy_example.py`` makes the result a function
of policy rather than of archive order:

1. **Pre-create the full skeleton.**  Enumerate every directory the archive
   implies (including implicit parents), create them with a restrictive mode
   such as ``0o700`` before extraction.  py7zr skips chmod for existing
   directories, so archive directory modes never take effect mid-extraction.
2. **Extract under a fixed umask** (``0o077`` in the example).  This pins the
   modes of any implicit parent or Windows-only member that py7zr leaves to
   ``open()``.
3. **Converge bottom-up.**  Remove links first, then chmod files deepest-first,
   then directories deepest-first, always with ``follow_symlinks=False``.  Never
   chmod a path you have not lstat'ed.

That example turns a hostile archive (``0000`` files, ``0777`` directories,
setuid, symlinks) into ``0750`` directories, ``0750`` executables under
``bin/`` and ``0640`` data files, with no links and no special bits.  Run it
with ``.venv/bin/python utils/restore_policy_example.py``.

Additional guardrails worth adding in the service, outside py7zr:

* Extract into a fresh directory that is not reachable by other tenants and
  contains no pre-existing symlinks; the in-root link-following result above is
  only exploitable when such links exist.
* Reject or normalise members whose ``attributes & 0x8000`` is set but whose
  upper half does not describe a plausible type, instead of letting
  ``posix_mode`` drive a chmod.
* Do not rely on ``extract(targets=..., recursive=True)`` as a containment
  boundary: it is a string-prefix match, so ``targets=["etc"]`` also selects
  ``etcpasswd`` and ``etc2/``.  Containment against the destination is enforced
  separately, but member selection is not a path boundary.
* Use ``WriterFactory`` for scanning or AV passes, and treat it as
  permission-free: it will not tell you what the archive would have restored.

Verification
------------

::

    .venv/bin/python utils/perm_restore_probe.py
    .venv/bin/python utils/restore_policy_example.py

Both create a temporary directory, print what they observed, and exit non-zero
on a policy or expectation failure.  ``--keep`` preserves the tree;
``--root DIR`` uses a caller-supplied directory.

Platform-dependent conclusions
------------------------------

These were measured here and must be re-checked on the recovery fleet's actual
target:

* **Special bits.** Linux and macOS both clear setuid/setgid on ``chmod`` by an
  unprivileged process, but the accepted sets differ by filesystem.  On this
  APFS host the Python ``os.chmod`` call returned success while the bits were
  silently dropped; a ``chmod(1)`` invocation returned ``EPERM`` instead.
  Sticky survived on a directory.  If the service runs as root, setuid/setgid
  *will* be applied, so the "trim special bits" rule must be enforced in
  policy, not left to the kernel.
* **Ownership.** py7zr never calls ``chown``; the recovered tree belongs to the
  service account.  Archives that relied on owner/group semantics will not
  reproduce them.
* **Symlink modes.** ``lchmod`` is not available on Linux, so the symlink mode
  is the creation default there too, but the exact default differs by umask and
  by filesystem.  Do not reason about link permissions; policy should remove
  links or accept them as-is.
* **Windows.** The entire POSIX branch (``os.name == "posix"``) is skipped.
  Only the read-only fallback runs, ACLs are not restored at all, and junctions
  are created with ``CreateJunction``.  A service running on Windows must not
  expect the Unix rows of the matrix above.
* **mount options.** ``noexec``, ``nosuid`` and read-only mounts change what is
  observable after extraction without changing what py7zr requested.  Record
  the mount flags alongside the probe output.
* **Filesystem type.** Some network or container filesystems refuse chmod or
  ignore mode bits; the probe's "requested" column would still show the archive
  mode.  Always compare requested with observed in the target environment.
