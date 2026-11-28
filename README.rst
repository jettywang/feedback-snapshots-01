auditwheel
==========

.. image:: https://travis-ci.org/pypa/auditwheel.svg?branch=main
    :target: https://travis-ci.org/pypa/auditwheel
.. image:: https://badge.fury.io/py/auditwheel.svg
    :target: https://pypi.org/project/auditwheel
.. image:: https://pepy.tech/badge/auditwheel/month
    :target: https://pepy.tech/project/auditwheel/month

Auditing and relabeling of Linux and Android wheels.

Overview
--------

``auditwheel`` is a command line tool to facilitate the creation of Python
`wheel packages <http://pythonwheels.com/>`_ (containing pre-compiled
binary extensions) that are compatible with a wide variety of distributions,
consistent with the `PEP 600 manylinux_x_y
<https://www.python.org/dev/peps/pep-0600/>`_, `PEP 513 manylinux1
<https://www.python.org/dev/peps/pep-0513/>`_, `PEP 571 manylinux2010
<https://www.python.org/dev/peps/pep-0571/>`_, `PEP 599 manylinux2014
<https://www.python.org/dev/peps/pep-0599/>`_ and `PEP 738 android
<https://www.python.org/dev/peps/pep-0738/>`_ platform tags.

``auditwheel show``: shows external shared libraries that the wheel depends on
(beyond the libraries included in the ``manylinux`` policies), and
checks the extension modules for the use of versioned symbols that exceed
the ``manylinux`` ABI.

``auditwheel repair``: copies these external shared libraries into the wheel itself,
and automatically modifies the appropriate ``RPATH`` entries such that these libraries
will be picked up at runtime. This accomplishes a similar result as if the libraries had
been statically linked without requiring changes to the build system. Packagers are
advised that bundling, like static linking, may implicate copyright concerns.

Requirements
------------
- OS: Linux (for Android wheels, macOS may also be used)
- Python: 3.11+
- `patchelf <https://github.com/NixOS/patchelf>`_: 0.14.5+

Only systems that use `ELF
<https://en.wikipedia.org/wiki/Executable_and_Linkable_Format>`_-based linkage
are supported (this should be essentially every Linux).

In general, building ``manylinux1`` wheels requires running on a CentOS5
machine, building ``manylinux2010`` wheels requires running on a CentOS6
machine, and building ``manylinux2014`` wheels requires running on a CentOS7
machine, so we recommend using the pre-built manylinux `Docker images
<https://quay.io/repository/pypa/manylinux_2_28_x86_64>`_, e.g. ::

  $ docker run -i -t -v `pwd`:/io quay.io/pypa/manylinux_2_28_x86_64 /bin/bash

Installation
------------

``auditwheel`` can be installed using pip:

.. code:: bash

  $ pip3 install auditwheel

Examples
--------

Inspecting a wheel: ::

    $ auditwheel show cffi-1.5.0-cp35-cp35m-linux_x86_64.whl

    cffi-1.5.0-cp35-cp35m-linux_x86_64.whl is consistent with the
    following platform tag: "linux_x86_64".

    The wheel references the following external versioned symbols in
    system-provided shared libraries: GLIBC_2.3.

    The following external shared libraries are required by the wheel:
    {
        "libc.so.6": "/lib64/libc-2.5.so",
        "libffi.so.5": "/usr/lib64/libffi.so.5.0.6",
        "libpthread.so.0": "/lib64/libpthread-2.5.so"
    }

    In order to achieve the tag platform tag "manylinux1_x86_64" the
    following shared library dependencies will need to be eliminated:

    libffi.so.5

Repairing a wheel. ::

    $ auditwheel repair cffi-1.5.2-cp35-cp35m-linux_x86_64.whl
    Repairing cffi-1.5.2-cp35-cp35m-linux_x86_64.whl
    Grafting: /usr/lib64/libffi.so.5.0.6
    Setting RPATH: _cffi_backend.cpython-35m-x86_64-linux-gnu.so to "$ORIGIN/.libs_cffi_backend"
    Previous filename tags: linux_x86_64
    New filename tags: manylinux1_x86_64
    Previous WHEEL info tags: cp35-cp35m-linux_x86_64
    New WHEEL info tags: cp35-cp35m-manylinux1_x86_64

    Fixed-up wheel written to /wheelhouse/cffi-1.5.2-cp35-cp35m-manylinux1_x86_64.whl


Repair provenance
-----------------

``auditwheel repair --provenance PATH`` optionally writes a JSON evidence
document for the repair. The document maps every input wheel member to its
SHA-256 digest, records each ``DT_NEEDED`` reference with the exact source file
that was resolved for that referrer, and lists the output wheel members together
with the ELF rewrite steps (rename, ``DT_NEEDED`` replacement, RPATH change,
strip and retag). When two members reference the same external library, the
library is grafted once but each referrer keeps its own reference record.

Paths in the document are relative to the document directory; files outside the
workspace are recorded by basename and digest. The input wheel, the output wheel
and the staged source libraries can therefore be moved together with the
workspace without rewriting the evidence. ``PATH`` may name a ``.json`` file
directly or a directory, in which case ``<output wheel>.provenance.json`` is
created inside it.

The evidence can be checked offline: ::

    $ auditwheel provenance wheelhouse/foo.whl.provenance.json
    $ auditwheel provenance --member foo.libs/libbar-1234abcd.so.1 wheelhouse/foo.whl.provenance.json

The first command recomputes the input and output wheel digests, the full
member inventories and any workspace-relative source digests. The second
resolves one repaired member back to its input members, the concrete source
file, and the recorded rewrite steps.

Limitations
-----------

1. ``auditwheel`` uses the `DT_NEEDED <https://en.wikipedia.org/wiki/Direct_binding>`_
   information (like ``ldd``) from the Python extension modules to determine
   which system libraries they depend on. Code that dynamically
   loads libraries at runtime using ``ctypes`` / ``cffi`` (from Python) or
   ``dlopen`` (from C/C++) doesn't contain this information in a way that can
   be statically determined, so dependencies that are loaded via those
   mechanisms will be missed.
2. There's nothing we can do about "fixing" binaries if they were compiled and
   linked against a too-recent version of ``libc`` or ``libstdc++``. These
   libraries (and some others) use symbol versioning for backward
   compatibility. In general, this means that code that was compiled against an
   old version of ``glibc`` will run fine on systems with a newer version of
   ``glibc``, but code what was compiled on a new system won't / might not run
   on older system.

   So, to compile widely-compatible binaries, you're best off doing the build
   on an old Linux distribution, such as a manylinux Docker image.

Testing
-------

The tests can be run with ``nox``, which will automatically install
test dependencies.

Some of the integration tests also require a running and accessible Docker
daemon. These tests will pull a number of docker images if they are not already
available on your system, but it won't update existing images.
To update these images manually, run: ::

    docker pull python:3.11-slim-trixie
    docker pull quay.io/pypa/manylinux2010_x86_64
    docker pull quay.io/pypa/manylinux2014_x86_64
    docker pull quay.io/pypa/manylinux_2_28_x86_64
    docker pull quay.io/pypa/manylinux_2_34_x86_64
    docker pull quay.io/pypa/musllinux_1_2_x86_64

You may also remove these images using ``docker rmi``.

Code of Conduct
---------------

Everyone interacting in the ``auditwheel`` project's codebases, issue trackers,
chat rooms, and mailing lists is expected to follow the
`PSF Code of Conduct`_.

.. _PSF Code of Conduct: https://github.com/pypa/.github/blob/main/CODE_OF_CONDUCT.md
