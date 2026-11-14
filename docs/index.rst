.. PyMacaroons documentation master file, created by
   sphinx-quickstart on Mon Sep  8 21:08:32 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. comment: split here

PyMacaroons
===========

PyMacaroons is a Python implementation of Macaroons. *They're better than cookies!*

Installation
------------

Install PyMacaroons by running:

    pip install pymacaroons

Contribute
----------

- `Issue Tracker`_
- `Source Code`_

.. _Issue Tracker: https://github.com/ecordell/pymacaroons/issues
.. _Source Code: https://github.com/ecordell/pymacaroons

License
-------

The project is licensed under the MIT license.


.. comment: split here

Structured access caveats
-------------------------

The ``access`` namespace adds interpreter-owned constraints for a resource
scope (``access.resource``), an HTTP method (``access.method``), and a UTC
deadline (``access.expires``). Each predicate has exactly one interpreter;
unknown or malformed constraints are rejected and never fall through to
``satisfy_general`` callbacks. Appending another caveat for the same field
intersects with earlier values. See the "Structured access caveats" section
of the README for usage.

Contents:

.. toctree::
   :maxdepth: 2


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`




