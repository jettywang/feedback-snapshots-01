Code Examples
=============

This section of the documentation contains long-form code examples. These are
intended as references for developers that would like to get an understanding
of how h2 fits in with various Python I/O frameworks.

Example Servers
---------------

.. toctree::
   :maxdepth: 2

   asyncio-example
   curio-example
   eventlet-example
   gevent-example
   tornado-example
   twisted-example
   wsgi-example

Example Clients
---------------

.. toctree::
   :maxdepth: 2

   plain-sockets-example
   twisted-head-example
   twisted-post-example


Restricted Early Hints Consumer
-------------------------------

The :download:`restricted early hints example
<../../examples/early_hints/restricted_early_hints.py>` demonstrates consuming
HTTP/2 ``103 Early Hints`` without treating a hint as authorization.  Prefetch
is limited to a caller-supplied origin and path allowlist, uses a
credentialless fake fetcher, and stages results in a per-stream quarantine.
Only a final ``200``/``203`` response for that same stream, with a cache policy
that permits shared storage, commits the staged bytes to the authenticated
user's cache.  Final ``401`` responses, stream resets, and connection
termination discard the quarantine.
