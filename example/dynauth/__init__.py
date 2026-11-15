"""RFC 5176 Dynamic Authorization (CoA / Disconnect) policy adapter demo.

The package implements a server-side policy layer on top of pyrad: it binds
authenticated senders to the NASes and operations they may control, locates
sessions by explicit attribute combinations, applies changes atomically,
deduplicates replayed requests and answers with RFC 5176 Error-Cause values.
"""
