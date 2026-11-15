"""
Bounded, fair HTTP/2 send scheduling example.

This package is an *application layer* example built on top of the public
``h2`` API.  It does not modify the protocol stack.  The pieces are:

* :mod:`auth`      -- server-side authenticated principals and their budgets.
* :mod:`scheduler` -- the :class:`~scheduler.BoundedSendScheduler` fair queue.
* :mod:`transport` -- an in-memory h2 loopback used to drive a real stack.
* :mod:`demo`      -- scenarios showing proportional shares and lower bounds.
"""

from .auth import AuthDirectory, Principal
from .scheduler import BoundedSendScheduler, SchedulerConfig, StreamState

__all__ = [
    "AuthDirectory",
    "Principal",
    "BoundedSendScheduler",
    "SchedulerConfig",
    "StreamState",
]
