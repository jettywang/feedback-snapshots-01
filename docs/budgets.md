# Sharing a Verification Budget

A service that verifies many accounts at once usually wants to cap how much
memory and CPU Argon2 may use at the same time.
{mod}`argon2` lets the application provide that shared budget instead of
inventing its own around the library.

Create one {class}`argon2.VerificationLimiter` and pass it to every
{class}`argon2.PasswordHasher` that serves the same worker or service:

```python
import argon2

limiter = argon2.VerificationLimiter(capacity=4)
ph = argon2.PasswordHasher(limiter=limiter)
```

Each call to {meth}`argon2.PasswordHasher.verify` now takes one share of the
budget before it enters Argon2.
It releases the share only after the Argon2 call really returns -- whether
that is a success, a mismatch, or an error.
Verification stays inline; no background task or thread is created.

## Observing the Budget

{meth}`argon2.VerificationLimiter.snapshot` returns a consistent
{class}`argon2.VerificationBudget` that shows how much is running and how
many callers are queued:

```python
budget = limiter.snapshot()
print(budget.in_flight, budget.waiting, budget.can_enter)
```

The counters are also exposed as properties on the limiter itself if you
only need one value, for example for metrics.

## Bounded and Cancellable Waiting

If all shares are taken, {meth}`argon2.PasswordHasher.verify` waits without
running Argon2.
Pass *wait_timeout* to bound that wait and *cancel_event* to abort it from
another thread:

```python
try:
    ph.verify(hash, password, wait_timeout=0.05, cancel_event=stop)
except argon2.exceptions.VerificationTimeout:
    ...
```

* :exc:`argon2.exceptions.VerificationTimeout` means no share became free in
  time, so no Argon2 call was started.
* :exc:`argon2.exceptions.VerificationCancelled` means *cancel_event* was set
  while waiting; again, no Argon2 call was started.

Once the Argon2 call has started, a cancellation request does not interrupt
it.
The share stays held until the call actually ends, so the budget never
under-reports work that is still consuming resources.

## Callers That Cannot Block

Some callers -- an event loop or a request handler with its own deadline --
prefer a handle over a blocking call.
{meth}`argon2.PasswordHasher.start_verify` runs one verification on a daemon
thread and returns a {class}`argon2.VerificationTask`:

```python
task = ph.start_verify(hash, password, wait_timeout=0.05)
try:
    matched = task.result(timeout=0.5)
except argon2.exceptions.VerificationTimeout:
    # Our own deadline passed.  Argon2 may still be running and still
    # holds its share; the task finishes in the background.
    ...
```

The task's *wait_timeout* bounds how long it may wait for a share; if it
expires the task ends with
:exc:`argon2.exceptions.VerificationTimeout` and never starts Argon2.
{meth}`argon2.VerificationTask.wait` and
{meth}`argon2.VerificationTask.result` wait for the outcome, and
{meth}`argon2.VerificationTask.cancel` withdraws a task that has not started
yet.
Cancelling a task that is already running returns ``False`` and leaves the
share alone.
