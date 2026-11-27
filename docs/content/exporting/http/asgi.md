---
title: ASGI
weight: 3
---

To use Prometheus with [ASGI](http://asgi.readthedocs.org/en/latest/), there is
`make_asgi_app` which creates an ASGI application.

```python
from prometheus_client import make_asgi_app

app = make_asgi_app()
```
Such an application can be useful when integrating Prometheus metrics with ASGI
apps.

By default, the ASGI application will respect `Accept-Encoding:gzip` headers used by Prometheus
and compress the response if such a header is present. This behaviour can be disabled by passing 
`disable_compression=True` when creating the app, like this:

```python
app = make_asgi_app(disable_compression=True)
```

## Protecting the event loop with a collection budget

Custom collectors can be slow or block (for example while querying another
system). Pass a `CollectionBudget` to bound both the per-scrape generation
time and the total number of scrapes generating output at once.

```python
from prometheus_client import CollectionBudget, make_asgi_app

budget = CollectionBudget(max_concurrent=4, max_scrape_seconds=2.0)
app = make_asgi_app(budget=budget)
```

- `max_concurrent` limits how many scrapes generate output at the same time. A
  scrape that cannot acquire a slot fails immediately instead of queueing.
- `max_scrape_seconds` limits how long one scrape may spend generating the
  response. Collection always runs on a worker thread, so a blocked collector
  never stalls the event loop; an overrun is abandoned and the request returns
  promptly.

A scrape that exceeds either limit receives a `503 Service Unavailable`
response rather than a partial metrics payload. Slots are always released when
a scrape finishes or is rejected, so a failed scrape never reduces the capacity
available to later scrapes. `budget.diagnostics_snapshot()` returns counters
(`total`, `succeeded`, `rejected_concurrency`, `rejected_timeout`) for
observability.
