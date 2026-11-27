---
title: WSGI
weight: 2
---

To use Prometheus with [WSGI](http://wsgi.readthedocs.org/en/latest/), there is
`make_wsgi_app` which creates a WSGI application.

```python
from prometheus_client import make_wsgi_app
from wsgiref.simple_server import make_server

app = make_wsgi_app()
httpd = make_server('', 8000, app)
httpd.serve_forever()
```

Such an application can be useful when integrating Prometheus metrics with WSGI
apps.

The method `start_wsgi_server` can be used to serve the metrics through the
WSGI reference implementation in a new thread.

```python
from prometheus_client import start_wsgi_server

start_wsgi_server(8000)
```

By default, the WSGI application will respect `Accept-Encoding:gzip` headers used by Prometheus
and compress the response if such a header is present. This behaviour can be disabled by passing
`disable_compression=True` when creating the app, like this:

```python
app = make_wsgi_app(disable_compression=True)
```

## Protecting worker threads with a collection budget

Custom collectors can be slow or block (for example while querying another
system). Under a scrape storm this can tie up every WSGI worker thread. Pass a
`CollectionBudget` to bound both the per-scrape generation time and the total
number of scrapes generating output at once.

```python
from prometheus_client import CollectionBudget, make_wsgi_app

budget = CollectionBudget(max_concurrent=4, max_scrape_seconds=2.0)
app = make_wsgi_app(budget=budget)
```

- `max_concurrent` limits how many scrapes generate output at the same time. A
  scrape that cannot acquire a slot fails immediately instead of queueing.
- `max_scrape_seconds` limits how long one scrape may spend generating the
  response. Generation runs on a separate worker thread, so a collector that
  overruns is abandoned and the serving thread returns promptly.

A scrape that exceeds either limit receives a `503 Service Unavailable`
response rather than a partial metrics payload. Slots are always released when
a scrape finishes or is rejected, so a failed scrape never reduces the capacity
available to later scrapes. `budget.diagnostics_snapshot()` returns counters
(`total`, `succeeded`, `rejected_concurrency`, `rejected_timeout`) for
observability.