---
title: Node exporter textfile collector
weight: 2
---

The [textfile collector](https://github.com/prometheus/node_exporter#textfile-collector)
allows machine-level statistics to be exported out via the Node exporter.

This is useful for monitoring cronjobs, or for writing cronjobs to expose metrics
about a machine system that the Node exporter does not support or would not make sense
to perform at every scrape (for example, anything involving subprocesses).

```python
from prometheus_client import CollectorRegistry, Gauge, write_to_textfile

registry = CollectorRegistry()
g = Gauge('raid_status', '1 if raid array is okay', registry=registry)
g.set(1)
write_to_textfile('/configured/textfile/path/raid.prom', registry)
```

A separate registry is used, as the default registry may contain other metrics
such as those from the Process Collector.

## API Reference

### `write_to_textfile(path, registry, escaping='allow-utf-8', tmpdir=None)`

Writes metrics from the registry to a file in Prometheus text format.

The file is written atomically: metrics are first written to a temporary file in the same
directory as `path` (or in `tmpdir` if provided), then renamed into place. This prevents the
Node exporter from reading a partially written file.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `str` | required | Destination file path. Must end in `.prom` for the Node exporter textfile collector to process it. |
| `registry` | `Collector` | required | Registry whose metrics are written. |
| `escaping` | `str` | `'allow-utf-8'` | Escaping scheme for metric and label names. Accepted values: `'allow-utf-8'`, `'underscores'`, `'dots'`, `'values'`. |
| `tmpdir` | `Optional[str]` | `None` | Directory for the temporary file used during the atomic write. Defaults to the same directory as `path`. If provided, must be on the same filesystem as `path`. |

Returns `None`. Raises an exception if the file cannot be written; the temporary file is cleaned
up automatically on failure.

## Safe commits with fencing generations

When two services publish the same `*.prom` path (for example during a
publisher rotation), the atomic rename above is not enough: a publisher whose
credentials have been revoked can still overwrite a newer file produced by the
publisher that replaced it. `safe_write_to_textfile` adds an optional fencing
layer on top of the same temporary-file-plus-rename mechanism.

Each publisher is identified by a stable name and receives a monotonically
increasing *generation* from a `GenerationAuthority`. The highest generation
that has committed is persisted in a `<path>.generation` sidecar next to the
metrics file, and an advisory `<path>.lock` serializes concurrent commits. A
publisher that has been revoked, or whose generation is older than the one
already committed, can never install its output — even if it finishes after
its replacement.

```python
from prometheus_client import (
    CollectorRegistry, Gauge, GenerationAuthority, safe_write_to_textfile,
)

authority = GenerationAuthority()
generation = authority.grant('service-a')     # rotates in this publisher
# authority.revoke('service-a')               # called when it is rotated out

registry = CollectorRegistry()
Gauge('raid_status', '1 if raid array is okay', registry=registry).set(1)

receipt = safe_write_to_textfile(
    '/configured/textfile/path/raid.prom',
    registry,
    publisher='service-a',
    eligibility=authority.as_check(),
)
```

Instead of raising, every attempt returns a `CommitReceipt` whose `status`
distinguishes the three possible outcomes so callers can alert on the right
condition:

| `status` | Meaning |
|----------|---------|
| `CommitStatus.COMMITTED` | The metrics file was atomically replaced and the sidecar updated. |
| `CommitStatus.REVOKED` | The publisher is no longer eligible, or its generation is older than the one already committed. The existing file is untouched. |
| `CommitStatus.FAILED` | Staging or renaming raised an exception; the exception is attached as `receipt.error` and the last good file is preserved. |

The `escaping` and `tmpdir` arguments behave exactly as in
`write_to_textfile`, so all existing text formats and staging layouts remain
supported. Eligibility is re-checked while holding the commit lock, so a
revocation that happens while the metrics are being generated or staged still
takes effect. Pre-rendered bytes may be passed as `payload` to skip registry
serialization.

### `safe_write_to_textfile(path, registry, publisher, eligibility, escaping='allow-utf-8', tmpdir=None, payload=None)`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `str` | required | Destination file path. Must end in `.prom` for the textfile collector. |
| `registry` | `Collector` | required | Registry whose metrics are written. Ignored when `payload` is given. |
| `publisher` | `str` | required | Stable identifier of the publishing service. |
| `eligibility` | `Callable[[str], Optional[int]]` | required | Returns the publisher's current fencing generation, or `None` once revoked. |
| `escaping` | `str` | `'allow-utf-8'` | Escaping scheme, identical to `write_to_textfile`. |
| `tmpdir` | `Optional[str]` | `None` | Directory for the staging temp file. Must be on the same filesystem as `path`. |
| `payload` | `Optional[bytes]` | `None` | Pre-rendered metrics bytes; registry serialization is skipped when set. |

Returns a `CommitReceipt`. The helper never raises for an expected commit
outcome; filesystem errors are reported on the receipt as `CommitStatus.FAILED`.