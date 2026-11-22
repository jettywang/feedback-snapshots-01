# Security audit logging

When you raise the default log level of your business loggers to save log
volume, security-relevant events need special treatment:

- they must remain **archived** at their original security level, and
- whenever one does *not* reach the normal log output, the on-call engineer
  must be able to reconcile **why** it was filtered.

*structlog* ships a small, dependency-free channel for this in
{mod}`structlog.audit`.
It is independent of the wrapper class you use: the only logger surface it
relies on is `logging.Logger.getEffectiveLevel` /
`logging.Logger.isEnabledFor`, so the same router works with loggers that
inherit the raised default level, loggers that set their own level, and
third-party code that uses the standard-library `logging` module directly.

## The two exits

A security event is any event dict carrying a truthy `security_audit` key --
conventionally bound once on a dedicated logger:

```python
audit_log = structlog.get_logger().bind(security_audit=True)
```

{class}`~structlog.audit.SecurityAuditRouter` is a processor that must run
**first**, before any expensive processor and before
{func}`structlog.stdlib.filter_by_level`.
Every security event then takes exactly one of two exits:

1. **Archived**: the wrapped logger accepts the level.
   A copy of the event dict goes to the sink's `emit_archived()` and normal
   processing continues. The event keeps its original level.
2. **Witnessed**: the wrapped logger would filter the event (or is disabled).
   An immutable, JSON-serializable {class}`~structlog.audit.FilterWitness`
   goes to the sink's `emit_witness()`, and
   {exc}`structlog.DropEvent` is raised so nothing leaks into ordinary
   output.

Non-security events are returned on the first line of the processor after a
single dictionary lookup, so ordinary callers keep their existing level
behavior and pay no sink or clock cost.

## Wiring it up

```python
import structlog

from structlog.audit import ListAuditSink, SecurityAuditRouter

sink = ListAuditSink()  # in production, ship this to your audit pipeline

structlog.configure(
    processors=[
        SecurityAuditRouter(sink),
        structlog.stdlib.filter_by_level,
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
```

Given a root logger configured at `WARNING`, an informational security event
is filtered and witnessed instead of being rendered:

```pycon
>>> import logging
>>> from structlog.audit import ListAuditSink, SecurityAuditRouter
>>> sink = ListAuditSink()
>>> log = structlog.wrap_logger(
...     logging.getLogger("payments"),
...     processors=[
...         SecurityAuditRouter(sink, clock=lambda: 1763000000.0),
...         structlog.stdlib.filter_by_level,
...         structlog.processors.JSONRenderer(),
...     ],
...     wrapper_class=structlog.stdlib.BoundLogger,
... ).bind(security_audit=True)
>>> logging.getLogger("payments").setLevel(logging.WARNING)
>>> log.info("api_key_rotated", audit_event_id="EVT-42")
>>> witness = sink.witnesses[0]
>>> witness.reason
'below_effective_level'
>>> witness.level
'info'
>>> witness.effective_level_name
'warning'
>>> witness.audit_event_id
'EVT-42'
```

A warning-level event from the same logger is accepted, emitted normally, and
archived with its original level intact:

```pycon
>>> log.warning("rate_limit_breached", audit_event_id="EVT-43")
>>> sink.archived[0]["event"]
'rate_limit_breached'
>>> len(sink.witnesses)  # only the filtered event left a witness
1
```

## Witness fields

Each {class}`~structlog.audit.FilterWitness` answers one reconciliation
question:

| field | question it answers |
|---|---|
| `event`, `audit_event_id` | which event was filtered |
| `level`, `level_number` | the security level it was filed at |
| `reason` | machine-readable cause (`below_effective_level`, `logger_disabled`) |
| `effective_level`, `effective_level_name` | the threshold that decided |
| `logger_name` | which logger applied the threshold |
| `filtered_at` | Unix timestamp for ordering and retention |

Witnesses are frozen dataclasses; `to_dict()` returns a plain mapping that
`json.dumps` accepts.

## Overhead

The router keeps an explicit budget:

- ordinary (non-security) events do one dict lookup and return; the sink and
  clock are never touched,
- a filtered security event performs one effective-level read, builds one
  witness, writes once to the sink, and skips all later rendering,
- an accepted security event writes one defensive copy to the archive before
  the normal chain runs.

`SecurityAuditRouter.stats()` reports `archived` and `filtered` counters plus
`sink_ns`, the nanoseconds spent *only* inside sink calls, so the cost of
accountability is measurable independently of the rest of the chain.

## Custom sinks

Implement the {class}`~structlog.audit.AuditSink` protocol to forward the two
exits to real infrastructure -- for example, an archive topic and a
reconciliation topic.
Sinks should not raise: they must never change whether a business log call
succeeds.
{class}`~structlog.audit.ListAuditSink` is the in-memory reference
implementation used in tests.
