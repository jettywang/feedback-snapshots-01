# Exceptions

While you should use a proper crash reporter like [Sentry](https://sentry.io) in production, *structlog* has helpers for formatting exceptions for humans and machines.

All *structlog*'s exception features center around passing an `exc_info` key-value pair in the event dict.
There are three possible behaviors depending on its value:

1. If the value is a tuple, render it as if it was returned by {func}`sys.exc_info`.
2. If the value is an Exception, render it.
3. If the value is true but no tuple, call {func}`sys.exc_info` and render that.

If there is no `exc_info` key or false, the event dict is not touched.
This behavior is analog to the one of the stdlib's logging.


## Transformations

*structlog* comes with {class}`structlog.processors.ExceptionRenderer` that deduces and removes the `exc_info` key as outlined above, calls a user-supplied function with the synthesized `exc_info`, and stores its return value in the `exception` key.
The most common use-cases are already covered by the following processors:

{func}`structlog.processors.format_exc_info`

: Formats it to a flat string like the standard library would on the console.

{obj}`structlog.processors.dict_tracebacks`

: Uses {class}`structlog.tracebacks.ExceptionDictTransformer` to give you a structured and JSON-serializable `exception` key.


## Size-Budgeted Exceptions

Centralized log systems typically reject or truncate events that exceed a per-event size limit.
A single verbose exception -- think wide stacks, long cause chains, or large local variables -- can therefore blow the whole event, causing both the exception and every other field to be lost.

{class}`structlog.processors.BudgetedExceptionRenderer` renders the exception like {class}`structlog.processors.ExceptionRenderer`, but guarantees that the serialized `exception` field never exceeds a byte budget:

```python
from structlog.processors import BudgetedExceptionRenderer, JSONRenderer

structlog.configure(
    processors=[
        BudgetedExceptionRenderer(max_size=4096),
        JSONRenderer(),
    ]
)
```

When the full rendering does not fit, the renderer falls back through progressively smaller, deterministic detail levels -- root-cause traceback, frame caps, a single root-cause stack, and finally a minimal `{"exc_type", "exc_value"}` object -- until one fits.
The event is *never* dropped, so ordinary events logged right after an over-budget exception are unaffected.

Whenever the exception had to be reduced, truncation metadata is stored under a dedicated key (`exception_truncation` by default).
It records the chosen detail level, the cause-chain length, and the original and rendered sizes:

```python
{
    "event": "something broke",
    "exception": "[truncated] ValueError: root cause ...",
    "exception_truncation": {
        "detail": "root_summary",
        "chain_length": 4,
        "original_size": 18204,
        "rendered_size": 312,
        "dropped_bytes": 17892,
    },
}
```

This keeps a traceable root-cause summary and an audit trail of what was cut, while leaving room for the rest of the event.
The budget is measured with the same serializer as your renderer (JSON by default), and works with both the built-in string formatter and {class}`structlog.tracebacks.ExceptionDictTransformer`.


### Customizing Dict Tracebacks

{class}`structlog.tracebacks.ExceptionDictTransformer` can be customized with a number of parameters.
If these prove insufficient, see {ref}`Custom Filtering of Dict Tracebacks <custom-dict-tracebacks>`.


## Console rendering

Our {doc}`console-output`'s {class}`structlog.dev.ConsoleRenderer` takes an *exception_formatter* argument that allows for customizing the output of exceptions.

{func}`structlog.dev.plain_traceback`

: Is the default if [Rich] is not installed.
  As the name suggests, it renders a plain traceback.

{class}`structlog.dev.RichTracebackFormatter`

: Uses [Rich] to render a colorful traceback.
  It's a class because it allows for customizing the output by passing arguments to Rich.
: It's the default if Rich is installed.

:::{seealso}
{doc}`console-output` for more information on *structlog*'s console features.
:::

:::{deprecated} 26.1.0
Support for [*better-exceptions*] is deprecated and will be removed in a future release.
Use [Rich] instead.
:::

[*better-exceptions*]: https://github.com/qix-/better-exceptions
[Rich]: https://github.com/Textualize/rich
