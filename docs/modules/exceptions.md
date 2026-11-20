# Exceptions

`UnroutableError`, `NackError` and the connection error a publish raises carry two attributes:
`publish`, the [`FailedPublish`][pika.exceptions.FailedPublish] to send again, and `failure`, the
[`PublishFailure`][pika.exceptions.PublishFailure] view to log. The second withholds the body, the
header table and the person-identifying properties; see
[Publishing failures and what they disclose](adapters/blocking.md#publishing-failures-and-what-they-disclose).

::: pika.exceptions
    options:
      members: true
      show_if_no_docstring: true
