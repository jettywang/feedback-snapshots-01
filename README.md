# Python SDK v2 for [CloudEvents](https://github.com/cloudevents/spec)

[![PyPI version](https://badge.fury.io/py/cloudevents.svg)](https://badge.fury.io/py/cloudevents)

## Status

This SDK is still considered a work in progress, therefore things might (and
will) break with every update.

This SDK current supports the following versions of CloudEvents:

- v1.0
- v0.3

## Python SDK

Package [**cloudevents**](src/cloudevents) provides primitives to work with
[CloudEvents specification](https://github.com/cloudevents/spec).

### Installing

The CloudEvents SDK can be installed with pip:

```
pip install cloudevents
```

## Sending CloudEvents

Below we will provide samples on how to send cloudevents using the popular
[`requests`](http://docs.python-requests.org) library.

### Binary HTTP CloudEvent

```python
from cloudevents.core.v1.event import CloudEvent
from cloudevents.core.bindings.http import to_binary_event
import requests

# Create a CloudEvent
# - The CloudEvent "id" is generated if omitted. "specversion" defaults to "1.0".
attributes = {
    "type": "com.example.sampletype1",
    "source": "https://example.com/event-producer",
}
data = {"message": "Hello World!"}
event = CloudEvent(attributes, data)

# Creates the HTTP request representation of the CloudEvent in binary content mode
message = to_binary_event(event)

# POST
requests.post("<some-url>", data=message.body, headers=message.headers)
```

### Structured HTTP CloudEvent

```python
from cloudevents.core.v1.event import CloudEvent
from cloudevents.core.bindings.http import to_structured_event
import requests

# Create a CloudEvent
# - The CloudEvent "id" is generated if omitted. "specversion" defaults to "1.0".
attributes = {
    "type": "com.example.sampletype2",
    "source": "https://example.com/event-producer",
}
data = {"message": "Hello World!"}
event = CloudEvent(attributes, data)

# Creates the HTTP request representation of the CloudEvent in structured content mode
message = to_structured_event(event)

# POST
requests.post("<some-url>", data=message.body, headers=message.headers)
```

You can find a complete example of turning a CloudEvent into a HTTP request
[in the samples' directory](samples/http-json-cloudevents/client.py).

## Receiving CloudEvents

The code below shows how to consume a cloudevent using the popular python web framework
[flask](https://flask.palletsprojects.com/en/2.2.x/quickstart/):

```python
from flask import Flask, request

from cloudevents.core.bindings.http import from_http_event, HTTPMessage

app = Flask(__name__)


# create an endpoint at http://localhost:/3000/
@app.route("/", methods=["POST"])
def home():
    # create a CloudEvent
    event = from_http_event(HTTPMessage(dict(request.headers), request.get_data()))

    # you can access cloudevent fields as seen below
    print(
        f"Found {event.get_id()} from {event.get_source()} with type "
        f"{event.get_type()} and specversion {event.get_specversion()}"
    )

    return "", 204


if __name__ == "__main__":
    app.run(port=3000)
```

You can find a complete example of turning a CloudEvent into a HTTP request
[in the samples' directory](samples/http-json-cloudevents/json_sample_server.py).

## Approving CloudEvent content

A service can approve an event's content once, then hand the approval to an
asynchronous worker that picks the protocol binding and content mode later. The
approval covers every attribute, every extension present on the event and the
event data, and is independent of the transport.

```python
from cloudevents.core.approval import EventApproval, approve
from cloudevents.core.bindings import http, kafka

# Approval side: decide and record the approved content.
approval = approve(event)  # pass key=b"..." for an HMAC approval
job = {"event": event, "approval": approval.to_dict()}

# Worker side: choose a binding after approval; the approval still holds.
approval = EventApproval.from_dict(job["approval"])  # key=b"..." if keyed
message = kafka.to_binary_event(event, approval=approval)

# Changing the approved content is rejected before anything is published.
event.get_data()["total"] = 0
http.to_structured_event(event, approval=approval)
# ApprovalMismatchError: [phase=pre_publish] ... content differs at: data.total
```

A compact token (`to_dict()`) carries only the digest, so it cannot list the
changed paths; keep the in-process `EventApproval` from `approve()` if you want
path-level diagnostics such as `data.total`. Tokens are transport-neutral, so a
worker can comfortably send the same approval through an HTTP binary request and
a Kafka structured message without re-approving.

Every binding accepts `approval=` on `to_binary`, `to_structured` and their
`*_event` convenience wrappers. Failures always carry a `phase` marker:
`ApprovalPhase.APPROVE` while approving, `ApprovalPhase.VERIFY` for explicit
`verify()` calls and `ApprovalPhase.PRE_PUBLISH` when a binding rejects the
event just before serialisation. Switching bindings or content modes does not
invalidate the approval; changing the data, a standard attribute or an
extension does.

## SDK versioning

The goal of this package is to provide support for all released versions of CloudEvents,
ideally while maintaining the same API. It will use semantic versioning
with following rules:

- MAJOR version increments when backwards incompatible changes is introduced.
- MINOR version increments when backwards compatible feature is introduced
  INCLUDING support for new CloudEvents version.
- PATCH version increments when a backwards compatible bug fix is introduced.

## Community

- There are bi-weekly calls immediately following the [Serverless/CloudEvents
  call](https://github.com/cloudevents/spec#meeting-time) at
  9am PT (US Pacific). Which means they will typically start at 10am PT, but
  if the other call ends early then the SDK call will start early as well.
  See the [CloudEvents meeting minutes](https://docs.google.com/document/d/1OVF68rpuPK5shIHILK9JOqlZBbfe91RNzQ7u_P7YCDE/edit#)
  to determine which week will have the call.
- Slack: #cloudeventssdk channel under
  [CNCF's Slack workspace](https://slack.cncf.io/).
- Email: https://lists.cncf.io/g/cncf-cloudevents-sdk
- Contact for additional information: Denis Makogon (`@denysmakogon` on slack).

Each SDK may have its own unique processes, tooling and guidelines, common
governance related material can be found in the
[CloudEvents `docs`](https://github.com/cloudevents/spec/tree/main/docs)
directory. In particular, in there you will find information concerning
how SDK projects are
[managed](https://github.com/cloudevents/spec/blob/main/docs/GOVERNANCE.md),
[guidelines](https://github.com/cloudevents/spec/blob/main/docs/SDK-maintainer-guidelines.md)
for how PR reviews and approval, and our
[Code of Conduct](https://github.com/cloudevents/spec/blob/main/docs/GOVERNANCE.md#additional-information)
information.

If there is a security concern with one of the CloudEvents specifications, or
with one of the project's SDKs, please send an email to
[cncf-cloudevents-security@lists.cncf.io](mailto:cncf-cloudevents-security@lists.cncf.io).

## Additional SDK Resources

- [List of current active maintainers](MAINTAINERS.md)
- [How to contribute to the project](CONTRIBUTING.md)
- [SDK's License](LICENSE)
- [SDK's Release process](RELEASING.md)

## Maintenance

We use [uv][uv] for dependency and package management, [ruff][ruff] and [isort][isort]
for autoformatting and [pre-commit][pre-commit] to automate those with commit
hooks.

For information on releasing version bumps see [RELEASING.md](RELEASING.md)

[uv]: https://docs.astral.sh/uv/
[ruff]: https://docs.astral.sh/ruff
[isort]: https://pycqa.github.io/isort/
[pre-commit]: https://pre-commit.com
