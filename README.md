# PyMacaroons

[![Build Status](https://github.com/ecordell/pymacaroons/workflows/CI/badge.svg?branch=master)](https://github.com/ecordell/pymacaroons/actions?workflow=CI)
[![Downloads](https://img.shields.io/pypi/dd/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)
[![Latest Version](https://img.shields.io/pypi/v/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)
[![Supported Python implementations](https://img.shields.io/pypi/implementation/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)
[![Development Status](https://img.shields.io/pypi/status/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)
[![Wheel Status](https://img.shields.io/pypi/wheel/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)
[![License](https://img.shields.io/pypi/l/pymacaroons.svg)](https://pypi.python.org/pypi/pymacaroons/)

This is a Python implementation of Macaroons. PyMacaroons is stable and does not change frequently. Please see the GitHub issues for the current roadmap. 

## What is a Macaroon? 
Macaroons, like cookies, are a form of bearer credential. Unlike opaque tokens, macaroons embed *caveats* that define specific authorization requirements for the *target service*, the service that issued the root macaroon and which is capable of verifying the integrity of macaroons it receives. 

Macaroons allow for delegation and attenuation of authorization. They are simple and fast to verify, and decouple authorization policy from the enforcement of that policy.

For a simple example, see the [Quickstart Guide](#quickstart). For more in-depth examples check out the [functional tests](https://github.com/ecordell/pymacaroons/blob/master/tests/functional_tests/functional_tests.py) and [references](#references-and-further-reading).

## Installing 

To install PyMacaroons:

    pip install pymacaroons


## Quickstart

### Create a Macaroon

```python
from pymacaroons import Macaroon, Verifier

# Keys for signing macaroons are associated with some identifier for later 
# verification. This could be stored in a database, key value store, 
# memory, etc.
keys = {
    'key-for-bob': 'asdfasdfas-a-very-secret-signing-key'
}

# Construct a Macaroon. The location and identifier will be visible after
# construction, and identify which service and key to use to verify it.
m = Macaroon(
    location='cool-picture-service.example.com',
    identifier='key-for-bob',
    key=keys['key-for-bob']
)

# Add a caveat for the target service
m.add_first_party_caveat('picture_id = bobs_cool_cat.jpg')

# Inspect Macaroon (useful for debugging)
print(m.inspect())
# location cool-picture-service.example.com
# identifier key-for-bob
# cid picture_id = bobs_cool_cat.jpg
# signature 83d8fa280b09938d3cffe045634f544ffaf712ff2c51ac34828ae8a42b277f8f

# Serialize for transport in a cookie, url, OAuth token, etc
serialized = m.serialize()

print(serialized)
# MDAyZWxvY2F0aW9uIGNvb2wtcGljdHVyZS1zZXJ2aWNlLmV4YW1wbGUuY29tCjAwMWJpZGVudGlmaWVyIGtleS1mb3ItYm9iCjAwMjdjaWQgcGljdHVyZV9pZCA9IGJvYnNfY29vbF9jYXQuanBnCjAwMmZzaWduYXR1cmUgg9j6KAsJk408_-BFY09UT_r3Ev8sUaw0goropCsnf48K
```

### Verifying Macaroon
```python
# Some time later, the service recieves the macaroon and must verify it
n = Macaroon.deserialize("MDAyZWxvY2F0aW9uIGNvb2wtcGljdHVyZS1zZXJ2aWNlLmV4YW1wbGUuY29tCjAwMWJpZGVudGlmaWVyIGtleS1mb3ItYm9iCjAwMjdjaWQgcGljdHVyZV9pZCA9IGJvYnNfY29vbF9jYXQuanBnCjAwMmZzaWduYXR1cmUgg9j6KAsJk408_-BFY09UT_r3Ev8sUaw0goropCsnf48K")

v = Verifier()

# General caveats are verified by arbitrary functions
# that return True only if the caveat is understood and met
def picture_access_validator(predicate):
    # in this case, predicate = 'picture_id = bobs_cool_cat.jpg'
    if predicate.split(' = ')[0] != 'picture_id':
        return False
    return predicate.split(' = ')[1] == 'bobs_cool_cat.jpg'
    
# The verifier is informed of all relevant contextual information needed
# to verify incoming macaroons
v.satisfy_general(picture_access_validator)

# Note that in this case, the picture_access_validator() is just checking
# equality. This is equivalent to a satisfy_exact call, which just checks for
# string equality
v.satisfy_exact('picture_id = bobs_cool_cat.jpg')

# Verify the macaroon using the key matching the macaroon identifier
verified = v.verify(
    n,
    keys[n.identifier]
)

# if verified is True, the macaroon was untampered (signatures matched) AND 
# all caveats were met
```

## Discharge routing safety

A third-party caveat's `location` is attacker-controlled metadata: it is not
covered by the macaroon signature. Never build a discharge URL from it.

`DischargeRegistry` treats locally configured services as the only source of
service identity and endpoints. It resolves a caveat by exact caveat id;
`location` is used only to break a tie when several configured services
explicitly claim the same id, and an ambiguous or unknown hint is refused.
Requests contain only the requested `caveat_id`, never the root macaroon,
other caveats, or previously obtained discharges.

```python
from pymacaroons import (
    DischargeClient, DischargeRegistry, DischargeService, Endpoint,
)

registry = DischargeRegistry([
    DischargeService(
        'org-a', Endpoint('https://org-a.example/discharge'),
        location_hints=['org-a'], caveat_ids=['shared-id'],
    ),
    DischargeService(
        'org-b', Endpoint('https://org-b.example/discharge'),
        location_hints=['org-b'], caveat_ids=['shared-id'],
    ),
])
client = DischargeClient(registry, transport)
result = client.fetch(root_macaroon.caveats[0])
binding = result.bind(root_macaroon)
```

`transport.send(request)` receives `request.method`, `request.headers`, and
`request.body` (the minimal JSON payload). The transport must not follow
redirects; the client also refuses redirect statuses and any final URL that
differs from the configured endpoint.

Keep three separate conclusions when auditing a discharge:

- **Destination**: which configured endpoint received which caveat id. The
  caveat `location` is only an untrusted routing hint.
- **Authentication**: the target service authenticates the discharge with the
  caveat key derived from the root macaroon. HTTPS only protects the
  configured transport; it does not authenticate the returned macaroon.
- **Root binding**: `result.bind(root)` binds the discharge to one specific
  root signature. A discharge obtained from the wrong organization will bind
  structurally but fail signature verification at the target.

`build_report(result, binding, target_verified=...)` returns these three
sections separately rather than a single "success" flag. A complete example
is in `examples/discharge_routing_demo.py`.

## Documentation

The latest documentation can always be found on [ReadTheDocs](http://pymacaroons.readthedocs.org/en/latest/).

## Python notes

Compatible with Python 2 and 3. CI builds are generated for 2.7, 3.5, 3.6, 3.7, 3.8 and 3.9, as well as PyPy3. May be compatible with other versions (or may require tweaking - feel free to contribute!)

## Running Tests

To run the tests:

`tox`

To run against a specific version of Python:

`tox -e py39`

[tox](https://tox.wiki/en/latest/) is used for running tests locally against multiple versions of Python. Tests will only run against versions available to tox. 

## More Macaroons

The [libmacaroons library](https://github.com/rescrv/libmacaroons) comes with Python and Go bindings, but PyMacaroons is implemented directly in Python for further portability and ease of installation. Benchmarks coming, but some speed tradeoffs are expected.

The [Ruby-Macaroons](https://github.com/localmed/ruby-macaroons) library is available for Ruby. PyMacaroons and Ruby-Macaroons are completely compatible (they can be used interchangibly within the same target service).

PyMacaroons, libmacaroons, and Ruby-Macaroons all use the same underlying cryptographic library (libsodium).

## References and Further Reading

- [The Macaroon Paper](http://research.google.com/pubs/pub41892.html)
- [Mozilla Macaroon Tech Talk](https://www.youtube.com/watch?v=CGBZO5n_SUg)
- [libmacaroons](https://github.com/rescrv/libmacaroons)
- [Ruby-Macaroons](https://github.com/localmed/ruby-macaroons)
- [libnacl](https://github.com/saltstack/libnacl)

