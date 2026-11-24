# Atomic configuration updates

When a service runs several workers and reloads configuration at runtime, an
update must be **all or nothing**: a new record is exposed only after every
value is in place and every validator passes. If validation fails, the service
keeps serving the previously approved configuration.

The `TransactionManager` provides generation-based, atomic updates on top of a
regular `Dynaconf` instance.

## Basic usage

```python
from dynaconf import Dynaconf, Validator
from dynaconf.transaction import TransactionManager

settings = Dynaconf(
    environments=False,
    ITEM_ONE="v1",
    ITEM_TWO="v1",
    validators=[Validator("ITEM_TWO", must_exist=True)],
)
manager = TransactionManager(settings)

with manager.transaction() as tx:
    tx.set("ITEM_ONE", "v2")
    tx.set("ITEM_TWO", "v2")

# The whole record becomes visible only after the context exits successfully.
assert settings.ITEM_ONE == "v2"
```

Writes are buffered while the transaction is open. Until `commit()` runs,
readers keep seeing the previously approved configuration, so a partially
written record can never leak.

## Validation and rollback on failure

Pass `validate="all"` (the default) to collect every validator error,
`validate=True` to stop at the first failure, or `validate=False` to skip
validation.

```python
tx = manager.begin()
tx.set("ITEM_ONE", "v2")
tx.set("ITEM_TWO", "bad")  # rejected by a validator
try:
    tx.commit(validate="all")
except ValidationError:
    # The live configuration is untouched and keeps the approved values.
    ...
```

On failure the live object is never mutated. `manager.rollback()` restores the
configuration to the generation approved immediately before the current one.

## Diagnosing rejected candidates

Every candidate - committed, failed or cancelled - is kept with the changes
that were attempted and the error that stopped it.

```python
manager.history()                 # all candidates
manager.history(status="failed")  # only rejected ones
manager.candidate(generation=3)   # look one generation up
```

## Consistent reads across workers

A commit swaps the whole internal state atomically. To read several keys from
the *same* generation - for example inside a worker handling one request - pin
the generation with `consistent_read()`:

```python
with manager.consistent_read() as view:
    one = view("ITEM_ONE")
    two = view("ITEM_TWO")  # always from the same validated generation
```

`read_generation()` returns the current generation number together with a
coherent snapshot of all its values.

## Fresh reads and environment switching

Single-key `get_fresh()` and environment switching (`using_env()`,
`from_env()`) keep working as usual. The manager registers an in-memory loader
that re-applies the committed generation whenever Dynaconf reloads its sources,
so a fresh read never falls back to stale file values for keys that belong to
the approved generation.

## Lazy values

Lazy values (for example `@format {this.OTHER}`) are evaluated against the
generation that contains them, so a value and the keys it references always
come from the same record.
