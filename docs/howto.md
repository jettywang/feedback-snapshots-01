# How to Hash a Password

*argon2-cffi* comes with an high-level API and uses the officially recommended low-memory Argon2 parameters that result in a verification time of 40--50ms on recent-ish hardware.

:::{warning}
The current memory requirement is set to rather conservative 64 MB.
However, in memory constrained environments such as Docker containers that can lead to problems.
One possible non-obvious symptom are apparent freezes that are caused by swapping.

Please check {doc}`parameters` for more details.
:::

Unless you have any special requirements, all you need to know is:

```python
>>> from argon2 import PasswordHasher
>>> ph = PasswordHasher()
>>> hash = ph.hash("correct horse battery staple")
>>> hash  # doctest: +SKIP
'$argon2id$v=19$m=65536,t=3,p=4$MIIRqgvgQbgj220jfp0MPA$YfwJSVjtjSU0zzV/P3S9nnQ/USre2wvJMjfCIjrTQbg'
>>> ph.verify(hash, "correct horse battery staple")
True
>>> ph.check_needs_rehash(hash)
False
>>> ph.verify(hash, "Tr0ub4dor&3")
Traceback (most recent call last):
...
argon2.exceptions.VerifyMismatchError: The password does not match the supplied hash
```

A login function could thus look like this:

```{literalinclude} login_example.py
```

---

While the {class}`argon2.PasswordHasher` class has the aspiration to be good to use out of the box, it has all the parametrization you'll need.

## Adding an Application-Managed Pepper

If your application keeps an additional secret outside of the password
database -- sometimes called a *pepper* -- use the separate
{class}`argon2.PepperedPasswordHasher` entry point.
It wraps regular Argon2 digests in a small envelope that records the key
generation, and asks a caller-supplied {class}`argon2.KeyProvider` for the
matching key:

```python
>>> from argon2 import KeyProvider, PepperedPasswordHasher
>>> class KeyRing(KeyProvider):
...     def __init__(self, keys, current):
...         self._keys = keys
...         self._current = current
...     def current_generation(self):
...         return self._current
...     def key_for_generation(self, generation):
...         return self._keys.get(generation)
>>> keys = {0: b"old-key", 1: b"new-key"}
>>> ph = PepperedPasswordHasher(KeyRing(keys, 0))
>>> old_digest = ph.hash("correct horse battery staple")
>>> ph = PepperedPasswordHasher(KeyRing(keys, 1))
>>> receipt = ph.verify(old_digest, "correct horse battery staple")
>>> receipt.status.value, receipt.needs_rehash
('rotated', True)
>>> migrated = ph.migrate(old_digest, "correct horse battery staple")
>>> ph.verify(migrated, "correct horse battery staple").status.value
'current'
```

The provider, not *argon2-cffi*, owns the key material and decides which
generation is approved for new writes.
Old digests are always verified with the generation recorded in their
envelope.
After a rotation, an old user therefore still verifies and receives a receipt
with `status` {attr}`argon2.PepperStatus.ROTATED` and `needs_rehash` set to
`True`.
New registrations only ever use `current_generation()`.
When that generation's material is unavailable,
{meth}`~argon2.PepperedPasswordHasher.hash` raises
{exc}`argon2.exceptions.KeyMaterialUnavailableError` instead of falling back to
another generation.

The same error is raised when a digest's recorded generation is unavailable,
which is deliberately distinct from a wrong password
({exc}`argon2.exceptions.VerifyMismatchError`).
Keep old generations available until every record has been migrated.

Migration is explicit and only happens after a successful verification:
{meth}`~argon2.PepperedPasswordHasher.migrate` re-verifies the password, writes
a new digest with the current generation, and returns the original digest
unchanged if no rehash is needed.
Never migrate on a failed login.
A process whose configuration is older than a digest's generation reports
{attr}`argon2.PepperStatus.FUTURE` and refuses to migrate it, so records are
never downgraded.

The pepper and all passwords in the example live only in memory; neither is
included in the encoded digest.

