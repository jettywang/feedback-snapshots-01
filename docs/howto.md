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

## Verification receipts and migration windows

A successful verification only proves that a stored digest is usable; it does not prove that its metadata was fully present in the hash text or that the record has already been migrated.
If your password library holds more than one generation of records, {meth}`argon2.PasswordHasher.verify_with_report` returns a structured {class}`argon2.VerificationReport` that separates:

- the low-level cryptographic outcome ({class}`argon2.VerificationOutcome`),
- the parsing evidence from {func}`argon2.inspect_hash`, including values the library inferred for legacy Argon2 v1.2 records, and
- whether the record fits a registered {class}`argon2.VerificationPolicy` and whether it {attr}`argon2.VerificationReport.needs_rehash`.

The three independent failure modes -- an inapplicable format, uninterpretable parameters, and a genuine password mismatch -- therefore get distinct outcomes instead of one boolean.
The regular {meth}`~argon2.PasswordHasher.verify` method keeps its original return value and exception contract.

```{literalinclude} login_report_example.py
```

---

While the {class}`argon2.PasswordHasher` class has the aspiration to be good to use out of the box, it has all the parametrization you'll need.
