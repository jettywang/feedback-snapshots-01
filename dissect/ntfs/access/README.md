# Offline DACL access auditing

`dissect.ntfs.access` answers one narrow, offline question:

> Given an **explicit token SID set**, an object type and a requested access
> mask, what can the DACL of a parsed NTFS security descriptor **prove** about
> the access decision?

It is built on the `SecurityDescriptor` / `ACL` / `ACE` parser in
`dissect.ntfs.secure` and never reads the host's current user, group
memberships, privileges, logon session or claims. Every input needed for an
evaluation is supplied by the caller, so the same descriptor and token always
produce the same, re-computable answer.

## The three-valued decision

A binary allow/deny answer is unsafe for offline review because some ACEs
cannot be evaluated without context that was deliberately not supplied.
Results are therefore three-valued (`Decision`):

| Decision    | Meaning                                                                          |
|-------------|----------------------------------------------------------------------------------|
| `ALLOW`     | The DACL proves that every requested non-privilege bit is granted.               |
| `DENY`      | The DACL proves that at least one requested bit is denied or never granted. This is a hard result, even when other ACEs are unevaluable. |
| `UNDECIDED` | An applicable ACE cannot be evaluated from the supplied context and an allow cannot be proven. |

`UNDECIDED` is deliberately conservative: an unevaluable ACE is never silently
skipped and then followed by an `ALLOW`.

## What is modelled

### Generic right mapping

Generic bits (`GENERIC_READ/WRITE/EXECUTE/ALL`) in both the request and the ACE
masks are mapped first, using the file/directory generic mapping from the
Windows SDK (`FILE_GENERIC_READ = 0x120089`, `FILE_GENERIC_WRITE = 0x116`,
`FILE_GENERIC_EXECUTE = 0x1200A0`, `FILE_ALL_ACCESS = 0x1F01FF`). Files and
directories share one mapping. Only `ObjectType.FILE` and `ObjectType.DIRECTORY`
are known; any other object type raises `ValueError`.

### Sequential allow/deny walk

ACEs are examined in their **stored order**, and every step is recorded in
`AccessDecision.trace` with the raw mask, the post-mapping effective mask and
the action taken. Deny ACEs take effect at the position they appear; a denied
bit cannot be restored by a later allow. For ordinary allow/deny ACEs the final
granted/denied *bit set* is order-independent (Windows unions all grants and
all denials), but the recorded path and the intermediate masks differ — see the
ordering example below.

### Inherit-only and inherited ACEs

* `INHERIT_ONLY_ACE` (`0x08`) ACEs protect child objects, not the object that
  carries the DACL, so they are skipped (and logged).
* `INHERITED_ACE` (`0x10`) ACEs are fully effective on the current object.

### NULL DACL versus empty DACL

These are distinct states with opposite outcomes:

* A **NULL DACL** (no DACL present) grants every access to every token → `ALLOW`.
* An **empty DACL** (present, zero ACEs) grants nothing → `DENY` for an
  ordinary request; under `MAXIMUM_ALLOWED` it completes with a zero granted
  mask.

### Owner and OWNER RIGHTS

The owner implicitly receives `READ_CONTROL` and `WRITE_DAC`. An
`OWNER RIGHTS` (`S-1-3-4`) ACE suppresses that implicit grant and constrains
the owner to the rights it lists.

### MAXIMUM_ALLOWED

A `MAXIMUM_ALLOWED` request returns the union of every proven grant. Deny ACEs
do not shrink this union (matching the documented access-check behaviour), and
a NULL DACL returns `FILE_ALL_ACCESS`.

## What forces UNDECIDED

| Construct                      | Why it cannot be decided offline                              |
|--------------------------------|---------------------------------------------------------------|
| Callback/conditional ACE (`*_CALLBACK*`) with condition data | Token claims, device attributes and the conditional expression are not supplied. |
| Property-scoped object ACE (`*_OBJECT*` with an ObjectType GUID) | No active property/attribute GUID is supplied. |
| Compound ACE (`ACCESS_ALLOWED_COMPOUND`) | Requires the server identity of an impersonation chain. |
| `ACCESS_SYSTEM_SECURITY`       | Gated on `SeSecurityPrivilege`, which is never modelled.      |
| Any other applicable special ACE | No offline semantics are assumed.                            |

ACEs whose trustee SID is not in the token are simply skipped, and an
unevaluable ACE for an unrelated trustee does not make the result `UNDECIDED`.

## What this interface deliberately does NOT cover

These Windows access-control semantics are outside the model. Each returned
`AccessDecision.coverage` lists the same set.

* **Privileges.** `SeBackupPrivilege`, `SeRestorePrivilege`,
  `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, etc. are not modelled, so
  privilege-based bypass and `ACCESS_SYSTEM_SECURITY` cannot be evaluated.
* **Mandatory integrity control.** The token integrity level versus the
  `SYSTEM_MANDATORY_LABEL` ACE (no-read-up / no-execute-up / no-write-up policy)
  is not evaluated.
* **SACL auditing and `SYSTEM_*` ACEs.** Audit, alarm, resource attribute,
  scoped policy ID, process trust label and `SYSTEM_ACCESS_FILTER` (central
  access policy) ACEs do not participate in the discretionary check here.
* **Conditional expressions and claims.** Callback ACE conditions would need
  token and device claims plus an expression evaluator.
* **Share ACLs and inheritance at creation.** Only the on-disk DACL is
  considered; share-level permissions and how the DACL was originally inherited
  or defaulted are out of scope.
* **Other object managers.** Only NTFS file/directory generic mappings are
  known; registry, service, token and other object-type mappings are rejected.

## Example

```python
from dissect.ntfs.access import (
    AceSpec, Decision, build_descriptor, evaluate_descriptor_bytes,
)

user = "S-1-5-21-10-20-30-1000"
token = [user, "S-1-5-32-545"]

descriptor = build_descriptor([
    AceSpec("ACCESS_DENIED", user, 0x2),       # FILE_WRITE_DATA
    AceSpec("ACCESS_ALLOWED", user, 0x1F01FF), # FILE_ALL_ACCESS
])

result = evaluate_descriptor_bytes(descriptor, token, 0x1F01FF)
print(result.render_path())
assert result.decision == Decision.DENY
assert result.denied_mask == 0x2
```

A full, runnable walk-through including ACE ordering, NULL versus empty DACLs,
generic mapping, inheritance and conditional ACEs is in
`examples/offline_access_audit_demo.py`.

## Ordering example

Reordering plain allow/deny ACEs changes the recorded walk but not the final
bit set, whereas a misordered **conditional** ACE is the case where a naive
tool could reach the wrong conclusion. This evaluator returns `UNDECIDED` (or a
hard `DENY` if an explicit deny matches) regardless of position:

```python
conditional_first = build_descriptor([
    AceSpec("ACCESS_ALLOWED_CALLBACK", user, 0x3, application_data=b"\x00" * 4),
    AceSpec("ACCESS_DENIED", user, 0x1),
])
# -> DENY (explicit deny is decisive) and the callback ACE is logged undecided,
#    never skipped and never treated as an allow.
```
