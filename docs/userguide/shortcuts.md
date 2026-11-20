---
title: Shortcuts
description: Understanding permission query functions and their relationships.
---

# Permission Query Functions

Django Guardian provides several shortcut functions for querying permissions. Understanding their relationships and differences is crucial for proper usage.

## Permission Query Functions Overview

When working with object permissions in django-guardian, there are three main functions for querying permissions:

### Function Relationships

- **`get_perms(user, obj)`**: Returns ALL permissions (user + group permissions combined)
- **`get_user_perms(user, obj)`**: Returns ONLY direct user permissions
- **`get_group_perms(user, obj)`**: Returns ONLY group permissions

For any user and object: `get_perms(user, obj) = get_user_perms(user, obj) + get_group_perms(user, obj)`

### Key Differences

| Function | Returns | Type | Includes Groups | Use Case |
|----------|---------|------|----------------|----------|
| `get_perms()` | All permissions | `list[str]` | Yes | General permission checking |
| `get_user_perms()` | Direct user permissions only | `QuerySet` | No | Permission management interfaces |
| `get_group_perms()` | Group permissions only | `QuerySet` | N/A | Understanding permission inheritance |

## Important Notes

- **Inactive users** (`is_active=False`): All functions return empty results
- **Return types**: `get_perms()` returns a list, while `get_user_perms()` and `get_group_perms()` return QuerySets
- **Group behavior**: When `get_group_perms()` is called with a user, it returns permissions from ALL groups the user belongs to
- **Superusers**: `get_perms()` returns all available permissions for the object's model

## Common Use Cases

### General Permission Checking

Use `get_perms()` when you need to check if a user has a specific permission, regardless of whether it comes from direct assignment or group membership:

```python
from guardian.shortcuts import get_perms

user_perms = get_perms(user, article)
if 'change_article' in user_perms:
    # User can change this article (either directly or through groups)
    allow_editing = True
```

### Permission Management Interfaces

Use `get_user_perms()` and `get_group_perms()` when building interfaces that show the source of permissions:

```python
from guardian.shortcuts import get_user_perms, get_group_perms

# Show user what permissions they have directly
direct_perms = get_user_perms(user, article)

# Show user what permissions they have through groups
group_perms = get_group_perms(user, article)

# Display in UI: "You have 'edit' permission directly, and 'delete' through the 'Editors' group"
```

### Permission Auditing

Use individual functions to understand permission inheritance:

```python
from guardian.shortcuts import get_perms, get_user_perms, get_group_perms

all_perms = get_perms(user, document)
direct_perms = list(get_user_perms(user, document).values_list('codename', flat=True))
group_perms = list(get_group_perms(user, document).values_list('codename', flat=True))

print(f"All permissions: {all_perms}")
print(f"Direct permissions: {direct_perms}")
print(f"Group permissions: {group_perms}")
```

### Paginated Membership Listing

Compliance pages that list who can access a single object should use
`get_users_with_perms_paged()`. It paginates in the database with
`LIMIT`/`OFFSET` instead of loading the full member list into memory first,
and returns a `PagedUsersWithPerms` object together with pagination metadata:

```python
from guardian.shortcuts import get_users_with_perms_paged

page = get_users_with_perms_paged(document, page=1, page_size=25)
for user in page.results:
    ...  # render one row per authorized user

page.total_count   # total distinct authorized users
page.total_pages   # number of pages at this page size
page.has_next      # whether another page exists
```

Duplicate authorization rows and users reachable through several groups (or
both a direct and a group grant) are returned once because the underlying
queryset is always `DISTINCT`. Ordering is deterministic: the user primary
key is appended as the final tie-breaker, so users sharing every requested
sort value keep a fixed position and concatenating consecutive pages yields
the complete authorized member set without overlaps or gaps. Pass custom
sort fields with `order_by`; the primary key tie-breaker is still applied:

```python
get_users_with_perms_paged(document, page=2, page_size=25, order_by="last_login")
```

Inactive users (`is_active=False`) are included: like
`get_users_with_perms()`, this is a membership query over stored
authorizations and does not filter on account status.

**Query count.** Each page costs one `COUNT(*)` query plus one
`LIMIT`/`OFFSET` query — two queries per page regardless of `page_size`;
there is no per-row query. Pass `count_total=False` to skip the count and
serve a page with a single query (then `total_count`, `total_pages` and
`has_next` are `None` and end-of-data is detected from a short result page).

**Changes during pagination.** `OFFSET`/`LIMIT` is evaluated per request
against the current database state; no snapshot is taken. Pages are stable
as long as the underlying authorizations do not change, but grants added or
removed while a client is walking the pages shift offsets: an inserted grant
before the current offset can repeat a row on the next page, a removed grant
can skip one. For a point-in-time consistent walk, wrap the requests in a
transaction using a repeatable-read isolation level, or paginate a frozen
snapshot of the membership.

### Selective Permission Removal

Use `get_user_perms()` when you need to remove only direct permissions without affecting group permissions:

```python
from guardian.shortcuts import get_user_perms, remove_perm

# Remove only direct user permissions, keep group permissions intact
direct_perms = get_user_perms(user, article)
for perm in direct_perms:
    remove_perm(perm.codename, user, article)
```

## Common Pitfalls

!!! warning "Don't Confuse get_user_perms() with get_perms()"

    Many developers expect `get_user_perms()` to return the same results as `get_perms()`, but this is incorrect:

    ```python
    # This user has permissions through group membership only
    user.groups.add(editors_group)  # editors_group has 'change_article' permission

    get_perms(user, article)      # Returns: ['change_article']
    get_user_perms(user, article) # Returns: [] (empty - no direct permissions)
    ```

!!! tip "Use get_perms() for Most Cases"

    Unless you specifically need to distinguish between direct and inherited permissions, use `get_perms()` for general permission checking.

## Examples

### Basic Usage

```python
from django.contrib.auth.models import User
from guardian.shortcuts import assign_perm, get_perms, get_user_perms, get_group_perms
from myapp.models import Article

user = User.objects.get(username='john')
article = Article.objects.get(pk=1)

# Assign direct permission
assign_perm('change_article', user, article)

# Check all permissions (includes direct + group)
all_perms = get_perms(user, article)  # ['change_article']

# Check only direct permissions
direct_perms = get_user_perms(user, article)  # QuerySet with 'change_article'

# Check only group permissions
group_perms = get_group_perms(user, article)  # Empty QuerySet
```

### Group Permissions Example

```python
from django.contrib.auth.models import User, Group
from guardian.shortcuts import assign_perm, get_perms, get_user_perms, get_group_perms

user = User.objects.get(username='jane')
group = Group.objects.create(name='editors')
article = Article.objects.get(pk=1)

# Add user to group and assign group permission
user.groups.add(group)
assign_perm('delete_article', group, article)

# Now check permissions
all_perms = get_perms(user, article)        # ['delete_article']
direct_perms = get_user_perms(user, article) # Empty QuerySet
group_perms = get_group_perms(user, article)  # QuerySet with 'delete_article'
```

### Mixed Permissions Example

```python
# User has both direct and group permissions
assign_perm('change_article', user, article)  # Direct permission
assign_perm('delete_article', group, article) # Group permission (user is in group)

all_perms = get_perms(user, article)        # ['change_article', 'delete_article']
direct_perms = get_user_perms(user, article) # QuerySet with 'change_article'
group_perms = get_group_perms(user, article)  # QuerySet with 'delete_article'
```
