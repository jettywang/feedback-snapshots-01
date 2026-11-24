# Field-visibility-consistent list endpoint

A self-contained DRF demo showing how one field-visibility policy can drive
serialization, ordering, filtering, search, pagination metadata **and** export,
so the public representation and the query that produces it can never diverge.

## The single source of truth

`visibility.FieldVisibility` resolves the fields a caller may see:

- `PUBLIC_FIELDS = ('id', 'name', 'category', 'status')` — any authenticated user.
- `STAFF_ONLY_FIELDS = ('internal_note', 'risk_score')` — staff/admins only.

Every other component derives its allowed set from this class rather than
keeping its own allow-list:

| Concern              | Component                          | How visibility is applied                                   |
| -------------------- | ---------------------------------- | ----------------------------------------------------------- |
| Representation       | `CaseRecordSerializer`             | Drops hidden fields for non-staff callers.                  |
| Ordering             | `VisibilityOrderingFilter`         | Intersects ordering fields with the visible set.            |
| Exact filtering      | `VisibilityDjangoFilterBackend`    | Drops query params targeting hidden fields.                 |
| Free-text search     | `VisibilitySearchFilter`           | Removes hidden fields from the search field list.           |
| Pagination metadata  | `VisibilityPageNumberPagination`   | Counts the visible queryset and echoes `visible_fields`.    |
| Export               | `CSVCasesRenderer`                 | Columns come from the same visible-field policy.            |

## Rules, made verifiable

1. **Hidden fields never decide membership.** For a non-staff caller a filter,
   ordering term, or search term that references an internal field is removed
   before it reaches the ORM. An internal value therefore cannot change which
   rows appear, and cannot be used as an oracle to probe hidden data. Free-text
   search is confined to visible fields, so a term that exists only internally
   behaves identically to a term that exists nowhere.
2. **Admins keep the full approved surface.** Staff may filter, order, search
   and read every field listed in the policy (the *approved* set); nothing is
   exposed beyond it.
3. **Pagination metadata is consistent.** `count` is computed from the same
   visibility-filtered queryset that produces `results`, so an ignored hidden
   filter leaves `count` unchanged. The envelope also returns `visible_fields`,
   letting a client cross-check that the rows and the metadata follow one rule.
4. **Export equals representation.** The CSV columns are exactly the caller's
   visible fields, read from the already-serialized rows.

## Synthetic data

`tests.py` builds two datasets, `alpha` and `beta`, whose rows are identical on
every public field and differ only in `internal_note` / `risk_score`. One row is
distinguishable *only* through its internal values, which is what proves a
hidden field cannot drive result membership. `dataset` partitions the fixtures
but is deliberately not an API field.

## Run

```sh
.venv/bin/python -m pytest -q -o addopts= tests/field_visibility_demo/tests.py
```

Endpoints (under the test root urlconf):

- `GET /api/field-visibility/cases/` — list, filter, search, order, paginate.
- `GET /api/field-visibility/cases/<id>/` — detail (same serializer policy).
- Add `?format=csv` for the visibility-consistent CSV export.
