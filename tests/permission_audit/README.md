# Permission audit mini app

A self-contained, re-runnable DRF app that traces **which permission checks
a real request actually goes through** before any new permission is added.
Routes are produced by a real `SimpleRouter` registration; requests are
driven through the Django test client / `APIClient`, not by calling view
methods directly.

## How to run

```sh
# pytest form, assertions on every check and every business handler
.venv/bin/python -m pytest -v -o addopts= tests/permission_audit/

# standalone form, prints the full trace per request
.venv/bin/python -m tests.permission_audit.run_demo
```

No external services are required (in-memory SQLite, synced via
`run_syncdb`, mirroring the suite's `--no-migrations` setup).

## Layout

- `permissions.py` — tracing permission classes; every
  `has_permission` / `has_object_permission` call is appended to
  `PERMISSION_CALL_LOG` with class, layer, action and object pk.
- `views.py` — `ReportViewSet(GenericViewSet)` with the three routing
  situations below; every handler records itself in `BUSINESS_CALL_LOG`,
  including whether it received an object and how it loaded it.
- `urls.py` — `SharedCollectionRouter` (a `SimpleRouter` subclass) that
  swaps the stock list `Route` for one mapping both `get` and `post`.
- `run_demo.py` — standalone runner that configures Django in-process and
  prints the full trace table.
- `test_permission_trace.py` — 11 tests pinning every finding below.

## How the routes are actually bound

| URL pattern | Name | Router method map | `permission_classes` source |
| --- | --- | --- | --- |
| `^reports/$` | `report-list` | `{get: list, post: submit_report}` | action override on the merged Route |
| `^reports/(?P<pk>[^/.]+)/$` | `report-detail` | `{get: retrieve, put: update, patch: partial_update, delete: destroy}` | class default only (no override in initkwargs) |
| `^reports/(?P<pk>[^/.]+)/publish/$` | `report-publish` | `{post: publish}` | `@action(permission_classes=[TracingIsStaff])` |
| `^reports/(?P<pk>[^/.]+)/archive/$` | `report-archive` | `{post: archive}` | `@action(permission_classes=[TracingIsStaff])` |

Two DRF constraints drive this shape and are worth knowing before adding
permissions:

1. `@action` cannot decorate the reserved names `list`/`create`/etc.
   (`routers.SimpleRouter.get_routes` raises `ImproperlyConfigured`), and an
   empty `url_path` falls back to the method name, so two handlers cannot be
   put on the bare collection URL via a plain `@action`. The router subclass
   emits the merged `Route` using the same `ViewSet.as_view(action_map,
   **initkwargs)` call every router-generated view uses.
2. A `Route` carries one `initkwargs` dict, hence one
   `permission_classes` list for **all** HTTP methods on that pattern.
   `MethodMapper` cannot give GET and POST different classes on the same URL;
   the shared policy (`TracingPublicReadAuthenticatedWrite`) therefore
   branches on `request.method`.

## What each request actually checks (measured, not assumed)

Request-layer check = `APIView.initial()` -> `check_permissions()`.
Object-layer check = `GenericAPIView.get_object()` ->
`check_object_permissions()`, which only runs when the handler calls
`self.get_object()`.

| # | Request | Status | Permission calls observed | Handler got object? |
| --- | --- | --- | --- | --- |
| 1a | GET `/reports/` anonymous | 200 | request: `TracingPublicReadAuthenticatedWrite` | `list` ran, no object |
| 1b | POST `/reports/` anonymous | 403 | request: same class, denied on method branch | handler never ran |
| 1c | POST `/reports/` authenticated | 201 | request: same class, allowed | `submit_report` ran, no object |
| 2a | GET `/reports/1/` anonymous | 200 | request **and** object: `TracingAllowAny` (pk=1) | `retrieve`, yes |
| 2b | PATCH `/reports/1/` anonymous | 200 | request **and** object: `TracingAllowAny` (pk=1) | `partial_update`, yes |
| 2c | DELETE `/reports/1/` anonymous | 204 | request **and** object: `TracingAllowAny` (pk=1) | `destroy`, yes |
| 3a | POST `.../publish/` anonymous | 403 | request only: `TracingIsStaff` | handler never ran |
| 3b | POST `.../publish/` non-staff user | 403 | request only: `TracingIsStaff` | handler never ran |
| 3c | POST `.../publish/` staff | 200 | request only: `TracingIsStaff` — **object layer never runs** | `publish`, yes, via `get_object_or_404` |
| 3d | POST `.../archive/` staff | 200 | request **and** object: `TracingIsStaff` (pk=1) | `archive`, yes, via `self.get_object()` |

Key conclusions:

- The two methods on one URL share a single policy class; the public read
  survives as the `SAFE_METHODS` branch, not as a separate permission entry.
- Every default-inherited detail route inherits the class-level
  `TracingAllowAny`, including writes — anonymous PATCH/DELETE succeed today.
- `publish` declares an object-aware permission but bypasses the object
  layer because it loads the row with `get_object_or_404`. The
  `has_object_permission` of `TracingIsStaff` is provably never consulted.
  `archive` is the in-app control showing the same policy does run the
  object layer when `self.get_object()` is used.

## Step-by-step rollout checklist

Each step is independently shippable and reversible; re-run the two commands
above after every step.

- [ ] **Step 0 — Freeze the baseline.** Keep the tracing tests green. They
  document the current checks, so any later change that silently removes a
  check fails the suite instead of reaching production.
- [ ] **Step 1 — Keep the public reads.** Leave `GET /reports/` and
  `GET /reports/{pk}/` reachable anonymously. On the shared collection Route
  this means preserving the `SAFE_METHODS` branch; do not replace the merged
  Route's policy with a blanket `IsAuthenticated` (that would also lock GET).
- [ ] **Step 2 — Lock collection writes.** Tighten only the non-safe branch
  of the shared collection policy so `POST /reports/` requires
  authentication (the audit app already models this; a production policy is
  `IsAuthenticated` plus an explicit safe-method allow). Verify 1a stays 200
  while 1b stays 403.
- [ ] **Step 3 — Replace the class default.** Swap
  `permission_classes = [AllowAny]` on `ReportViewSet` for
  `IsAuthenticatedOrReadOnly` (or an equivalent tracing class). This closes
  anonymous PATCH/PUT/DELETE on `report-detail` while leaving retrieve public;
  tests 2a must stay 200 and 2b/2c must turn into 401/403 for anonymous.
- [ ] **Step 4 — Restore object-level enforcement on `publish`.** Make
  `publish` call `self.get_object()` (delete the manual
  `get_object_or_404`), matching `archive`. After this, a staff request must
  show both permission layers in the trace; add a regression test asserting
  `has_object_permission` is recorded for publish.
- [ ] **Step 5 — Add the object rule once enforcement exists.** With Step 4
  in place, introduce the actual object-level predicate (ownership,
  report state, etc.). Adding it before Step 4 has no effect, because the
  object layer is currently skipped.
- [ ] **Step 6 — Re-audit and remove tracing.** Once all steps land, replace
  the tracing classes with production permissions and keep the non-tracing
  assertions (status codes + handler/object evidence).

## Public reads that must stay open, and what still needs evidence

**Retain as public (already evidenced by the tests):**

- `GET /reports/` — list, request-layer check only, no object involved.
- `GET /reports/{pk}/` — retrieve, both layers run; keep the safe-method
  allow when changing the class default in Step 3.

**Detail operations that still need independent evidence before tightening:**

- `POST /reports/{pk}/publish/` — today only the request layer is proven to
  run. There is **no evidence that any object-level rule is evaluated**, so
  tightening to a per-object policy requires Step 4 first plus a test that
  observes the object check; a rule written now would be dead code.
- `PUT`/`PATCH`/`DELETE /reports/{pk}/` — object checks do run, but only
  against `AllowAny`. A real predicate (owner-only, role-on-state) needs its
  own allow/deny test fixtures per object state; the current suite only
  proves *where* the hook runs, not *what* it should decide.
- `POST /reports/{pk}/archive/` — both layers already run, so it can adopt
  the object rule immediately in Step 5; use it as the reference
  implementation for publish.
