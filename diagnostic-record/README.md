# Request diagnostic hand-off — project-lead record

This directory is the shareable material for one failed OpenStack API call.
It is generated offline, with local substitutes only, and contains no real
credentials or addresses.

Regenerate it (from the repository root):

```sh
.venv/bin/python -m keystoneauth1.tests.unit.diagnostic_scenario \
    --output diagnostic-record
```

## What was simulated

1. **Catalog selection** — a local catalog substitute holds a `compute`
   service. The request asks for it by `service_type` and `service_name`
   only; the endpoint is taken from that catalog entry.
2. **Re-authentication** — the business substitute answers the first
   exchange with `401`. The session invalidates the auth plugin, fetches a
   fresh token, and repeats the same request.
3. **Final error** — the repeated exchange answers `500` with a synthetic
   error body, which the session turns into `InternalServerError`.

Three fictional private markers are placed in the three stages:

| Stage | Where the marker lives | Value |
| --- | --- | --- |
| Catalog | catalog entry `service.name` | `fictional-catalog-name-Zx81` |
| Re-authentication | 401 response `error.details` | `fictional-reauth-token-Qw77` |
| Final error | 500 response `error.details` | `fictional-error-detail-Rt42` |

## The two files

- `public.json` — the shareable export. Same `request_id` on every stage,
  with `stages` in the order `catalog, request, response, reauth, request,
  response, error`. Service name and endpoint appear as
  `{"redacted": true, "sha256": ...}`; identity headers appear as
  `{SHA256}...`; each private marker is replaced by its digest. None of the
  three marker literals appear in this file.
- `internal.json` — the controlled debugging record for the same
  `request_id`. It keeps the real catalog name, endpoint and both identity
  tokens, so an engineer can match a digest in `public.json` back to the
  actual cause.

## How to read it

- Start from `request_id`; it is identical in both files and on every
  stage.
- The `reauth` stage (with `triggered: true`, `invalidated: true`,
  `retried: true`) marks the boundary between the two exchanges. The second
  `request` stage carries `after_reauth: true`.
- `policy` records which independent switches were approved for this call:
  here `service_name`, `endpoint`, `user_token` and `service_token` are all
  withheld.
- `private_marker_digests` lists the digests of the configured private
  markers. A digest in `public.json` can be looked up against
  `internal.json` or its `private_markers` list.

`request_kind` distinguishes a normal (`standard`) call from one that also
carries a service identity (`dual-token`).
