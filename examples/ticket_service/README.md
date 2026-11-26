# Ticket Service — optional operation-permit view on top of OmniAuth

A demo Rack app showing how to layer an *optional* operation-permit view
onto OmniAuth logins without changing how the user profile (auth hash)
behaves today.

## The idea

- The **profile view** (`GET /profile`) keeps the existing behavior: user
  info and extra claims are merged for display (extra wins on duplicate
  keys). This merge is display sugar only.
- The **permission view** (`TicketService::PermissionView`) never reads
  the merged profile. A permit is decided by three things together:
  1. **strategy registration** — the provider determines the tenant
     (`PROVIDER_TENANTS`), never a user-supplied claim;
  2. **the policy registry** — `PolicyRegistry` approves exactly one claim
     source (auth-hash layer + key + required value) per tenant/operation;
  3. **the actual claim source** — the claim is read from the approved
     layer (`info` or `extra`) of the raw auth hash only.
- Because of (3), a same-named key in the other layer — or a lucky merge
  order — can never stand in for an approved source.
- Login state and permit state are reported separately
  (`GET /permits/export`), so "logged in but the permit is unavailable or
  denied" is clearly distinguishable from "logged in and permitted".
- Every export attempt from the low-level tickets page
  (`POST /tickets/export`) is written to the `AuditLog` with the tenant
  and the claim layer that took effect.

## The demo scenario

Two fictional directory providers (`alpha_directory`, `beta_directory`)
vouch for the same person ("Casey Jordan") and place the same
`role: "ticket_exporter"` placeholder in **both** the `info` and `extra`
layers. The registry approves only tenant `alpha`'s `extra`-layer claim.
Both logins succeed and their merged profiles are identical, yet only the
alpha principal may export tickets.

## Run the tests

```sh
rspec examples/ticket_service/spec
```

## Files

- `app.rb` — Rack app, routes, tenant mapping, registry wiring
- `lib/ticket_service/policy_registry.rb` — approved claim sources per tenant/operation
- `lib/ticket_service/permission_view.rb` — permit decisions with explicit statuses
- `lib/ticket_service/audit_log.rb` — audit trail (tenant + effective layer)
- `lib/ticket_service/providers.rb` — the two fictional OmniAuth strategies
- `spec/ticket_service_spec.rb` — end-to-end and unit coverage
