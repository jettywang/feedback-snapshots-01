# Grape Entity view -> role migration evidence

## Example A — directly migratable (old view == new role)

### case admin/full
- public output (old == new): `{sku: "GX-100", name: "Fictional Gadget", cost_price: "42.00", marketing_blurb: "shiny", margin: "11%", recall_notice: "none", supplier: "Acme Fictional Co", audit: {tag: "TAG-9", reviewer: "reviewer-jules"}}`
- Pro output   (old == new): `{sku: "GX-100", name: "Fictional Gadget", marketing_blurb: "shiny", margin: "11%", recall_notice: "none", supplier: "Acme Fictional Co", audit: {tag: "TAG-9", reviewer: "reviewer-jules"}, pro_badge: "PRO"}`
- nested entity actually constructed + options received:
    - `NewGadgetEntity` got `{role: :admin, capabilities: [:show_blurb]}`
    - `NewAuditTagEntity` got `{role: :admin, capabilities: [:show_blurb], attr_path: [], root: nil, only: nil, except: nil}`
- condition call order (NEW pipeline, short-circuit visible):
    - sku exposed=true
    - name exposed=true
    - cost_price exposed=true
        - 1/1 HashCondition[{role: :admin}] => true
    - marketing_blurb exposed=true
        - 1/1 BlockCondition["role_capability:show_blurb"] => true
    - margin exposed=true
        - 1/1 BlockCondition["role_if:"] => true
    - recall_notice exposed=true
        - 1/1 HashCondition(unless)[{role: :guest}] => true
    - warehouse_bin exposed=false
        - 1/1 HashCondition[{role: :staff}] => false
    - supplier exposed=true
        - 1/1 HashCondition[{role: :admin}] => true
    - audit exposed=true
        - 1/1 BlockCondition["role_if::admin|:staff"] => true
    - tag exposed=true
    - reviewer exposed=true
        - 1/1 HashCondition[{role: :admin}] => true

### case staff/staff
- public output (old == new): `{sku: "GX-100", name: "Fictional Gadget", marketing_blurb: "shiny", margin: "11%", recall_notice: "none", warehouse_bin: "B-7", audit: {tag: "TAG-9"}}`
- Pro output   (old == new): `{sku: "GX-100", name: "Fictional Gadget", marketing_blurb: "shiny", margin: "11%", recall_notice: "none", warehouse_bin: "B-7", audit: {tag: "TAG-9"}, cost_price: "42.00", pro_badge: "PRO"}`
- nested entity actually constructed + options received:
    - `NewGadgetEntity` got `{role: :staff, capabilities: [:show_blurb]}`
    - `NewAuditTagEntity` got `{role: :staff, capabilities: [:show_blurb], attr_path: [], root: nil, only: nil, except: nil}`
- condition call order (NEW pipeline, short-circuit visible):
    - sku exposed=true
    - name exposed=true
    - cost_price exposed=false
        - 1/1 HashCondition[{role: :admin}] => false
    - marketing_blurb exposed=true
        - 1/1 BlockCondition["role_capability:show_blurb"] => true
    - margin exposed=true
        - 1/1 BlockCondition["role_if:"] => true
    - recall_notice exposed=true
        - 1/1 HashCondition(unless)[{role: :guest}] => true
    - warehouse_bin exposed=true
        - 1/1 HashCondition[{role: :staff}] => true
    - supplier exposed=false
        - 1/1 HashCondition[{role: :admin}] => false
    - audit exposed=true
        - 1/1 BlockCondition["role_if::admin|:staff"] => true
    - tag exposed=true
    - reviewer exposed=false
        - 1/1 HashCondition[{role: :admin}] => false

### case guest/public
- public output (old == new): `{sku: "GX-100", name: "Fictional Gadget"}`
- Pro output   (old == new): `{sku: "GX-100", name: "Fictional Gadget"}`
- nested entity actually constructed + options received:
    - `NewGadgetEntity` got `{role: :guest, capabilities: []}`
- condition call order (NEW pipeline, short-circuit visible):
    - sku exposed=true
    - name exposed=true
    - cost_price exposed=false
        - 1/1 HashCondition[{role: :admin}] => false
    - marketing_blurb exposed=false
        - 1/1 BlockCondition["role_capability:show_blurb"] => false
    - margin exposed=false
        - 1/1 BlockCondition["role_if:"] => false
    - recall_notice exposed=false
        - 1/1 HashCondition(unless)[{role: :guest}] => false
    - warehouse_bin exposed=false
        - 1/1 HashCondition[{role: :staff}] => false
    - supplier exposed=false
        - 1/1 HashCondition[{role: :admin}] => false
    - audit exposed=false
        - 1/1 BlockCondition["role_if::admin|:staff"] => false

## Example B — inherited gate + parent short-circuit

### auditor summary — over-exposure vs not-evaluated
- OVER-EXPOSED by naive rewrite (order change made a gate pass): [:archive_code, :risk_score]
- NOT EVALUATED in OLD rule (parent gate short-circuited the chain): ["archive_code (1 of its conditions ran; the rest were skipped)"]
- NO GATE AT ALL (unconditional, evaluated trivially / always present): [:doc_id, :internal_note]

### role=admin
- OLD public output   : `{doc_id: "DOC-7", custodian: {name: "custodian-priya"}, archive_code: "ARC-X", internal_note: "NOTE-visible-always", risk_score: 9}`
- NAIVE public output : `{doc_id: "DOC-7", custodian: {name: "custodian-priya"}, archive_code: "ARC-X", internal_note: "NOTE-visible-always", risk_score: 9}`
- FIXED public output : `{doc_id: "DOC-7", custodian: {name: "custodian-priya"}, archive_code: "ARC-X", internal_note: "NOTE-visible-always", risk_score: 9}`
- nested custodian constructed? OLD=true NAIVE=true FIXED=true
    - custodian options when built: `{role: :admin, view: :full, attr_path: [], root: nil, only: nil, except: nil}`
- OLD archive_code condition order (first gate fails => trailing block NOT evaluated):
    - exposed=true short_circuited=false
        - 1/2 HashCondition[{view: :full}] => true
        - 2/2 BlockCondition["old:block:archive_scope"] => true
- fields with NO condition (never evaluated, simply always present):
    - [:doc_id, :internal_note, :name]

### role=auditor
- OLD public output   : `{doc_id: "DOC-7", internal_note: "NOTE-visible-always"}`
- NAIVE public output : `{doc_id: "DOC-7", archive_code: "ARC-X", internal_note: "NOTE-visible-always", risk_score: 9}`
- FIXED public output : `{doc_id: "DOC-7", internal_note: "NOTE-visible-always"}`
- nested custodian constructed? OLD=false NAIVE=false FIXED=false
- OLD archive_code condition order (first gate fails => trailing block NOT evaluated):
    - exposed=false short_circuited=true
        - 1/2 HashCondition[{view: :full}] => false
- fields with NO condition (never evaluated, simply always present):
    - [:doc_id, :internal_note]

### role=guest
- OLD public output   : `{doc_id: "DOC-7", internal_note: "NOTE-visible-always"}`
- NAIVE public output : `{doc_id: "DOC-7", internal_note: "NOTE-visible-always"}`
- FIXED public output : `{doc_id: "DOC-7", internal_note: "NOTE-visible-always"}`
- nested custodian constructed? OLD=false NAIVE=false FIXED=false
- OLD archive_code condition order (first gate fails => trailing block NOT evaluated):
    - exposed=false short_circuited=true
        - 1/2 HashCondition[{view: :full}] => false
- fields with NO condition (never evaluated, simply always present):
    - [:doc_id, :internal_note]

## Migration classifier — blocked declaration sites

| entity.field | verdict | reason | suggested rewrite |
|---|---|---|---|
| EntityB1.release_notes | blocked | HashCondition reads non-role key(s) [:version] (e.g. view/version/type) | No role axis exists. Either keep `if: { version: }`, or first define which roles imply v2 and switch to role_if(...) under a documented role/version matrix. |
| EntityB1.compat_line | blocked | HashCondition reads non-role key(s) [:view, :channel] (e.g. view/version/type) | Two axes (view + channel). Split into a role gate AND a separate channel condition joined by the existing hash-merge; do not collapse channel into role. |
| EntityB2.draft_banner | blocked | SymbolCondition reads options[:show_draft], not the role | Symbol reads options[:show_draft]. Keep as-is unless show_draft is provably derived from role; then use role_capability(:show_draft). |
| EntityB3.medical_flag | blocked | BlockCondition `block:object_state` may read object state or non-role options | Predicate depends on object#sensitive? which roles cannot express. Keep the block; a role gate can be ADDED but not replace this check. |
| EntityB4.combined_field | blocked | BlockCondition `block:mixed` may read object state or non-role options | Mixed predicate. Split: `if: role_if(:admin)` for the role part, keep a block for object.confirmed?; AND them (array of conditions). |
| EntityB5.internal_ticket | blocked | HashCondition reads non-role key(s) [:channel] (e.g. view/version/type) | unless reads :channel. Keep unless on channel, or model a role capability; a single role cannot encode channel scoping. |
| EntityB6.regional_data | blocked | HashCondition reads non-role key(s) [:region] (e.g. view/version/type) | Nested :region gate is orthogonal to role. Keep role_if(:staff) on the wrapper and retain `if: { region: :eu }` on the leaf. |
| EntityControl.normal_field | migratable | all conditions are role-derived | pure role gate — safe to migrate mechanically |
## Assertions
- PASS: A/base output identical [admin/full]
- PASS: A/Pro  output identical [admin/full]
- PASS: A/base output identical [staff/staff]
- PASS: A/Pro  output identical [staff/staff]
- PASS: A/base output identical [guest/public]
- PASS: A/Pro  output identical [guest/public]
- PASS: B/fixed preserves old visibility [admin]
- PASS: B/fixed preserves old visibility [auditor]
- PASS: B/fixed preserves old visibility [guest]
- PASS: naive migration over-exposes [:archive_code, :risk_score] for :auditor (the trap)
