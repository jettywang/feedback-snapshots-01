# frozen_string_literal: true

require 'ostruct'

# ===========================================================================
# Example A - DIRECTLY MIGRATABLE
# Parent and child BOTH declare explicit gates, and every gate is read purely
# from one runtime key. Old style keys on options[:view] (+ a symbol flag);
# new style compiles to the identical condition classes on options[:role].
#
# Runtime mapping kept 1:1 by the runner so serializable output must match:
#   view: :full   <-> role: :admin
#   view: :staff  <-> role: :staff
#   view: :public <-> role: :guest
# ===========================================================================

# Nested objects rendered through `using:`. Two classes keep each pipeline on
# a single key space (view vs role); both expose the same fields.
class OldAuditTagEntity < Grape::Entity
  expose :tag
  expose :reviewer, if: { view: :full }
end

class NewAuditTagEntity < Grape::Entity
  extend RoleMigration::RoleDsl
  expose :tag
  expose :reviewer, if: role_if(:admin)
end

# ---------------- OLD style: view conditions --------------------------------
class OldGadgetEntity < Grape::Entity
  expose :sku, :name
  expose :cost_price, if: { view: :full }                                   # HashCondition
  expose :marketing_blurb, if: :show_blurb                                  # SymbolCondition
  expose :margin, if: RoleMigration::Tracer.block('old:block:margin') { |_object, options|
    options[:view] != :public
  }                                                                         # BlockCondition
  expose :recall_notice, unless: { view: :public }

  # with_options Hash merges with the per-field Hash into one HashCondition.
  with_options if: { view: :staff } do
    expose :warehouse_bin
    expose :supplier, if: { view: :full }
  end

  # Nested `using`: block OR-gate; nested entity gets the SAME options hash.
  expose :audit,
         using: OldAuditTagEntity,
         if: RoleMigration::Tracer.block('old:block:audit_or') { |_object, options| options[:view] != :public }
end

# Inherited child re-declaring an inherited field with its OWN explicit gate.
class OldGadgetProEntity < OldGadgetEntity
  expose :cost_price, override: true, if: { view: :staff }
  expose :pro_badge, if: RoleMigration::Tracer.block('old:block:pro_badge') { |_object, options|
    %i[full staff].include?(options[:view])
  }
end

# ---------------- NEW style: role declarations ------------------------------
class NewGadgetEntity < Grape::Entity
  extend RoleMigration::RoleDsl

  expose :sku, :name
  expose :cost_price, if: role_if(:admin)                                   # HashCondition { role: :admin }
  expose :marketing_blurb, if: role_capability(:show_blurb)                 # BlockCondition on capabilities
  expose :margin, if: role_if { |_object, options| options[:role] != :guest }
  expose :recall_notice, unless: role_unless(:guest)

  with_options if: role_if(:staff) do
    expose :warehouse_bin
    expose :supplier, if: role_if(:admin)
  end

  expose :audit, using: NewAuditTagEntity, if: role_if(:admin, :staff)      # OR BlockCondition
end

class NewGadgetProEntity < NewGadgetEntity
  expose :cost_price, override: true, if: role_if(:staff)
  expose :pro_badge, if: role_if(:admin, :staff)
end

module ExampleAData
  def self.gadget
    OpenStruct.new(
      sku: 'GX-100', name: 'Fictional Gadget', cost_price: '42.00',
      marketing_blurb: 'shiny', margin: '11%', recall_notice: 'none',
      warehouse_bin: 'B-7', supplier: 'Acme Fictional Co', pro_badge: 'PRO',
      audit: OpenStruct.new(tag: 'TAG-9', reviewer: 'reviewer-jules')
    )
  end

  CASES = [
    { label: 'admin/full',    old: { view: :full,   show_blurb: true },  new: { role: :admin, capabilities: [:show_blurb] } },
    { label: 'staff/staff',  old: { view: :staff,  show_blurb: true },  new: { role: :staff, capabilities: [:show_blurb] } },
    { label: 'guest/public', old: { view: :public, show_blurb: false }, new: { role: :guest, capabilities: [] } }
  ].freeze
end
