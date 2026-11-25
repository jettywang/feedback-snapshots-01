# frozen_string_literal: true

require 'ostruct'

# ===========================================================================
# Catalogue of declaration SITES that cannot be migrated to a pure role
# declaration mechanically. Each entity below contains one or more blocked
# sites; the runner feeds every exposure through MigrationClassifier and
# prints the verdict + suggested rewrite alongside this source.
# ===========================================================================

# B1. Hash condition on a non-role key (version/type/view with extra axis).
class EntityB1 < Grape::Entity
  expose :release_notes, if: { version: 'v2' }
  expose :compat_line, if: { view: :full, channel: :beta } # mixed axes
end

# B2. Symbol condition on a non-role boolean flag.
class EntityB2 < Grape::Entity
  expose :draft_banner, if: :show_draft
end

# B3. Block condition reading OBJECT state (not just options[:role]).
class EntityB3 < Grape::Entity
  expose :medical_flag, if: RoleMigration::Tracer.block('block:object_state') { |object, _options|
    object.sensitive?
  }
end

# B4. Block mixing object + role in one predicate (must be split, not replaced).
class EntityB4 < Grape::Entity
  expose :combined_field, if: RoleMigration::Tracer.block('block:mixed') { |object, options|
    options[:role] == :admin && object.confirmed?
  }
end

# B5. unless on a non-role key.
class EntityB5 < Grape::Entity
  expose :internal_ticket, unless: { channel: :public }
end

# B6. with_options merging a role gate with a non-role nested gate.
class EntityB6 < Grape::Entity
  with_options if: { role: :staff } do
    expose :regional_data, if: { region: :eu }
  end
end

# A clean, migratable control to prove the classifier returns :migratable.
class EntityControl < Grape::Entity
  extend RoleMigration::RoleDsl
  expose :normal_field, if: role_if(:admin)
end

module BlockedData
  def self.sample
    Object.new.tap do |o|
      def o.sensitive? = true
      def o.confirmed? = true
      def o.release_notes = 'rn'
      def o.compat_line = 'cl'
      def o.draft_banner = 'db'
      def o.medical_flag = 'mf'
      def o.combined_field = 'cf'
      def o.internal_ticket = 'it'
      def o.regional_data = 'rd'
      def o.normal_field = 'nf'
    end
  end

  # Human-facing rewrite guidance keyed by entity -> field.
  GUIDANCE = {
    'EntityB1.release_notes' => 'No role axis exists. Either keep `if: { version: }`, or first define which roles imply v2 and switch to role_if(...) under a documented role/version matrix.',
    'EntityB1.compat_line'  => 'Two axes (view + channel). Split into a role gate AND a separate channel condition joined by the existing hash-merge; do not collapse channel into role.',
    'EntityB2.draft_banner' => 'Symbol reads options[:show_draft]. Keep as-is unless show_draft is provably derived from role; then use role_capability(:show_draft).',
    'EntityB3.medical_flag' => 'Predicate depends on object#sensitive? which roles cannot express. Keep the block; a role gate can be ADDED but not replace this check.',
    'EntityB4.combined_field' => 'Mixed predicate. Split: `if: role_if(:admin)` for the role part, keep a block for object.confirmed?; AND them (array of conditions).',
    'EntityB5.internal_ticket' => 'unless reads :channel. Keep unless on channel, or model a role capability; a single role cannot encode channel scoping.',
    'EntityB6.regional_data' => 'Nested :region gate is orthogonal to role. Keep role_if(:staff) on the wrapper and retain `if: { region: :eu }` on the leaf.'
  }.freeze
end
