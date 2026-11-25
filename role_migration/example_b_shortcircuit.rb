# frozen_string_literal: true

require 'ostruct'

# ===========================================================================
# Example B - CANNOT BE MIGRATED NAIVELY: inherited gate + parent short-circuit
#
# grape-entity conditions do not silently flow between different fields. The
# "child inherits the old view gate" pattern is expressed by the child
# OVERRIDING a parent field and re-declaring that gate as the FIRST condition
# of its own chain, followed by a child-specific rule.
#
# Old rule: the first condition is the parent view gate. When it fails,
# Enumerable#all? short-circuits and the child's trailing block is NOT
# evaluated ("not evaluated", distinct from "evaluated false").
#
# Naive view->role rewrite: the inherited gate is replaced by a broader role
# gate (admin OR auditor). The trailing child rule then gets evaluated and the
# field is over-exposed to :auditor. The fix repeats a narrow explicit gate.
# ===========================================================================

class OldCustodianEntity < Grape::Entity
  expose :name
end

class NewCustodianEntity < Grape::Entity
  expose :name
end

# ---------------- OLD rule --------------------------------------------------
class OldDocumentEntity < Grape::Entity
  expose :doc_id
  expose :archive_code, if: { view: :full }                         # parent view gate
  expose :custodian, using: OldCustodianEntity, if: { view: :full }
end

class OldMemoEntity < OldDocumentEntity
  # Child re-declares archive_code: inherited view gate FIRST, child block
  # second. For non-:full views the parent gate fails first -> block never runs.
  # An Array `if` keeps the explicit ordering [parent hash, child block].
  expose :archive_code,
         override: true,
         if: [
           { view: :full },
           RoleMigration::Tracer.block('old:block:archive_scope') { |_object, options|
             options[:view] == :full
           }
         ]
  # Field present on every representation (no gate) - used to show the
  # difference between "hidden by a gate" and "never conditionally evaluated".
  expose :internal_note
  expose :risk_score, if: RoleMigration::Tracer.block('old:block:risk_score') { |_object, options|
    options[:view] == :full
  }
end

# ---------------- NAIVE NEW rule (the trap) ---------------------------------
class NaiveDocumentEntity < Grape::Entity
  extend RoleMigration::RoleDsl
  expose :doc_id
  expose :archive_code, if: role_if(:admin, :auditor)
  expose :custodian, using: NewCustodianEntity, if: role_if(:admin) # old view:full has no auditor
end

class NaiveMemoEntity < NaiveDocumentEntity
  extend RoleMigration::RoleDsl
  # The "inherited" gate became a broader role gate; archive_code now leaks to
  # :auditor because the first condition no longer fails for that role.
  expose :archive_code,
         override: true,
         if: [
           role_if(:admin, :auditor),
           RoleMigration::Tracer.block('new:block:archive_scope') { |_object, options|
             %i[admin auditor].include?(options[:role])
           }
         ]
  expose :internal_note
  expose :risk_score, if: role_if(:admin, :auditor)
end

# ---------------- FIXED NEW rule --------------------------------------------
class FixedDocumentEntity < Grape::Entity
  extend RoleMigration::RoleDsl
  expose :doc_id
  expose :archive_code, if: role_if(:admin, :auditor)
  expose :custodian, using: NewCustodianEntity, if: role_if(:admin)
end

class FixedMemoEntity < FixedDocumentEntity
  extend RoleMigration::RoleDsl
  # Narrowest explicit gate repeated on the leaf; parent gate is defense-in-depth.
  expose :archive_code, override: true, if: role_if(:admin)
  expose :internal_note
  expose :risk_score, if: role_if(:admin)
end

module ExampleBData
  def self.document
    OpenStruct.new(
      doc_id: 'DOC-7',
      archive_code: 'ARC-X',
      internal_note: 'NOTE-visible-always',
      risk_score: 9,
      custodian: OpenStruct.new(name: 'custodian-priya')
    )
  end

  # Both keys present so old and new entities run in the same represent call.
  CASES = [
    { label: 'admin',   role: :admin,   view: :full },
    { label: 'auditor', role: :auditor, view: :audit },
    { label: 'guest',   role: :guest,   view: :public }
  ].freeze
end
