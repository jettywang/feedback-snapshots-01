# frozen_string_literal: true

module Grape
  class Entity
    module Provenance
      # Class-level DSL that turns a plain Grape::Entity into a claim-bearing,
      # receipt-producing entity. `expose_claim` behaves exactly like `expose`
      # (it delegates to it) but additionally registers and tags the resulting
      # exposure with a stable, approved-or-not claim identifier.
      module EntityClassExtension
        def claim_ledger
          @claim_ledger ||= ClaimLedger.new
        end

        def expose_claim(claim_id, *args, **kwargs, &block)
          attribute = args.first
          overridden_ids = override_targets(attribute, kwargs)
          expose(*args, **kwargs, &block)
          exposure = last_registered_exposure(attribute)
          tag_exposure(exposure, claim_id)
          register_claim(claim_id, exposure, overridden_ids)
          claim_id
        end

        private

        def override_targets(attribute, kwargs)
          return [] unless kwargs[:override]

          scope = (@nesting_stack || []).last&.nested_exposures || root_exposures
          scope.select { |exposure| exposure.attribute == attribute.to_sym }.map do |exposure|
            Provenance.claim_id_of(exposure)
          end.compact
        end

        def last_registered_exposure(attribute)
          scope = (@nesting_stack || []).last&.nested_exposures || root_exposures
          scope.select { |exposure| exposure.attribute == attribute.to_sym }.last
        end

        def tag_exposure(exposure, claim_id)
          Provenance.tag_claim(exposure, claim_id)
          return unless exposure.respond_to?(:nested_exposures)

          exposure.nested_exposures.each { |nested| Provenance.inherit_claim(nested, claim_id) }
        end

        def register_claim(claim_id, exposure, overridden_ids)
          claim_ledger.mark_superseded!(overridden_ids)
          claim_ledger.register(
            entity_class: self,
            attribute: exposure.attribute,
            key: exposure.key,
            nesting: exposure.nesting?,
            override: exposure.override?,
            kind: Provenance.kind_of(exposure),
            overridden_ids: overridden_ids,
            explicit_id: claim_id
          )
        end
      end

      # Instance-level behaviour: open a Trace for one render, build a frozen
      # Receipt from it, and memoize so that re-reading the receipt never runs
      # the entity (and therefore never runs a formatter) a second time.
      module EntityInstanceExtension
        def serializable_hash(runtime_options = {})
          return nil if object.nil?

          output, trace = Provenance.with_trace(Trace.new) { super }
          @provenance_last_trace = trace
          @provenance_output = output
          output
        end

        def provenance_receipt(approval_registry = self.class.approval_registry, runtime_options = {})
          @provenance_receipt ||= begin
            output = serializable_hash(runtime_options)
            Receipt.new(
              trace: @provenance_last_trace,
              ledger: self.class.claim_ledger,
              output: output,
              approval_registry: approval_registry
            )
          end
        end
      end
    end
  end
end
