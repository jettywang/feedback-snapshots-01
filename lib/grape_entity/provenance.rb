# frozen_string_literal: true

require 'set'
require 'grape-entity'
require 'grape_entity/provenance/claim_ledger'
require 'grape_entity/provenance/approval_registry'
require 'grape_entity/provenance/trace'
require 'grape_entity/provenance/receipt'
require 'grape_entity/provenance/exposure_instrumentation'
require 'grape_entity/provenance/entity_extension'

module Grape
  class Entity
    # Optional source-receipt layer for Grape::Entity.
    #
    # Requiring this file does not change how existing entities render: the
    # instrumentation only writes when a Trace is active, and a Trace is opened
    # solely by Grape::Entity::Provenance::Entity.
    module Provenance
      CLAIM_IVAR = :@provenance_claim_id
      INHERITED_IVAR = :@provenance_inherited_from

      class << self
        # Runs a block with a Trace bound to the current thread, then restores
        # the previous binding. Returns [block_result, trace].
        def with_trace(trace)
          previous = Thread.current[:grape_entity_provenance_trace]
          Thread.current[:grape_entity_provenance_trace] = trace
          result = yield
          [result, trace]
        ensure
          Thread.current[:grape_entity_provenance_trace] = previous
        end

        def current_trace
          Thread.current[:grape_entity_provenance_trace]
        end

        def tag_claim(exposure, claim_id)
          exposure.instance_variable_set(CLAIM_IVAR, claim_id.to_sym)
        end

        def inherit_claim(exposure, parent_id)
          exposure.instance_variable_set(INHERITED_IVAR, parent_id.to_sym) unless claim_tagged?(exposure)
        end

        def claim_tagged?(exposure)
          exposure.instance_variable_defined?(CLAIM_IVAR) ||
            exposure.instance_variable_defined?(INHERITED_IVAR)
        end

        def claim_id_of(exposure)
          exposure.instance_variable_get(CLAIM_IVAR) ||
            exposure.instance_variable_get(INHERITED_IVAR)
        end

        def kind_of(exposure)
          name = exposure.class.name.split('::').last
          name.sub(/Exposure\z/, '').gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase.to_sym
        end

        # Reconstruct the output path of the current exposure. While descending
        # nestings Options already maintains the full path in its attr_path
        # stack, so it is reused verbatim; at the top level the exposure's own
        # key is the whole path.
        def path_from(options, key)
          stack = options.respond_to?(:opts_hash) ? options.opts_hash[:attr_path] : nil
          stack && stack.any? ? stack.dup : [key]
        end

        def install!
          Exposure::Base.prepend(Exposure::Instrumentation)
          Exposure::FormatterExposure.prepend(Exposure::FormatterInstrumentation)
          Exposure::FormatterBlockExposure.prepend(Exposure::FormatterInstrumentation)
        end
      end

      # Base class for entities that publish source receipts. Subclasses keep
      # the full Grape::Entity DSL and additionally gain expose_claim.
      class Entity < Grape::Entity
        extend EntityClassExtension
        prepend EntityInstanceExtension

        class << self
          def inherited(subclass)
            super
            subclass.instance_variable_set(:@claim_ledger, claim_ledger.dup)
            subclass.approval_registry = approval_registry
          end

          attr_accessor :approval_registry
        end

        self.approval_registry = ApprovalRegistry.new
      end

      install!
    end
  end
end
