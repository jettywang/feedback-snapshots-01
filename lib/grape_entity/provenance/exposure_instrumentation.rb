# frozen_string_literal: true

module Grape
  class Entity
    module Exposure
      # Observation hooks shared by every exposure subtype. They write into the
      # thread-local Trace opened by a Provenance entity and otherwise stay
      # completely passive: the original methods keep their exact behaviour.
      module Instrumentation
        # Grape::Entity rebuilds exposures through `dup` on subclassing, which
        # would otherwise drop the provenance tags. Carry them across so an
        # exposure inherited and later overridden still points at its claim.
        def dup(*args, &block)
          super.tap do |copy|
            copy.instance_variable_set(Provenance::CLAIM_IVAR,
                                      instance_variable_get(Provenance::CLAIM_IVAR)) if
              instance_variable_defined?(Provenance::CLAIM_IVAR)
            copy.instance_variable_set(Provenance::INHERITED_IVAR,
                                      instance_variable_get(Provenance::INHERITED_IVAR)) if
              instance_variable_defined?(Provenance::INHERITED_IVAR)
          end
        end

        def conditions_met?(entity, options)
          result = super
          trace = Grape::Entity::Provenance.current_trace
          if trace && Provenance.claim_tagged?(self)
            trace.record_condition(
              Provenance.claim_id_of(self),
              met: result,
              path: Provenance.path_from(options, key(entity))
            )
          end
          result
        end

        def serializable_value(entity, options)
          result = super
          trace = Grape::Entity::Provenance.current_trace
          if trace && Provenance.claim_tagged?(self)
            trace.record_adoption(
              Provenance.claim_id_of(self),
              path: Provenance.path_from(options, key(entity)),
              value: result,
              kind: Provenance.kind_of(self),
              nesting: nesting?
            )
          end
          result
        end
      end

      # Extra hook for the two exposure types that run a formatter. The run is
      # recorded at the moment it executes, so "which formatters actually ran"
      # is empirical evidence rather than an inference from the declaration.
      module FormatterInstrumentation
        def value(entity, options)
          trace = Grape::Entity::Provenance.current_trace
          if trace && Provenance.claim_tagged?(self)
            trace.record_formatter_run(
              Provenance.claim_id_of(self),
              formatter_name: @format_with.respond_to?(:to_sym) ? @format_with.to_sym : :inline_proc,
              formatter_kind: self.class.name.split('::').last.to_sym
            )
          end
          super
        end
      end
    end
  end
end
