# frozen_string_literal: true

# Non-invasive instrumentation layered on top of the unmodified grape-entity
# in /lib. It records three things the migration decision depends on:
#   1. every exposure whose condition chain is evaluated (and the field name),
#   2. the ordered, per-condition evaluation result (so short-circuiting is
#      visible - conditions after the first failing one are never called),
#   3. every (nested) Grape::Entity instance and the exact options hash it
#      received from its parent via Options#for_nesting / RepresentExposure.
module RoleMigration
  module Tracer
    @records = []
    @stack = []
    @entity_inits = []

    class << self
      attr_reader :records, :entity_inits

      def reset!
        @records = []
        @stack = []
        @entity_inits = []
      end

      # Blocks used as :if / :unless are registered here so the trace can show
      # a stable human name instead of an anonymous Proc.
      def block(name, &block)
        @named_blocks ||= {}
        @named_blocks[block] = name
        block
      end

      def block_name(block)
        (@named_blocks || {})[block]
      end

      def start_exposure(exposure, options)
        frame = {
          field: exposure.attribute,
          key: exposure.key,
          options: options.respond_to?(:opts_hash) ? options.opts_hash.dup : options.dup,
          calls: [],
          short_circuited: false,
          exposed: nil
        }
        @stack.push(frame)
        @records.push(frame)
      end

      def end_exposure(result)
        frame = @stack.pop
        frame[:exposed] = result
        frame
      end

      def record_condition(condition, result, index, total)
        frame = @stack.last
        return unless frame

        frame[:calls] << {
          index: index,
          of: total,
          kind: condition.class.name.split('::').last,
          inverse: condition.inversed?,
          detail: describe(condition),
          result: result
        }
        # Base#conditions_met? uses Enumerable#all?; the first false stops
        # iteration, so any chain whose size exceeds the evaluated count was
        # short-circuited and its trailing conditions were not evaluated.
        frame[:short_circuited] = true if result == false && index < total
      end

      def record_entity_init(entity_class, options)
        @entity_inits << {
          entity: entity_class.name,
          options: options.respond_to?(:opts_hash) ? options.opts_hash.dup : options.dup
        }
      end

      private

      def describe(condition)
        case condition
        when Grape::Entity::Condition::HashCondition
          condition.cond_hash
        when Grape::Entity::Condition::SymbolCondition
          condition.symbol
        when Grape::Entity::Condition::BlockCondition
          RoleMigration::Tracer.block_name(condition.block) || condition.block
        end
      end
    end
  end

  # Wrap the condition-chain entry point. #conditions_met? calls
  # Array#all? so the wrapping preserves native short-circuit behaviour;
  # we only observe each condition actually visited.
  module ConditionsMetTracing
    def conditions_met?(entity, options)
      RoleMigration::Tracer.start_exposure(self, options)
      total = @conditions.size
      index = 0
      met = @conditions.all? do |condition|
        index += 1
        result = condition.met?(entity, options)
        RoleMigration::Tracer.record_condition(condition, result, index, total)
        result
      end
      RoleMigration::Tracer.end_exposure(met)
      met
    end
  end

  # Capture the exact options a (possibly nested) entity is constructed with.
  module InitTracing
    def initialize(object, options = {})
      RoleMigration::Tracer.record_entity_init(self.class, options)
      super
    end
  end
end

Grape::Entity::Exposure::Base.prepend(RoleMigration::ConditionsMetTracing)
Grape::Entity.prepend(RoleMigration::InitTracing)
