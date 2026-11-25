# frozen_string_literal: true

module Grape
  class Entity
    module Exposure
      class RepresentExposure < Base
        attr_reader :using_class_name, :subexposure

        def setup(using_class_name, subexposure)
          @using_class = nil
          @using_class_name = using_class_name
          @subexposure = subexposure
        end

        def dup_args
          [*super, using_class_name, subexposure]
        end

        def ==(other)
          super &&
            @using_class_name == other.using_class_name &&
            @subexposure == other.subexposure
        end

        def value(entity, options)
          new_options = options.for_nesting(key(entity))
          new_options = disclosure_options_for_merge(options, new_options) if disclosure_merge?(options)
          using_class.represent(@subexposure.value(entity, options), new_options)
        end

        def valid?(entity)
          @subexposure.valid? entity
        end

        def using_class
          @using_class ||= if @using_class_name.respond_to? :constantize
                             @using_class_name.constantize
                           else
                             @using_class_name
                           end
        end

        private

        def using_options_for(options)
          options.for_nesting(key)
        end

        def disclosure_merge?(options)
          options.respond_to?(:disclosure_context) && options.disclosure_context && for_merge
        end

        # Merged child fields become fields of the enclosing payload node, so
        # the child must not claim a payload path of its own. It keeps the
        # parent's scope and reports its withheld fields through the parent's
        # rollup so the receipt entry matches the merged output exactly.
        def disclosure_options_for_merge(parent_options, child_options)
          child_options.merge(
            disclosure_skip_entry: true,
            disclosure_occurrence: parent_options.disclosure_occurrence,
            disclosure_scope: parent_options.disclosure_scope,
            disclosure_mode: parent_options[:disclosure_mode],
            disclosure_rollup: parent_options[:disclosure_rollup]
          )
        end
      end
    end
  end
end
