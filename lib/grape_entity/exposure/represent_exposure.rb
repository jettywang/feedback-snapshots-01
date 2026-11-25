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
          new_options = nested_options(entity, options)
          using_class.represent(@subexposure.value(entity, options), new_options)
        end

        # Used when this exposure feeds a safe merge: keeps the provenance
        # attached to the represented data instead of unwrapping to a hash.
        def serializable_payload(entity, options)
          represented = valid_value(entity, options)
          represented = represented.__getobj__ if payload_builder?(represented)
          represented.is_a?(MergePayload) ? represented : nil
        end

        def serializable_value(entity, options)
          partial_output = valid_value(entity, options)

          if payload_builder?(partial_output)
            partial_output.__getobj__.hash
          elsif partial_output.respond_to?(:serializable_hash)
            partial_output.serializable_hash
          elsif partial_output.is_a?(Array) && partial_output.all? { |o| o.respond_to?(:serializable_hash) }
            partial_output.map(&:serializable_hash)
          elsif partial_output.is_a?(Hash)
            partial_output.each do |key, val|
              partial_output[key] = val.serializable_hash if val.respond_to?(:serializable_hash)
            end
          else
            partial_output
          end
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

        def payload_builder?(output)
          output.is_a?(NestingExposure::OutputBuilder) && output.__getobj__.is_a?(MergePayload)
        end

        def nested_options(entity, options)
          new_options = options.for_nesting(key(entity))
          return new_options unless safe_merge?

          new_options.merge(collect_provenance: true, provenance_path: [], serializable: true)
        end

        def using_options_for(options)
          options.for_nesting(key)
        end
      end
    end
  end
end
