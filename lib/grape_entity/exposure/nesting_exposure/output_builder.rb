# frozen_string_literal: true

module Grape
  class Entity
    module Exposure
      class NestingExposure
        class OutputBuilder < SimpleDelegator
          def initialize(entity, options = {})
            @entity = entity
            @options = options
            @output_hash = {}
            @output_collection = []
            @provenance = Provenance.new if options[:collect_provenance]

            super(@output_hash)
          end

          def add(exposure, result)
            # Save a result array in collections' array if it should be merged
            if result.is_a?(Array) && exposure.for_merge
              @output_collection << result.map { |item| unwrap_payload(item) }
            elsif exposure.safe_merge?
              add_safely(exposure, payload_for(exposure, result))
            elsif exposure.for_merge
              # If we have an array which should not be merged - save it with a key as a hash
              # If we have hash which should be merged - save it without a key (merge)
              return unless result

              record_merged_provenance(result)
              @output_hash.merge! result, &merge_strategy(exposure.for_merge)
            else
              key = exposure.key(@entity)
              @output_hash[key] = result
              record_provenance(key, exposure)
            end
          end

          def kind_of?(klass)
            klass == output.class || super
          end
          alias is_a? kind_of?

          def __getobj__
            output
          end

          private

          def unwrap_payload(item)
            item.is_a?(MergePayload) ? item.hash : item
          end

          # Represent exposures can hand back a payload carrying the source
          # provenance of every field; other exposures contribute plain hashes.
          def payload_for(exposure, result)
            if exposure.respond_to?(:serializable_payload)
              exposure.serializable_payload(@entity, @options) || result
            else
              result
            end
          end

          # Scope provenance to the containing nesting, excluding the
          # contributing exposure's own key which is still on the path stack.
          def add_safely(exposure, result)
            result = result.__getobj__ if result.is_a?(self.class) && result.__getobj__.is_a?(MergePayload)
            payload = result.is_a?(MergePayload) ? result : nil
            result_hash = payload ? payload.hash : result
            return unless result_hash.is_a?(Hash)

            inherit_provenance(payload.provenance) if payload
            provenance_path = payload ? Array(@options[:attr_path]) : current_path
            SafeMerger.new(@output_hash, @entity.merge_report, @entity, current_path,
                           payload&.provenance, provenance_path)
                      .merge!(result_hash, exposure)
          end

          def inherit_provenance(nested)
            return unless @provenance

            nested.sources.each do |(path, field), source|
              @provenance.record(path, field, source.label, source.attribute, source.entity_class, source.override?)
            end
          end

          def record_merged_provenance(result)
            return unless @provenance

            result.each_key { |field| @provenance.record(current_path, field, nil, nil, nil, false) }
          end

          def record_provenance(key, exposure)
            return unless @provenance

            @provenance.record(current_path, key, exposure.merge_source, exposure.attribute,
                               exposure.class, exposure.override?)
          end

          def current_path
            base = Array(@options[:provenance_path])
            base + Array(@options[:attr_path])[0...-1]
          end

          # If output_collection contains at least one element we have to represent the output as a collection
          def output
            if @output_collection.empty?
              output = @output_hash
            else
              output = @output_collection
              output << @output_hash unless @output_hash.empty?
              output.flatten!
            end

            @provenance ? MergePayload.new(output, @provenance) : output
          end

          # In case if we want to solve collisions providing lambda to :merge option
          def merge_strategy(for_merge)
            if for_merge.respond_to? :call
              for_merge
            else
              -> {}
            end
          end
        end
      end
    end
  end
end
