# frozen_string_literal: true

require "dry/core/cache"
require "dry/core/equalizer"

module Dry
  module Schema
    # Coerces keys in a hash using provided coercer function
    #
    # @api private
    class KeyCoercer
      extend ::Dry::Core::Cache
      include ::Dry::Equalizer(:key_map, :coercer)

      TO_SYM = :to_sym.to_proc.freeze

      attr_reader :key_map, :coercer, :attribution_policy

      # @api private
      def self.new(*args, **kwargs)
        fetch_or_store(*args, kwargs) { super(*args, **kwargs) }
      end

      # @api private
      def self.symbolized(*args, **kwargs)
        new(*args, **kwargs, &TO_SYM)
      end

      # @api private
      def initialize(key_map, attribution_policy: nil, &coercer)
        @attribution_policy = attribution_policy && KeyAttribution::Policy.normalize(attribution_policy)
        @key_map = key_map.coercible(&coercer)
      end

      # @api private
      def call(result)
        source = result.to_h

        if attribution_policy
          report = KeyAttribution::Report.new(attribution_policy)
          coerced = key_map.write(source, EMPTY_HASH.dup, {tracker: report})
          report.finalize!(coerced)
          result.key_attribution = report
          coerced
        else
          key_map.write(source)
        end
      end
      alias_method :[], :call
    end
  end
end
