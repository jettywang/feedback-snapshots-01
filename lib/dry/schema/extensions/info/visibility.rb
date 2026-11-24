# frozen_string_literal: true

require "dry/schema/constants"

module Dry
  module Schema
    # @api private
    module Info
      # Documentation visibility policy for the info export
      #
      # Declares which parts of a schema's documentation are internal-only and
      # must be redacted before the info hash is shared with external parties.
      # The policy only affects documentation export; validation is unchanged.
      #
      # @example
      #   Dry::Schema.JSON do
      #     configure do |config|
      #       config.info_visibility = {
      #         keys: %w[audit_token address.room],
      #         values: {state: %w[blocked]},
      #         error_examples: :internal
      #       }
      #     end
      #
      #     required(:state).filled(:string, included_in?: %w[active blocked])
      #   end
      #
      # @api public
      class Visibility
        # @api private
        INTERNAL = :internal

        # @api private
        PUBLIC = :public

        # @api private
        attr_reader :internal_keys

        # @api private
        attr_reader :internal_values

        # @api private
        attr_reader :error_examples

        # @api private
        def initialize(keys: EMPTY_ARRAY, values: EMPTY_HASH, error_examples: INTERNAL)
          @internal_keys = keys.map { |key| self.class.path(key) }.freeze
          @internal_values = values.to_h { |key, list| [self.class.path(key), list] }.freeze
          @error_examples = error_examples
        end

        # Redact internal-only information from an exported info hash
        #
        # @param info [Hash] the full (internal) info hash
        #
        # @return [Hash] the public info hash
        #
        # @api private
        def call(info)
          {keys: redact_keys(info[:keys], EMPTY_ARRAY)}
        end

        # Coerce a key path declaration into an array of symbols
        #
        # @example
        #   Visibility.path("address.room") # => [:address, :room]
        #   Visibility.path(:email)         # => [:email]
        #
        # @api private
        def self.path(key)
          key.is_a?(::Array) ? key.map(&:to_sym) : key.to_s.split(".").map(&:to_sym)
        end

        private

        # @api private
        def redact_keys(keys, path)
          keys.each_with_object({}) do |(name, key_info), output|
            key_path = path + [name]

            next if internal_keys.include?(key_path)

            output[name] = redact_key(key_info, key_path)
          end
        end

        # @api private
        def redact_key(key_info, path)
          redacted = key_info.dup
          redacted[:keys] = redact_keys(key_info[:keys], path) if key_info[:keys]

          if key_info[:member].is_a?(::Hash)
            redacted[:member] = redact_key(key_info[:member], path)
          end

          redact_examples(redact_values(redacted, path))
        end

        # @api private
        def redact_values(redacted, path)
          return redacted unless redacted[:values]

          allowed = redacted[:values] - Array(internal_values[path])

          if allowed.empty?
            redacted.delete(:values)
          else
            redacted[:values] = allowed
          end

          redacted
        end

        # @api private
        def redact_examples(redacted)
          return redacted unless redacted[:examples]

          visible = if error_examples.equal?(PUBLIC)
                      redacted[:examples]
                    else
                      redacted[:examples].select { _1[:valid] }
                    end

          if visible.empty?
            redacted.delete(:examples)
          else
            redacted[:examples] = visible
          end

          redacted
        end
      end
    end
  end
end
