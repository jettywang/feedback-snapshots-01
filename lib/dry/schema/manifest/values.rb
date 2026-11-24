# frozen_string_literal: true

module Dry
  module Schema
    module Manifest
      # Encodes predicate arguments and other runtime values as JSON-safe data
      #
      # Encoding is tagged so that, for example, the symbol `:int` and the
      # string `"int"` can never produce the same manifest entry.
      #
      # @api private
      module Values
        module_function

        # @api private
        def dump(value)
          case value
          when ::Symbol
            {"symbol" => value.to_s}
          when ::String
            {"string" => value}
          when ::Integer
            {"integer" => value}
          when ::Float
            {"float" => value.to_s}
          when ::NilClass
            {"null" => true}
          when ::TrueClass, ::FalseClass
            {"boolean" => value}
          when ::Regexp
            {"regexp" => value.source, "options" => value.options}
          when ::Range
            {"range" => dump(value.begin), "end" => dump(value.end), "exclude_end" => value.exclude_end?}
          when ::BigDecimal
            {"decimal" => value.to_s("F")}
          when ::Rational
            {"rational" => [value.numerator, value.denominator]}
          when ::DateTime, ::Date, ::Time
            {value.class.name => value.iso8601}
          when ::Array
            {"array" => value.map { |item| dump(item) }}
          when ::Hash
            {"hash" => value.map { |key, item| [dump(key), dump(item)] }.sort_by { |pair| Canonical.dump(pair) }}
          when ::Set
            {"set" => value.map { |item| dump(item) }.sort_by { |item| Canonical.dump(item) }}
          when ::Module
            {"constant" => value.name || value.inspect}
          when ::Proc
            {"proc" => value.source_location}
          else
            if value.equal?(::Dry::Core::Constants::Undefined)
              {"undefined" => true}
            else
              {"opaque" => value.class.name, "inspect" => value.inspect}
            end
          end
        end

        # @api private
        def dump_all(values)
          values.map { |value| dump(value) }
        end

      end

      # Deterministic JSON encoding used for fingerprints and document digests
      #
      # @api private
      module Canonical
        module_function

        # @api private
        def dump(value)
          case value
          when ::Hash
            "{#{value.map { |key, item| "#{::JSON.generate(key.to_s)}:#{dump(item)}" }.sort.join(",")}}"
          when ::Array
            "[#{value.map { |item| dump(item) }.join(",")}]"
          when ::String
            ::JSON.generate(value)
          when ::Numeric, ::NilClass, ::TrueClass, ::FalseClass
            ::JSON.generate(value)
          else
            ::JSON.generate(value.to_s)
          end
        end

        # @api private
        def digest(value)
          ::Digest::SHA256.hexdigest(dump(value))
        end
      end
    end
  end
end
