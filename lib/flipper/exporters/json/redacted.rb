require "json"
require "flipper/exporters/json/export"
require "flipper/typecast"

module Flipper
  module Exporters
    module Json
      # Public: Builds a view-only export suitable for sharing with external
      # partners. Gate types and anonymous counts are preserved so recipients
      # can see how features are controlled, but actor identifiers, group
      # names, and expressions are never included. The payload carries a
      # license marker and is rejected by the normal import path, so it can
      # never replace production gates. Use the default exporter for full
      # backups.
      class Redacted
        VERSION = 1

        # Public: License marker identifying a view-only export.
        LICENSE = "view-only".freeze

        # Public: Placeholder used in place of expression gate values, which
        # may embed values that cannot be made public.
        REDACTED_EXPRESSION = "[REDACTED]".freeze

        # Raised when a redacted export is missing its license marker or
        # would leak a sensitive gate value.
        class InvalidRedactionError < StandardError; end

        def call(adapter)
          all = adapter.get_all

          features = all.each_with_object({}) do |(feature_key, gates), result|
            result[feature_key] = redact_gates(gates)
          end

          payload = {
            "version" => VERSION,
            "license" => LICENSE,
            "features" => features,
          }

          validate!(payload, all)

          Json::Export.new(contents: Typecast.to_json(payload), version: VERSION)
        end

        private

        def redact_gates(gates)
          {
            "boolean" => gates[:boolean],
            "actors" => count(gates[:actors]),
            "groups" => count(gates[:groups]),
            "percentage_of_actors" => gates[:percentage_of_actors],
            "percentage_of_time" => gates[:percentage_of_time],
            "expression" => gates[:expression] ? REDACTED_EXPRESSION : nil,
          }
        end

        def count(value)
          value.respond_to?(:size) ? value.size : 0
        end

        # Internal: Verifies the license marker is present and that no
        # sensitive value (actor identifiers, group names, or expressions)
        # made it into the payload.
        def validate!(payload, all)
          unless payload["license"] == LICENSE
            raise InvalidRedactionError, "redacted export is missing its license marker"
          end

          sensitive = sensitive_values(all)
          leaked = strings_in(payload).find { |string| sensitive.include?(string) }
          if leaked
            raise InvalidRedactionError, "redacted export contains sensitive value: #{leaked.inspect}"
          end
        end

        def sensitive_values(all)
          all.flat_map do |_feature_key, gates|
            values = Array(gates[:actors]).map(&:to_s) + Array(gates[:groups]).map(&:to_s)
            values << Typecast.to_json(gates[:expression]) if gates[:expression]
            values
          end.reject(&:empty?)
        end

        def strings_in(object)
          case object
          when Hash
            object.flat_map { |key, value| strings_in(key) + strings_in(value) }
          when Array
            object.flat_map { |element| strings_in(element) }
          when String
            [object]
          else
            []
          end
        end
      end
    end
  end
end
