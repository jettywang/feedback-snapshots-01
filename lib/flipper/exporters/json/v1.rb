require "json"
require "time"
require "flipper/exporters/json/export"

module Flipper
  module Exporters
    module Json
      class V1
        VERSION = 1

        def call(adapter)
          # Build a new structure rather than mutating the hash returned by
          # the adapter, which may be a reference to the adapter's live data.
          features = adapter.get_all.transform_values do |gates|
            gates.transform_values do |value|
              case value
              when Set
                value.to_a
              when Hash
                value.transform_values { |item| item.is_a?(Time) ? item.utc.iso8601 : item }
              else
                value
              end
            end
          end

          json = Typecast.to_json({
            version: VERSION,
            features: features,
          })

          Json::Export.new(contents: json, version: VERSION)
        end
      end
    end
  end
end
