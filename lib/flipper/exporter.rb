require "flipper/exporters/json/v1"
require "flipper/exporters/json/redacted"

module Flipper
  module Exporter
    extend self

    FORMATTERS = {
      json: {
        1 => Flipper::Exporters::Json::V1,
      }
    }.freeze

    def build(format: :json, version: 1, redacted: false)
      if redacted
        unless format == :json
          raise ArgumentError, "redacted exports are only available in json format"
        end
        return Flipper::Exporters::Json::Redacted.new
      end
      FORMATTERS.fetch(format).fetch(version).new
    end
  end
end
