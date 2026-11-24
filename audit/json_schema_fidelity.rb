# frozen_string_literal: true

# Local audit: compare dry-schema runtime (Params/JSON) with the exported
# JSON Schema for a tightened schema version pair. No external services.

require "dry/schema"
require "json"
require "date"

Dry::Schema.load_extensions(:json_schema)

module Audit
  module ExportCheck
    module_function

    # Small draft-06 subset evaluator for the keywords the exporter emits.
    # :annotation ignores `format`; :enforce applies ISO-8601 for `date`.
    # Returns true/false, or :unknown when a keyword cannot be evaluated
    # faithfully in Ruby (e.g. an invalid regex produced by `format?`).
    def accept?(schema, value, format: :annotation)
      return true if schema == true
      return false if schema == false

      schema = stringify_keys(schema)
      return false unless type_matches?(schema["type"], value)
      return false if schema.key?("enum") && schema["enum"].none? { |allowed| allowed == value }
      return false if schema.key?("const") && schema["const"] != value

      checks = [
        numeric_bounds?(schema, value),
        string_bounds?(schema, value, format),
        pattern_matches?(schema, value),
        array_bounds?(schema, value, format),
        object_bounds?(schema, value, format)
      ]
      return :unknown if checks.include?(:unknown)
      return false if checks.include?(false)

      if schema.key?("anyOf")
        results = schema["anyOf"].map { |sub| accept?(sub, value, format: format) }
        return :unknown if results.include?(:unknown)
        return false if results.none?(true)
      end
      return false if schema.key?("not") && accept?(schema["not"], value, format: format) == true

      true
    end

    def pattern_matches?(schema, value)
      return true unless schema["pattern"]
      return :unknown unless value.is_a?(String)

      Regexp.new(schema["pattern"]).match?(value)
    rescue RegexpError
      :unknown
    end

    def stringify_keys(hash)
      hash.to_h { |key, val| [key.to_s, val] }
    end

    def type_matches?(type, value)
      return true if type.nil?

      Array(type).any? do |name|
        case name
        when "null" then value.nil?
        when "boolean" then value.equal?(true) || value.equal?(false)
        when "object" then value.is_a?(Hash)
        when "array" then value.is_a?(Array)
        when "string" then value.is_a?(String)
        when "integer" then value.is_a?(Integer) || (value.is_a?(Float) && value.finite? && value == value.to_i)
        when "number" then value.is_a?(Numeric)
        else false
        end
      end
    end

    def numeric_bounds?(schema, value)
      minimum = schema["minimum"]
      exclusive = schema["exclusiveMinimum"]
      return true unless minimum || exclusive
      return false unless value.is_a?(Numeric)
      return false if minimum && value < minimum
      return false if exclusive && value <= exclusive

      true
    end

    def string_bounds?(schema, value, format)
      return true unless value.is_a?(String)
      return false if schema["minLength"] && value.length < schema["minLength"]
      return false if schema["maxLength"] && value.length > schema["maxLength"]
      return false if format == :enforce && schema["format"] == "date" && !iso_date?(value)

      true
    end

    def array_bounds?(schema, value, format)
      return true unless value.is_a?(Array)
      return false if schema["minItems"] && value.length < schema["minItems"]
      return false if schema["maxItems"] && value.length > schema["maxItems"]

      if schema["items"]
        return false unless value.all? { |item| accept?(schema["items"], item, format: format) }
      end

      true
    end

    def object_bounds?(schema, value, format)
      return true unless value.is_a?(Hash)

      normalized = value.to_h { |key, val| [key.to_s, val] }
      Array(schema["required"]).each { |key| return false unless normalized.key?(key) }

      properties = stringify_keys(schema["properties"] || {})
      properties.each do |key, sub|
        next unless normalized.key?(key)

        return false unless accept?(sub, normalized[key], format: format)
      end

      if schema["additionalProperties"] == false
        return false unless (normalized.keys - properties.keys).empty?
      end

      true
    end

    def iso_date?(value)
      return false unless %r{\A\d{4}-\d{2}-\d{2}\z}.match?(value)

      Date.iso8601(value)
      true
    rescue ArgumentError
      false
    end
  end

  module Schemas
    module_function

    # v1: permissive baseline used by existing partners.
    def v1(processor)
      processor.call do
        required(:tenant_id).value(:integer)
        required(:role).value(:string)
        optional(:scopes).value(:array).each(:string)
        optional(:expires_on).value(:date)
        optional(:channel).value(:string)
      end
    end

    # v2: tightened migration.
    def v2(processor)
      processor.call do
        config.validate_keys = true

        required(:tenant_id).value(:integer, gt?: 0)
        required(:role).value(:string, included_in?: %w[admin editor viewer])
        required(:scopes).value(:array, min_size?: 1, max_size?: 5)
          .each(:string, included_in?: %w[read write approve])
        required(:expires_on).value(:date)
        optional(:channel).maybe(:string, included_in?: %w[web mobile])
        required(:tier).value(Dry::Schema::Types::String.default("free".freeze))
      end
    end
  end

  CASES = [
    ["full", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro", channel: "web"}],
    ["no_tier(default)", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-02-29"}],
    ["channel_null", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro", channel: nil}],
    ["loose_date", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-2-9", tier: "pro"}],
    ["tenant_string", {"tenant_id" => "7", "role" => "admin", "scopes" => ["read"], "expires_on" => "2024-02-29", "tier" => "pro"}],
    ["tenant_float", {tenant_id: 7.0, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro"}],
    ["scopes_two", {tenant_id: 7, role: "editor", scopes: %w[read approve], expires_on: "2024-02-29", tier: "pro"}],
    ["extra_key", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro", admin: true}],
    ["missing_scopes", {tenant_id: 7, role: "admin", expires_on: "2024-02-29", tier: "pro"}],
    ["scopes_empty", {tenant_id: 7, role: "admin", scopes: [], expires_on: "2024-02-29", tier: "pro"}],
    ["scopes_six", {tenant_id: 7, role: "admin", scopes: %w[read read read read read read], expires_on: "2024-02-29", tier: "pro"}],
    ["scope_invalid", {tenant_id: 7, role: "admin", scopes: %w[delete], expires_on: "2024-02-29", tier: "pro"}],
    ["role_case", {tenant_id: 7, role: "Admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro"}],
    ["tenant_zero", {tenant_id: 0, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro"}],
    ["tenant_missing", {role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro"}],
    ["date_invalid", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "not-a-date", tier: "pro"}],
    ["tier_null", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: nil}],
    ["channel_tv", {tenant_id: 7, role: "admin", scopes: %w[read], expires_on: "2024-02-29", tier: "pro", channel: "tv"}]
  ].freeze

  module_function

  def label(value)
    value == :unknown ? "N/A" : (value ? "OK" : "FAIL")
  end

  def verdict(schema, input)
    schema.call(input).success? ? "OK" : "FAIL"
  rescue StandardError => e
    "RAISE #{e.class}"
  end

  def run
    params_v1 = Schemas.v1(Dry::Schema.method(:Params))
    json_v1 = Schemas.v1(Dry::Schema.method(:JSON))
    params_v2 = Schemas.v2(Dry::Schema.method(:Params))
    json_v2 = Schemas.v2(Dry::Schema.method(:JSON))

    puts "## Exports"
    {v1: [params_v1, json_v1], v2: [params_v2, json_v2]}.each do |name, (params, json)|
      puts "#{name} params_json_equal_json=#{params.json_schema == json.json_schema}"
      puts "#{name} export=#{JSON.generate(json.json_schema)}"
    end
    puts

    # Partners receive the JSON text, not the in-memory hash: symbol enums
    # and other Ruby-only values are stringified by JSON.generate.
    export = JSON.parse(JSON.generate(json_v2.json_schema))
    puts "## Runtime vs export matrix"
    puts "| case | v1 Params | v1 JSON | v2 Params | v2 JSON | v2 export (format ignored) | v2 export (format enforced) |"
    puts "|---|---|---|---|---|---|---|"
    CASES.each do |name, input|
      puts [
        "| #{name}",
        verdict(params_v1, input),
        verdict(json_v1, input),
        verdict(params_v2, input),
        verdict(json_v2, input),
        label(ExportCheck.accept?(export, input)),
        label(ExportCheck.accept?(export, input, format: :enforce))
      ].join(" | ") + " |"
    end
  end
end

Audit.run if $PROGRAM_NAME == __FILE__
