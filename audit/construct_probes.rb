# frozen_string_literal: true

# Construct-level probes: for each rule shape, show the actual export and
# what Params/JSON accept at runtime. Run with the pinned bundle:
#   BUNDLE_FROZEN=true .feedback/bundle-env exec ruby -Ilib audit/construct_probes.rb

require_relative "json_schema_fidelity"

Dry::Schema.load_extensions(:json_schema)

module Audit
  module ConstructProbes
    module_function

    def params(&block) = Dry::Schema.Params(&block)
    def json(&block) = Dry::Schema.JSON(&block)

    def export_of(schema)
      JSON.generate(schema.json_schema)
    rescue StandardError => e
      "EXPORT_ERROR #{e.class}: #{e.message.lines.first.strip}"
    end

    def outcome(schema, input)
      schema.call(input).success? ? "OK" : "FAIL"
    rescue StandardError => e
      "RAISE #{e.class}"
    end

    def row(name, builder, inputs)
      p_schema = builder.call(Dry::Schema.method(:Params))
      j_schema = builder.call(Dry::Schema.method(:JSON))
      exp = export_of(j_schema)
      exp_result =
        if exp.start_with?("EXPORT_ERROR")
          exp
        else
          parsed = JSON.parse(JSON.generate(j_schema.json_schema))
          inputs.map { |i| Audit.label(Audit::ExportCheck.accept?(parsed, i)) }.join("/")
        end
      p_results = inputs.map { |i| outcome(p_schema, i) }.join("/")
      j_results = inputs.map { |i| outcome(j_schema, i) }.join("/")
      input_desc = inputs.map(&:inspect).join(" ; ")

      puts "| #{name} | #{input_desc} | #{exp} | #{p_results} | #{j_results} | #{exp_result} |"
    rescue StandardError => e
      puts "| #{name} | DEFINE_ERROR | #{e.class}: #{e.message.lines.first.strip} | - | - | - |"
    end

    CASES = [
      ["validate_keys", ->(p) { p.call { config.validate_keys = true; required(:a).value(:string) } },
       [{a: "x", extra: 1}]],
      ["defaulted required", ->(p) { p.call { required(:tier).value(Dry::Schema::Types::String.default("free".freeze)) } },
       [{}, {tier: "pro"}]],
      ["filled(:hash)", ->(p) { p.call { required(:h).filled(:hash) } },
       [{h: {}}, {h: {a: 1}}]],
      ["filled bare", ->(p) { p.call { required(:v).filled } },
       [{v: ""}, {v: []}, {v: 0}]],
      ["filled(:array)", ->(p) { p.call { required(:v).filled(:array) } },
       [{v: []}, {v: [1]}]],
      ["maybe hash nested", ->(p) { p.call { required(:h).maybe(:hash) { required(:a).value(:string) } } },
       [{h: {}}, {h: {a: "x"}}, {h: nil}]],
      ["maybe + enum", ->(p) { p.call { required(:v).maybe(:string, included_in?: %w[a b]) } },
       [{v: nil}, {v: "a"}, {v: ""}]],
      ["maybe + const", ->(p) { p.call { required(:v).maybe(:integer, eql?: 1) } },
       [{v: nil}, {v: 1}]],
      ["true? only", ->(p) { p.call { required(:v).value(:true?) } },
       [{v: true}, {v: false}]],
      ["bool + true?", ->(p) { p.call { required(:v).value(:bool, :true?) } },
       [{v: true}, {v: false}]],
      ["hash min_size", ->(p) { p.call { required(:v).value(:hash, min_size?: 2) } },
       [{v: {a: 1}}, {v: {a: 1, b: 2}}]],
      ["integer min_size", ->(p) { p.call { required(:v).value(:integer, min_size?: 100) } },
       [{v: 1}, {v: 2**200}]],
      ["array size?", ->(p) { p.call { required(:v).value(:array, size?: 2) } },
       [{v: [1]}, {v: [1, 2]}]],
      ["array(:hash) min_size", ->(p) { p.call { required(:v).array(:hash, min_size?: 2) } },
       [{v: [{a: 1}]}, {v: [{a: 1, b: 2}]}]],
      ["format with /i", ->(p) { p.call { required(:v).value(:string, format?: /\A[a-z]+\z/i) } },
       [{v: "AB"}, {v: "ab"}]],
      ["format plain anchors", ->(p) { p.call { required(:v).value(:string, format?: /\Aabc\z/) } },
       [{v: "abc"}, {v: "xabc"}]],
      ["symbol enum", ->(p) { p.call { required(:v).value(included_in?: %i[a b]) } },
       [{v: :a}, {v: "a"}]],
      ["uuid_v4?", ->(p) { p.call { required(:v).value(:uuid_v4?) } },
       [{v: "A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11"}, {v: "a0eebc999c0b4ef8bb6d6bb9bd380a11"}]],
      ["string gt", ->(p) { p.call { required(:v).value(:string, gt?: "m") } },
       [{v: "z"}, {v: "a"}]],
      ["date gt", ->(p) { p.call { required(:v).value(:date, gt?: Date.new(2024, 1, 1)) } },
       [{v: "2024-02-29"}, {v: "2023-01-01"}]],
      ["float odd", ->(p) { p.call { required(:v).value(:float, :odd?) } },
       [{v: 3.0}, {v: 2.0}]],
      ["integer coercion", ->(p) { p.call { required(:v).value(:integer) } },
       [{v: "7"}, {v: 7.0}, {v: 7}]],
      ["float strictness", ->(p) { p.call { required(:v).value(:float) } },
       [{v: 42}, {v: 42.0}]],
      ["maybe empty string", ->(p) { p.call { required(:v).maybe(:string) } },
       [{v: ""}, {v: nil}]],
      ["maybe array each", ->(p) { p.call { required(:v).maybe(:array).each(:integer) } },
       [{v: nil}, {v: [1]}]],
      ["filter + date", ->(p) { p.call { required(:v).filter(format: /\A\d{4}-\d{2}-\d{2}\z/).value(:date) } },
       [{v: "2024-2-9"}, {v: "2024-02-29"}]],
      ["size? Range", ->(p) { p.call { required(:v).value(:array, size?: 2..4) } },
       [{v: [1]}, {v: [1, 2]}]]
    ].freeze

    def run
      puts "| construct | inputs | export | Params | JSON | export accepts |"
      puts "|---|---|---|---|---|---|"
      CASES.each { |name, builder, inputs| row(name, builder, inputs) }
    end
  end
end

Audit::ConstructProbes.run if $PROGRAM_NAME == __FILE__
