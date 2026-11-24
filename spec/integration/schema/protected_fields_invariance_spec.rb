# frozen_string_literal: true

# Tools for a small generative regression around legal inputs.
#
# The generator deliberately only performs transformations whose semantics are
# clear for a given processor:
#
#   * symbol/string/mixed key forms
#   * reordering keys inside nested hashes
#   * decimal integer strings for `Dry::Schema::Params` (which coerces them)
#
# It never permutes array elements because their index is part of a diagnostic
# path, and it never sends decimal integer strings to `Dry::Schema::JSON`,
# which does not coerce them.
module ProtectedFieldsInvariance
  SEED = 20_261_120

  ORDER_KEYS = %w[id role note lines].freeze
  LINE_KEYS = %w[sku qty].freeze
  KEY_FORMS = %i[symbol_keys string_keys outer_strings outer_symbols].freeze

  # A diagnostic from a test double that should be distinguishable from a real
  # diagnostic by both its path and its position in the message set.
  MessageDouble = Struct.new(:path, :predicate, :text)

  # A minimal result-shaped object with a fixed success flag.
  class ValueResult
    attr_reader :to_h

    def initialize(to_h, success:)
      @to_h = to_h
      @success = success
    end

    def success?
      @success
    end

    def message_set(_options = {})
      EMPTY_MESSAGES
    end

    EMPTY_MESSAGES = [].freeze
  end

  # A result-shaped object used to prove that the invariant assertion really
  # compares values and diagnostic paths instead of only checking success.
  class ResultDouble
    attr_reader :to_h

    def initialize(result, to_h: result.to_h, message_set: result.message_set)
      @success = result.success?
      @to_h = to_h
      @message_set = message_set
    end

    def success?
      @success
    end

    # Mirrors Result#message_set(options), which callers may invoke with
    # `hints: false`. The double stores an already-selected message list.
    def message_set(_options = {})
      @message_set
    end
  end

  InvariantViolation = Class.new(StandardError)

  # Maps a short description to the minimal input and the exact path
  # diagnostics we expect from the schema itself. With these expectations the
  # invariance check cannot pass vacuously if a rule stops being applied.
  SCENARIOS = {
    "minimal legal nested shape" => [
      {order: {id: 1, role: "member", lines: [{sku: "ab", qty: 1}]}},
      []
    ],
    "optional key present and valid" => [
      {order: {id: 1, role: "member", note: "ok", lines: [{sku: "ab", qty: 1}]}},
      []
    ],
    "optional key present but too short" => [
      {order: {id: 1, role: "member", note: "x", lines: [{sku: "ab", qty: 1}]}},
      [[[:order, :note], :min_size?, "size cannot be less than 2"]]
    ],
    "empty array is legal" => [
      {order: {id: 1, role: "member", lines: []}},
      []
    ],
    "integer lower bound violation" => [
      {order: {id: 0, role: "member", lines: [{sku: "ab", qty: 1}]}},
      [[[:order, :id], :gt?, "must be greater than 0"]]
    ],
    "membership violation" => [
      {order: {id: 1, role: "admin", lines: [{sku: "ab", qty: 1}]}},
      [[[:order, :role], :included_in?, "must be one of: member, manager"]]
    ],
    "array element string size violation" => [
      {order: {id: 1, role: "member", lines: [{sku: "a", qty: 1}]}},
      [[[:order, :lines, 0, :sku], :min_size?, "size cannot be less than 2"]]
    ],
    "array element integer lower bound violation" => [
      {order: {id: 1, role: "member", lines: [{sku: "ab", qty: 0}]}},
      [[[:order, :lines, 0, :qty], :gt?, "must be greater than 0"]]
    ],
    "second array element violation keeps its index" => [
      {order: {id: 1, role: "member", lines: [{sku: "ab", qty: 1}, {sku: "cd", qty: 0}]}},
      [[[:order, :lines, 1, :qty], :gt?, "must be greater than 0"]]
    ],
    "missing required nested key" => [
      {order: {id: 1, lines: [{sku: "ab", qty: 1}]}},
      [[[:order, :role], :key?, "is missing"]]
    ],
    "array type violation" => [
      {order: {id: 1, role: "member", lines: "not-an-array"}},
      [[[:order, :lines], :array?, "must be an array"]]
    ],
    "array element type violation" => [
      {order: {id: 1, role: "member", lines: [nil]}},
      [[[:order, :lines, 0], :hash?, "must be a hash"]]
    ],
    "compound protected-field violations" => [
      {order: {id: 0, role: "admin", lines: [{sku: "ab", qty: 0}]}},
      [
        [[:order, :id], :gt?, "must be greater than 0"],
        [[:order, :lines, 0, :qty], :gt?, "must be greater than 0"],
        [[:order, :role], :included_in?, "must be one of: member, manager"]
      ]
    ]
  }.freeze

  # Params accepts decimal integer strings. JSON is strict about integer
  # types, so its generated inputs keep native integers only.
  ENTRY_POINTS = {
    "Params" => {processor: :Params, integer_forms: %i[native decimal_string]},
    "JSON" => {processor: :JSON, integer_forms: %i[native]}
  }.freeze

  module_function

  def build_schema(processor)
    Dry::Schema.public_send(processor) do
      required(:order).hash do
        required(:id).filled(:integer, gt?: 0)
        required(:role).filled(:string, included_in?: %w[member manager])
        optional(:note).filled(:string, min_size?: 2)
        required(:lines).array(:hash) do
          required(:sku).filled(:string, min_size?: 2)
          required(:qty).filled(:integer, gt?: 0)
        end
      end
    end
  end

  def build_schema_with_key_validation(processor)
    Dry::Schema.public_send(processor) do
      config.validate_keys = true

      required(:order).hash do
        required(:id).filled(:integer, gt?: 0)
        required(:role).filled(:string)
        optional(:note).filled(:string, min_size?: 2)
        required(:lines).array(:hash) do
          required(:sku).filled(:string)
          required(:qty).filled(:integer)
        end
      end
    end
  end

  # Yields the same small hash written with each key form, plus a couple of
  # reorderings. Used where only the key form, not the values, varies.
  module KeyFormVariants
    module_function

    def each(value)
      KEY_FORMS.each do |form|
        transformed = ProtectedFieldsInvariance.transform_key_form(value, form)
        yield transformed
        yield transformed.to_a.reverse.to_h
      end
    end
  end

  def deep_dup(value)
    case value
    when Hash
      value.each_with_object({}) { |(key, child), copy| copy[key] = deep_dup(child) }
    when Array
      value.map { |child| deep_dup(child) }
    else
      value
    end
  end

  def outcome(result)
    {
      success: result.success?,
      value: result.to_h,
      diagnostics: diagnostics(result)
    }
  end

  # Hints are derived, extension-specific embellishments. Compare the
  # schema's own path diagnostics so the regression is independent of the
  # ambient `:hints` extension configuration.
  def diagnostics(result)
    result.message_set(hints: false).map do |message|
      [message.path, message.predicate, message.text]
    end.sort_by { |path, predicate, text| [path.map(&:to_s), predicate.to_s, text] }
  end

  def assert_same_outcome!(reference, candidate, label: nil)
    expected = outcome(reference)
    actual = outcome(candidate)

    return true if expected == actual

    raise InvariantViolation, <<~MESSAGE
      legal input changed the outcome#{label ? " for #{label}" : ""}
      expected value:       #{expected[:value].inspect}
      actual value:         #{actual[:value].inspect}
      expected diagnostics: #{expected[:diagnostics].inspect}
      actual diagnostics:   #{actual[:diagnostics].inspect}
    MESSAGE
  end

  def variants(input, integer_forms)
    rng = Random.new(SEED)

    # The fixed seed only chooses a couple of key-order permutations; values
    # come from the small scenario table above, never from random data.
    order_orders = [
      ORDER_KEYS,
      ORDER_KEYS.reverse,
      ORDER_KEYS.shuffle(random: rng),
      ORDER_KEYS.shuffle(random: rng)
    ].uniq
    line_orders = [LINE_KEYS, LINE_KEYS.reverse].uniq

    generated = integer_forms.flat_map do |integer_form|
      semantic_input = apply_integer_form(input, integer_form)

      order_orders.flat_map do |order_order|
        line_orders.flat_map do |line_order|
          ranks = ranks_for(order_order, line_order)

          KEY_FORMS.map do |key_form|
            reordered = reorder(
              transform_key_form(semantic_input, key_form),
              ranks
            )

            {
              integer_form: integer_form,
              key_form: key_form,
              order_order: order_order,
              line_order: line_order,
              input: reordered
            }
          end
        end
      end
    end

    # Hash equality ignores insertion order, so de-duplicate using an
    # order-preserving signature. This keeps reordered variants that would
    # otherwise look identical.
    generated.uniq { |variant| signature(variant.fetch(:input)) }
  end

  def signature(value)
    case value
    when Hash
      [:hash, value.map { |key, child| [key, signature(child)] }]
    when Array
      [:array, value.map { |child| signature(child) }]
    else
      [value.class, value]
    end
  end

  def apply_integer_form(input, form)
    case form
    when :native
      deep_dup(input)
    when :decimal_string
      stringify_integer_fields(input)
    else
      raise ArgumentError, "unknown integer form: #{form.inspect}"
    end
  end

  def stringify_integer_fields(input)
    copy = deep_dup(input)
    order = copy[:order]
    return copy unless order.is_a?(Hash)

    order[:id] = order[:id].to_s if order[:id].is_a?(Integer)

    lines = order[:lines]
    return copy unless lines.is_a?(Array)

    lines.each do |line|
      next unless line.is_a?(Hash)

      line[:qty] = line[:qty].to_s if line[:qty].is_a?(Integer)
    end

    copy
  end

  def key_for(key, form, depth)
    string_key =
      case form
      when :symbol_keys then false
      when :string_keys then true
      when :outer_strings then depth <= 1
      when :outer_symbols then depth >= 2
      else
        raise ArgumentError, "unknown key form: #{form.inspect}"
      end

    string_key ? key.to_s : key.to_sym
  end

  def transform_key_form(value, form, depth = 0)
    case value
    when Hash
      value.each_with_object({}) do |(key, child), copy|
        copy[key_for(key, form, depth)] = transform_key_form(child, form, depth + 1)
      end
    when Array
      value.map { |child| transform_key_form(child, form, depth) }
    else
      value
    end
  end

  def reorder(value, ranks, depth = 0)
    case value
    when Hash
      rank = ranks.fetch(depth, {})
      sorted = value.keys.sort_by { |key| rank.fetch(key.to_s, rank.length + KEY_FORMS.length) }

      sorted.each_with_object({}) do |key, copy|
        copy[key] = reorder(value[key], ranks, depth + 1)
      end
    when Array
      value.map { |child| reorder(child, ranks, depth) }
    else
      value
    end
  end

  def ranks_for(order_order, line_order)
    {
      1 => order_order.each_with_index.to_h,
      2 => line_order.each_with_index.to_h
    }
  end

  def result_double(result, value: result.to_h, messages: result.message_set(hints: false))
    ResultDouble.new(result, to_h: value, message_set: messages)
  end

  def move_diagnostic(messages, from:, to:)
    messages.map do |message|
      if message.path == from
        ProtectedFieldsInvariance::MessageDouble.new(to, message.predicate, message.text)
      else
        message
      end
    end
  end

  # A tiny property-test-style shrinker: apply only reductions that keep the
  # failure reproduced, and stop when no reduction changes the input.
  def shrink(input)
    reductions = [
      ->(candidate) { drop_nested_key(candidate, :order, :note) },
      ->(candidate) { keep_first_element(candidate, :order, :lines) }
    ]

    current = deep_dup(input)

    loop do
      smaller = reductions.lazy
        .map { |reduction| reduction.call(current) }
        .find { |candidate| candidate != current && yield(candidate) }

      break unless smaller

      current = smaller
    end

    current
  end

  def drop_nested_key(input, parent_key, key)
    copy = deep_dup(input)
    parent = copy[parent_key]
    return copy unless parent.is_a?(Hash)

    parent.delete(key)
    copy
  end

  def keep_first_element(input, parent_key, key)
    copy = deep_dup(input)
    parent = copy[parent_key]
    return copy unless parent.is_a?(Hash)

    array = parent[key]
    return copy unless array.is_a?(Array) && array.length > 1

    parent[key] = array.first(1)
    copy
  end

  def symbolize_keys(value)
    case value
    when Hash
      value.each_with_object({}) { |(key, child), copy| copy[key.to_sym] = symbolize_keys(child) }
    when Array
      value.map { |child| symbolize_keys(child) }
    else
      value
    end
  end
end

RSpec.describe Dry::Schema, "protected fields under legal key and order variations" do
  include ProtectedFieldsInvariance

  entry_points = ProtectedFieldsInvariance::ENTRY_POINTS
  scenarios = ProtectedFieldsInvariance::SCENARIOS

  entry_points.each do |entry_name, entry_config|
    context "with Dry::Schema.#{entry_name}" do
      let(:schema) { build_schema(entry_config.fetch(:processor)) }
      let(:integer_forms) { entry_config.fetch(:integer_forms) }

      scenarios.each do |label, (input, expected_diagnostics)|
        it "keeps the same value and path diagnostics for #{label}" do
          reference = schema.(deep_dup(input))

          expect(reference.to_h).to eq(input)
          expect(diagnostics(reference)).to eq(expected_diagnostics)

          variants(input, integer_forms).each do |variant|
            result = schema.(variant.fetch(:input))
            variant_label = [
              entry_name,
              label,
              variant.fetch(:integer_form),
              variant.fetch(:key_form),
              variant.fetch(:order_order).join(","),
              variant.fetch(:line_order).join(",")
            ].join(" / ")

            assert_same_outcome!(reference, result, label: variant_label)
          end
        end
      end
    end
  end

  describe "protected fields under unexpected-key validation" do
    let(:schema) { build_schema_with_key_validation(processor) }

    ProtectedFieldsInvariance::ENTRY_POINTS.each_key do |entry_name|
      context "with Dry::Schema.#{entry_name}" do
        let(:processor) do
          ProtectedFieldsInvariance::ENTRY_POINTS.fetch(entry_name).fetch(:processor)
        end

        it "rejects unexpected siblings regardless of key form and order" do
          legal = {
            "id" => 1,
            "role" => "member",
            "note" => "ok",
            "lines" => [{"sku" => "ab", "qty" => 1}]
          }
          # `not` is a prefix sibling of `note`. Loose prefix matching in the
          # key validator would silently allow it.
          illegal = legal.merge("not" => "x")

          reference = schema.(order: illegal)
          expect(diagnostics(reference)).to eq(
            [[[:order, :not], :unexpected_key, "is not allowed"]]
          )

          ProtectedFieldsInvariance::KeyFormVariants.each(illegal) do |variant|
            result = schema.(order: variant)
            expect(diagnostics(result)).to eq(diagnostics(reference))
          end
        end

        it "rejects unexpected siblings inside array elements after reordering" do
          # `sk` is a prefix sibling of `sku`.
          illegal = {
            "lines" => [{"sk" => "x", "qty" => 1, "sku" => "ab"}],
            "role" => "member",
            "id" => 1
          }

          reference = schema.(order: illegal)
          expect(diagnostics(reference)).to eq(
            [[[:order, :lines, 0, :sk], :unexpected_key, "is not allowed"]]
          )

          ProtectedFieldsInvariance::KeyFormVariants.each(illegal) do |variant|
            result = schema.(order: variant)
            expect(diagnostics(result)).to eq(diagnostics(reference))
          end
        end
      end
    end
  end

  describe "failure-path value coercion" do
    let(:schema) { build_schema(:Params) }

    it "coerces keys that did not fail when another key fails pre-coercion" do
      filtered = Dry::Schema.Params do
        required(:age).filter(format?: /\d+/).filled(:integer, gt?: 18)
        required(:order).hash do
          required(:id).filled(:integer)
        end
      end

      result = filtered.(
        age: "not-a-number",
        order: {id: "7"}
      )

      expect(result).to be_failure
      # `age` failed its filter and keeps its raw value; `order.id` had no
      # error and must still receive Params coercion.
      expect(result.to_h).to eq(age: "not-a-number", order: {id: 7})
      expect(diagnostics(result)).to eq(
        [[[:age], :format?, "is in invalid format"]]
      )
    end

    it "still coerces allowed decimal integer strings when another key fails" do
      result = schema.(
        order: {
          id: "1",
          role: "admin",
          lines: [{sku: "ab", qty: "1"}]
        }
      )

      expect(result).to be_failure
      expect(result.to_h).to eq(
        order: {id: 1, role: "admin", lines: [{sku: "ab", qty: 1}]}
      )
      expect(diagnostics(result)).to eq(
        [[[:order, :role], :included_in?, "must be one of: member, manager"]]
      )
    end

    it "coerces string integers for a nested array element whose sibling fails" do
      result = schema.(
        order: {
          id: 1,
          role: "member",
          lines: [{sku: "a", qty: "2"}]
        }
      )

      expect(result).to be_failure
      expect(result.to_h).to eq(
        order: {id: 1, role: "member", lines: [{sku: "a", qty: 2}]}
      )
      expect(diagnostics(result)).to eq(
        [[[:order, :lines, 0, :sku], :min_size?, "size cannot be less than 2"]]
      )
    end
  end

  describe "entry-specific allowed types" do
    let(:minimal_input) do
      {order: {id: 1, role: "member", lines: [{sku: "ab", qty: 1}]}}
    end

    it "lets Params coerce decimal integer strings without changing the outcome" do
      params_schema = build_schema(:Params)
      reference = params_schema.(deep_dup(minimal_input))
      coerced = params_schema.(
        order: {id: "1", role: "member", lines: [{sku: "ab", qty: "1"}]}
      )

      expect(outcome(coerced)).to eq(outcome(reference))
      expect(coerced.to_h).to eq(order: {id: 1, role: "member", lines: [{sku: "ab", qty: 1}]})
    end

    it "does not coerce decimal integer strings for JSON" do
      json_schema = build_schema(:JSON)
      result = json_schema.(
        order: {id: "1", role: "member", lines: [{sku: "ab", qty: "1"}]}
      )

      expect(result).to be_failure
      expect(diagnostics(result)).to eq(
        [
          [[:order, :id], :int?, "must be an integer"],
          [[:order, :lines, 0, :qty], :int?, "must be an integer"]
        ]
      )
    end
  end

  describe "variant generator" do
    let(:minimal_input) do
      {order: {id: 1, role: "member", lines: [{sku: "ab", qty: 1}]}}
    end

    it "uses a fixed seed and produces reproducible permutations" do
      first = variants(minimal_input, %i[native decimal_string])
      second = variants(minimal_input, %i[native decimal_string])

      expect(second.map { |variant| signature(variant.fetch(:input)) })
        .to eq(first.map { |variant| signature(variant.fetch(:input)) })
    end

    it "covers symbol, string and mixed key forms, plus reordered nested keys" do
      generated = variants(minimal_input, %i[native])

      expect(generated.map { |variant| variant.fetch(:key_form) }.uniq)
        .to match_array(ProtectedFieldsInvariance::KEY_FORMS)
      expect(generated.map { |variant| variant.fetch(:order_order) }.uniq.length)
        .to be >= 2
      expect(generated.map { |variant| variant.fetch(:line_order) }.uniq.length)
        .to be >= 2
    end

    it "never permutes array elements because their index is part of the path" do
      two_lines = {
        order: {
          id: 1,
          role: "member",
          lines: [{sku: "ab", qty: 1}, {sku: "cd", qty: 2}]
        }
      }

      variants(two_lines, %i[native]).each do |variant|
        lines = symbolize_keys(variant.fetch(:input)).fetch(:order).fetch(:lines)

        expect(lines.map { |line| line.fetch(:sku) }).to eq(%w[ab cd])
      end
    end
  end

  describe "invariant assertion" do
    # These examples exercise the comparison machinery with synthetic results,
    # so they stay meaningful regardless of which rules the schema applies.
    let(:value) do
      {order: {id: 1, role: "member", lines: [{sku: "ab", qty: 0}]}}
    end
    let(:messages) do
      [
        ProtectedFieldsInvariance::MessageDouble.new(
          [:order, :lines, 0, :qty], :gt?, "must be greater than 0"
        ),
        ProtectedFieldsInvariance::MessageDouble.new(
          [:order, :id], :gt?, "must be greater than 0"
        )
      ]
    end
    let(:reference) do
      result_double(
        ProtectedFieldsInvariance::ValueResult.new(value, success: false),
        messages: messages
      )
    end

    it "fails when a test double associates a diagnostic with a sibling path" do
      moved = move_diagnostic(
        messages,
        from: [:order, :lines, 0, :qty],
        to: [:order, :lines, 0, :sku]
      )
      tampered = result_double(
        ProtectedFieldsInvariance::ValueResult.new(value, success: false),
        messages: moved
      )

      expect { assert_same_outcome!(reference, tampered) }
        .to raise_error(ProtectedFieldsInvariance::InvariantViolation) { |error|
          expect(error.message).to include("[:order, :lines, 0, :qty]")
          expect(error.message).to include("[:order, :lines, 0, :sku]")
        }
    end

    it "fails when a test double changes only a value" do
      changed = deep_dup(value)
      changed[:order][:id] = 99
      tampered = result_double(
        ProtectedFieldsInvariance::ValueResult.new(changed, success: false),
        messages: messages
      )

      expect { assert_same_outcome!(reference, tampered) }
        .to raise_error(ProtectedFieldsInvariance::InvariantViolation, /expected value:/)
    end

    it "does not raise when the outcome is unchanged" do
      expect { assert_same_outcome!(reference, reference) }.not_to raise_error
    end

    it "shrinks the failing case to the minimal legal nested example" do
      # Both the predicate and the tamper are derived from the candidate's
      # shape, never from the schema's rules, so the fixture stays independent
      # of the behavior under test. Any first line gives us a qty diagnostic
      # to move onto its sibling key.
      failing = lambda do |candidate|
        first_line = candidate.dig(:order, :lines, 0)
        next false unless first_line

        messages = [
          ProtectedFieldsInvariance::MessageDouble.new(
            [:order, :lines, 0, :qty], :gt?, "must be greater than 0"
          )
        ]
        moved = move_diagnostic(
          messages,
          from: [:order, :lines, 0, :qty],
          to: [:order, :lines, 0, :sku]
        )
        result = ProtectedFieldsInvariance::ValueResult.new(candidate, success: false)
        tampered = result_double(result, messages: moved)

        begin
          assert_same_outcome!(result, tampered)
          false
        rescue ProtectedFieldsInvariance::InvariantViolation
          true
        end
      end

      start = {
        order: {
          id: 1,
          role: "member",
          note: "ok",
          lines: [{sku: "ab", qty: 0}, {sku: "cd", qty: 1}]
        }
      }

      minimal = shrink(start, &failing)

      expect(minimal).to eq(
        order: {id: 1, role: "member", lines: [{sku: "ab", qty: 0}]}
      )
      expect(failing.call(minimal)).to be(true)
      expect(failing.call(start)).to be(true)
    end
  end
end
