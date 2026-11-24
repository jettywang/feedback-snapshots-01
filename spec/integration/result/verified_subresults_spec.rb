# frozen_string_literal: true

require "dry/schema"
require "dry/types"
require "dry/schema/messages/i18n"
require "i18n"

Dry::Schema.load_extensions(:hints) unless Dry::Schema::Result.method_defined?(:hints)

RSpec.describe "Verified subresults from failed dry-schema results" do
  before do
    I18n.backend.store_translations(
      :en,
      dry_schema: {
        errors: {
          parent_allowed?: "parent constraint rejected",
          positive_code?: "code must be positive"
        }
      }
    )
  end

  def flatten_entries(value, path = [], &block)
    return enum_for(:flatten_entries, value, path) unless block_given?

    case value
    when Hash
      if value.empty?
        yield path, value
      else
        value.each { |key, child| flatten_entries(child, path + [key], &block) }
      end
    when Array
      if value.empty?
        yield path, value
      else
        value.each_with_index { |child, index| flatten_entries(child, path + [index], &block) }
      end
    else
      yield path, value
    end
  end

  def error_paths(result)
    result.errors.map { |message| Dry::Schema::Path[message.path] }
  end

  # Reference extraction contract: a coerced value is deliverable only when no
  # failure sits on its exact path or on any ancestor path.
  def verified_entries(result)
    paths = error_paths(result)

    flatten_entries(result.to_h).reject do |path, _value|
      path = Dry::Schema::Path.new(path)
      paths.any? { |error_path| path.include?(error_path) }
    end.to_h
  end

  def status_for(result, path, called_paths)
    path = Array(path)
    path_object = Dry::Schema::Path.new(path)
    paths = error_paths(result)

    exact_error = paths.any? { |error_path| error_path.keys == path }
    ancestor_error = paths.any? { |error_path| path_object.include?(error_path) }
    called = called_paths.include?(path)

    if exact_error
      :explicitly_rejected
    elsif ancestor_error && !called
      :not_executed
    elsif ancestor_error
      :ran_but_remains_covered_by_failed_ancestor
    elsif called
      :passed
    else
      :not_executed
    end
  end

  def build_array_schema(call_log, &code_rule)
    predicates = Module.new do
      include Dry::Logic::Predicates

      predicate(:parent_allowed?) do |element|
        element[:state] == "active"
      end

      predicate(:positive_code?) do |value|
        call_log << value
        code_rule.call(value)
      end
    end

    Dry::Schema.Params do
      config.predicates = predicates
      config.messages.backend = :i18n

      required(:items).array(:hash, :parent_allowed?) do
        required(:state).filled(:string)
        required(:code).value(:integer, :positive_code?)
      end
    end
  end

  def error_double(path, coerced_value, leaf_name: Dry::Schema::Path[path].last)
    path = Dry::Schema::Path[path]

    double(
      "error at #{path.keys.join(".")}",
      path: path,
      leaf_name: leaf_name,
      coerced_value: coerced_value
    )
  end

  context "with two same-type siblings and one failing parent" do
    let(:call_log) { [] }
    let(:blocked_rule) { spy("recording rule items[0].code") }
    let(:verified_rule) { spy("recording rule items[1].code") }

    let(:rules_by_value) do
      {
        1 => blocked_rule,
        2 => verified_rule
      }
    end

    let(:paths_by_value) do
      {
        1 => [:items, 0, :code],
        2 => [:items, 1, :code]
      }
    end

    let(:called_paths) do
      call_log.map { |value| paths_by_value.fetch(value) }
    end

    let(:schema) do
      rules = rules_by_value
      build_array_schema(call_log) { |value| rules.fetch(value).call(value) }
    end

    let(:result) do
      schema.call(
        items: [
          {state: "blocked", code: "1"},
          {state: "active", code: "2"}
        ]
      )
    end

    before do
      allow(blocked_rule).to receive(:call).and_return(true)
      allow(verified_rule).to receive(:call).and_return(true)
    end

    it "coerces both sibling leaf values to the same type" do
      expect(result.to_h.dig(:items, 0, :code)).to be_a(Integer).and eq(1)
      expect(result.to_h.dig(:items, 1, :code)).to be_a(Integer).and eq(2)
    end

    it "keeps the parent failure usable through the existing error API" do
      expect(result).to be_failure
      expect(result.errors.to_h).to eq(
        items: {0 => ["parent constraint rejected"]}
      )

      expect(result.error?([:items, 0])).to be(true)
      # A failed ancestor is not a failure on the descendant spec, and a
      # short-circuit hint must not be reported as an error.
      expect(result.error?([:items, 0, :code])).to be(false)
      expect(result.error?([:items, 1, :code])).to be(false)
    end

    it "records the blocked path as not run and the sibling path as passed" do
      result

      expect(blocked_rule).not_to have_received(:call)
      expect(verified_rule).to have_received(:call).with(2).once
      expect(result.hints.to_h).to eq(
        items: {0 => {code: ["code must be positive"]}}
      )
      expect(called_paths).to eq([[:items, 1, :code]])

      expect(status_for(result, [:items, 0, :code], called_paths)).to eq(:not_executed)
      expect(status_for(result, [:items, 1, :code], called_paths)).to eq(:passed)
    end

    it "excludes the coerced value under the failed parent and keeps the full verified path" do
      expect(verified_entries(result)).to eq(
        [:items, 1, :state] => "active",
        [:items, 1, :code] => 2
      )

      code_entries = verified_entries(result).select { |path, _value| path.last == :code }

      expect(code_entries).to eq([:items, 1, :code] => 2)
      expect(code_entries.keys.first).to eq([:items, 1, :code])
    end
  end

  context "when all three execution outcomes occur in one array" do
    let(:call_log) { [] }

    let(:paths_by_value) do
      {
        1 => [:items, 0, :code],
        0 => [:items, 1, :code],
        2 => [:items, 2, :code]
      }
    end

    let(:called_paths) do
      call_log.map { |value| paths_by_value.fetch(value) }
    end

    let!(:result) do
      schema = build_array_schema(call_log) { |value| value.positive? }

      schema.call(
        items: [
          {state: "blocked", code: "1"},
          {state: "active", code: "0"},
          {state: "active", code: "2"}
        ]
      )
    end

    it "distinguishes parent-blocked, explicitly rejected, and passed paths" do
      expect(call_log).to eq([0, 2])
      expect(called_paths).to eq([[:items, 1, :code], [:items, 2, :code]])

      expect(status_for(result, [:items, 0, :code], called_paths)).to eq(:not_executed)
      expect(status_for(result, [:items, 1, :code], called_paths)).to eq(:explicitly_rejected)
      expect(status_for(result, [:items, 2, :code], called_paths)).to eq(:passed)

      expect(result.errors.to_h).to eq(
        items: {
          0 => ["parent constraint rejected"],
          1 => {code: ["code must be positive"]}
        }
      )
    end

    it "prunes only the rejected leaf while preserving its passing sibling field" do
      expect(verified_entries(result)).to eq(
        [:items, 1, :state] => "active",
        [:items, 2, :state] => "active",
        [:items, 2, :code] => 2
      )
    end
  end

  context "with nested objects" do
    let(:call_log) { [] }

    let(:schema) do
      log = call_log
      predicates = Module.new do
        include Dry::Logic::Predicates

        predicate(:parent_allowed?) do |element|
          element[:state] == "active"
        end

        predicate(:positive_code?) do |value|
          log << value
          value.positive?
        end
      end

      Dry::Schema.Params do
        config.predicates = predicates
        config.messages.backend = :i18n

        required(:account).hash do
          required(:blocked).value(:hash, :parent_allowed?).hash do
            required(:state).filled(:string)
            required(:code).value(:integer, :positive_code?)
          end

          required(:verified).value(:hash, :parent_allowed?).hash do
            required(:state).filled(:string)
            required(:code).value(:integer, :positive_code?)
          end
        end
      end
    end

    let!(:result) do
      schema.call(
        account: {
          blocked: {state: "blocked", code: "1"},
          verified: {state: "active", code: "2"}
        }
      )
    end

    it "uses the complete nested path for parent coverage and delivery" do
      expect(call_log).to eq([2])
      expect(result.error?([:account, :blocked])).to be(true)
      expect(result.error?([:account, :blocked, :code])).to be(false)

      expect(verified_entries(result)).to eq(
        [:account, :verified, :state] => "active",
        [:account, :verified, :code] => 2
      )
    end
  end

  context "when selecting error doubles" do
    it "selects by leaf field name when field names differ" do
      errors = [
        error_double([:account, :name], ""),
        error_double([:account, :code], 0)
      ]

      selected = errors.find { |error| error.leaf_name == :code }

      expect(selected.path.keys).to eq([:account, :code])
      expect(selected.coerced_value).to eq(0)
    end

    it "uses the coercion result to disambiguate same-leaf array siblings" do
      errors = [
        error_double([:items, 0, :code], 1),
        error_double([:items, 1, :code], 2)
      ]

      leaf_matches = errors.select { |error| error.leaf_name == :code }
      expect(leaf_matches.size).to eq(2)

      selected = leaf_matches.find { |error| error.coerced_value == 2 }

      expect(selected.path.keys).to eq([:items, 1, :code])
    end

    it "uses the full path prefix so a same-type sibling cannot be counted" do
      errors = [
        error_double([:items, 0], {code: 1}, leaf_name: :code),
        error_double([:items, 1, :code], 0)
      ]

      candidate_path = Dry::Schema::Path[[:items, 1, :code]]
      selected = errors.select { |error| candidate_path.include?(error.path) }

      expect(selected.map { |error| error.path.keys }).to eq([[:items, 1, :code]])
    end
  end
end
