# frozen_string_literal: true

RSpec.describe Dry::Schema, "key attribution" do
  let(:rule_values) { [] }

  let(:predicates) do
    observed_values = rule_values

    Module.new do
      include Dry::Logic::Predicates

      define_singleton_method(:observed_owner_rule?) do |value|
        observed_values << value
        value.is_a?(::Integer) && value.positive?
      end
    end
  end

  def build_params_schema(predicate_registry, **options)
    conflict = options.fetch(:conflict, :reject)
    permit_aliases = options.fetch(:permit_aliases, true)
    validate_keys = options.fetch(:validate_keys, false)
    alias_definition = options.fetch(:alias_definition, [:owner])

    Dry::Schema.Params do
      config.predicates = predicate_registry
      config.validate_keys = validate_keys
      config.key_attribution = true
      config.key_conflict_policy = conflict
      config.permit_key_aliases = permit_aliases

      required(:items).array(:hash) do
        required(:owner_id, aliases: alias_definition)
          .filled(:integer, :observed_owner_rule?)
      end
    end
  end

  it "tracks a registered alias through Params coercion and runs the rule once" do
    schema = build_params_schema(predicates)

    result = schema.("items" => [{"owner" => "42"}])

    expect(result).to be_success
    expect(result.to_h).to eql(items: [{owner_id: 42}])
    expect(rule_values).to eql([42])

    source = result.key_attribution.origin_for([:items, 0, :owner_id])
    expect(source.source_path).to eql([:items, 0, :owner])
    expect(source.raw_source_path).to eql([:items, 0, "owner"])
    expect(source.value).to eql(42)
    expect(source).to be_alias
  end

  it "keeps canonical input attribution without requiring alias use" do
    schema = build_params_schema(predicates)

    result = schema["items" => [{"owner_id" => "42"}]]

    expect(result).to be_success
    expect(result.to_h).to eql(items: [{owner_id: 42}])
    expect(rule_values).to eql([42])

    source = result.key_attribution.origin_for([:items, 0, :owner_id])
    expect(source.source_path).to eql([:items, 0, :owner_id])
    expect(source).not_to be_alias
  end

  it "preserves JSON value conventions" do
    registry = predicates

    schema = Dry::Schema.JSON do
      config.predicates = registry
      config.key_attribution = true

      required(:items).array(:hash) do
        required(:owner_id, aliases: [:owner])
          .filled(:integer, :observed_owner_rule?)
      end
    end

    result = schema.("items" => [{"owner" => 42}])

    expect(result).to be_success
    expect(result.to_h).to eql(items: [{owner_id: 42}])
    expect(rule_values).to eql([42])
    expect(result.key_attribution.source_path_for([:items, 0, :owner_id]))
      .to eql([:items, 0, :owner])
  end

  it "rejects a registered alias when alias permission is disabled" do
    schema = build_params_schema(predicates, permit_aliases: false)

    result = schema.("items" => [{"owner" => "42"}])

    expect(result).to be_failure
    expect(rule_values).to eql([])
    expect(result.errors.to_h).to eql(
      items: {0 => {owner: ["alias is not permitted for this write interface"]}}
    )

    violation = result.key_attribution.violations.first
    expect(violation.code).to eql(:alias_not_permitted)
    expect(violation.path).to eql([:items, 0, :owner])
  end

  it "rejects conflicting spellings before business rules run" do
    schema = build_params_schema(predicates, conflict: :reject)

    result = schema.("items" => [{"owner_id" => "7", "owner" => "42"}])

    expect(result).to be_failure
    expect(rule_values).to eql([])
    expect(result.errors.to_h).to eql(
      items: {0 => {owner: ["conflicts with another approved spelling"]}}
    )

    conflict = result.key_attribution.conflicts.first
    expect(conflict.canonical_path).to eql([:items, 0, :owner_id])
    expect(conflict.source_paths).to eql([
      [:items, 0, :owner_id],
      [:items, 0, :owner]
    ])
    expect(result.key_attribution.error_paths).to eql([[:items, 0, :owner]])
    expect(result.message_set.map(&:predicate)).to eql([:conflicting_keys])
  end

  it "can explicitly merge conflicting spellings and then run business rules" do
    schema = build_params_schema(predicates, conflict: :merge)

    result = schema.("items" => [{"owner_id" => "7", "owner" => "42"}])

    expect(result).to be_success
    expect(result.to_h).to eql(items: [{owner_id: 42}])
    expect(rule_values).to eql([42])
    expect(result.key_attribution.decisions).to include(
      [:items, 0, :owner_id] => :conflict_merged
    )
  end

  it "can choose the first spelling deterministically" do
    schema = build_params_schema(predicates, conflict: :first)

    result = schema.("items" => [{"owner_id" => "7", "owner" => "42"}])

    expect(result).to be_success
    expect(result.to_h).to eql(items: [{owner_id: 7}])
    expect(rule_values).to eql([7])
  end

  it "lets key validation accept registered aliases while still rejecting unknown keys" do
    schema = build_params_schema(predicates, validate_keys: true)

    result = schema.("items" => [{"owner" => "42", "mystery" => "x"}])

    expect(result).to be_failure
    expect(result.errors.to_h[:items][0].keys).to eql([:mystery])
    expect(result.message_set.map(&:path)).to include([:items, 0, :mystery])
  end

  it "preserves default schema calls when attribution is not configured" do
    schema = Dry::Schema.Params do
      required(:items).array(:hash) do
        required(:owner_id).filled(:integer)
      end
    end

    canonical = schema.("items" => [{"owner_id" => "42"}])
    expect(canonical).to be_success
    expect(canonical.to_h).to eql(items: [{owner_id: 42}])
    expect(canonical.key_attribution).not_to be_enabled
    expect(canonical.key_attribution.sources).to eql([])

    alias_input = schema.("items" => [{"owner" => "42"}])
    expect(alias_input).to be_failure
    expect(alias_input.errors.to_h).to eql(
      items: {0 => {owner_id: ["is missing"]}}
    )
  end
end
