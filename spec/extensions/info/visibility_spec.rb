# frozen_string_literal: true

RSpec.describe Dry::Schema::JSON, "#info documentation visibility" do
  before do
    Dry::Schema.load_extensions(:info)
  end

  subject(:schema) do
    Dry::Schema.JSON do
      configure do |config|
        config.info_examples = {
          "email" => ["jane@doe.org", {value: "not-an-email", valid: false}],
          "address.room" => [{value: "13B", valid: false}],
          "lines.sku" => ["A-1"]
        }
        config.info_visibility = {
          keys: %w[audit_token address.room],
          values: {"state" => %w[blocked]}
        }
      end

      required(:email).filled(:string)
      required(:state).filled(:string, included_in?: %w[active blocked])
      required(:audit_token).filled(:string)

      required(:address).hash do
        required(:street).filled(:string)
        optional(:room).maybe(:string)
      end

      required(:lines).array(:hash) do
        required(:sku).filled(:string)
      end
    end
  end

  describe "internal export (default)" do
    it "exports included_in? value sets" do
      expect(schema.info[:keys][:state][:values]).to eql(%w[active blocked])
    end

    it "expands range value sets" do
      schema = Dry::Schema.JSON do
        required(:age).filled(:integer, included_in?: 18..20)
      end

      expect(schema.info[:keys][:age][:values]).to eql([18, 19, 20])
    end

    it "exports declared examples, including error examples" do
      expect(schema.info[:keys][:email][:examples]).to eql(
        [{value: "jane@doe.org", valid: true}, {value: "not-an-email", valid: false}]
      )
    end

    it "attaches examples to nested keys and array members" do
      address = schema.info[:keys][:address]
      lines = schema.info[:keys][:lines]

      expect(address[:keys][:room][:examples]).to eql([{value: "13B", valid: false}])
      expect(lines[:member][:keys][:sku][:examples]).to eql([{value: "A-1", valid: true}])
    end

    it "raises when examples are declared for unknown keys" do
      schema = Dry::Schema.JSON do
        configure do |config|
          config.info_examples = {"nope" => ["x"]}
        end

        required(:email).filled(:string)
      end

      expect { schema.info }.to raise_error(ArgumentError, /unknown keys: nope/)
    end
  end

  describe "public export" do
    subject(:public_info) { schema.info(visibility: :public) }

    it "keeps public types and approved enum members for form generation" do
      expect(public_info[:keys][:email]).to include(type: "string", required: true)
      expect(public_info[:keys][:state][:values]).to eql(%w[active])
    end

    it "removes internal-only keys, including nested ones" do
      expect(public_info[:keys]).not_to have_key(:audit_token)
      expect(public_info[:keys][:address][:keys]).not_to have_key(:room)
      expect(public_info[:keys][:address][:keys]).to have_key(:street)
    end

    it "drops error examples but keeps valid examples" do
      expect(public_info[:keys][:email][:examples]).to eql([{value: "jane@doe.org", valid: true}])
    end

    it "omits the values list when every member is internal" do
      schema = Dry::Schema.JSON do
        configure do |config|
          config.info_visibility = {values: {"state" => %w[blocked]}}
        end

        required(:state).filled(:string, included_in?: %w[blocked])
      end

      expect(schema.info(visibility: :public)[:keys][:state]).not_to have_key(:values)
    end

    it "can expose error examples when the policy allows it" do
      schema = Dry::Schema.JSON do
        configure do |config|
          config.info_examples = {"email" => [{value: "nope", valid: false}]}
          config.info_visibility = {error_examples: :public}
        end

        required(:email).filled(:string)
      end

      expect(schema.info(visibility: :public)[:keys][:email][:examples])
        .to eql([{value: "nope", valid: false}])
    end

    it "does not mutate the internal export" do
      schema.info(visibility: :public)

      expect(schema.info[:keys][:state][:values]).to eql(%w[active blocked])
      expect(schema.info[:keys]).to have_key(:audit_token)
    end
  end

  describe "custom predicates" do
    subject(:schema) do
      Dry::Schema.JSON do
        configure do |config|
          config.predicates = Module.new {
            include Dry::Logic::Predicates

            def self.audit_ref?(input, prefix)
              input.start_with?(prefix)
            end
          }
        end

        required(:ref).filled(:string, audit_ref?: "INT-SECRET-PREFIX")
      end
    end

    it "never exports custom predicate arguments" do
      expect(schema.info[:keys][:ref]).to eql(required: true, type: "string", nullable: false)
      expect(schema.info(visibility: :public)[:keys][:ref])
        .to eql(required: true, type: "string", nullable: false)
    end
  end

  describe "composed schemas" do
    let(:inner) do
      Dry::Schema.JSON do
        configure do |config|
          config.info_examples = {"card" => [{value: "4111-0000", valid: false}]}
        end

        required(:card).filled(:string)
      end
    end

    subject(:schema) do
      payment = inner

      Dry::Schema.JSON do
        configure do |config|
          config.info_visibility = {keys: %w[payment.card]}
        end

        required(:payment).schema(payment)
      end
    end

    it "applies the outer policy to inlined keys" do
      expect(schema.info(visibility: :public)[:keys][:payment][:keys]).to be_empty
      expect(schema.info[:keys][:payment][:keys]).to have_key(:card)
    end

    it "does not leak examples declared on the composed schema" do
      expect(schema.info[:keys][:payment][:keys][:card]).not_to have_key(:examples)
      expect(inner.info[:keys][:card][:examples]).to eql([{value: "4111-0000", valid: false}])
      expect(inner.info(visibility: :public)[:keys][:card]).not_to have_key(:examples)
    end
  end

  describe "validation" do
    it "is not affected by the documentation policy" do
      input = {
        email: "jane@doe.org",
        state: "blocked",
        audit_token: "secret",
        address: {street: "Main St", room: "13B"},
        lines: [{sku: "A-1"}]
      }

      schema.info(visibility: :public)

      result = schema.call(input)

      expect(result).to be_success
      expect(result.to_h).to eql(input)
    end

    it "still rejects values outside the exported (redacted) value set" do
      result = schema.call(
        email: "jane@doe.org",
        state: "blocked",
        audit_token: "secret",
        address: {street: "Main St"},
        lines: [{sku: "A-1"}]
      )

      expect(result).to be_success
      expect(schema.info(visibility: :public)[:keys][:state][:values]).to eql(%w[active])
    end
  end

  it "rejects unknown visibility" do
    expect { schema.info(visibility: :bogus) }
      .to raise_error(ArgumentError, /unknown info visibility/)
  end
end
