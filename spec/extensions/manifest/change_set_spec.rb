# frozen_string_literal: true

RSpec.describe "Dry::Schema::Manifest::ChangeSet" do
  before { Dry::Schema.load_extensions(:manifest) }

  def build(schema, name)
    Dry::Schema::Manifest.build(schema, name: name)
  end

  describe "structural changes" do
    it "reports an added predicate on a new field" do
      base = build(Dry::Schema.define { required(:name).value(:string) }, "base")
      extended = build(
        Dry::Schema.define do
          required(:name).value(:string)
          required(:age).value(:integer)
        end,
        "extended"
      )

      added = extended.changes_from(base).changes.select { |change| change.kind == "added" }

      expect(added.map(&:field).uniq).to eql(["age"])
      expect(added.map(&:predicate)).to contain_exactly("key?", "int?")
      expect(added).to all(be_approval_required)
    end

    it "reports a removed predicate when a later definition drops a rule" do
      before_schema = Dry::Schema.define do
        required(:name).value(:string)
        required(:age).value(:integer)
      end
      after_schema = Dry::Schema.define do
        required(:name).value(:string)
      end

      removed = build(after_schema, "after").changes_from(build(before_schema, "before"))
        .changes.select { |change| change.kind == "removed" }

      expect(removed.map(&:field).uniq).to eql(["age"])
      expect(removed).to all(be_approval_required)
    end

    it "keeps nested array paths distinct from scalar paths" do
      inventory = build(
        Dry::Schema.define do
          required(:items).array(:hash) do
            required(:sku).value(:string)
          end
          required(:label).value(:string)
        end,
        "nested"
      )

      expect(inventory.entries.map(&:field_path)).to include("items[].sku", "items", "label")
    end
  end

  describe "offline operation" do
    it "compares two committed documents without a schema at hand" do
      schema = Dry::Schema.define { required(:name).value(:string, min_size: 2) }
      document = build(schema, "committed").to_json

      change_set = Dry::Schema::Manifest.compare(JSON.parse(document), JSON.parse(document))

      expect(change_set.approval_required?).to be(false)
      expect(change_set.changes.map(&:kind)).to all(eql("unchanged"))
    end

    it "refuses a document whose digest does not match" do
      schema = Dry::Schema.define { required(:name).value(:string) }
      document = JSON.parse(build(schema, "x").to_json)
      document["predicates"][0]["args"] = [{"symbol" => "tampered"}]

      expect(Dry::Schema::Manifest.verify(document)).to be(false)
    end
  end

  describe "built-in implementation drift" do
    it "detects a redefinition of a canonical predicate as a rebinding" do
      base = build(Dry::Schema.define { required(:name).value(:string, min_size: 2) }, "before")
      original = Dry::Logic::Predicates::Methods.instance_method(:min_size?)

      Dry::Logic::Predicates::Methods.module_eval do
        remove_method(:min_size?)
        def min_size?(num, input)
          input.size >= num
        end
      end

      begin
        redefined = build(Dry::Schema.define { required(:name).value(:string, min_size: 2) }, "after")
        change = redefined.changes_from(base).changes.find { |item| item.predicate == "min_size?" }

        expect(change.kind).to eql("rebound")
        expect(change).to be_approval_required
        expect(change.reasons.join(" ")).to include("implementation digest changed")
      ensure
        Dry::Logic::Predicates::Methods.module_eval do
          remove_method(:min_size?)
          define_method(:min_size?, original)
        end
      end
    end
  end

  describe "explicit rebinding" do
    it "reports an argument change as a rebound of the same predicate" do
      base = build(Dry::Schema.define { required(:age).value(:integer, gt: 18) }, "base")
      candidate = build(Dry::Schema.define { required(:age).value(:integer, gt: 21) }, "candidate")
      change = candidate.changes_from(base).changes.find { |item| item.predicate == "gt?" }

      expect(change.kind).to eql("rebound")
      expect(change).to be_approval_required
      expect(change.reasons.join(" ")).to include("Predicate arguments changed")
      expect(change.previous_binding["args"]).to eql([{"integer" => 18}])
      expect(change.current_binding["args"]).to eql([{"integer" => 21}])
    end

    it "reports a rebound when the same predicate name resolves to a different module" do
      other_module = Module.new do
        include Dry::Logic::Predicates

        define_singleton_method(:gt?) { |num, input| input >= num }
      end
      stub_const("OtherPredicates", other_module)

      base = build(Dry::Schema.define { required(:age).value(:integer, gt: 18) }, "base")
      candidate = build(
        Dry::Schema.define do
          config.predicates = OtherPredicates
          required(:age).value(:integer, gt: 18)
        end,
        "candidate"
      )

      change = candidate.changes_from(base).changes.find { |item| item.predicate == "gt?" }

      expect(change.kind).to eql("rebound")
      expect(change.previous_stable_id).not_to be_nil
      expect(change.current_stable_id).to be_nil
      expect(change).to be_approval_required
      expect(change.reasons.join(" ")).to include("builtin")
    end
  end
end
