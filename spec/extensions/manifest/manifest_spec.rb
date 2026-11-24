# frozen_string_literal: true

RSpec.describe "Predicate manifest extension" do
  before { Dry::Schema.load_extensions(:manifest) }

  # A recording stand-in: every call is appended, nothing is inferred.
  let(:calls) { [] }

  let(:recorder) do
    log = calls
    predicate_module = Module.new do
      include Dry::Logic::Predicates

      define_singleton_method(:gt?) do |num, input|
        log << [:gt?, num, input]
        input > num
      end
    end

    stub_const("AuditPredicates", predicate_module)
  end

  let(:parent) do
    Dry::Schema.define do
      required(:account).hash do
        required(:name).value(:string, min_size: 2, max_size: 32)
        required(:age).value(:integer, gt: 18)
      end
      required(:score).value(:integer, gt: 0)
    end
  end

  let(:child) do
    recorder_ref = recorder

    Dry::Schema.define(parent: parent) do
      config.predicates = recorder_ref

      required(:account).hash do
        required(:name).value(:string, max_size: 32, min_size: 2)
        required(:age).value(:integer, gt: 18)
      end
    end
  end

  let(:parent_inventory) { Dry::Schema::Manifest.build(parent, name: "parent") }
  let(:child_inventory) { Dry::Schema::Manifest.build(child, name: "child") }
  let(:change_set) { child_inventory.changes_from(parent_inventory) }

  describe "inventory" do
    it "records every compiled predicate with a field and logical path" do
      fields = parent_inventory.entries.map(&:field_path)

      expect(fields).to include("account.name", "account.age", "score")
    end

    it "gives built-in rules a stable id that does not depend on the host path" do
      entry = parent_inventory.entries.find { |candidate| candidate.predicate == :min_size? }
      serialized = parent_inventory.to_json

      expect(entry.kind).to eql("builtin")
      expect(entry.stable_id).to start_with("dry-schema-predicate/v1:")
      expect(entry.binding.source_path).to eql("dry-logic/lib/dry/logic/predicates.rb")
      expect(serialized).not_to include(Dir.pwd)
    end

    it "uses the same stable id for the same built-in rule in two schemas" do
      entry = parent_inventory.entries.find { |candidate| candidate.predicate == :min_size? }
      other = Dry::Schema::Manifest.build(
        Dry::Schema.define { required(:name).value(:string, min_size: 2) }
      ).entries.find { |candidate| candidate.predicate == :min_size? }

      expect(entry.stable_id).to eql(other.stable_id)
    end

    it "makes runtime-only bindings explicit evidence gaps" do
      inventory = child_inventory
      gaps = inventory.evidence_gaps

      expect(gaps.map { |gap| gap["predicate"] }).to include("gt?")
      expect(gaps).to all(include("evidence_gap"))
      expect(inventory.builtins).to all(satisfy { |entry| entry.stable_id.start_with?("dry-schema-predicate/v1:") })
    end

    it "verifies its own digests and rejects a tampered document" do
      document = child_inventory.to_json

      expect(Dry::Schema::Manifest.verify(document)).to be(true)

      tampered = JSON.parse(document)
      tampered["predicates"][0]["predicate"] = "evil?"
      expect(Dry::Schema::Manifest.verify(tampered)).to be(false)
    end
  end

  describe "parent/child change set" do
    it "treats an equivalent reordering as proof_order, not a change" do
      name_changes = change_set.changes.select { |change| change.field == "account.name" }
      reordered = name_changes.select { |change| %w[min_size? max_size?].include?(change.predicate) }

      expect(reordered.map(&:kind)).to all(eql("proof_order"))
      expect(reordered.map(&:approval_required?)).to all(be(false))
      expect(name_changes.reject { |change| change.kind == "proof_order" }.map(&:kind)).to all(eql("unchanged"))
    end

    it "reports a rebinding of the same predicate name" do
      change = change_set.changes.find do |candidate|
        candidate.field == "account.age" && candidate.predicate == "gt?"
      end

      expect(change.kind).to eql("rebound")
      expect(change.approval_required?).to be(true)
      expect(change.reasons.join(" ")).to include("different implementation")
      expect(change.current_binding["registry"]).to eql("AuditPredicates")
      expect(change.current_binding["kind"]).to eql("runtime")
    end

    it "leaves untouched fields unchanged" do
      change = change_set.changes.find do |candidate|
        candidate.field == "score" && candidate.predicate == "gt?"
      end

      expect(change.kind).to eql("unchanged")
      expect(change.approval_required?).to be(false)
    end

    it "exposes exactly one field for re-approval" do
      expect(change_set.approval_required.map(&:field)).to eql(["account.age"])
    end
  end

  describe "side effects" do
    it "builds manifests and change sets without calling any predicate" do
      # Compilation itself resolves predicate methods but must not call them.
      parent
      child
      expect(calls).to be_empty

      parent_inventory
      child_inventory
      change_set
      change_set.report

      expect(calls).to be_empty
    end

    it "proves the spy records calls made through actual validation" do
      schema = child

      expect(schema.(account: {name: "ab", age: 18}, score: 1).errors.to_h)
        .to eql(account: {age: ["must be greater than 18"]})

      expect(calls).to eql([[:gt?, 18, 18]])
    end
  end
end
