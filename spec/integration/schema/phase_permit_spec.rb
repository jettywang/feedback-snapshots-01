# frozen_string_literal: true

RSpec.describe Dry::Schema, "phase permits" do
  let(:counter) { {calls: 0} }

  let(:schema) do
    count = counter

    Dry::Schema.define do
      config.validate_keys = true

      required(:name).filled(:string)
      required(:age).filled(:integer, gt?: 18)

      after(:rule_applier, permit: :finalization) do |result|
        count[:calls] += 1

        raise Dry::Schema::PhaseFailure, "final authorization failed" if result[:age] == 99

        result
      end
    end
  end

  describe "a permitted call with valid input" do
    subject(:result) { schema.call({name: "Jane", age: 20}, permit: :finalization) }

    it "runs the sensitive callback exactly once" do
      result

      expect(counter[:calls]).to be(1)
    end

    it "is deliverable and records every phase" do
      expect(result.diagnostics.deliverable?).to be(true)
      expect(result.diagnostics.completed_phases)
        .to eql(%i[keys coercion validation finalization])
    end

    it "lists the callback among performed actions" do
      callbacks = result.diagnostics.performed.select { |action| action.kind.equal?(:callback) }

      expect(callbacks.map { |action| [action.step, action.phase, action.type, action.sensitive] })
        .to eql([[:rule_applier, :finalization, :after, true]])
    end
  end

  describe "a permitted call with an unexpected key" do
    subject(:result) { schema.call({bogus: true, name: "Jane", age: 20}, permit: :finalization) }

    it "does not run the sensitive callback" do
      result

      expect(counter[:calls]).to be(0)
    end

    it "locates the first failure in the keys phase" do
      expect(result.diagnostics.first_failure_phase).to be(:keys)
      expect(result.diagnostics.first_failure[:step]).to be(:key_validator)
    end

    it "records the callback as skipped because of the precondition" do
      skipped = result.diagnostics.skipped

      expect(skipped.map { |action| [action.step, action.skip_reason] })
        .to eql([[:rule_applier, :precondition]])
    end

    it "is not deliverable" do
      expect(result.diagnostics.deliverable?).to be(false)
      expect(result.diagnostics.halted?).to be(false)
    end
  end

  describe "a permitted call with a rule failure" do
    subject(:result) { schema.call({name: "", age: 20}, permit: :finalization) }

    it "does not run the sensitive callback" do
      result

      expect(counter[:calls]).to be(0)
    end

    it "locates the first failure in the validation phase" do
      expect(result.diagnostics.first_failure_phase).to be(:validation)
      expect(result.diagnostics.first_failure[:step]).to be(:rule_applier)
    end

    it "keeps rule messages unchanged" do
      expect(result.errors.to_h).to eql(name: ["must be filled"])
    end
  end

  describe "a permitted call whose final callback fails" do
    subject(:result) { schema.call({name: "Jane", age: 99}, permit: :finalization) }

    it "runs the sensitive callback once before failing" do
      result

      expect(counter[:calls]).to be(1)
    end

    it "locates the first failure in the finalization phase" do
      expect(result.diagnostics.first_failure_phase).to be(:finalization)
      expect(result.diagnostics.first_failure[:step]).to be(:rule_applier)
      expect(result.diagnostics.error).to eql("final authorization failed")
    end

    it "halts processing and is not deliverable" do
      expect(result.diagnostics.halted?).to be(true)
      expect(result.diagnostics.deliverable?).to be(false)
    end

    it "captures the partial output at the failure" do
      expect(result.diagnostics.partial_output).to eql(name: "Jane", age: 99)
    end
  end

  describe "a callback raising an ordinary error" do
    subject(:result) { raiser.call({name: "Jane"}, permit: :finalization) }

    let(:raiser) do
      Dry::Schema.define do
        required(:name).filled(:string)

        after(:rule_applier, permit: :finalization) { |_result| raise "boom" }
      end
    end

    it "keeps propagating the error" do
      expect { result }.to raise_error("boom")
    end
  end

  describe "a call without a permit" do
    subject(:result) { schema.call({name: "Jane", age: 20}) }

    it "skips the sensitive callback" do
      result

      expect(counter[:calls]).to be(0)
    end

    it "validates normally but is not deliverable" do
      expect(result.success?).to be(true)
      expect(result.diagnostics.deliverable?).to be(false)
      expect(result.diagnostics.skipped.map(&:skip_reason)).to eql([:permit])
    end
  end
end
