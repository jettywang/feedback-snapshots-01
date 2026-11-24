# frozen_string_literal: true

require "dry/schema/diagnostics"

RSpec.describe Dry::Schema::Diagnostics do
  subject(:diagnostics) { described_class.new(permit: :finalization) }

  def action(overrides = {})
    described_class::Action.new(
      **{
        kind: :step, step: :rule_applier, phase: :validation, type: :core
      }.merge(overrides)
    )
  end

  describe "a successful run" do
    before do
      diagnostics.record(action)
      diagnostics.finish!(Dry::Schema::Result.new({name: "Jane"}, message_compiler: proc {}))
    end

    it "is successful and deliverable" do
      expect(diagnostics.success?).to be(true)
      expect(diagnostics.deliverable?).to be(true)
      expect(diagnostics.halted?).to be(false)
    end

    it "reports no first failure" do
      expect(diagnostics.first_failure).to be_nil
      expect(diagnostics.failed_phase).to be_nil
    end

    it "captures the final output as partial output" do
      expect(diagnostics.partial_output).to eql(name: "Jane")
      expect(diagnostics.final_output).to eql(name: "Jane")
    end
  end

  describe "a skipped sensitive action" do
    before do
      diagnostics.record(action)
      diagnostics.record(
        action(kind: :callback, phase: :finalization, type: :after, sensitive: true,
               skip_reason: :permit)
      )
      diagnostics.finish!(Dry::Schema::Result.new({name: "Jane"}, message_compiler: proc {}))
    end

    it "stays successful but is not deliverable" do
      expect(diagnostics.success?).to be(true)
      expect(diagnostics.deliverable?).to be(false)
    end

    it "reports the skipped action and its reason" do
      expect(diagnostics.skipped.map(&:skip_reason)).to eql([:permit])
    end
  end

  describe "a failed run" do
    before do
      diagnostics.record(action(step: :key_coercer, phase: :keys))
      diagnostics.record(action)
      diagnostics.current_action.fail!("boom")
      diagnostics.fail!(phase: :validation, step: :rule_applier, error: "boom",
                        errors: [:some_ast], output: {name: "Jane"})
      diagnostics.finish!(
        Dry::Schema::Result.new({name: "Jane"}, message_compiler: proc {}), halted: true
      )
    end

    it "locates the first failure" do
      expect(diagnostics.first_failure).to eql(
        phase: :validation, step: :rule_applier, error: "boom", errors: [:some_ast]
      )
      expect(diagnostics.first_failure_phase).to be(:validation)
    end

    it "is halted and not deliverable" do
      expect(diagnostics.halted?).to be(true)
      expect(diagnostics.success?).to be(false)
      expect(diagnostics.deliverable?).to be(false)
    end

    it "keeps the output snapshot taken at failure" do
      expect(diagnostics.partial_output).to eql(name: "Jane")
    end

    it "groups failures by phase" do
      expect(diagnostics.errors_by_phase).to eql(validation: ["boom"])
    end

    it "excludes failed phases from completed phases" do
      expect(diagnostics.completed_phases).to eql([:keys])
    end
  end

  describe "Action" do
    it "derives its state from skip_reason and error" do
      expect(action).to be_performed
      expect(action(skip_reason: :permit)).to be_skipped
      expect(action(error: "boom")).to be_failed
    end
  end
end
