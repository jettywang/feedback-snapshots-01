# frozen_string_literal: true

require "dry/schema/step"

RSpec.describe Dry::Schema::Step, "permits" do
  let(:executor) { proc { |result| result } }

  it "is not sensitive by default" do
    step = described_class.new(type: :after, name: :rule_applier, executor: executor)

    expect(step).to_not be_sensitive
    expect(step.permit).to be_nil
  end

  it "exposes the phase of the action" do
    step = described_class.new(type: :after, name: :rule_applier, executor: executor)

    expect(step.phase).to be(:finalization)
  end

  it "carries a permit for sensitive callbacks" do
    step = described_class.new(
      type: :after, name: :rule_applier, executor: executor, permit: :finalization
    )

    expect(step).to be_sensitive
    expect(step.permit).to be(:finalization)
  end

  it "keeps the permit when scoped to a path" do
    step = described_class.new(
      type: :after, name: :rule_applier, executor: executor, permit: :finalization
    )

    expect(step.scoped([:user]).permit).to be(:finalization)
  end

  it "rejects unknown permits" do
    expect {
      described_class.new(type: :before, name: :key_coercer, executor: executor, permit: :nope)
    }.to raise_error(ArgumentError, /Unknown phase :nope/)
  end
end
