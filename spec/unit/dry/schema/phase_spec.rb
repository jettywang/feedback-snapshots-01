# frozen_string_literal: true

require "dry/schema/phase"

RSpec.describe Dry::Schema::Phase do
  describe ".for" do
    it "maps core steps to phases" do
      expect(described_class.for(type: :core, name: :key_validator)).to be(:keys)
      expect(described_class.for(type: :core, name: :key_coercer)).to be(:keys)
      expect(described_class.for(type: :core, name: :filter_schema)).to be(:filter)
      expect(described_class.for(type: :core, name: :value_coercer)).to be(:coercion)
      expect(described_class.for(type: :core, name: :rule_applier)).to be(:validation)
    end

    it "keeps before callbacks in the phase of their step" do
      expect(described_class.for(type: :before, name: :rule_applier)).to be(:validation)
    end

    it "moves after-rule callbacks to finalization" do
      expect(described_class.for(type: :after, name: :rule_applier)).to be(:finalization)
    end

    it "keeps after callbacks of earlier steps in the step phase" do
      expect(described_class.for(type: :after, name: :key_coercer)).to be(:keys)
    end
  end

  describe ".normalize_permit" do
    it "grants nothing for nil or false" do
      expect(described_class.normalize_permit(nil)).to eql([])
      expect(described_class.normalize_permit(false)).to eql([])
    end

    it "grants every phase for true and :all" do
      expect(described_class.normalize_permit(true)).to eql(described_class::ORDER)
      expect(described_class.normalize_permit(:all)).to eql(described_class::ORDER)
    end

    it "treats a phase as authorization for its prerequisites" do
      expect(described_class.normalize_permit(:validation))
        .to eql(%i[keys filter coercion validation])
      expect(described_class.normalize_permit(:finalization))
        .to eql(described_class::ORDER)
    end

    it "raises for unknown phases" do
      expect { described_class.normalize_permit(:nope) }
        .to raise_error(ArgumentError, /Unknown phase :nope/)
    end

    it "raises for unsupported permit values" do
      expect { described_class.normalize_permit(1) }
        .to raise_error(ArgumentError, /\+permit\+ must be/)
    end
  end

  describe ".permit_covers?" do
    it "covers a phase granted by the permit" do
      expect(described_class.permit_covers?(:finalization, :finalization)).to be(true)
    end

    it "covers earlier phases" do
      expect(described_class.permit_covers?(:validation, :keys)).to be(true)
    end

    it "does not cover later phases" do
      expect(described_class.permit_covers?(:coercion, :finalization)).to be(false)
    end

    it "does not cover anything without a permit" do
      expect(described_class.permit_covers?(nil, :keys)).to be(false)
    end
  end
end
