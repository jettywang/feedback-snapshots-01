require 'spec_helper'
require 'rollbar/destination'

describe Rollbar::Destination do
  describe '#initialize' do
    it 'defaults to permitting every section' do
      destination = described_class.new(:desk, double)

      Rollbar::Destination::SECTIONS.each do |section|
        expect(destination.permits?(section)).to be(true)
      end
    end

    it 'keeps only the known sections from the allowlist' do
      destination = described_class.new(:desk, double, [:request, :nope, :extra])

      expect(destination.data_scope).to be_eql([:request, :extra])
      expect(destination.permits?(:person)).to be(false)
    end

    it 'treats :all as permission for every section' do
      destination = described_class.new(:desk, double, :all)

      expect(destination.data_scope).to be_eql(Rollbar::Destination::SECTIONS)
    end

    it 'string section names are accepted' do
      destination = described_class.new(:desk, double, %w[request])

      expect(destination.permits?(:request)).to be(true)
      expect(destination.permits?(:person)).to be(false)
    end
  end

  describe '#add_transform' do
    it 'accepts a block and a callable handler' do
      destination = described_class.new
      handler = proc { |_options| }

      destination.add_transform(handler)
      destination.add_transform { |_options| }

      expect(destination.transform.size).to be_eql(2)
    end

    it 'replaces the handlers through #transform=' do
      destination = described_class.new
      destination.add_transform { |_options| }

      new_handler = proc { |_options| }
      destination.transform = new_handler

      expect(destination.transform).to be_eql([new_handler])
    end
  end

  describe '#deliver' do
    it 'calls the sender with the payload and the destination itself' do
      payload = { 'data' => {} }
      sender = double
      destination = described_class.new(:desk, sender)

      expect(sender).to receive(:call).with(payload, destination)

      destination.deliver(payload)
    end
  end

  describe '#initialize_copy' do
    it 'does not share the transform list with the original destination' do
      sender = double
      original = described_class.new(:desk, sender)
      original.add_transform { |_options| }

      copy = original.dup
      copy.add_transform { |_options| }

      expect(original.transform.size).to be_eql(1)
      expect(copy.transform.size).to be_eql(2)
      expect(copy.permitted_sections).not_to be(original.permitted_sections)
    end
  end
end
