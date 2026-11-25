# frozen_string_literal: true

describe Grape::ServeStream::Representation do
  describe '#project' do
    it 'keeps only the declared fields' do
      representation = described_class.new(fields: %i[id name])

      expect(representation.project({ id: 1, name: 'Ada', secret: 's' })).to eq({ id: 1, name: 'Ada' })
    end

    it 'leaves a record without the declared fields empty' do
      representation = described_class.new(fields: %i[id name])

      expect(representation.project({ other: 1 })).to eq({})
    end

    it 'serves the record unchanged when no fields are declared' do
      record = { id: 1, secret: 's' }

      expect(described_class.new.project(record)).to be(record)
    end

    it 'serves nil unchanged' do
      expect(described_class.new(fields: %i[id]).project(nil)).to be_nil
    end

    it 'reads a Struct through its #to_h' do
      record = Struct.new(:id, :secret).new(1, 's')

      expect(described_class.new(fields: %i[id]).project(record)).to eq({ id: 1 })
    end

    it 'reads String keys as well as Symbol keys' do
      expect(described_class.new(fields: %i[id]).project({ 'id' => 1 })).to eq({ id: 1 })
    end

    it 'names a record it cannot project' do
      expect { described_class.new(fields: %i[id]).project(Object.new) }
        .to raise_error(ArgumentError, /cannot project Object/)
    end
  end

  describe 'a represent callable' do
    it 'answers the projected record itself' do
      representation = described_class.new(represent: ->(record) { record.slice(:id) })

      expect(representation.project({ id: 1, secret: 's' })).to eq({ id: 1 })
    end

    it 'cannot be combined with fields' do
      expect { described_class.new(fields: %i[id], represent: ->(_) {}) }
        .to raise_error(ArgumentError, /either :fields or :represent/)
    end
  end

  describe 'fields: :first' do
    it 'locks the fields of the first record' do
      representation = described_class.new(fields: described_class::FIRST)

      expect(representation.project({ id: 1, name: 'Ada' })).to eq({ id: 1, name: 'Ada' })
      expect(representation.project({ id: 2, name: 'Grace', secret: 's' })).to eq({ id: 2, name: 'Grace' })
      expect(representation.fields).to eq(%i[id name])
    end

    it 'reports no fields until the first record' do
      expect(described_class.new(fields: described_class::FIRST).fields).to be_nil
    end
  end

  describe '#to_h' do
    it 'carries the revision and label with the field set' do
      representation = described_class.new(fields: %i[id], version: 'v2', name: 'ops_export')

      expect(representation.to_h).to include(fields: %i[id], mode: :declared, version: 'v2', name: 'ops_export')
    end
  end
end
