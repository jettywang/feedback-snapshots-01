# frozen_string_literal: true

describe Grape::ServeStream::Policy do
  it 'freezes its revision' do
    expect(described_class.new(version: 'v1').version).to eq('v1')
    expect(described_class.new(version: :v1).version).to eq('v1')
    expect(described_class.new(version: 'v1')).to be_frozen
  end

  it 'permits every record without a permitted callable' do
    policy = described_class.new(version: 'v1')

    expect(policy).to be_permitted({ id: 1 })
  end

  it 'asks the permitted callable' do
    policy = described_class.new(version: 'v1', permitted: ->(record) { record[:id].odd? })

    expect(policy).to be_permitted({ id: 1 })
    expect(policy).not_to be_permitted({ id: 2 })
  end
end
