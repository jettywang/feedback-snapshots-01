require 'flipper/policy'

RSpec.describe Flipper::Policy::Scenario do
  it 'coerces gate values into adapter-shaped data' do
    scenario = described_class.new(:plan) do |s|
      s.feature :billing,
        boolean: true,
        actors: ['User;1', :'User;2'],
        groups: [:pilot],
        percentage_of_actors: 25,
        percentage_of_time: 10,
        expression: { 'Equal' => [{ 'Property' => ['plan'] }, 'pro'] }
    end

    config = scenario.features['billing']
    expect(config[:boolean]).to eq('true')
    expect(config[:actors]).to eq(Set['User;1', 'User;2'])
    expect(config[:groups]).to eq(Set['pilot'])
    expect(config[:percentage_of_actors]).to eq('25')
    expect(config[:percentage_of_time]).to eq('10')
    expect(config[:expression]).to eq('Equal' => [{ 'Property' => ['plan'] }, 'pro'])
  end

  it 'rejects an unknown gate name' do
    expect {
      described_class.new(:bad) { |s| s.feature :billing, nonsense: true }
    }.to raise_error(ArgumentError, /unknown gate :nonsense/)
  end

  it 'stores unknown expressions as raw data without evaluating them' do
    scenario = described_class.new(:unknown) do |s|
      s.feature :billing, expression: { 'UnreleasedGate' => [1] }
    end

    expect { scenario.build_adapter }.not_to raise_error
    expect(scenario.build_adapter.get_all.dig('billing', :expression))
      .to eq('UnreleasedGate' => [1])
  end

  it 'builds independent adapters that do not share the source config' do
    scenario = described_class.new(:plan) { |s| s.feature :billing, actors: ['User;1'] }
    first = scenario.build_adapter
    second = scenario.build_adapter

    first.get_all.dig('billing', :actors) << 'User;9'
    expect(second.get_all.dig('billing', :actors)).to eq(Set['User;1'])
  end
end

RSpec.describe Flipper::Policy::Roster do
  let(:roster) do
    described_class.new([
      Flipper::Policy::Employee.new('User;1', 'plan' => 'pro'),
      { flipper_id: 'User;2', properties: { 'plan' => 'free' } },
    ])
  end

  it 'wraps hashes and keeps one record per id' do
    expect(roster.size).to eq(2)
    roster.add('User;1')
    expect(roster.size).to eq(2)
  end

  it 'finds employees and reports missing ids' do
    expect(roster['User;1'].flipper_properties['plan']).to eq('pro')
    expect(roster.missing_ids(['User;1', 'User;9'])).to eq(['User;9'])
    expect(roster.with_ids(['User;2']).map(&:flipper_id)).to eq(['User;2'])
  end
end

RSpec.describe Flipper::Policy::Employee do
  it 'acts as a Flipper actor' do
    employee = described_class.new(7, team: 'finance')
    actor = Flipper::Types::Actor.new(employee)

    expect(actor.value).to eq('7')
    expect(actor.flipper_properties['team']).to eq('finance')
  end

  it 'stringifies property keys' do
    expect(described_class.new(1, plan: 'pro')['plan']).to eq('pro')
  end
end
