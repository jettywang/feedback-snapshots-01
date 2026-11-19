require 'flipper/policy'
require 'flipper/adapters/read_only'

RSpec.describe Flipper::Policy::Preflight do
  let(:roster) do
    Flipper::Policy.roster([
      Flipper::Policy::Employee.new('User;1', 'plan' => 'pro', 'team' => 'finance'),
      Flipper::Policy::Employee.new('User;2', 'plan' => 'pro', 'team' => 'sales'),
      Flipper::Policy::Employee.new('User;3', 'plan' => 'free', 'team' => 'sales'),
      Flipper::Policy::Employee.new('User;4', 'plan' => 'free', 'team' => 'finance'),
    ])
  end

  let(:groups) do
    { pilot: ->(actor) { actor['team'] == 'finance' } }
  end

  subject(:preflight) { described_class.new(roster, groups: groups) }

  describe '#check' do
    context 'an actor-only pilot' do
      let(:scenario) do
        Flipper::Policy.scenario(:pilot) { |s| s.feature :billing, actors: ['User;1'] }
      end

      it 'matches only the explicitly enabled employees' do
        report = preflight.check(scenario)
        result = report.for_feature(:pilot, :billing)

        expect(result.matched_employee_ids).to eq(['User;1'])
        expect(result.open_gates).to eq([:actor])
        expect(result.state).to eq(:conditional)
        expect(result).not_to be_full_rollout
      end
    end

    context 'a trial group plus expression and percentage of actors' do
      let(:scenario) do
        Flipper::Policy.scenario(:trial) do |s|
          s.feature :billing,
            groups: [:pilot],
            expression: { 'Equal' => [{ 'Property' => ['plan'] }, 'pro'] },
            percentage_of_actors: 50
        end
      end

      it 'unions the deterministic gates and explains the widened audience' do
        report = preflight.check(scenario)
        result = report.for_feature(:trial, :billing)

        expect(result.matched_employee_ids).to contain_exactly('User;1', 'User;2', 'User;4')
        expect(result.open_gates).to contain_exactly(:group, :expression)
        expect(result.matched_count).to eq(3)
        expect(result).not_to be_full_rollout
      end
    end

    context 'an unknown expression' do
      let(:scenario) do
        Flipper::Policy.scenario(:unknown) do |s|
          s.feature :billing,
            expression: { 'UnreleasedGate' => [{ 'Property' => ['plan'] }] }
        end
      end

      it 'leaves the gate closed and hands the function to the approver' do
        result = preflight.check(scenario).for_feature(:unknown, :billing)

        expect(result.matched_employee_ids).to be_empty
        expect(result).to have_unknowns
        dependency = result.unknown_dependencies.find { |d| d.kind == :unknown_function }
        expect(dependency.detail).to eq('UnreleasedGate')
        expect(dependency.feature).to eq('billing')
      end
    end

    context 'a fully open boolean gate' do
      let(:scenario) do
        Flipper::Policy.scenario(:full) { |s| s.feature :billing, boolean: true }
      end

      it 'reports a full rollout reaching every employee' do
        result = preflight.check(scenario).for_feature(:full, :billing)

        expect(result).to be_full_rollout
        expect(result.state).to eq(:on)
        expect(result.matched_employee_ids).to eq(roster.ids)
        expect(preflight.check(scenario).full_rollouts.map(&:feature)).to eq(['billing'])
      end
    end

    context 'compared against a baseline' do
      let(:baseline) do
        Flipper::Policy.scenario(:current) { |s| s.feature :billing, actors: ['User;1'] }
      end

      let(:planned) do
        Flipper::Policy.scenario(:planned) do |s|
          s.feature :billing, groups: [:pilot]
        end
      end

      let(:full) do
        Flipper::Policy.scenario(:full) { |s| s.feature :billing, boolean: true }
      end

      it 'names only the employees the scenario newly adds' do
        report = preflight.check([planned, full], baseline: baseline)

        expect(report.for_feature(:planned, :billing).added_employee_ids).to eq(['User;4'])
        expect(report.for_feature(:full, :billing).added_employee_ids).to eq(
          ['User;2', 'User;3', 'User;4']
        )
        expect(report.expansions.size).to eq(2)
      end

      it 'does not report expansion when the baseline is unchanged' do
        result = preflight.check(baseline, baseline: baseline).for_feature(:current, :billing)
        expect(result.added_employee_ids).to eq([])
        expect(result).not_to be_expands
      end
    end

    context 'the other unknown dependencies' do
      it 'flags an unregistered group and an unmodeled actor' do
        scenario = Flipper::Policy.scenario(:gaps) do |s|
          s.feature :billing, groups: [:ghost], actors: ['User;999']
        end

        result = preflight.check(scenario).for_feature(:gaps, :billing)
        kinds = result.unknown_dependencies.map(&:kind)

        expect(kinds).to include(:unregistered_group, :unmodeled_actor)
        expect(result.matched_employee_ids).to be_empty
      end

      it 'flags a property some employees lack' do
        scenario = Flipper::Policy.scenario(:props) do |s|
          s.feature :billing,
            expression: { 'Equal' => [{ 'Property' => ['region'] }, 'eu'] }
        end

        result = preflight.check(scenario).for_feature(:props, :billing)
        expect(result.unknown_dependencies.map(&:kind)).to include(:missing_property)
      end

      it 'treats a fractional percentage of time as an unknown probabilistic gate' do
        scenario = Flipper::Policy.scenario(:time) do |s|
          s.feature :billing, percentage_of_time: 25
        end

        result = preflight.check(scenario).for_feature(:time, :billing)
        expect(result.unknown_dependencies.map(&:kind)).to include(:percentage_of_time)
        expect(result.matched_employee_ids).to be_empty
      end

      it 'treats a 100 percent time rollout as a full, deterministic open' do
        scenario = Flipper::Policy.scenario(:time_full) do |s|
          s.feature :billing, percentage_of_time: 100
        end

        result = preflight.check(scenario).for_feature(:time_full, :billing)
        expect(result).to be_full_rollout
        expect(result.open_gates).to eq([:percentage_of_time])
      end
    end

    it 'renders an approval-oriented text explanation' do
      scenario = Flipper::Policy.scenario(:full) { |s| s.feature :billing, boolean: true }
      text = preflight.check(scenario).to_text

      expect(text).to include('Policy preflight (read-only)')
      expect(text).to include('every employee (4 of 4)')
    end

    it 'serializes to plain data' do
      scenario = Flipper::Policy.scenario(:pilot) { |s| s.feature :billing, actors: ['User;1'] }
      hash = preflight.check(scenario).to_h

      expect(hash.dig('pilot', 'billing', :matched_employee_ids)).to eq(['User;1'])
      expect(hash.dig('pilot', 'billing', :open_gates)).to eq([:actor])
    end
  end

  describe 'read-only guarantee' do
    let(:scenario) do
      Flipper::Policy.scenario(:full) { |s| s.feature :billing, boolean: true }
    end

    it 'evaluates through a ReadOnly adapter' do
      adapter = Flipper::Adapters::ReadOnly.new(scenario.build_adapter)
      flipper = Flipper.new(adapter, memoize: false)
      feature = flipper.feature(:billing)

      expect(adapter).to be_read_only
      expect { feature.enable(false) }.to raise_error(Flipper::Adapters::ReadOnly::WriteAttempted)
    end

    it 'does not mutate the scenario across repeated checks' do
      preflight.check(scenario)
      snapshot = scenario.build_adapter.get_all

      preflight.check(scenario)
      preflight.check(scenario)

      expect(scenario.build_adapter.get_all).to eq(snapshot)
      expect(scenario.features['billing'][:boolean]).to eq('true')
    end

    it 'never touches the global group registry for local groups' do
      expect { preflight.check(scenario) }.not_to change { Flipper.group_names }
    end
  end
end
