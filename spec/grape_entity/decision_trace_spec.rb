# frozen_string_literal: true

describe Grape::Entity::DecisionTrace do
  # A PORO so the suite does not depend on ostruct (no longer a default gem on Ruby 4).
  let(:model_class) do
    Struct.new(:public_field, :role_field, :chained, :child_only, :inner)
  end

  let(:parent_entity) do
    Class.new(Grape::Entity) do
      expose :public_field

      parent_line = __LINE__ + 1
      expose :role_field, if: ->(object, options) { options[:role] == :admin }
      const_set(:PARENT_ROLE_LINE, parent_line)

      # Two conditions on one exposure via with_options: the block option is
      # collected into if_extras and the symbol becomes the inline :if, which
      # compiles first. A failing symbol condition therefore short-circuits
      # the block condition.
      chained_line = __LINE__ + 2
      with_options(if: ->(object, options) { options[:role] == :admin }) do
        expose :chained, if: :trusted
      end
      const_set(:CHAINED_LINE, chained_line)
    end
  end

  let(:child_entity) do
    parent = parent_entity
    Class.new(parent) do
      child_line = __LINE__ + 1
      expose :role_field, if: ->(object, options) { options[:role] == :auditor }, override: true
      const_set(:CHILD_ROLE_LINE, child_line)

      expose :child_only, unless: { blocked: true }
    end
  end

  let(:model) { model_class.new('public', 'secret', 'chained-value', 'child-value', nil) }

  def render(entity_class, object = model, **options)
    trace = Grape::Entity::DecisionTrace.new
    entity = entity_class.new(object, **options, decision_trace: trace)
    [entity.serializable_hash, trace, entity]
  end

  describe 'passing, rejecting and skipping conditions' do
    it 'records :met for a passing condition' do
      _output, trace = render(child_entity, role: :auditor, trusted: true)

      role = trace.for_field(:role_field)
      expect(role.outcome).to eq :visible
      expect(role.conditions.map(&:status)).to eq [:met]
      expect(role.conditions.first.result).to be true
    end

    it 'records :unmet for a rejecting condition and hides the field' do
      _output, trace = render(child_entity, role: :guest, trusted: true)

      role = trace.for_field(:role_field)
      expect(role.outcome).to eq :hidden
      expect(role.conditions.map(&:status)).to eq [:unmet]
      expect(role.conditions.first.result).to be false
    end

    it 'records :not_executed for conditions skipped by short-circuiting' do
      # The inline symbol condition compiles first and fails, so the block
      # condition collected into if_extras never runs.
      _output, trace = render(parent_entity, role: :admin, trusted: false)

      chained = trace.for_field(:chained)
      expect(chained.outcome).to eq :hidden
      expect(chained.conditions.map(&:status)).to eq [:unmet, :not_executed]
      expect(chained.conditions.last.result).to be_nil
    end

    it 'keeps the external output identical whether or not tracing is enabled' do
      traced_output, = render(child_entity, role: :guest, trusted: true)
      plain_output = child_entity.new(model, role: :guest, trusted: true).serializable_hash

      expect(traced_output).to eq plain_output
      expect(plain_output).to eq(public_field: 'public', child_only: 'child-value')
    end

    it 'exposes the same three states across the two entity layers' do
      _output, trace = render(child_entity, role: :guest, trusted: false)
      statuses = trace.exposure_results.flat_map { |result| result.conditions.map(&:status) }

      expect(statuses).to include :met
      expect(statuses).to include :unmet
      expect(statuses).to include :not_executed
    end
  end

  describe 'declaration locations' do
    it 'points the inherited condition at the parent class source line' do
      inherited = parent_entity.find_exposure(:role_field)
      location = inherited.conditions.first.source_location

      expect(location.path).to eq __FILE__
      expect(location.lineno).to eq parent_entity::PARENT_ROLE_LINE
      expect(location.to_s).to include(__FILE__)
    end

    it 'points the overriding condition at the child class source line' do
      overridden = child_entity.find_exposure(:role_field)
      location = overridden.conditions.first.source_location

      expect(location.path).to eq __FILE__
      expect(location.lineno).to eq child_entity::CHILD_ROLE_LINE
    end

    it 'preserves the parent declaration location for exposures inherited without override' do
      parent = parent_entity
      grandchild = Class.new(parent) { expose :another_one }

      inherited_location = grandchild.find_exposure(:role_field).conditions.first.source_location
      expect(inherited_location.lineno).to eq parent::PARENT_ROLE_LINE
    end

    it 'includes the declaration location in the explanation of every decision' do
      _output, trace = render(child_entity, role: :guest, trusted: true)

      role_explanation = trace.explain(:role_field).first
      expect(role_explanation[:declared_at]).to include(__FILE__)
      expect(role_explanation[:conditions].first[:declared_at]).to include(__FILE__)
    end
  end

  describe 'no second invocation of user code' do
    it 'evaluates each condition at most once while rendering' do
      calls = 0
      counting_condition = ->(object, options) { calls += 1; options[:role] == :admin }

      entity_class = Class.new(Grape::Entity) do
        expose :role_field, if: counting_condition
      end

      trace = Grape::Entity::DecisionTrace.new
      entity_class.new(model, role: :guest, decision_trace: trace).serializable_hash

      expect(calls).to eq 1
      expect(trace.counters[:evaluated_conditions]).to eq 1
      expect(trace.counters[:unmet_conditions]).to eq 1
    end

    it 'does not run any condition again when the explanation is built' do
      calls = 0
      counting_condition = ->(object, options) { calls += 1; options[:role] == :admin }

      entity_class = Class.new(Grape::Entity) do
        expose :role_field, if: counting_condition
      end

      trace = Grape::Entity::DecisionTrace.new
      entity = entity_class.new(model, role: :guest, decision_trace: trace)
      entity.serializable_hash

      expect {
        trace.explain
        trace.explain(:role_field)
        entity.explain_decisions
        entity.explain_decisions(:role_field)
        entity.decision_counters
      }.not_to(change { calls })
    end

    it 'counters reconcile evaluated, skipped and field-level outcomes' do
      _output, trace = render(child_entity, role: :guest, trusted: false)
      counters = trace.counters

      expect(counters[:evaluated_conditions]).to(
        eq(counters[:met_conditions] + counters[:unmet_conditions])
      )
      expect(counters[:not_executed_conditions]).to be > 0
      expect(counters[:visible_fields] + counters[:hidden_fields]).to eq trace.exposure_results.size
    end
  end

  describe 'scope separation' do
    it 'never includes the audit trace or its data in the rendered hash' do
      output, trace, entity = render(child_entity, role: :auditor, trusted: true)

      expect(output).not_to have_key :decision_trace
      expect(output.keys).to match_array %i[public_field role_field child_only]
      expect(entity.decision_trace).to be trace
      expect(entity.explain_decisions).to be_an Array
    end

    it 'returns empty explanations when tracing is not enabled' do
      entity = child_entity.new(model, role: :guest)

      expect(entity.decision_trace).to be_nil
      expect(entity.explain_decisions).to eq []
      expect(entity.decision_counters).to be_nil
    end

    it 'shares one trace through nested represented entities' do
      inner_entity = Class.new(Grape::Entity) do
        expose :role_field, if: ->(object, options) { options[:role] == :admin }
      end
      outer_entity = Class.new(Grape::Entity) do
        expose :inner, using: inner_entity
      end

      trace = Grape::Entity::DecisionTrace.new
      nested_model = model_class.new(nil, 'secret', nil, nil, model_class.new(nil, 'inner-secret'))
      outer_entity.new(nested_model, role: :guest, decision_trace: trace).serializable_hash

      fields = trace.exposure_results.map(&:field)
      expect(fields).to eq %i[inner role_field]
      expect(trace.for_field(:role_field).outcome).to eq :hidden
    end

    it 'marks conditions as not executed when only/except filters the key out' do
      entity_class = Class.new(Grape::Entity) do
        expose :role_field, if: ->(object, options) { raise 'condition must not run' }
      end

      trace = Grape::Entity::DecisionTrace.new
      output = entity_class.new(model, only: [:public_field], decision_trace: trace).serializable_hash

      expect(output).to eq({})
      decision = trace.for_field(:role_field)
      expect(decision.outcome).to eq :hidden
      expect(decision.conditions.map(&:status)).to eq [:not_executed]
    end
  end
end
