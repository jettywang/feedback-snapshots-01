# frozen_string_literal: true

require 'grape_entity/provenance/demo_entities'

RSpec.describe Grape::Entity::Provenance do
  Demo = Grape::Entity::Provenance::DemoEntities
  let(:merge_entity) { Demo::MergeEntity }
  let(:override_entity) { Demo::OverrideEntity }
  let(:conditional_entity) { Demo::ConditionalOverrideEntity }
  let(:equal_entity) { Demo::EqualValueEntity }
  let(:registry) { Demo.approval_registry }

  def receipt_for(entity_class, object, options = {})
    entity_class.new(object, options).provenance_receipt(registry)
  end

  def claim_ids_in(node)
    case node
    when Hash
      node.flat_map do |key, value|
        key.to_s.include?('claim') ? Array(value) : claim_ids_in(value)
      end
    when Array
      node.flat_map { |element| claim_ids_in(element) }
    else
      []
    end.uniq
  end

  describe 'same-name nested segments are merged' do
    let(:receipt) { receipt_for(merge_entity, name: 'ada', kind: 'admin', internal_note: 'secret') }

    it 'renders the two segments as one readable object' do
      expect(receipt.to_h[:output]).to eq(profile: { name: 'ADA', kind: 'admin' }, internal_note: 'secret')
    end

    it 'traces every leaf field to its adopting claim' do
      fields = receipt.to_h[:fields].index_by { |field| field[:path_key] }
      expect(fields[:'profile.name'][:claim_id]).to eq(:merge_name)
      expect(fields[:'profile.name'][:relationship]).to eq(:formatted_transcription)
      expect(fields[:'profile.kind'][:claim_id]).to eq(:merge_kind)
      expect(fields[:'profile.kind'][:relationship]).to eq(:direct_delegation)
    end

    it 'records the structural merge of the two nested declarations' do
      expect(receipt.to_h[:segment_merges]).to contain_exactly(
        key: :profile,
        relationship: :nested_segment_merge,
        claim_ids: %i[merge_profile_first merge_profile_second]
      )
    end

    it 'runs only the formatter attached to an adopted field' do
      receipt # build
      expect(receipt.to_h[:formatter_runs].map { |run| run[:formatter_name] }).to eq([:upcase])
    end

    it 'redacts the unapproved claim in the public receipt' do
      public_receipt = receipt.public_receipt
      note = public_receipt[:fields].find { |field| field[:path_key] == :internal_note }
      expect(note[:claim_id]).to eq(:unapproved_claim)
      ids = claim_ids_in(public_receipt)
      expect(ids).not_to include(:merge_internal_note)
      expect(ids).to all(be_in(registry.approved_ids + [:unapproved_claim]))
    end
  end

  describe 'a later plain value overrides the whole nested segment' do
    let(:receipt) { receipt_for(override_entity, profile: 'p', name: 'n') }

    it 'replaces the segment rather than merging into it' do
      expect(receipt.to_h[:output]).to eq(profile: '[p]')
    end

    it 'attributes the surviving field to the overriding claim' do
      field = receipt.to_h[:fields].first
      expect(field[:path_key]).to eq(:profile)
      expect(field[:claim_id]).to eq(:override_profile_replacement)
      expect(field[:relationship]).to eq(:override_replacement)
    end

    it 'marks the earlier nested declaration as superseded, not condition-only' do
      expect(receipt.to_h[:superseded_claims]).to contain_exactly(
        hash_including(
          claim_id: :override_profile_nested,
          reason: :superseded_by_override,
          superseded_by: :override_profile_replacement
        )
      )
      expect(receipt.to_h[:condition_only_candidates]).to be_empty
    end

    it 'runs the replacement formatter and none of the superseded ones' do
      expect(receipt.to_h[:formatter_runs].map { |run| run[:claim_id] })
        .to eq([:override_profile_replacement])
    end
  end

  describe 'a conditional override can be disabled' do
    context 'when the condition is not met' do
      let(:receipt) { receipt_for(conditional_entity, { profile: 'p', name: 'n' }, {}) }

      it 'drops the key entirely because the nested segment was superseded' do
        expect(receipt.to_h[:output]).to eq({})
        expect(receipt.to_h[:fields]).to be_empty
      end

      it 'records the replacement as a condition-only candidate' do
        expect(receipt.to_h[:condition_only_candidates]).to contain_exactly(
          hash_including(
            claim_id: :conditional_profile_replacement,
            reason: :condition_not_met
          )
        )
      end

      it 'keeps the nested segment listed as superseded and runs no formatter' do
        expect(receipt.to_h[:superseded_claims].first[:claim_id])
          .to eq(:conditional_profile_nested)
        expect(receipt.to_h[:formatter_runs]).to be_empty
      end
    end

    context 'when the condition is met' do
      let(:receipt) do
        receipt_for(conditional_entity, { profile: 'p', name: 'n' }, use_override: true)
      end

      it 'adopts the replacement value and runs its formatter' do
        expect(receipt.to_h[:output]).to eq(profile: '[p]')
        expect(receipt.to_h[:condition_only_candidates]).to be_empty
        expect(receipt.to_h[:formatter_runs].map { |run| run[:claim_id] })
          .to eq([:conditional_profile_replacement])
      end
    end
  end

  describe 'two declarations yielding the same value' do
    let(:receipt) { receipt_for(equal_entity, {}) }

    it 'keeps both as adopted claims instead of hiding one' do
      ids = receipt.to_h[:fields].map { |field| field[:claim_id] }
      expect(ids).to contain_exactly(:equal_primary, :equal_secondary)
    end

    it 'groups them by identical value fingerprint, distinct from condition-only' do
      group = receipt.to_h[:equal_value_groups].first
      expect(group[:value]).to eq('same')
      expect(group[:claim_ids]).to contain_exactly(:equal_primary, :equal_secondary)
      expect(receipt.to_h[:condition_only_candidates]).to be_empty
    end
  end

  describe 're-reading a receipt' do
    let(:entity) { override_entity.new(profile: 'p', name: 'n') }
    let(:receipt) { entity.provenance_receipt(registry) }

    it 'does not execute formatters again' do
      receipt
      expect { receipt.public_receipt }.not_to(change { Demo::FORMATTER_CALLS[:bracket] })
      expect { receipt.to_h }.not_to(change { Demo::FORMATTER_CALLS[:bracket] })
      expect { receipt.formatter_runs }.not_to(change { Demo::FORMATTER_CALLS[:bracket] })
    end

    it 'returns a deeply frozen, already materialized structure' do
      expect(receipt.to_h).to be_frozen
      expect(receipt.to_h[:fields].first).to be_frozen
      expect(receipt.public_receipt).to be_frozen
    end

    it 'never serializes twice for the same entity instance' do
      allow(entity).to receive(:serializable_hash).and_call_original
      receipt.public_receipt
      receipt.to_h
      expect(entity).to have_received(:serializable_hash).once
    end
  end

  describe 'the public receipt only references approved identifiers' do
    it 'routes every claim identifier through the approval registry' do
      receipt = receipt_for(merge_entity, name: 'a', kind: 'k', internal_note: 'x')
      ids = claim_ids_in(receipt.public_receipt)
      expect(ids).to all(be_in(registry.approved_ids + [:unapproved_claim]))
    end
  end

  describe 'subclass inheritance' do
    let(:parent) do
      Class.new(Grape::Entity::Provenance::Entity) { expose_claim :inherited_name, :name }
    end
    let(:child) do
      Class.new(parent) do
        expose_claim :child_override, :name, override: true,
                                            proc: ->(_object, _options) { 'child' }
      end
    end

    it 'keeps an independent ledger per class' do
      child
      expect(parent.claim_ledger.superseded_ids).to be_empty
      expect(child.claim_ledger.ids).to contain_exactly(:inherited_name, :child_override)
    end

    it 'records the inherited claim as superseded in the child only' do
      local_registry = Grape::Entity::Provenance::ApprovalRegistry.new(%i[inherited_name child_override])
      receipt = child.new({ name: 'mom' }, {}).provenance_receipt(local_registry)
      expect(receipt.to_h[:output]).to eq(name: 'child')
      expect(receipt.to_h[:superseded_claims].first[:claim_id]).to eq(:inherited_name)
      expect(receipt.to_h[:fields].first[:claim_id]).to eq(:child_override)
    end
  end
end
