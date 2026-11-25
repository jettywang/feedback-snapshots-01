# frozen_string_literal: true

describe Grape::Entity::Disclosure do
  let(:levels) { %i[summary detail] }

  let(:order_entity) do
    Class.new(Grape::Entity) do
      expose :id, scope: :summary
      expose :total, scope: :summary
      expose :memo, scope: :detail
      expose :note, scope: :detail
    end
  end

  let(:group_entity) do
    order_klass = order_entity
    Class.new(Grape::Entity) do
      expose :name, scope: :summary
      expose :orders, using: order_klass
    end
  end

  let(:batch_entity) do
    group_klass = group_entity
    Class.new(Grape::Entity) do
      expose :batch_id, scope: :summary
      expose :groups, using: group_klass
    end
  end

  let(:order_one) { { id: 1, total: 10, memo: 'first memo', note: 'first note' } }
  let(:order_two) { { id: 2, total: 20, memo: 'second memo', note: 'second note' } }

  # The same two objects are referenced from both groups, in opposite order.
  let(:group_a) { { name: 'a', orders: [order_one, order_two] } }
  let(:group_b) { { name: 'b', orders: [order_two, order_one] } }
  let(:batch) { { batch_id: 'batch-1', groups: [group_a, group_b] } }

  def policy_with(&resolver)
    Grape::Entity::Disclosure::Policy.new(
      levels: levels,
      identifier: ->(object) { object[:id] if object.is_a?(Hash) },
      &resolver
    )
  end

  def summarize(path_to_summarize)
    policy_with do |object, occurrence, _options|
      next nil unless object.key?(:memo)

      occurrence.path == path_to_summarize ? :summary : :detail
    end
  end

  describe 'opt-in behavior' do
    it 'renders exactly like the unscoped entity when no disclosure is requested' do
      plain = batch_entity.represent(batch, serializable: true)
      scoped = batch_entity.represent(batch, serializable: true, disclosure: false)

      expect(scoped).to eq(plain)
      expect(plain[:groups][0][:orders][0]).to include(:memo, :note)
    end

    it 'treats a supplied receipt as an opt-in and records full occurrences' do
      receipt = Grape::Entity::Disclosure::Receipt.new
      payload = batch_entity.represent(batch, serializable: true, receipt: receipt)

      expect(payload[:groups][0][:orders][0]).to include(:memo, :note)
      expect(receipt).not_to be_empty
      expect(receipt.entries.map(&:mode)).to all(eq(:full))
    end
  end

  describe 'per-occurrence scopes' do
    it 'summarizes only the exact occurrence granted a summary, not its sibling reference' do
      result = batch_entity.represent_with_receipt(batch, disclosure: summarize([:groups, 0, :orders, 1]))

      first_group = result.payload[:groups][0]
      second_group = result.payload[:groups][1]

      expect(first_group[:orders][0]).to eq(id: 1, total: 10, memo: 'first memo', note: 'first note')
      expect(first_group[:orders][1]).to eq(id: 2, total: 20)

      # order_two is the same object, but it was not granted summary here.
      expect(second_group[:orders][0]).to eq(id: 2, total: 20, memo: 'second memo', note: 'second note')
      expect(second_group[:orders][1]).to eq(id: 1, total: 10, memo: 'first memo', note: 'first note')
    end

    it 'follows the actual output order when groups are swapped' do
      swapped = { batch_id: 'batch-1', groups: [group_b, group_a] }
      result = batch_entity.represent_with_receipt(swapped, disclosure: summarize([:groups, 0, :orders, 0]))

      # First group now starts with order_two, the occurrence that was lowered.
      expect(result.payload[:groups][0][:orders][0]).to eq(id: 2, total: 20)
      expect(result.payload[:groups][0][:orders][1]).to include(:memo, :note)
      expect(result.payload[:groups][1][:orders][0]).to include(:memo, :note)
      expect(result.payload[:groups][1][:orders][1]).to include(:memo, :note)
      expect(result.receipt.entry_at([:groups, 0, :orders, 0]).identifier).to eq(2)
      expect(result.receipt.entry_at([:groups, 0, :orders, 0]).mode).to eq(:summary)
    end

    it 'can grant different scopes to the same object in different groups' do
      resolver = policy_with do |object, occurrence, _options|
        next nil unless object.key?(:memo)

        if occurrence.group_path == [:groups, 0, :orders] && object[:id] == 2
          :summary
        elsif occurrence.group_path == [:groups, 1, :orders] && object[:id] == 2
          :detail
        end
      end

      result = batch_entity.represent_with_receipt(batch, disclosure: resolver)
      references = result.receipt.entries_for_object(2)

      expect(references.map { |entry| entry.path }).to eq(
        [[:groups, 0, :orders, 1], [:groups, 1, :orders, 0]]
      )
      expect(references.map(&:mode)).to eq(%i[summary full])
      expect(references.map(&:effective_scope)).to eq([%i[summary], %i[summary detail]])
    end

    it 'lets a nested disclosure inherit the scope of its enclosing occurrence' do
      # Only the groups carry a scope resolution; their orders inherit it.
      resolver = policy_with do |object, occurrence, _options|
        next nil unless object.key?(:name)

        occurrence.path == [:groups, 1] ? :summary : nil
      end

      result = batch_entity.represent_with_receipt(batch, disclosure: resolver)

      expect(result.payload[:groups][1][:orders].first).to eq(id: 2, total: 20)
      inherited = result.receipt.entries_for_group(:orders)
                        .select { |entry| entry.group_path.first == :groups && entry.group_path[1] == 1 }
      expect(inherited.map(&:inherited)).to all(be true)
      expect(inherited.map(&:effective_scope)).to all(eq([:summary]))
    end
  end

  describe 'receipt' do
    it 'lists every occurrence with the fields actually present in the payload' do
      result = batch_entity.represent_with_receipt(batch, disclosure: summarize([:groups, 0, :orders, 1]))

      payload_entry = result.receipt.entry_at([])
      group_entry = result.receipt.entry_at([:groups, 0])
      kept_order = result.receipt.entry_at([:groups, 0, :orders, 0])
      summarized_order = result.receipt.entry_at([:groups, 0, :orders, 1])

      expect(payload_entry.fields).to eq(%i[batch_id groups])
      expect(group_entry.fields).to eq(%i[name orders])
      expect(kept_order.fields).to eq(%i[id total memo note])
      expect(summarized_order.fields).to eq(%i[id total])
      expect(summarized_order.scope_withheld_fields).to eq(%i[memo note])
      expect(result.receipt.withheld_fields_at([:groups, 0, :orders, 1])).to eq(%i[memo note])
      expect(kept_order.scope_withheld_fields).to be_empty

      # Fields agree with the payload at exactly the same path.
      expect(summarized_order.fields).to eq(result.payload[:groups][0][:orders][1].keys)
      expect(kept_order.fields).to eq(result.payload[:groups][0][:orders][0].keys)
    end

    it 'orders receipt entries like the public payload and numbers positions from one' do
      result = batch_entity.represent_with_receipt(batch, disclosure: summarize([:groups, 0, :orders, 1]))
      paths = result.receipt.to_a.map { |entry| entry[:path] }

      expect(paths).to eq(
        [
          [],
          [:groups, 0],
          [:groups, 0, :orders, 0],
          [:groups, 0, :orders, 1],
          [:groups, 1],
          [:groups, 1, :orders, 0],
          [:groups, 1, :orders, 1]
        ]
      )
      expect(result.receipt.to_a.map { |entry| entry[:position] }).to eq((1..7).to_a)
    end

    it 'distinguishes full and summary occurrences and records which rule applied' do
      result = batch_entity.represent_with_receipt(batch, disclosure: summarize([:groups, 0, :orders, 1]))
      entries = result.receipt.to_a

      order_entries = entries.select do |entry|
        entry[:entity] == order_entity.name.to_s || entry[:fields].include?(:id)
      end
      expect(order_entries.count).to eq(4)
      expect(order_entries.count { |entry| entry[:mode] == :summary }).to eq(1)
      expect(result.receipt.to_h[:visible_count]).to be > 0
      expect(result.receipt.to_h[:summarized_count]).to eq(1)
    end

    it 'is closed after the representation and rejects further writes' do
      result = batch_entity.represent_with_receipt(batch, disclosure: policy_with { |_o, _occ, _opts| :detail })

      expect(result.receipt).to be_closed
      expect { result.receipt.close! }.not_to raise_error
    end
  end

  describe 'one representation' do
    it 'shares the parent conditions, child entity options and receipt' do
      conditions = []
      counted_order_entity = Class.new(Grape::Entity) do
        expose :id, scope: :summary
        expose :memo, scope: :detail, if: lambda { |_object, options|
          conditions << options[:disclosure_scope]
          options[:allow_memo]
        }
      end
      counted_group_entity = Class.new(Grape::Entity) do
        expose :name, scope: :summary
        expose :orders, using: counted_order_entity
      end
      parent_entity = Class.new(Grape::Entity) do
        expose :batch_id, scope: :summary
        expose :groups, using: counted_group_entity
      end

      resolver = policy_with { |_object, _occurrence, _options| :detail }
      result = parent_entity.represent_with_receipt(batch, disclosure: resolver, allow_memo: true)

      expect(result.payload[:groups][0][:orders][0]).to include(:memo)
      # Each memo exposure evaluated against the entity's effective scope.
      expect(conditions).to all(eq([:summary, :detail]))
      expect(result.receipt.entry_at([:groups, 0, :orders, 0]).effective_scope).to eq([:summary, :detail])
    end
  end

  describe 'entity-level accessors' do
    it 'exposes a nil receipt and scope when disclosure was not requested' do
      entity = order_entity.new(order_one, serializable: true)

      expect(entity.disclosure_receipt).to be_nil
      expect(entity.disclosure_scope).to be_nil
    end

    it 'exposes the shared receipt and effective scope on a scoped instance' do
      receipt = Grape::Entity::Disclosure::Receipt.new
      entity = order_entity.new(
        order_one,
        disclosure: true,
        disclosure_context: Grape::Entity::Disclosure::Context.build(true, receipt: receipt),
        disclosure_occurrence: Grape::Entity::Disclosure::Occurrence.root,
        disclosure_scope: %i[summary]
      )

      expect(entity.disclosure_receipt).to be(receipt)
      expect(entity.disclosure_scope).to eq(%i[summary])
    end
  end

  describe 'present_collection' do
    it 'keeps the collection wrapper and records one occurrence per item' do
      order_klass = order_entity
      collection_entity = Class.new(Grape::Entity) do
        present_collection true, :orders
        expose :orders, using: order_klass
        expose :batch_id
      end

      payload = collection_entity.represent([order_one, order_two], serializable: true, disclosure: false)
      expect(payload[:orders].length).to eq(2)

      result = collection_entity.represent_with_receipt(
        [order_one, order_two],
        batch_id: 'batch-1',
        disclosure: policy_with { |object, _occ, _opts| object[:id] == 2 ? :summary : :detail }
      )

      expect(result.payload[:orders].map { |order| order.keys }).to eq(
        [%i[id total memo note], %i[id total]]
      )
      # The wrapper entity itself is one occurrence; the nested collection and
      # its items are additional occurrences.
      expect(result.receipt.entries.map(&:path)).to include([:orders, 1])
    end
  end

  describe 'nested entity additions' do
    it 'renders a nested entity with the parent order scope and records its own occurrence' do
      note_entity = Class.new(Grape::Entity) do
        expose :code, scope: :summary
        expose :text, scope: :detail
      end
      note_klass = note_entity
      order_with_note = Class.new(Grape::Entity) do
        expose :id, scope: :summary
        expose :memo, scope: :detail
        expose :note, using: note_klass
      end

      object = { id: 9, memo: 'secret', note: { code: 'n-9', text: 'extra detail' } }
      policy = policy_with do |candidate, _occurrence, _options|
        candidate.key?(:memo) ? :summary : nil
      end

      result = order_with_note.represent_with_receipt(object, disclosure: policy)

      expect(result.payload).to eq(id: 9, note: { code: 'n-9' })
      note_entry = result.receipt.entry_at(%i[note])
      expect(note_entry.fields).to eq(%i[code])
      expect(note_entry.scope_withheld_fields).to eq(%i[text])
      expect(note_entry.inherited).to be true
      expect(note_entry.effective_scope).to eq([:summary])
    end

    it 'reflects :only and :except filtering in the receipt fields' do
      result = batch_entity.represent_with_receipt(
        batch,
        disclosure: policy_with { |_o, _occ, _opts| :detail },
        only: [:batch_id, { groups: [:name, { orders: [:id] }] }]
      )

      order_entry = result.receipt.entry_at([:groups, 0, :orders, 0])
      expect(order_entry.fields).to eq(%i[id])
      expect(result.payload[:groups][0][:orders][0]).to eq(id: 1)
    end
  end

  describe 'synthetic download comparison' do
    # The same two order objects are referenced from both groups. Only the
    # order_two reference inside group "a" is lowered to summary; every other
    # reference keeps detail. The two runs swap the group order, so the same
    # logical permission change lands at a different output position.
    def compare_runs
      straight = batch_entity.represent_with_receipt(
        batch,
        disclosure: lower_order_two_in_group(0) # group "a" is first
      )
      swapped = batch_entity.represent_with_receipt(
        { batch_id: 'batch-1', groups: [group_b, group_a] },
        disclosure: lower_order_two_in_group(1) # group "a" is second
      )
      [straight, swapped]
    end

    def lower_order_two_in_group(group_index)
      policy_with do |object, occurrence, _options|
        next nil unless object.key?(:memo)

        occurrence.group_path == [:groups, group_index, :orders] && object[:id] == 2 ? :summary : :detail
      end
    end

    it 'matches payload fields to receipt fields at every occurrence' do
      compare_runs.each do |result|
        result.receipt.to_a.each do |entry|
          node = entry[:path].inject(result.payload) { |current, part| current[part] }

          expect(node).to be_a(Hash)
          expect(entry[:fields]).to eq(node.keys.map(&:to_sym))
        end
      end
    end

    it 'lowers exactly one occurrence while the repeated object keeps detail elsewhere' do
      straight, swapped = compare_runs

      [straight, swapped].each do |result|
        summaries = result.receipt.to_a.select { |entry| entry[:mode] == :summary }
        expect(summaries.length).to eq(1)
        expect(summaries.first[:identifier]).to eq(2)
      end

      # Only the group-a reference of order_two is lowered; the group-b
      # reference is always full. Output order differs because the groups swap.
      expect(straight.receipt.entries_for_object(2).map(&:mode)).to eq(%i[summary full])
      expect(swapped.receipt.entries_for_object(2).map(&:mode)).to eq(%i[full summary])
      expect(straight.receipt.entries_for_object(1).map(&:mode)).to eq(%i[full full])
      expect(swapped.receipt.entries_for_object(1).map(&:mode)).to eq(%i[full full])
    end

    it 'records the same logical grant at the output position of each run' do
      straight, swapped = compare_runs

      straight_summary = straight.receipt.to_a.find { |entry| entry[:mode] == :summary }
      swapped_summary = swapped.receipt.to_a.find { |entry| entry[:mode] == :summary }

      expect(straight_summary[:path]).to eq([:groups, 0, :orders, 1])
      expect(swapped_summary[:path]).to eq([:groups, 1, :orders, 1])
      expect(straight_summary[:granted_scope]).to eq([:summary])
      expect(swapped_summary[:granted_scope]).to eq([:summary])
      expect(straight_summary[:effective_scope]).to eq([:summary])
      expect(swapped_summary[:effective_scope]).to eq([:summary])
    end
  end

  describe 'merged nested entities' do
    it 'attributes merged child fields to the enclosing occurrence' do
      address_entity = Class.new(Grape::Entity) do
        expose :city, scope: :summary
        expose :street, scope: :detail
      end
      address_klass = address_entity
      user_entity = Class.new(Grape::Entity) do
        expose :name, scope: :summary
        expose :address, using: address_klass, merge: true
      end

      object = { name: 'u', address: { city: 'c', street: 's' } }
      policy = Grape::Entity::Disclosure::Policy.new(levels: levels, default: :summary)
      result = user_entity.represent_with_receipt(object, disclosure: policy)

      expect(result.payload).to eq(name: 'u', city: 'c')
      expect(result.receipt.to_a.length).to eq(1)
      expect(result.receipt.to_a.first[:fields]).to eq(%i[name city])
      expect(result.receipt.to_a.first[:scope_withheld_fields]).to eq(%i[street])
    end

    it 'keeps a non-merged child of a merged child at its real payload path' do
      city_entity = Class.new(Grape::Entity) do
        expose :zip, scope: :summary
        expose :district, scope: :detail
      end
      city_klass = city_entity
      address_entity = Class.new(Grape::Entity) do
        expose :street, scope: :summary
        expose :secret, scope: :detail
        expose :city, using: city_klass
      end
      address_klass = address_entity
      user_entity = Class.new(Grape::Entity) do
        expose :name, scope: :summary
        expose :address, using: address_klass, merge: true
      end

      object = {
        name: 'u',
        address: { street: 's', secret: 'x', city: { zip: 'z', district: 'd' } }
      }
      policy = Grape::Entity::Disclosure::Policy.new(levels: levels, default: :summary)
      result = user_entity.represent_with_receipt(object, disclosure: policy)

      expect(result.payload).to eq(name: 'u', street: 's', city: { zip: 'z' })
      expect(result.receipt.entry_at([]).scope_withheld_fields).to eq(%i[secret])
      expect(result.receipt.entry_at(%i[city]).fields).to eq(%i[zip])
      expect(result.receipt.entry_at(%i[city]).scope_withheld_fields).to eq(%i[district])
    end
  end

  describe 'server-supplied configuration' do
    it 'accepts a plain map of occurrence path to scope' do
      result = batch_entity.represent_with_receipt(
        batch,
        disclosure: {
          levels: levels,
          default: :detail,
          paths: { [:groups, 0, :orders, 1] => :summary }
        }
      )

      expect(result.payload[:groups][0][:orders][1]).to eq(id: 2, total: 20)
      expect(result.payload[:groups][1][:orders][0]).to include(:memo, :note)
      expect(result.receipt.entry_at([:groups, 0, :orders, 1]).mode).to eq(:summary)
      expect(result.receipt.entry_at([:groups, 1, :orders, 0]).mode).to eq(:full)
    end

    it 'creates a receipt for represent_with_receipt when the config asks for one' do
      result = batch_entity.represent_with_receipt(
        batch,
        disclosure: { levels: levels, default: :summary, receipt: true }
      )

      expect(result.receipt).to be_closed
      expect(result.receipt.to_a.length).to eq(7)
    end
  end

  describe 'scope declarations' do
    it 'rejects unknown exposure options early' do
      expect do
        Class.new(Grape::Entity) { expose :id, scope_levels: %i[summary] }
      end.to raise_error(ArgumentError, /scope_levels/)
    end

    it 'accepts a single scope label as well as an array' do
      entity = Class.new(Grape::Entity) do
        expose :id, scope: :summary
        expose :memo, scope: %i[detail extra]
      end

      result = entity.represent_with_receipt(
        order_one,
        disclosure: Grape::Entity::Disclosure::Policy.new(levels: %i[summary detail], default: :detail)
      )
      expect(result.payload).to eq(id: 1, memo: 'first memo')

      narrowed = entity.represent_with_receipt(
        order_one,
        disclosure: Grape::Entity::Disclosure::Policy.new(levels: %i[summary detail], default: :summary)
      )
      expect(narrowed.payload).to eq(id: 1)
    end

    it 'keeps every labelled field when the policy declares no levels' do
      entity = Class.new(Grape::Entity) do
        expose :id, scope: :summary
        expose :memo, scope: :detail
      end

      policy = Grape::Entity::Disclosure::Policy.new(default: :detail)
      result = entity.represent_with_receipt(order_one, disclosure: policy)
      expect(result.payload).to eq(id: 1, memo: 'first memo')
    end
  end
end

describe Grape::Entity::Disclosure::Policy do
  it 'exposes only an approved identifier while resolving scopes per occurrence' do
    policy = described_class.new(
      default: :summary,
      identifier: ->(object) { "order-#{object[:id]}" }
    ) do |object, occurrence, options|
      options[:tenant] == 'acme' && occurrence.index&.zero? ? :detail : nil
    end

    occurrence = Grape::Entity::Disclosure::Occurrence.new(path: [:orders, 0], collection: true)
    expect(policy.resolve({ id: 7 }, occurrence, Grape::Entity::Options.new(tenant: 'acme'))).to eq(:detail)
    expect(policy.resolve({ id: 7 }, occurrence, Grape::Entity::Options.new(tenant: 'other'))).to be_nil
    expect(policy.identifier_for({ id: 7 })).to eq('order-7')
  end

  it 'returns no identifier unless one was approved' do
    policy = described_class.new

    expect(policy.identifier_for({ id: 7 })).to be_nil
  end

  it 'rejects a malformed disclosure option' do
    expect do
      Grape::Entity.represent_with_receipt([], disclosure: 42)
    end.to raise_error(ArgumentError, /disclosure/)
  end
end

describe Grape::Entity::Disclosure::Receipt do
  it 'keeps a 1-based position per occurrence and refuses writes after closing' do
    receipt = described_class.new
    occurrence = Grape::Entity::Disclosure::Occurrence.new(path: [:orders, 0], collection: true)

    receipt.record(
      occurrence: occurrence, field: :orders, entity_class: Object, mode: :full,
      granted_scope: [:summary], effective_scope: %i[summary detail], inherited: false,
      policy_applied: true, identifier: 1, fields: %i[id]
    )
    receipt.finalize!(orders: [{ id: 1 }])

    expect(receipt.to_h[:entries].first[:position]).to eq(1)
    expect { receipt.record(occurrence: occurrence, field: :orders, entity_class: Object, mode: :full,
                            granted_scope: [], effective_scope: [], inherited: true,
                            policy_applied: false, identifier: nil, fields: []) }
      .to raise_error(FrozenError)
  end
end
