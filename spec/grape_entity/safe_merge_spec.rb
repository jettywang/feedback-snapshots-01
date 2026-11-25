# frozen_string_literal: true

describe 'safe field merging' do
  # First pair of nested entities: canonical aliases point at synthesized data.
  class CatalogCardEntity < Grape::Entity
    expose :handle, as: :display_name, source: :catalog
    expose :tier, as: :level, source: :catalog
  end

  class PartnerCardEntity < Grape::Entity
    expose :nick, as: :display_name, source: :partner
    expose :rank, as: :level, source: :partner, override: true
  end

  # Second pair of nested entities where one source is not authorized.
  class PublicFeedEntity < Grape::Entity
    expose :bio, as: :headline, source: :public_feed
  end

  class InternalMemoEntity < Grape::Entity
    expose :memo, as: :headline, source: :internal
  end

  let(:card_data) do
    {
      catalog: { handle: 'Ada', tier: 'gold' },
      partner: { nick: 'Ada', rank: 'platinum' }
    }
  end

  let(:brief_data) do
    {
      public_feed: { bio: 'public blurb' },
      internal: { memo: 'internal memo' }
    }
  end

  describe Grape::Entity do
    describe '.authorize_merge_sources' do
      it 'registers sources on the entity class' do
        klass = Class.new(Grape::Entity) { authorize_merge_sources :a, :b }
        expect(klass.authorized_merge_sources).to eq(%i[a b])
      end

      it 'does not register the same source twice' do
        klass = Class.new(Grape::Entity) { authorize_merge_sources :a, :a }
        expect(klass.authorized_merge_sources).to eq([:a])
      end

      it 'inherits authorized sources without letting subclasses mutate the parent' do
        parent = Class.new(Grape::Entity) { authorize_merge_sources :parent_src }
        child = Class.new(parent) { authorize_merge_sources :child_src }

        expect(child.authorized_merge_sources).to eq(%i[parent_src child_src])
        expect(parent.authorized_merge_sources).to eq([:parent_src])
      end
    end
  end

  describe 'merge: :safe with two nested entities' do
    let(:presenter_class) do
      catalog = CatalogCardEntity
      partner = PartnerCardEntity
      Class.new(Grape::Entity) do
        authorize_merge_sources :catalog, :partner
        expose :card do
          expose :catalog, merge: :safe, using: catalog
          expose :partner, merge: :safe, using: partner
        end
      end
    end

    it 'emits the shared field when both authorized sources agree' do
      output = presenter_class.represent(card_data, serializable: true)
      expect(output).to eq(card: { display_name: 'Ada', level: 'platinum' })
    end

    it 'records the approved merge with both contributing sources' do
      presenter = presenter_class.new(card_data)
      presenter.serializable_hash

      entry = presenter.merge_report.find([:card], :display_name)
      expect(entry).to be_merged
      expect(entry.sources.map(&:label)).to eq(%i[catalog partner])
      expect(entry.value).to eq('Ada')
      expect(entry.evidence.map(&:authorized?)).to eq([true, true])
    end

    it 'confirms a replacement when the later source declares override' do
      presenter = presenter_class.new(card_data)
      presenter.serializable_hash

      entry = presenter.merge_report.find([:card], :level)
      expect(entry).to be_replaced
      expect(entry.value).to eq('platinum')
      expect(entry.evidence.map(&:source).map(&:label)).to eq(%i[catalog partner])
      expect(entry.evidence.last).to be_override
      expect(entry.evidence.last.source.label).to eq(:partner)
    end

    it 'attributes every winning value to a declared, authorized source' do
      presenter = presenter_class.new(card_data)
      presenter.serializable_hash

      presenter.merge_report.entries.each do |entry|
        expect(entry.winning_evidence).to be_authorized
        expect(entry.winning_evidence.source.label).to be_present
      end
    end
  end

  describe 'unauthorized and conflicting sources' do
    let(:presenter_class) do
      public_feed = PublicFeedEntity
      internal = InternalMemoEntity
      Class.new(Grape::Entity) do
        authorize_merge_sources :internal
        expose :brief do
          expose :public_feed, merge: :safe, using: public_feed
          expose :internal, merge: :safe, using: internal
        end
      end
    end

    it 'withholds the field from the output while the conflict is pending' do
      output = presenter_class.represent(brief_data, serializable: true)
      expect(output).to eq(brief: {})
    end

    it 'keeps the concrete evidence for both sides of the conflict' do
      presenter = presenter_class.new(brief_data)
      presenter.serializable_hash

      expect(presenter.merge_report).to be_conflicts
      entry = presenter.merge_report.conflicts.first
      expect(entry).to be_conflict
      expect(entry.reason).to eq(:incompatible_values)
      expect(entry.sources.map(&:label)).to eq(%i[public_feed internal])
      expect(entry.evidence.map(&:authorized?)).to eq([false, true])
      expect(entry.evidence.map(&:value)).to eq(['public blurb', 'internal memo'])
    end

    it 'still exposes the authorized value through the report for review' do
      presenter = presenter_class.new(brief_data)
      presenter.serializable_hash

      entry = presenter.merge_report.find([:brief], :headline)
      expect(entry.value).to eq('internal memo')
      expect(entry.winning_evidence.source.label).to eq(:internal)
    end
  end

  describe 'source-based rather than name-based permission' do
    let(:presenter_class) do
      Class.new(Grape::Entity) do
        authorize_merge_sources :trusted
        expose :wrap do
          expose :trusted_one, merge: :safe, source: :trusted do |_|
            { shared: 'same', kept: 'yes' }
          end
          expose :rogue_one, merge: :safe, source: :rogue do |_|
            { shared: 'same', injected: 'blocked' }
          end
        end
      end
    end

    it 'trusts a field name only when its contributing source is authorized' do
      output = presenter_class.represent({}, serializable: true)
      expect(output).to eq(wrap: { shared: 'same', kept: 'yes' })
    end

    it 'marks the value unique to an unauthorized source as a conflict' do
      presenter = presenter_class.new({})
      presenter.serializable_hash

      entry = presenter.merge_report.find([:wrap], :injected)
      expect(entry).to be_conflict
      expect(entry.reason).to eq(:unauthorized_source)
      expect(entry.sources.map(&:label)).to eq([:rogue])
      expect(entry.evidence).to all(be_unauthorized)
    end

    it 'keeps an agreed value merged even when echoed by an unauthorized source' do
      presenter = presenter_class.new({})
      presenter.serializable_hash

      entry = presenter.merge_report.find([:wrap], :shared)
      expect(entry).to be_merged
      expect(entry.value).to eq('same')
    end
  end

  describe 'coexistence with the existing merge semantics' do
    it 'leaves the legacy merge: true behavior untouched' do
      klass = Class.new(Grape::Entity) do
        expose :something, merge: true
        expose :special, merge: ->(_key, v1, v2) { v1 && v2 ? 'brand new val' : v2 }
      end

      data = { something: { like_nested_hash: true }, special: { like_nested_hash: '12' } }
      expect(klass.represent(data, serializable: true)).to eq(like_nested_hash: 'brand new val')
    end

    it 'does not produce a report when no safe merge is declared' do
      klass = Class.new(Grape::Entity) { expose :name }
      presenter = klass.new(name: 'Ada')
      presenter.serializable_hash

      expect(presenter.merge_report).to be_empty
    end
  end

  describe 'collections' do
    it 'serializes safe-merged collections without exposing internal payloads' do
      item_entity = Class.new(Grape::Entity) { expose :id, source: :catalog }
      presenter_class = Class.new(Grape::Entity) do
        authorize_merge_sources :catalog
        expose :items, merge: :safe, using: item_entity
      end

      output = presenter_class.represent({ items: [{ id: 1 }, { id: 2 }] }, serializable: true)
      expect(output).to eq([{ id: 1 }, { id: 2 }])
    end

    it 'ignores a nil contribution while keeping sibling fields' do
      presenter_class = Class.new(Grape::Entity) do
        authorize_merge_sources :catalog
        expose :wrap do
          expose :maybe, merge: :safe, source: :catalog do |_| nil end
          expose :keep do |_| 'stays' end
        end
      end

      expect(presenter_class.represent({ maybe: nil }, serializable: true)).to eq(wrap: { keep: 'stays' })
    end
  end
end
