# frozen_string_literal: true

describe Grape::Entity do
  let(:child_entity) do
    Class.new(described_class) do
      format_with(:lowercase) { |value| value.to_s.downcase }

      expose :label, format_with: :lowercase
      expose :secret, visibility: :controlled, safe: true
    end
  end

  let(:business_entity) do
    child = child_entity

    Class.new(described_class) do
      format_with(:shout) { |value| "#{value.to_s.upcase}!" }

      expose :name, format_with: :shout
      expose :internal_code, external: false, safe: true
      expose :internal_note, visibility: :controlled, safe: true
      expose :child, using: child
    end
  end

  let(:public_output) { { name: 'WIDGET!', child: { label: 'part' } } }

  variants = {
    absent: { code: nil, note: nil, secret: nil },
    alpha: { code: 'ALPHA-7', note: 'alpha note', secret: 'child-secret-a' },
    beta: { code: 'BETA-3', note: 'beta note', secret: 'child-secret-b' }
  }

  def hash_object(values)
    child = { label: 'Part' }
    child[:secret] = values[:secret] if values[:secret]

    object = { name: 'Widget', child: child }
    object[:internal_code] = values[:code] if values[:code]
    object[:internal_note] = values[:note] if values[:note]
    object
  end

  def plain_child(values)
    Class.new do
      define_method(:label) { 'Part' }

      if values[:secret]
        define_method(:secret) { values[:secret] }
        private :secret
      end
    end.new
  end

  def plain_object(values)
    child = plain_child(values)

    Class.new do
      define_method(:name) { 'Widget' }
      define_method(:child) { child }

      if values[:code]
        define_method(:internal_code) { values[:code] }
        private :internal_code
      end

      if values[:note]
        define_method(:internal_note) { values[:note] }
        private :internal_note
      end
    end.new
  end

  def controlled_output_for(values)
    {
      name: 'WIDGET!',
      internal_code: values[:code],
      internal_note: values[:note],
      child: { label: 'part', secret: values[:secret] }
    }
  end

  describe 'external representation constraint' do
    it 'selects the expected hash and plain-object delegators' do
      hash = hash_object(variants[:alpha])
      plain = plain_object(variants[:alpha])

      expect(Grape::Entity::Delegator.new(hash)).to be_a(Grape::Entity::Delegator::HashObject)
      expect(Grape::Entity::Delegator.new(plain)).to be_a(Grape::Entity::Delegator::PlainObject)
    end

    variants.each do |variant_name, values|
      it "hides existence and values for the hash #{variant_name} variant" do
        object = hash_object(values)

        expect(business_entity.represent_external(object).serializable_hash).to eq(public_output)
        expect(business_entity.represent(object, visibility: :public).serializable_hash).to eq(public_output)
        expect(business_entity.represent(object, public: true).serializable_hash).to eq(public_output)
      end

      it "hides existence and values for the plain object #{variant_name} variant" do
        object = plain_object(values)

        expect(business_entity.represent_external(object).serializable_hash).to eq(public_output)
        expect(business_entity.represent(object, visibility: :public).serializable_hash).to eq(public_output)
        expect(business_entity.represent(object, public: true).serializable_hash).to eq(public_output)
      end

      it "keeps the controlled hash #{variant_name} variant distinguishable" do
        object = hash_object(values)

        expect(business_entity.represent(object).serializable_hash).to eq(controlled_output_for(values))
        expect(business_entity.represent(object, visibility: :controlled).serializable_hash)
          .to eq(controlled_output_for(values))
      end

      it "keeps the controlled plain object #{variant_name} variant distinguishable" do
        object = plain_object(values)

        expect(business_entity.represent(object).serializable_hash).to eq(controlled_output_for(values))
        expect(business_entity.represent(object, visibility: :controlled).serializable_hash)
          .to eq(controlled_output_for(values))
      end
    end

    it 'does not let only: override the external deny rule' do
      object = hash_object(variants[:alpha])

      output = business_entity.represent(object, visibility: :public, only: %i[name internal_code]).serializable_hash

      expect(output).to eq(name: 'WIDGET!')
    end

    it 'accepts the common controlled-only exposure aliases' do
      [
        { restricted: true },
        { private: true },
        { internal: true },
        { public: false },
        { external: false },
        { visibility: :controlled },
        { privacy: :private },
        { access: :restricted }
      ].each do |restriction_option|
        entity_class = Class.new(described_class) do
          expose :secret, **restriction_option.merge(safe: true)
        end

        object = { secret: 'value' }

        expect(entity_class.represent_external(object).serializable_hash).to eq({})
        expect(entity_class.represent_controlled(object).serializable_hash).to eq(secret: 'value')
      end
    end

    it 'accepts the common external viewer option spellings' do
      %i[
        external
        public
        restricted
      ].each do |boolean_option|
        output = business_entity
                 .represent(hash_object(variants[:alpha]), boolean_option => true)
                 .serializable_hash

        expect(output).to eq(public_output)
      end

      [
        { view: :public },
        { audience: :external },
        { privacy: :public },
        { access: :external },
        { access: :restricted },
        { viewer: :public }
      ].each do |viewer_option|
        output = business_entity
                 .represent(hash_object(variants[:alpha]), viewer_option)
                 .serializable_hash

        expect(output).to eq(public_output)
      end
    end

    it 'does not evaluate conditions or accessors for externally hidden exposures' do
      risky_entity = Class.new(described_class) do
        expose :name
        expose :internal_code, visibility: :controlled,
                               if: ->(*) { raise 'condition evaluated' }
      end

      object = Class.new do
        def name
          'Widget'
        end

        private

        def internal_code
          raise 'internal accessor evaluated'
        end
      end.new

      expect(risky_entity.represent_external(object).serializable_hash).to eq(name: 'Widget')
    end

    it 'prevents restricted accessor failures and missing attributes from changing public output' do
      risky_entity = Class.new(described_class) do
        expose :name
        expose :internal_code, restricted: true
      end

      present = Class.new do
        def name
          'Widget'
        end

        private

        def internal_code
          raise 'internal accessor evaluated'
        end
      end.new

      missing = Class.new do
        def name
          'Widget'
        end
      end.new

      expect(risky_entity.represent_external(present).serializable_hash).to eq(name: 'Widget')
      expect(risky_entity.represent_external(missing).serializable_hash).to eq(name: 'Widget')
      expect { risky_entity.represent(present).serializable_hash }.to raise_error(RuntimeError, 'internal accessor evaluated')
      expect { risky_entity.represent(missing).serializable_hash }.to raise_error(NoMethodError)
    end
  end
end
