RSpec.describe RubySMB::Server::Session do
  let(:user_id) { 'WORKGROUP\RubySMB' }
  subject(:session) { described_class.new(rand(0xffffffff), user_id: user_id) }

  it { is_expected.to respond_to :id }
  it { is_expected.to respond_to :key }
  it { is_expected.to respond_to :signing_required }
  it { is_expected.to respond_to :tree_connect_table }
  it { is_expected.to respond_to :creation_time }
  it { is_expected.to respond_to :owner }

  describe '#initialize' do
    it 'starts with no signing required' do
      expect(session.signing_required).to be_falsey
    end

    it 'starts with no tree connections' do
      expect(session.tree_connect_table).to be_empty
    end

    it 'starts in the in progress state' do
      expect(session.state).to be :in_progress
    end
  end

  describe '#is_anonymous' do
    it 'is false' do
      expect(session.is_anonymous).to be_falsey
    end

    context 'when the identity is set to anonymous' do
      let(:user_id) { RubySMB::Gss::Provider::IDENTITY_ANONYMOUS }

      it 'is true' do
        expect(session.is_anonymous).to be_truthy
      end
    end
  end

  describe '#owned_by?' do
    it 'is false when no owner is set' do
      expect(session.owned_by?(Object.new)).to be false
    end

    context 'when an owner is set' do
      let(:owner) { Object.new }
      subject(:session) { described_class.new(rand(0xffffffff), user_id: user_id, owner: owner) }

      it 'is true only for the owning connection' do
        expect(session.owned_by?(owner)).to be true
        expect(session.owned_by?(Object.new)).to be false
      end
    end
  end
end
