RSpec.describe RubySMB::Dcerpc::NegotiatedContext do
  let(:endpoint) { RubySMB::Dcerpc::Samr }
  let(:other_uuid) { 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
  let(:non_ndr_uuid) { 'f00dcafe-dead-beef-0000-000000000001' }

  let(:context) do
    bind = RubySMB::Dcerpc::Bind.new(endpoint: endpoint)
    bind.p_context_list.p_cont_elem[0]
  end

  let(:p_result) { RubySMB::Dcerpc::PResultT.new }

  subject(:negotiated) { described_class.new(context, p_result) }

  it 'exposes the proposed p_cont_id' do
    context.p_cont_id = 4
    expect(negotiated.p_cont_id).to eq(4)
  end

  it 'keeps a reference to the original abstract syntax' do
    expect(negotiated.abstract_syntax.if_uuid).to eq(endpoint::UUID)
    expect(negotiated.abstract_syntax.if_ver_major).to eq(endpoint::VER_MAJOR)
    expect(negotiated.abstract_syntax.if_ver_minor).to eq(endpoint::VER_MINOR)
  end

  it 'keeps the transfer syntaxes that were originally proposed' do
    expect(negotiated.proposed_transfer_syntaxes.first.if_uuid).to eq(RubySMB::Dcerpc::Ndr::UUID)
  end

  describe '#accepted?' do
    it 'is true for an acceptance result' do
      p_result.result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
      expect(negotiated).to be_accepted
    end

    it 'is false for a rejection result' do
      p_result.result = RubySMB::Dcerpc::BindAck::PROVIDER_REJECTION
      expect(negotiated).to_not be_accepted
    end
  end

  describe '#transfer_syntax_supported?' do
    it 'is true when the selected syntax was proposed' do
      expect(negotiated).to be_transfer_syntax_supported
    end

    it 'is false when the server selects a syntax that was never proposed' do
      p_result.transfer_syntax.if_uuid = non_ndr_uuid
      p_result.transfer_syntax.if_ver_major = 1
      p_result.transfer_syntax.if_ver_minor = 0
      expect(negotiated).to_not be_transfer_syntax_supported
    end
  end

  describe '#usable?' do
    it 'is usable when accepted with the proposed NDR syntax' do
      p_result.result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
      expect(negotiated).to be_usable
    end

    it 'is not usable when rejected even with an NDR transfer syntax' do
      p_result.result = RubySMB::Dcerpc::BindAck::USER_REJECTION
      expect(negotiated).to_not be_usable
    end

    it 'is not usable when an unsupported transfer syntax is selected' do
      p_result.result = RubySMB::Dcerpc::BindAck::ACCEPTANCE
      p_result.transfer_syntax.if_uuid = non_ndr_uuid
      p_result.transfer_syntax.if_ver_major = 1
      expect(negotiated).to_not be_usable
    end
  end

  describe '#for_endpoint?' do
    it 'matches the endpoint whose abstract syntax was proposed' do
      expect(negotiated.for_endpoint?(endpoint)).to be true
    end

    it 'does not match a different endpoint' do
      context.abstract_syntax.if_uuid = other_uuid
      expect(negotiated.for_endpoint?(RubySMB::Dcerpc::Srvsvc)).to be false
    end
  end
end
