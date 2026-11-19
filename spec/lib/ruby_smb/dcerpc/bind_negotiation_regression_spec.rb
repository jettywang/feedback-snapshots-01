require 'ruby_smb/dcerpc/client'
require 'stringio'

# End-to-end regression for DCE/RPC bind negotiation.
#
# These specs drive real bind/request sessions over an in-memory socket so the
# whole encode -> wire -> decode -> negotiation -> request path is exercised.
# The goal is to guarantee that every presentation context result stays bound
# to the abstract/transfer syntax that was originally proposed: a rejected or
# unknown context must never silently fall back to the default NDR decoding,
# and the first result must never be treated as representative of the whole
# bind.
RSpec.describe 'DCE/RPC bind presentation context negotiation' do
  let(:primary_endpoint) { RubySMB::Dcerpc::Samr }
  let(:secondary_uuid) { 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }
  let(:non_ndr_uuid) { 'f00dcafe-dead-beef-0000-000000000001' }
  let(:stub_packet) { RubySMB::Dcerpc::Winreg::EnumKeyRequest.new(lp_name: 'test') }
  let(:response_stub_bytes) { 'response-stub'.b }

  # A two-context bind: context 0 negotiates the real endpoint, context 2
  # negotiates a distinct abstract syntax.
  def build_multi_context_bind
    bind_req = RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint)
    bind_req.p_context_list.n_context_elem = 2
    second = bind_req.p_context_list.p_cont_elem[1]
    second.p_cont_id = 2
    second.abstract_syntax.if_uuid = secondary_uuid
    second.abstract_syntax.if_ver_major = 7
    second.abstract_syntax.if_ver_minor = 1
    bind_req
  end

  def bind_ack_with(results)
    ack = RubySMB::Dcerpc::BindAck.new
    ack.p_result_list.n_results = results.size
    results.each_with_index do |result_spec, index|
      result = ack.p_result_list.p_results[index]
      result.result = result_spec[:result]
      result.reason = result_spec.fetch(:reason, 0)
      transfer = result_spec[:transfer_syntax]
      if transfer
        result.transfer_syntax.if_uuid = transfer[:uuid]
        result.transfer_syntax.if_ver_major = transfer.fetch(:ver_major, 2)
        result.transfer_syntax.if_ver_minor = transfer.fetch(:ver_minor, 0)
      end
    end
    ack
  end

  def accepted(**opts)
    { result: RubySMB::Dcerpc::BindAck::ACCEPTANCE, reason: 0 }.merge(opts)
  end

  def rejected(reason, **opts)
    { result: RubySMB::Dcerpc::BindAck::PROVIDER_REJECTION, reason: reason }.merge(opts)
  end

  def response_pdu
    response = RubySMB::Dcerpc::Response.new
    response.stub = response_stub_bytes
    response
  end

  def new_client(socket)
    allow(IO).to receive(:select).and_return([[socket], [], []])
    described_client = RubySMB::Dcerpc::Client
    described_client.new('192.0.2.10', primary_endpoint, tcp_socket: socket)
  end

  # Run a full bind + request session against scripted PDUs. The bind request
  # the client sends is replaced by the supplied (possibly multi-context) one.
  def run_session(bind_req, ack, extra_responses = [])
    socket = ScriptedDcerpcSocket.new([ack] + extra_responses)
    client = new_client(socket)
    allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(bind_req)
    [client, socket]
  end

  def request_frame(socket)
    RubySMB::Dcerpc::Request.read(socket.written_frames.last)
  end

  describe 'per-context negotiation table' do
    it 'binds each result to the context proposed at the same position' do
      ack = bind_ack_with([
        accepted,
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED)
      ])
      client, = run_session(build_multi_context_bind, ack)
      client.bind

      table = client.instance_variable_get(:@context_negotiations)
      expect(table.keys).to contain_exactly(0, 2)

      first = table[0]
      expect(first).to be_a(RubySMB::Dcerpc::NegotiatedContext)
      expect(first.abstract_syntax.if_uuid).to eq(primary_endpoint::UUID)
      expect(first).to be_accepted
      expect(first).to be_usable
      expect(first.transfer_syntax.if_uuid).to eq(RubySMB::Dcerpc::Ndr::UUID)

      second = table[2]
      expect(second.abstract_syntax.if_uuid).to eq(secondary_uuid)
      expect(second).to_not be_accepted
      expect(second).to_not be_usable
      expect(second.reason).to eq(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED)
    end

    it 'records the selected NDR transfer syntax for an accepted context' do
      ack = bind_ack_with([accepted])
      client, = run_session(RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint), ack)
      client.bind

      negotiated = client.instance_variable_get(:@context_negotiations)[0]
      expect(negotiated.transfer_syntax.if_uuid).to eq(RubySMB::Dcerpc::Ndr::UUID)
      expect(negotiated.transfer_syntax.if_ver_major).to eq(RubySMB::Dcerpc::Ndr::VER_MAJOR)
      expect(negotiated.transfer_syntax.if_ver_minor).to eq(RubySMB::Dcerpc::Ndr::VER_MINOR)
    end

    it 'does not treat an accepted-but-unsupported transfer syntax as usable' do
      ack = bind_ack_with([
        accepted(transfer_syntax: { uuid: non_ndr_uuid, ver_major: 1, ver_minor: 0 })
      ])
      client, = run_session(RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint), ack)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      negotiated = client.instance_variable_get(:@context_negotiations)[0]
      expect(negotiated).to be_accepted
      expect(negotiated).to_not be_usable
      expect(negotiated).to_not be_transfer_syntax_supported
    end
  end

  describe 'mixed acceptance in a single bind' do
    it 'succeeds when the endpoint context is accepted even if another context is rejected' do
      ack = bind_ack_with([
        accepted,
        rejected(RubySMB::Dcerpc::BindAck::PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED)
      ])
      client, socket = run_session(build_multi_context_bind, ack, [response_pdu])

      expect { client.bind }.to_not raise_error
      expect(client.instance_variable_get(:@ctx_id)).to eq(0)

      raw_stub = client.dcerpc_request(stub_packet)
      expect(raw_stub).to eq(response_stub_bytes)
      expect(request_frame(socket).p_cont_id).to eq(0)
    end

    it 'fails when only the other (non-endpoint) context is accepted' do
      ack = bind_ack_with([
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED),
        accepted
      ])
      client, = run_session(build_multi_context_bind, ack)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      expect(client.instance_variable_get(:@ctx_id)).to eq(0)
    end

    it 'fails when every proposed context is rejected and reports the reasons' do
      ack = bind_ack_with([
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED),
        rejected(RubySMB::Dcerpc::BindAck::LOCAL_LIMIT_EXCEEDED)
      ])
      client, = run_session(build_multi_context_bind, ack)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError) do |error|
        expect(error.message).to include('p_cont_id=0')
        expect(error.message).to include('p_cont_id=2')
      end
    end
  end

  describe 'subsequent request/response attribution' do
    it 'uses the accepted p_cont_id even when it is not the first context' do
      bind_req = build_multi_context_bind
      # Endpoint context moves to a non-zero id; the secondary uses id 0.
      bind_req.p_context_list.p_cont_elem[0].p_cont_id = 5
      bind_req.p_context_list.p_cont_elem[1].p_cont_id = 0
      ack = bind_ack_with([
        accepted,
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED)
      ])
      client, socket = run_session(bind_req, ack, [response_pdu])

      client.bind
      expect(client.instance_variable_get(:@ctx_id)).to eq(5)

      client.dcerpc_request(stub_packet)
      expect(request_frame(socket).p_cont_id).to eq(5)
    end

    it 'refuses to send a request on an unknown context id' do
      ack = bind_ack_with([accepted])
      client, socket = run_session(RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint), ack, [response_pdu])
      client.bind
      client.instance_variable_set(:@ctx_id, 99)

      expect { client.dcerpc_request(stub_packet) }.to raise_error(RubySMB::Dcerpc::Error::BindError, /not accepted during bind/)
      expect(socket.written_frames.size).to eq(1)
    end

    it 'refuses to send a request on a context that was rejected' do
      ack = bind_ack_with([
        accepted,
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED)
      ])
      client, socket = run_session(build_multi_context_bind, ack, [response_pdu])
      client.bind
      client.instance_variable_set(:@ctx_id, 2)

      expect { client.dcerpc_request(stub_packet) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      expect(socket.written_frames.size).to eq(1)
    end
  end

  describe 'tampered and inconsistent negotiations' do
    it 'fails when the result order is swapped relative to the proposed contexts' do
      bind_req = build_multi_context_bind
      # Result 0 claims acceptance with a transfer syntax never proposed for
      # context 0 (it belongs to a different, non-NDR syntax), and result 1
      # rejects the secondary context whose abstract syntax does not match.
      ack = bind_ack_with([
        accepted(transfer_syntax: { uuid: non_ndr_uuid, ver_major: 1, ver_minor: 0 }),
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED)
      ])
      client, = run_session(bind_req, ack)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError)
    end

    it 'fails when a result is dropped so the counts no longer match' do
      ack = bind_ack_with([accepted])
      client, = run_session(build_multi_context_bind, ack)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError, /expected 2 .* got 1/)
    end

    it 'fails when extra results are returned for contexts that were never proposed' do
      ack = bind_ack_with([accepted, accepted, rejected(RubySMB::Dcerpc::BindAck::REASON_NOT_SPECIFIED)])
      client, = run_session(RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint), ack)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError, /expected 1 .* got 3/)
    end

    it 'does not inherit stale context state across a subsequent bind' do
      first_ack = bind_ack_with([accepted])
      socket = ScriptedDcerpcSocket.new([first_ack])
      client = new_client(socket)
      first_bind = RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint)
      allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(first_bind)
      client.bind
      expect(client.instance_variable_get(:@ctx_id)).to eq(0)

      # A new bind proposes only context 3 and the server rejects it. The old
      # context 0 must not be kept around or considered accepted.
      second_bind = RubySMB::Dcerpc::Bind.new(endpoint: primary_endpoint)
      second_bind.p_context_list.p_cont_elem[0].p_cont_id = 3
      second_ack = bind_ack_with([
        rejected(RubySMB::Dcerpc::BindAck::ABSTRACT_SYNTAX_NOT_SUPPORTED)
      ])
      socket.queue_responses([second_ack])
      allow(RubySMB::Dcerpc::Bind).to receive(:new).and_return(second_bind)

      expect { client.bind }.to raise_error(RubySMB::Dcerpc::Error::BindError)
      table = client.instance_variable_get(:@context_negotiations)
      expect(table.keys).to contain_exactly(3)
      expect(table).to_not have_key(0)
      expect { client.dcerpc_request(stub_packet) }.to raise_error(RubySMB::Dcerpc::Error::BindError)
    end
  end
end
