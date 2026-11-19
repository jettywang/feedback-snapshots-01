RSpec.describe 'SMB2 server handle ownership' do
  # A minimal socket object for the server client. No listening or accepting
  # socket is ever created: each dispatcher is a paired in-memory channel.
  class MemorySocket
    def initialize
      @closed = false
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  class MemoryDispatcher < RubySMB::Dispatcher::Base
    attr_reader :sent, :tcp_socket, :events
    attr_accessor :peer, :handler

    def initialize(side)
      @side = side
      @sent = []
      @events = []
      @inbox = []
      @tcp_socket = MemorySocket.new
    end

    def send_packet(packet)
      raw = packet.to_binary_s
      status = packet.respond_to?(:status_code) ? packet.status_code.name : nil
      @events << [@side, packet.class.name, status]
      @sent << [packet, raw]
      peer.deliver(raw)
    end

    def deliver(raw)
      @inbox << raw
      handler.call(raw) if handler
    end

    def recv_packet
      @inbox.shift
    end
  end

  class InMemoryServerClient < RubySMB::Server::ServerClient
    def process(raw_request)
      dialect.nil? ? handle_negotiate(raw_request) : handle_smb(raw_request)
    end
  end

  let(:server) { RubySMB::Server.new(server_sock: Object.new, gss_provider: gss_provider) }
  let(:gss_provider) do
    RubySMB::Gss::Provider::NTLM.new(allow_guests: true).tap do |provider|
      provider.put_account('alice', 'Password123!', domain: 'WORKGROUP')
      provider.put_account('bob', 'Password456!', domain: 'WORKGROUP')
    end
  end
  let(:share_name) { 'controlled' }
  let(:file_name) { 'owned.txt' }
  let(:access_log) { [] }
  let(:share) do
    RubySMB::Server::Share::Provider::VirtualDisk.new(share_name).tap do |virtual_disk|
      virtual_disk.add_dynamic_file(file_name) do |_server_client, session|
        # Records which authenticated identity actually handled the access.
        access_log << [:read, session.user_id.to_s]
        session.user_id.to_s
      end
    end
  end

  before(:each) do
    server.add_share(share)
  end

  # @return [Array] client, client dispatcher, server client
  def connect(username, password)
    client_dispatcher = MemoryDispatcher.new(:client)
    server_dispatcher = MemoryDispatcher.new(:server)
    client_dispatcher.peer = server_dispatcher
    server_dispatcher.peer = client_dispatcher

    server_client = InMemoryServerClient.new(server, server_dispatcher)
    server_dispatcher.handler = ->(raw) { server_client.process(raw) }

    client = RubySMB::Client.new(
      client_dispatcher,
      smb1: false, smb2: true, smb3: false,
      username: username, password: password, domain: 'WORKGROUP'
    )
    client.negotiate
    client.authenticate
    [client, client_dispatcher, server_client, server_dispatcher]
  end

  def session_for(server_client)
    server_client.session_table.values.fetch(0)
  end

  def handles_for(server_client, tree)
    processor = session_for(server_client).tree_connect_table.fetch(tree.id)
    processor.instance_variable_get(:@handles)
  end

  def last_request(dispatcher, klass)
    dispatcher.sent.reverse.find { |packet, _raw| packet.is_a?(klass) }.last
  end

  # Sign a request with the given server-side session key, then return the raw
  # bytes that should be replayed through a connection.
  def sign_request(request, session)
    RubySMB::Signing.smb2_sign(request, session.key).to_binary_s
  end

  # Inject raw request bytes into a connection exactly as the network loop
  # would, then return the response header and record it in the dispatcher log.
  def inject(server_dispatcher, raw_request)
    server_dispatcher.handler.call(raw_request)
    raw_response = server_dispatcher.peer.recv_packet
    RubySMB::SMB2::SMB2Header.read(raw_response)
  end

  # Align the numeric session id observed by both the client and server for a
  # single connection. The id is only an on-wire lookup key, not authority.
  def renumber_session(client, server_client, id)
    session = session_for(server_client)
    server_client.session_table.delete(session.id)
    session.id = id
    server_client.session_table[id] = session
    client.session_id = id
    session
  end

  # Align the numeric tree id observed by both the client and server for a
  # single connection.
  def renumber_tree(tree, server_client, id)
    session = session_for(server_client)
    processor = session.tree_connect_table.delete(tree.id)
    session.tree_connect_table[id] = processor
    tree.id = id
    processor
  end

  # Align the numeric file id observed by both the client and server for a
  # single connection, moving the existing handle to the new key.
  def renumber_file(file, server_client, tree, persistent, volatile)
    handles = handles_for(server_client, tree)
    handle = handles.delete(file.guid.to_binary_s)
    file.guid.persistent = persistent
    file.guid.volatile = volatile
    handles[file.guid.to_binary_s] = handle
    handle
  end

  it 'keeps sessions, trees, and file handles isolated when numeric ids collide' do
    alice, _alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    bob, _bob_dispatcher, bob_server_client, bob_server_dispatcher = connect('bob', 'Password456!')

    alice_tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    bob_tree = bob.tree_connect("\\\\localhost\\#{share_name}")
    alice_file = alice_tree.open_file(filename: file_name)
    bob_file = bob_tree.open_file(filename: file_name)

    # Force identical SessionId, TreeId and FileId values on both connections.
    alice_session = renumber_session(alice, alice_server_client, 0x5151)
    bob_session = renumber_session(bob, bob_server_client, 0x5151)
    alice_processor = renumber_tree(alice_tree, alice_server_client, 0x6161)
    bob_processor = renumber_tree(bob_tree, bob_server_client, 0x6161)
    alice_handle = renumber_file(alice_file, alice_server_client, alice_tree, 0x1010, 0x2020)
    bob_handle = renumber_file(bob_file, bob_server_client, bob_tree, 0x1010, 0x2020)

    expect(alice_session.id).to eq bob_session.id
    expect(alice_tree.id).to eq bob_tree.id
    expect(alice_file.guid.to_binary_s).to eq bob_file.guid.to_binary_s
    expect(alice_processor).to_not equal(bob_processor)
    expect(alice_handle).to_not equal(bob_handle)
    expect(alice_handle.file).to_not equal(bob_handle.file)

    # Legal access on each connection still resolves to that connection's own
    # session, processor and handle.
    expect(alice_file.read).to eq 'WORKGROUP\\alice'
    expect(bob_file.read).to eq 'WORKGROUP\\bob'
    expect(access_log).to eq [[:read, 'WORKGROUP\\alice'], [:read, 'WORKGROUP\\bob']]
    expect(alice_handle.file).to_not be_closed
    expect(bob_handle.file).to_not be_closed
  end

  it 'does not treat a matching numeric session id as a session on another connection' do
    alice, _alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    bob, _bob_dispatcher, bob_server_client, bob_server_dispatcher = connect('bob', 'Password456!')

    alice_session = renumber_session(alice, alice_server_client, 0x5151)
    renumber_session(bob, bob_server_client, 0x6262)

    request = RubySMB::SMB2::Packet::TreeConnectRequest.new
    request.smb2_header.session_id = alice_session.id
    request.path = "\\\\localhost\\#{share_name}"
    response = inject(bob_server_dispatcher, sign_request(request, session_for(bob_server_client)))

    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
    expect(alice_session.tree_connect_table).to be_empty
  end

  it 'does not let a tree id from one connection disconnect another connection tree' do
    alice, _alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    _bob, _bob_dispatcher, bob_server_client, bob_server_dispatcher = connect('bob', 'Password456!')
    alice_tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    alice_session = renumber_session(alice, alice_server_client, 0x5151)
    bob_session = session_for(bob_server_client)

    request = RubySMB::SMB2::Packet::TreeDisconnectRequest.new
    request.smb2_header.session_id = bob_session.id
    request.smb2_header.tree_id = alice_tree.id
    response = inject(bob_server_dispatcher, sign_request(request, bob_session))

    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_NETWORK_NAME_DELETED
    expect(alice_session.tree_connect_table).to include(alice_tree.id)
    expect(bob_session.tree_connect_table).to be_empty
    expect(bob_server_dispatcher.events).to include(
      [:server, 'RubySMB::SMB2::Packet::ErrorPacket', 'STATUS_NETWORK_NAME_DELETED']
    )
  end

  it 'does not resolve another connection file id and does not release its handle' do
    alice, _alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    bob, _bob_dispatcher, bob_server_client, bob_server_dispatcher = connect('bob', 'Password456!')
    alice_tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    bob_tree = bob.tree_connect("\\\\localhost\\#{share_name}")
    alice_file = alice_tree.open_file(filename: file_name)
    bob_file = bob_tree.open_file(filename: file_name)
    alice_session = session_for(alice_server_client)
    bob_session = session_for(bob_server_client)

    request = RubySMB::SMB2::Packet::CloseRequest.new
    request.smb2_header.session_id = bob_session.id
    request.smb2_header.tree_id = bob_tree.id
    request.file_id = alice_file.guid
    response = inject(bob_server_dispatcher, sign_request(request, bob_session))

    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_FILE_CLOSED
    expect(bob_server_dispatcher.events).to include(
      [:server, 'RubySMB::SMB2::Packet::ErrorPacket', 'STATUS_FILE_CLOSED']
    )
    expect(handles_for(alice_server_client, alice_tree)).to include(alice_file.guid.to_binary_s)
    expect(handles_for(bob_server_client, bob_tree)).to include(bob_file.guid.to_binary_s)
    expect(alice_file.read).to eq 'WORKGROUP\\alice'
    expect(bob_file.read).to eq 'WORKGROUP\\bob'
  end

  it 'rejects a signed request replayed from another authenticated connection' do
    alice, alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    bob, _bob_dispatcher, bob_server_client, bob_server_dispatcher = connect('bob', 'Password456!')
    alice_tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    alice_file = alice_tree.open_file(filename: file_name)

    # Same numeric SessionId on both connections, but a different session key.
    renumber_session(alice, alice_server_client, 0x5151)
    bob_session = renumber_session(bob, bob_server_client, 0x5151)
    expect(bob_session.key).to_not eq session_for(alice_server_client).key

    # Capture the signed read only after the numeric id has been aligned, so
    # the raw bytes carry the colliding id.
    alice_file.read
    replayed_read = last_request(alice_dispatcher, RubySMB::SMB2::Packet::ReadRequest)
    header = RubySMB::SMB2::SMB2Header.read(replayed_read)
    expect(header.session_id).to eq bob_session.id
    expect(header.flags.signed).to eq 1

    log_before_replay = access_log.dup
    response = inject(bob_server_dispatcher, replayed_read)
    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_INVALID_SIGNATURE
    expect(bob_server_dispatcher.events).to include(
      [:server, 'RubySMB::SMB2::Packet::ErrorPacket', 'STATUS_INVALID_SIGNATURE']
    )
    expect(access_log).to eq log_before_replay
    expect(alice_file.read).to eq 'WORKGROUP\\alice'
  end

  it 'rejects an unsigned request on a session that requires signing' do
    alice, _alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    alice_tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    alice_file = alice_tree.open_file(filename: file_name)

    request = RubySMB::SMB2::Packet::ReadRequest.new
    request.smb2_header.session_id = alice.session_id
    request.smb2_header.tree_id = alice_tree.id
    request.file_id = alice_file.guid
    request.read_length = 64
    request.channel = RubySMB::SMB2::SMB2_CHANNEL_NONE
    expect(request.smb2_header.flags.signed).to eq 0

    response = inject(alice_server_dispatcher, request.to_binary_s)
    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_ACCESS_DENIED
    expect(handles_for(alice_server_client, alice_tree)).to include(alice_file.guid.to_binary_s)
  end

  it 'keeps a guest session unsigned while honoring its own access semantics' do
    guest, guest_dispatcher, guest_server_client, guest_server_dispatcher = connect('mallory', 'not-a-real-password')
    expect(guest.session_is_guest).to be true
    expect(guest.signing_required).to be false

    tree = guest.tree_connect("\\\\localhost\\#{share_name}")
    file = tree.open_file(filename: file_name)
    expect(file.read).to eq 'WORKGROUP\\mallory'

    raw_read = last_request(guest_dispatcher, RubySMB::SMB2::Packet::ReadRequest)
    expect(RubySMB::SMB2::SMB2Header.read(raw_read).flags.signed).to eq 0
    expect(session_for(guest_server_client).signing_required).to be false

    # A signature on a guest request can not be keyed, so it is not accepted
    # as ownership proof.
    signed = RubySMB::Signing.smb2_sign(RubySMB::SMB2::Packet::ReadRequest.new, Random.new.bytes(16))
    signed.smb2_header.session_id = guest.session_id
    response = inject(guest_server_dispatcher, signed.to_binary_s)
    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_INVALID_SIGNATURE
    expect(guest_server_dispatcher.events).to include(
      [:server, 'RubySMB::SMB2::Packet::ErrorPacket', 'STATUS_INVALID_SIGNATURE']
    )
  end

  it 'clears the old session and handle after logoff so a late replay fails' do
    alice, alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    file = tree.open_file(filename: file_name)
    file.read
    replayed_read = last_request(alice_dispatcher, RubySMB::SMB2::Packet::ReadRequest)
    handle = handles_for(alice_server_client, tree).values.first

    alice.logoff!

    expect(alice_server_client.session_table).to be_empty
    expect(handle.file).to be_closed

    response = inject(alice_server_dispatcher, replayed_read)
    expect(response.nt_status.to_nt_status).to eq WindowsError::NTStatus::STATUS_USER_SESSION_DELETED
    expect(alice_server_dispatcher.events).to include(
      [:server, 'RubySMB::SMB2::Packet::ErrorPacket', 'STATUS_USER_SESSION_DELETED']
    )
    expect(alice_server_client.session_table).to be_empty
  end

  it 'releases only the disconnecting connection handles on disconnect' do
    alice, _alice_dispatcher, alice_server_client, alice_server_dispatcher = connect('alice', 'Password123!')
    bob, _bob_dispatcher, bob_server_client, bob_server_dispatcher = connect('bob', 'Password456!')
    alice_tree = alice.tree_connect("\\\\localhost\\#{share_name}")
    bob_tree = bob.tree_connect("\\\\localhost\\#{share_name}")
    alice_tree.open_file(filename: file_name)
    bob_file = bob_tree.open_file(filename: file_name)
    bob_handles = handles_for(bob_server_client, bob_tree).dup
    alice_handle = handles_for(alice_server_client, alice_tree).values.first
    expect(alice_handle.file).to_not be_closed

    alice_server_client.disconnect!

    expect(alice_server_client.session_table).to be_empty
    expect(alice_handle.file).to be_closed
    expect(handles_for(bob_server_client, bob_tree)).to eq bob_handles
    expect(bob_file.read).to eq 'WORKGROUP\\bob'
  end
end
