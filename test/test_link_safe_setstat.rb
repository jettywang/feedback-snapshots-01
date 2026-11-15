require "common"

# A purely in-memory SFTP server (no sockets, no threads). It models a tiny
# file system with symbolic links and records every request the client puts on
# the wire, so tests can prove the client only sends link-safe requests and
# never falls back to a link-following one when the target changes underneath
# it or an extension fails.
class InMemorySFTPChannel
  include Net::SFTP::Constants::PacketTypes
  include Net::SFTP::Constants::StatusCodes
  include Net::SFTP::Constants::OpenFlags

  Node = Struct.new(:kind, :permissions, :target)

  attr_reader :requests

  def initialize(version, extensions = {})
    @version = version
    @extensions = extensions
    @nodes = {}
    @handles = {}
    @next_handle = 0
    @outbound = +""
    @data_callbacks = []
    @process_callbacks = []
    @requests = []
    @fail_extended_with = nil
  end

  def filesystem
    @nodes
  end

  def add_file(path, permissions)
    @nodes[path] = Node.new(:file, permissions, nil)
  end

  def add_symlink(path, target, permissions)
    @nodes[path] = Node.new(:symlink, permissions, target)
  end

  def retarget_symlink(path, new_target)
    raise "not a symlink: #{path}" unless @nodes[path].kind == :symlink
    @nodes[path].target = new_target
  end

  # Makes the server reject every FXP_EXTENDED request with the given status,
  # modeling an advertised-but-disabled extension.
  def fail_extended_with!(code, message)
    @fail_extended_with = [code, message]
  end

  def on_data(&block)
    @data_callbacks << block
  end

  def on_process(&block)
    @process_callbacks << block
  end

  def on_extended_data(&block); end
  def on_close(&block); end

  def subsystem(_name, &block)
    block.call(self, true)
  end

  # Client -> server bytes stay buffered until the event loop runs.
  def send_data(data)
    @outbound << data
  end

  # One event-loop iteration: let the client poll its input, then drain and
  # answer every complete request frame it has enqueued.
  def process
    @process_callbacks.each { |callback| callback.call(self) }

    buffer = Net::SSH::Buffer.new(@outbound)
    @outbound = +""
    until buffer.eof?
      length = buffer.read_long
      raise "truncated frame in test server" if buffer.available < length
      handle_packet(Net::SFTP::Packet.new(buffer.read(length)))
    end
  end

  def request_types
    @requests.reject { |request| request[:type] == FXP_INIT }.map do |request|
      packet_name(request[:type])
    end
  end

  # Returns a fresh reader positioned after the type byte and request-id long,
  # which is the payload start for every non-INIT packet.
  def payload_of(request)
    buffer = Net::SSH::Buffer.new(request[:packet].content)
    buffer.read_byte
    buffer.read_long
    buffer
  end

  private

    def handle_packet(packet)
      if packet.type == FXP_INIT
        @requests << { :type => FXP_INIT, :id => nil, :packet => packet }
        @negotiated_version = [@version, packet.read_long].min
        extension_args = @extensions.flat_map { |name, data| [:string, name, :string, data] }
        send_reply(FXP_VERSION, :long, @negotiated_version, *extension_args)
        return
      end

      id = packet.read_long
      @requests << { :type => packet.type, :id => id, :packet => packet }

      case packet.type
      when FXP_LSTAT
        node = @nodes[packet.read_string]
        node ? reply(FXP_ATTRS, id, :raw, permissions_attributes(node).to_s) : status(id, FX_NO_SUCH_FILE)
      when FXP_STAT
        node = resolve(packet.read_string)
        node ? reply(FXP_ATTRS, id, :raw, permissions_attributes(node).to_s) : status(id, FX_NO_SUCH_FILE)
      when FXP_SETSTAT
        node = @nodes[packet.read_string]
        attrs = parse_attributes(packet)
        node ? (apply(node, attrs); status(id, FX_OK)) : status(id, FX_NO_SUCH_FILE)
      when FXP_FSETSTAT
        node = @handles[packet.read_string]
        attrs = parse_attributes(packet)
        node ? (apply(node, attrs); status(id, FX_OK)) : status(id, FX_INVALID_HANDLE)
      when FXP_OPEN
        path = packet.read_string
        packet.read_long if @version >= 5 # desired-access mask
        flags = packet.read_long
        parse_attributes(packet)
        node = @nodes[path]
        return status(id, FX_NO_SUCH_FILE) unless node
        node = resolve(path) || node if node.kind == :symlink && (flags & FV6::NOFOLLOW).zero?
        handle = "handle-#{@next_handle += 1}"
        @handles[handle] = node
        reply(FXP_HANDLE, id, :string, handle)
      when FXP_CLOSE
        @handles.delete(packet.read_string)
        status(id, FX_OK)
      when FXP_EXTENDED
        name = packet.read_string
        if name == Net::SFTP::Constants::Extensions::LSETSTAT
          return status(id, @fail_extended_with[0], @fail_extended_with[1]) if @fail_extended_with
          node = @nodes[packet.read_string]
          attrs = parse_attributes(packet)
          node ? (apply(node, attrs); status(id, FX_OK)) : status(id, FX_NO_SUCH_FILE)
        else
          status(id, FX_OP_UNSUPPORTED, "unknown extension #{name}")
        end
      else
        status(id, FX_BAD_MESSAGE, "unhandled packet type #{packet.type}")
      end
    end

    def resolve(path)
      node = @nodes[path]
      node && node.kind == :symlink ? @nodes[node.target] : node
    end

    def apply(node, attrs)
      node.permissions = attrs.permissions if attrs.attributes.key?(:permissions)
    end

    def permissions_attributes(node)
      Net::SSH::Buffer.from(:long, Net::SFTP::Protocol::V01::Attributes::F_PERMISSIONS,
        :long, node.permissions)
    end

    def parse_attributes(packet)
      attribute_factory.from_buffer(packet)
    end

    def attribute_factory
      @attribute_factory ||=
        if negotiated_version >= 6
          Net::SFTP::Protocol::V06::Attributes
        elsif negotiated_version >= 4
          Net::SFTP::Protocol::V04::Attributes
        else
          Net::SFTP::Protocol::V01::Attributes
        end
    end

    def negotiated_version
      @negotiated_version || @version
    end
    def reply(type, id, *args)
      send_reply(type, :long, id, *args)
    end

    # Frames a server message. Regular replies begin with a request id; the
    # FXP_VERSION handshake is the one exception and uses this directly.
    def send_reply(type, *args)
      payload = Net::SSH::Buffer.from(:byte, type, *args).to_s
      frame = Net::SSH::Buffer.from(:long, payload.length, :raw, payload).to_s
      @data_callbacks.each { |callback| callback.call(self, frame) }
    end

    def status(id, code, message = "")
      reply(FXP_STATUS, id, :long, code, :string, message, :string, "en")
    end

    def packet_name(type)
      @names ||= Net::SFTP::Constants::PacketTypes.constants.each_with_object({}) do |name, map|
        map[Net::SFTP::Constants::PacketTypes.const_get(name)] = name.to_s
      end
      @names[type]
    end
end

# Minimal Net::SSH connection surface: the SFTP session only needs a logger,
# a channel opener, and an event loop that pumps the in-memory channel.
class InMemorySSHConnection
  attr_reader :channel

  def initialize(channel)
    @channel = channel
    @pending_confirm = nil
  end

  def logger
    nil
  end

  # A real channel is confirmed asynchronously, after Net::SFTP::Session has
  # stored it. Queue the confirmation so it runs on the first event-loop pass.
  def open_channel(&block)
    @pending_confirm = block
    @channel
  end

  def loop(_wait = nil)
    while yield(self)
      @channel.process
      if @pending_confirm
        block = @pending_confirm
        @pending_confirm = nil
        block.call(@channel)
      end
    end
    @channel.process
  end
end

class LinkSafeSetstatTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::PacketTypes
  include Net::SFTP::Constants::OpenFlags

  LINK = "/link"
  TARGET_A = "/target-a"
  TARGET_B = "/target-b"

  def test_lsetstat_via_extension_changes_only_the_link_and_sends_no_follow_request
    channel = build_channel(3, true)
    channel.add_file(TARGET_A, 0644)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel)

    sftp.lsetstat!(LINK, :permissions => 0700)

    assert_equal 0700, channel.filesystem[LINK].permissions
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
    assert_equal ["FXP_EXTENDED"], channel.request_types
    assert_equal Net::SFTP::Constants::Extensions::LSETSTAT,
      channel.payload_of(channel.requests.last).read_string
  end

  def test_target_swap_after_lstat_still_only_modifies_the_link
    channel = build_channel(3, true)
    channel.add_file(TARGET_A, 0644)
    channel.add_file(TARGET_B, 0600)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel)

    assert_equal 0777, sftp.lstat!(LINK).permissions
    channel.retarget_symlink(LINK, TARGET_B)
    sftp.lsetstat!(LINK, :permissions => 0755)

    assert_equal 0755, channel.filesystem[LINK].permissions
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
    assert_equal 0600, channel.filesystem[TARGET_B].permissions
    assert_equal ["FXP_LSTAT", "FXP_EXTENDED"], channel.request_types
    refute_includes channel.request_types, "FXP_SETSTAT"
  end

  def test_extension_failure_keeps_reason_and_sends_no_setstat_fallback
    channel = build_channel(3, true)
    channel.fail_extended_with!(8, "extension disabled")
    channel.add_file(TARGET_A, 0644)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel)

    response = sftp.lsetstat(LINK, :permissions => 0700).wait.response

    refute response.ok?
    assert_equal 8, response.code
    assert_equal "extension disabled", response.message
    assert_equal ["FXP_EXTENDED"], channel.request_types
    refute_includes channel.request_types, "FXP_SETSTAT"
    assert_equal 0777, channel.filesystem[LINK].permissions
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
  end

  def test_missing_capability_refuses_before_any_packet_leaves_the_client
    channel = build_channel(3, false)
    channel.add_file(TARGET_A, 0644)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel, 3)

    assert_raises(Net::SFTP::UnsupportedOperation) do
      sftp.lsetstat!(LINK, :permissions => 0700)
    end

    assert_equal [], channel.request_types
    assert_equal 0777, channel.filesystem[LINK].permissions
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
  end

  def test_v6_native_lsetstat_uses_setstat_without_touching_target
    channel = build_channel(6, false)
    channel.add_file(TARGET_A, 0644)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel)

    sftp.lsetstat!(LINK, :permissions => 0750)

    assert_equal 0750, channel.filesystem[LINK].permissions
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
    assert_equal ["FXP_SETSTAT"], channel.request_types
  end

  def test_v6_nofollow_handle_changes_the_link_itself
    channel = build_channel(6, false)
    channel.add_file(TARGET_A, 0644)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel)

    handle = sftp.open!(LINK, "r", {}, :no_follow => true)
    sftp.flsetstat!(handle, :permissions => 0750)
    sftp.close!(handle)

    assert_equal 0750, channel.filesystem[LINK].permissions
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
    assert_equal ["FXP_OPEN", "FXP_FSETSTAT", "FXP_CLOSE"], channel.request_types
    open_payload = channel.payload_of(channel.requests.first)
    open_payload.read_string # path
    open_payload.read_long   # desired access
    flags = open_payload.read_long
    assert(flags & FV6::NOFOLLOW != 0, "expected NOFOLLOW flag in #{flags.inspect}")
  end

  def test_flsetstat_refuses_a_plain_handle_even_after_target_swap
    channel = build_channel(6, false)
    channel.add_file(TARGET_A, 0644)
    channel.add_file(TARGET_B, 0600)
    channel.add_symlink(LINK, TARGET_A, 0777)
    sftp = connect(channel)

    plain_handle = sftp.open!(LINK, "r", {})
    channel.retarget_symlink(LINK, TARGET_B)

    assert_raises(Net::SFTP::UnknownHandle) do
      sftp.flsetstat(plain_handle, :permissions => 0750)
    end

    assert_equal ["FXP_OPEN"], channel.request_types
    assert_equal 0644, channel.filesystem[TARGET_A].permissions
    assert_equal 0600, channel.filesystem[TARGET_B].permissions
  end

  private

    def build_channel(version, with_extension)
      extensions = with_extension ? { Net::SFTP::Constants::Extensions::LSETSTAT => "1" } : {}
      InMemorySFTPChannel.new(version, extensions)
    end

    def connect(channel, offered_version = nil)
      sftp = Net::SFTP::Session.new(InMemorySSHConnection.new(channel), offered_version)
      sftp.loop { sftp.opening? }
      sftp
    end
end
