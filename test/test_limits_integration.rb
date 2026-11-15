require 'common'
require 'tmpdir'
require 'timeout'
require 'logger'

# An in-memory SFTP server: every packet the client sends through the fake
# channel is parsed, answered immediately and recorded so a test can assert on
# the actual packet lengths and the peak number of requests in flight. No real
# socket or SSH transport is involved.
class InMemorySFTPServer
  include Net::SFTP::Constants::PacketTypes

  attr_reader :sent, :peak_in_flight, :written

  def initialize(limits: nil, read_data: nil)
    @limits = limits
    @read_data = read_data
    @sent = []
    @written = {}
    @in_flight = 0
    @peak_in_flight = 0
  end

  # Called by the fake channel with one framed SFTP packet (the exact bytes
  # Net::SFTP::Session#send_packet handed to the channel). Returns a pair:
  # an immediate reply (the version handshake, which has no request id) and a
  # deferred reply held until the channel's next drain, so requests sent while
  # a batch is processed stay in flight and #peak_in_flight stays meaningful.
  def receive(message)
    outer = Net::SSH::Buffer.new(message)
    length = outer.read_long
    packet = Net::SFTP::Packet.new(outer.read(length))
    type = packet.type

    return [answer_init, []] if type == FXP_INIT

    id = packet.read_long

    @in_flight += 1
    @peak_in_flight = [@peak_in_flight, @in_flight].max
    # Keep the raw inner packet: the parsed buffer's read position is consumed
    # by the server below, so assertions re-parse a fresh packet.
    @sent << { :type => type, :wire_length => message.bytesize, :inner_length => length, :raw => packet.to_s }

    [nil, [answer(type, id, packet)]]
  end

  # Settles the in-flight count once a deferred batch has been delivered.
  def settle(count)
    @in_flight -= count
  end

  private

  def answer_init
    version = 3
    if @limits
      frame(FXP_VERSION, :long, version,
            :string, Net::SFTP::Protocol::Limits::EXTENSION_NAME, :string, "1")
    else
      frame(FXP_VERSION, :long, version)
    end
  end

  def answer(type, id, packet)
    case type
    when FXP_OPEN then status_or_handle(id, "handle")
    when FXP_OPENDIR then status_or_handle(id, "dirhandle")
    when FXP_CLOSE then status(id)
    when FXP_FSTAT then fstat(id)
    when FXP_WRITE then write(packet, id)
    when FXP_READ then read(packet, id)
    when FXP_READDIR then status(id, Net::SFTP::Constants::StatusCodes::FX_EOF)
    when FXP_MKDIR, FXP_SETSTAT, FXP_FSETSTAT, FXP_REMOVE, FXP_RMDIR then status(id)
    when FXP_EXTENDED then extended(packet, id)
    else raise "unexpected packet type #{type}"
    end
  end

  def write(packet, id)
    packet.read_string # handle
    offset = packet.read_int64
    data = packet.read_string
    (@written[offset] ||= +"") << data
    status(id)
  end

  def read(packet, id)
    packet.read_string # handle
    offset = packet.read_int64
    length = packet.read_long
    data = (@read_data || +"").byteslice(offset, length) || +""
    if data.empty?
      status(id, Net::SFTP::Constants::StatusCodes::FX_EOF)
    else
      frame(FXP_DATA, :long, id, :string, data)
    end
  end

  def fstat(id)
    # Empty attributes (flags word 0); downloads only need the size to decide
    # whether to fstat, and StringIO sinks skip local permission work.
    frame(FXP_ATTRS, :long, id, :long, 0)
  end

  def extended(packet, id)
    name = packet.read_string
    if name == Net::SFTP::Protocol::Limits::EXTENSION_NAME && @limits
      values = Array(@limits).dup
      values << 0 while values.length < 4
      frame(FXP_EXTENDED_REPLY, :long, id, :long, values[0], :long, values[1],
            :long, values[2], :long, values[3])
    else
      status(id, Net::SFTP::Constants::StatusCodes::FX_OP_UNSUPPORTED)
    end
  end

  def status_or_handle(id, handle)
    frame(FXP_HANDLE, :long, id, :string, handle)
  end

  def status(id, code = Net::SFTP::Constants::StatusCodes::FX_OK)
    frame(FXP_STATUS, :long, id, :long, code)
  end

  def frame(type, *args)
    data = Net::SSH::Buffer.from(:byte, type, *args).to_s
    Net::SSH::Buffer.from(:long, data.length, :raw, data).to_s
  end
end

class FakeChannel
  attr_reader :server

  def initialize(server)
    @server = server
    @pending = []
    @newly_sent = []
    @immediate = []
    @on_data = []
    @on_process = nil
    @ssh_confirm = nil
  end

  # Real Net::SSH invokes the channel-confirmation callback from the event
  # loop, after Session#connect has stored the channel; hold it until the
  # next drain to mimic that ordering.
  attr_writer :ssh_confirm

  # Requests are held until a later drain, mimicking a network round trip.
  # Anything sent while replies are being delivered lands in a separate
  # generation so it cannot be answered within the same iteration. The
  # version handshake has no request id and is answered immediately.
  def send_data(message)
    immediate, deferred = @server.receive(message)
    @immediate << immediate if immediate
    @newly_sent.concat(deferred)
  end

  def on_data(&block); @on_data << block; end
  def on_extended_data(&block); end
  def on_process(&block); @on_process = block; end
  def on_close(&block); @on_close = block; end
  def subsystem(name, &block); block.call(self, true) if block; end
  def close; end

  # One event-loop iteration. Every reply queued in the previous generation is
  # delivered, the way a real SSH loop processes all data that has arrived;
  # requests those callbacks send join the next generation and are answered on
  # a later iteration. The generation boundary is what keeps requests in
  # flight, so #peak_in_flight reflects the real pipeline width.
  def drain(session)
    if @ssh_confirm
      confirm = @ssh_confirm
      @ssh_confirm = nil
      confirm.call(self)
    end

    immediate = @immediate
    @immediate = []
    immediate.each { |reply| deliver(reply) }

    batch = @pending
    @pending = []
    batch.each { |reply| deliver(reply) }
    @server.settle(batch.length)

    @pending.concat(@newly_sent)
    @newly_sent = []

    @on_process.call(self) if @on_process
  end

  private

  def deliver(reply)
    return unless reply

    @on_data.each { |callback| callback.call(self, reply) }
  end
end

class FakeSSH
  attr_reader :channel, :logger

  def initialize(server)
    @channel = FakeChannel.new(server)
    @logger = Logger.new(IO::NULL)
  end

  # Real Net::SSH invokes the confirmation callback from the event loop, after
  # Session#connect has stored the channel; the channel fires it on the next
  # drain to mimic that ordering.
  def open_channel(&block)
    @channel.ssh_confirm = block
    @channel
  end

  def loop
    while yield
      @channel.drain(self)
    end
  end
end

class LimitsIntegrationTest < Net::SFTP::TestCase
  Limits = Net::SFTP::Protocol::Limits

  WRITE_TYPE = Net::SFTP::Constants::PacketTypes::FXP_WRITE
  READ_TYPE  = Net::SFTP::Constants::PacketTypes::FXP_READ

  def connect(limits: nil, read_data: nil)
    @server = InMemorySFTPServer.new(:limits => limits, :read_data => read_data)
    @ssh = FakeSSH.new(@server)
    @sftp = Net::SFTP::Session.new(@ssh, 3)
    pump_while { @sftp.opening? }
    @sftp
  end

  # Drives the in-memory event loop for as long as the block still says the
  # operation is pending. Always pumps at least once so a connection whose
  # confirmation is queued still gets its opening callbacks fired.
  def pump_while
    Timeout.timeout(10) do
      guard = 0
      loop do
        raise "event loop stopped making progress" if (guard += 1) > 10_000
        @ssh.channel.drain(@sftp)
        break unless yield
      end
    end
  end

  def upload!(sftp, size, options = {})
    io = StringIO.new("x" * size)
    upload = sftp.upload(io, "/remote", options.merge(:name => "<memory>"))
    pump_while { upload.active? }
    io
  end

  def download!(sftp, data, options = {})
    sink = StringIO.new
    download = sftp.download("/remote", sink, options)
    pump_while { download.active? }
    sink.string
  end

  def write_packets
    @server.sent.select { |item| item[:type] == WRITE_TYPE }
  end

  def read_packets
    @server.sent.select { |item| item[:type] == READ_TYPE }
  end

  def joined_written_content
    @server.written.keys.sort.each_with_object(+"") do |offset, out|
      out << @server.written[offset]
    end
  end

  def test_no_extension_keeps_client_default_chunk_and_concurrency
    sftp = connect
    # Larger than requests * read_size so the full 64-request window opens.
    size = 32_000 * 70

    upload!(sftp, size)

    assert_equal 32_000, write_packets.map { |item| data_length(item) }.max
    assert_equal 64, @server.peak_in_flight
    assert_equal "x" * size, joined_written_content
  end

  def test_smaller_server_packet_limit_shrinks_every_write_packet
    sftp = connect(:limits => [2_000, 0, 0, 0])
    size = 10_000

    upload!(sftp, size)

    chunks = write_packets
    refute_empty chunks
    assert chunks.all? { |item| item[:wire_length] <= 2_000 }
    # The budget is the packet limit minus the real framing and WRITE overhead.
    expected_payload = 2_000 - Limits::WRITE_OVERHEAD - "handle".bytesize
    assert_equal expected_payload, chunks.map { |item| data_length(item) }.max
    assert_equal "x" * size, joined_written_content
  end

  def test_smaller_server_write_length_shrinks_chunks_but_not_concurrency
    sftp = connect(:limits => [0, 0, 4_000, 0])
    # Enough 4_000-byte chunks to fill the full 64-request window.
    size = 4_000 * 70

    upload!(sftp, size)

    assert_equal 4_000, write_packets.map { |item| data_length(item) }.max
    assert_equal 64, @server.peak_in_flight
    assert_equal "x" * size, joined_written_content
  end

  def test_larger_server_limits_do_not_enlarge_client_defaults
    huge = 1 << 20
    sftp = connect(:limits => [huge, huge, huge, huge])
    size = 32_000 * 70

    upload!(sftp, size)

    assert_equal 32_000, write_packets.map { |item| data_length(item) }.max
    assert_equal 64, @server.peak_in_flight
    assert_equal "x" * size, joined_written_content
  end

  def test_malicious_huge_values_are_ignored
    sftp = connect(:limits => [1 << 40, 1 << 40, 1 << 40, 1 << 40])
    size = 32_000 * 70

    upload!(sftp, size)

    assert_equal 32_000, write_packets.map { |item| data_length(item) }.max
    assert_equal "x" * size, joined_written_content
  end

  def test_contradictory_limits_use_the_smallest_effective_budget
    # The packet budget works out to fewer payload bytes than the write-length
    # field (120), so it must win; the open-handle field separately caps how
    # many requests may be outstanding.
    packet_payload = 40
    packet_limit = Limits::WRITE_OVERHEAD + "handle".bytesize + packet_payload
    sftp = connect(:limits => [packet_limit, 0, 120, 4])
    size = packet_payload * 30

    upload!(sftp, size)

    assert_equal packet_payload, write_packets.map { |item| data_length(item) }.max
    assert_equal 4, @server.peak_in_flight
    assert_equal "x" * size, joined_written_content
  end

  def test_write_length_field_wins_when_it_is_the_tightest_budget
    # A generous packet limit leaves write-length (120) as the binding cap.
    packet_limit = Limits::WRITE_OVERHEAD + "handle".bytesize + 500
    sftp = connect(:limits => [packet_limit, 0, 120, 0])
    size = 120 * 70

    upload!(sftp, size)

    assert_equal 120, write_packets.map { |item| data_length(item) }.max
    assert_equal 64, @server.peak_in_flight
    assert_equal "x" * size, joined_written_content
  end

  def test_tiny_packet_limit_keeps_progressing_one_byte_at_a_time
    sftp = connect(:limits => [Limits::PACKET_FRAMING_BYTES + 1, 0, 0, 0])
    size = 20

    upload!(sftp, size)

    assert_equal 1, write_packets.map { |item| data_length(item) }.max
    assert_equal "x" * size, joined_written_content
  end

  def test_download_honors_read_packet_budget_and_preserves_content
    packet_limit = Limits::READ_REQUEST_OVERHEAD + "handle".bytesize + 777
    data = "y" * 5_000
    sftp = connect(:limits => [packet_limit, 0, 0, 0], :read_data => data)

    result = download!(sftp, data)

    refute_empty read_packets
    assert read_packets.all? { |item| item[:wire_length] <= packet_limit }
    assert_equal 777, read_packets.map { |item| requested_length(item) }.max
    assert_equal data, result
  end

  def test_download_read_length_field_caps_requests
    data = "z" * 3_000
    sftp = connect(:limits => [0, 250, 0, 0], :read_data => data)

    result = download!(sftp, data)

    assert_equal 250, read_packets.map { |item| requested_length(item) }.max
    assert_equal data, result
  end

  def test_download_without_extension_uses_default_read_size
    data = "w" * 40_000
    sftp = connect(:read_data => data)

    result = download!(sftp, data)

    assert_equal 32_000, read_packets.map { |item| requested_length(item) }.max
    assert_equal data, result
  end

  def test_zero_limits_are_treated_as_no_limit
    sftp = connect(:limits => [0, 0, 0, 0])
    size = 70_000

    upload!(sftp, size)

    assert_equal 32_000, write_packets.map { |item| data_length(item) }.max
    assert_equal "x" * size, joined_written_content
  end

  def test_recursive_upload_never_opens_more_than_the_negotiated_handle_cap
    Dir.mktmpdir do |dir|
      8.times { |i| File.write(File.join(dir, "file#{i}"), "x" * 1_000) }
      sftp = connect(:limits => [0, 0, 0, 3])

      upload = sftp.upload(dir, "/remote")
      pump_while { upload.active? }

      opens = @server.sent.count { |item| item[:type] == FXP_OPEN }
      assert_equal 8, opens
      assert_equal 3, @server.peak_in_flight
    end
  end

  def test_download_read_window_is_capped_by_negotiated_open_handles
    # Many chunks so the window can grow, but the server only allows two
    # outstanding requests on the single open handle.
    data = "q" * (32_000 * 10)
    sftp = connect(:limits => [0, 0, 0, 2], :read_data => data)

    result = download!(sftp, data)

    assert_equal 2, @server.peak_in_flight
    assert_equal data, result
  end

  private

  def data_length(item)
    packet = Net::SFTP::Packet.new(item[:raw])
    packet.read_long # request id
    packet.read_string # handle
    packet.read_int64 # offset
    packet.read_string.bytesize
  end

  def requested_length(item)
    packet = Net::SFTP::Packet.new(item[:raw])
    packet.read_long # request id
    packet.read_string # handle
    packet.read_int64 # offset
    packet.read_long
  end
end
