# frozen_string_literal: true

require "net/ftp"
require "test/unit"

class PhaseTimeoutRegressionClock
  attr_reader :now, :waits

  def initialize(journal)
    @now = 0.0
    @journal = journal
    @waits = []
  end

  def advance(seconds)
    raise ArgumentError, "negative clock advancement" if seconds < 0

    @now += seconds.to_f
    @journal << [:clock, @now]
    @now
  end

  def wait_for(owner, budget, ready_after: nil)
    started_at = @now
    @waits << { owner: owner, budget: budget, started_at: started_at }
    @journal << [:wait, owner, budget, started_at]

    if budget.nil?
      advance(ready_after || 0.0)
      return true
    end

    if ready_after && ready_after < budget
      advance(ready_after)
      true
    else
      advance(budget)
      false
    end
  end
end

class PhaseTimeoutRecordingSocket
  attr_reader :role, :writes, :out_of_band, :reads, :close_sites
  attr_accessor :ready_after

  def initialize(role, clock, journal, script = [], remote_address: nil)
    @role = role
    @clock = clock
    @journal = journal
    @script = script.dup
    @remote_address = remote_address || Addrinfo.tcp("127.0.0.1", 21)
    @writes = []
    @out_of_band = []
    @reads = []
    @close_sites = []
    @shutdowns = []
    @closed = false
    @ready_after = nil
  end

  def to_io
    self
  end

  def closed?
    @closed
  end

  def wait_readable(budget)
    @clock.wait_for(@role, budget, ready_after: @ready_after)
  end

  def read_nonblock(maxlen, output = nil, exception: true)
    action = @script.first

    if action.is_a?(Array) && action[0] == :wait
      @script.shift
      @ready_after = action[1] || 0.0
      return :wait_readable
    end

    @ready_after = nil

    if action.nil? || action == :eof
      @script.shift if action == :eof
      raise EOFError, "end of file reached" if exception

      return nil
    end

    if action == :stall
      return :wait_readable unless exception

      raise Errno::EAGAIN
    end

    raise "unexpected script action: #{action.inspect}" unless action.is_a?(String)

    @script.shift
    @reads << action
    @journal << [:read, @role, action.bytesize]

    if output
      output.replace(action)
      return output
    end

    action
  end

  def write_nonblock(data, exception: true)
    @writes << data.dup
    @journal << [:write, @role, data]
    data.bytesize
  end

  def write(data)
    write_nonblock(data)
  end

  def send(data, flags)
    @out_of_band << [data.dup, flags]
    @journal << [:out_of_band, @role, data, flags]
    data.bytesize
  end

  def shutdown(how)
    @shutdowns << how
    @journal << [:shutdown, @role, how]
    0
  end

  def shutdowns
    @shutdowns.dup
  end

  def remote_address
    @remote_address
  end

  def local_address
    Addrinfo.tcp("127.0.0.1", 2120)
  end

  def close
    return if @closed

    sites = (caller_locations(1, 24) || [])
      .select { |location| location.path && location.path.end_with?("net/ftp.rb") }
      .map(&:base_label)
    @close_sites << sites
    @closed = true
    @journal << [:close, @role, sites]
  end
end

class PhaseTimeoutRecordingServer
  attr_reader :port, :accepts, :close_sites, :shutdowns, :drain_reads

  def initialize(clock, journal, budget, connection, ready_after: nil, port: 31337)
    @clock = clock
    @journal = journal
    @budget = budget
    @connection = connection
    @ready_after = ready_after
    @port = port
    @accepts = 0
    @close_sites = []
    @shutdowns = []
    @drain_reads = 0
    @closed = false
  end

  def local_address
    Addrinfo.tcp("127.0.0.1", @port)
  end

  def closed?
    @closed
  end

  def accept
    @accepts += 1
    @journal << [:accept, "data-listener"]
    ready = @clock.wait_for("data-listener", @budget, ready_after: @ready_after)

    unless ready
      error = Net::OpenTimeout.new("data handshake budget elapsed")
      @journal << [:timeout, "data-listener", @clock.now]
      raise error
    end

    @connection
  end

  def shutdown(how)
    @shutdowns << how
    @journal << [:shutdown, "data-listener", how]
    0
  end

  def read(length = nil, buffer = nil)
    @drain_reads += 1
    @journal << [:server_drain, "data-listener"]
    nil
  end

  def close
    return if @closed

    sites = (caller_locations(1, 24) || [])
      .select { |location| location.path && location.path.end_with?("net/ftp.rb") }
      .map(&:base_label)
    @close_sites << sites
    @closed = true
    @journal << [:close, "data-listener", sites]
  end
end

class FTPPhaseTimeoutRegressionTest < Test::Unit::TestCase
  CONTROL_BUDGET = 7.0
  DATA_BUDGET = 11.0
  READ_BUDGET = 13.0
  FILE_BODY = "0123456789abcdef".b.freeze
  HALF_BODY = FILE_BODY.byteslice(0, 8).b

  def setup
    @journal = []
    @clock = PhaseTimeoutRegressionClock.new(@journal)
  end

  def test_control_handshake_budget_expiry_is_locatable_without_commands
    journal = @journal
    control = PhaseTimeoutRecordingSocket.new("control", @clock, journal, [:stall])
    ftp = Net::FTP.new(nil, passive: false, read_timeout: CONTROL_BUDGET)
    ftp.define_singleton_method(:open_socket) do |host, port|
      journal << [:open_socket, host, port]
      control
    end

    error = assert_raise(Net::ReadTimeout) do
      ftp.connect("ftp.example", 21)
    end

    assert_instance_of(Net::ReadTimeout, error)
    assert_nil(ftp.last_response)
    assert_equal([:open_socket, "ftp.example", 21], @journal.first)
    assert_equal([], control.writes)
    assert_equal([], control.out_of_band)
    assert_equal(1, @clock.waits.size)
    assert_equal("control", @clock.waits[0][:owner])
    assert_equal(CONTROL_BUDGET, @clock.waits[0][:budget])
    assert_equal(0.0, @clock.waits[0][:started_at])
    assert_equal(CONTROL_BUDGET, @clock.now)
    assert_equal([], control.close_sites)
    assert_false(control.closed?)
    assert_false(ftp.closed?)

    assert_raise(Net::ReadTimeout) { ftp.noop }
    assert_equal(["NOOP\r\n"], control.writes)
    assert_equal(CONTROL_BUDGET * 2, @clock.now)

    ftp.close
    assert_true(control.closed?)
    assert_equal(1, control.close_sites.size)
    assert_includes(control.close_sites.last, "close")
    assert_equal([Socket::SHUT_WR], control.shutdowns)
  ensure
    ftp&.close
  end

  def test_data_handshake_budget_expiry_after_preliminary_reply
    ftp, control, data, server, port_command = build_transfer_session(
      data_script: [],
      server_ready_after: nil,
      final_response: "225 ABOR successful\r\n"
    )

    delivered = String.new
    error = assert_raise(Net::OpenTimeout) do
      ftp.retrbinary("RETR half.bin", 4) { |chunk| delivered << chunk }
    end

    assert_instance_of(Net::OpenTimeout, error)
    assert_equal("", delivered)
    assert_equal("150 Opening data connection\n", ftp.last_response)
    assert_equal(logged_in_commands + [port_command, "RETR half.bin\r\n"], control.writes)
    assert_equal([], control.out_of_band)

    data_wait = @clock.waits.find { |wait| wait[:owner] == "data-listener" }
    assert_not_nil(data_wait)
    assert_equal(DATA_BUDGET, data_wait[:budget])
    assert_equal(1.0, data_wait[:started_at])
    assert_equal(1.0 + DATA_BUDGET, @clock.now)

    assert_equal(1, server.accepts)
    assert_equal(1, server.close_sites.size)
    assert_includes(server.close_sites.last, "transfercmd")
    assert_equal([], data.close_sites)
    assert_false(control.closed?)

    response = ftp.abort
    assert_equal("225 ABOR successful\n", response)
    assert_equal([["ABOR\r\n", Socket::MSG_OOB]], control.out_of_band)

    ftp.close
    assert_true(control.closed?)
    assert_includes(control.close_sites.last, "close")
  ensure
    ftp&.close
  end

  def test_transfer_read_budget_expiry_after_half_file
    ftp, control, data, server, port_command = build_transfer_session(
      data_script: [HALF_BODY, :stall],
      server_ready_after: 2.0,
      final_response: "426 Connection closed; transfer aborted\r\n"
    )

    delivered = String.new
    error = assert_raise(Net::ReadTimeout) do
      ftp.retrbinary("RETR half.bin", 4) { |chunk| delivered << chunk }
    end

    assert_instance_of(Net::ReadTimeout, error)
    assert_equal(HALF_BODY, delivered)
    assert_equal(8, delivered.bytesize)
    assert_equal(16, FILE_BODY.bytesize)
    assert_equal(logged_in_commands + [port_command, "RETR half.bin\r\n"], control.writes)
    assert_equal("150 Opening data connection\n", ftp.last_response)
    assert_equal([], control.out_of_band)

    data_wait = @clock.waits.find { |wait| wait[:owner] == "data" }
    assert_not_nil(data_wait)
    assert_equal(READ_BUDGET, data_wait[:budget])
    assert_equal(3.0, data_wait[:started_at])
    assert_equal(3.0 + READ_BUDGET, @clock.now)

    assert_equal(1, server.close_sites.size)
    assert_includes(server.close_sites.last, "transfercmd")
    assert_equal(1, data.close_sites.size)
    assert_includes(data.close_sites.last, "retrbinary")

    server_close_at = @journal.rindex { |event| event[0] == :close && event[1] == "data-listener" }
    data_read_at = @journal.index { |event| event[0] == :read && event[1] == "data" }
    data_close_at = @journal.rindex { |event| event[0] == :close && event[1] == "data" }
    assert_not_nil(server_close_at)
    assert_not_nil(data_read_at)
    assert_not_nil(data_close_at)
    assert_operator(server_close_at, :<, data_read_at)
    assert_operator(data_read_at, :<, data_close_at)

    response = ftp.abort
    assert_equal("426 Connection closed; transfer aborted\n", response)
    assert_equal([["ABOR\r\n", Socket::MSG_OOB]], control.out_of_band)

    ftp.close
    assert_true(control.closed?)
  ensure
    ftp&.close
  end

  def test_success_crosses_control_data_and_read_boundaries
    ftp, control, data, server, port_command = build_transfer_session(
      data_script: [[:wait, 1.0], FILE_BODY, :eof],
      server_ready_after: 2.0,
      final_response: "226 Transfer complete\r\n",
      follow_up_response: "200 NOOP ok\r\n"
    )

    delivered = String.new
    ftp.retrbinary("RETR full.bin", 4) do |chunk|
      delivered << chunk
    end

    assert_equal(FILE_BODY, delivered)
    assert_equal(16, delivered.bytesize)
    assert_equal(logged_in_commands + [port_command, "RETR full.bin\r\n"], control.writes)
    assert_equal("226 Transfer complete\n", ftp.last_response)

    control_wait = @clock.waits.find { |wait| wait[:owner] == "control" }
    listener_wait = @clock.waits.find { |wait| wait[:owner] == "data-listener" }
    data_wait = @clock.waits.find { |wait| wait[:owner] == "data" }

    assert_equal(CONTROL_BUDGET, control_wait[:budget])
    assert_equal(0.0, control_wait[:started_at])
    assert_equal(DATA_BUDGET, listener_wait[:budget])
    assert_equal(1.0, listener_wait[:started_at])
    assert_equal(READ_BUDGET, data_wait[:budget])
    assert_equal(3.0, data_wait[:started_at])
    assert_equal(4.0, @clock.now)

    assert_equal(1, server.close_sites.size)
    assert_includes(server.close_sites.last, "transfercmd")
    assert_equal([Socket::SHUT_WR], data.shutdowns)
    assert_equal(1, data.close_sites.size)
    assert_includes(data.close_sites.last, "retrbinary")

    assert_nil(ftp.noop)
    assert_equal("200 NOOP ok\n", ftp.last_response)
    assert_equal(logged_in_commands + [port_command, "RETR full.bin\r\n", "NOOP\r\n"], control.writes)

    ftp.close
    assert_true(control.closed?)
    assert_includes(control.close_sites.last, "close")
  ensure
    ftp&.close
  end

  private

  def logged_in_commands
    [
      "USER anonymous\r\n",
      "PASS anonymous@\r\n",
      "TYPE I\r\n"
    ]
  end

  def build_transfer_session(data_script:, server_ready_after:, final_response:, follow_up_response: nil)
    journal = @journal
    control_script = [
      [:wait, 1.0],
      "220 FTP recording ready\r\n",
      "331 Please specify the password\r\n",
      "230 Login successful\r\n",
      "200 Type set to I\r\n",
      "200 PORT command successful\r\n",
      "150 Opening data connection\r\n",
      final_response
    ]
    control_script << follow_up_response if follow_up_response

    control = PhaseTimeoutRecordingSocket.new("control", @clock, @journal, control_script)
    data = PhaseTimeoutRecordingSocket.new("data", @clock, @journal, data_script)
    server = PhaseTimeoutRecordingServer.new(
      @clock,
      @journal,
      DATA_BUDGET,
      data,
      ready_after: server_ready_after
    )

    ftp = Net::FTP.new(nil, passive: false, read_timeout: CONTROL_BUDGET)
    ftp.define_singleton_method(:open_socket) do |host, port|
      journal << [:open_socket, host, port]
      control
    end
    ftp.connect("127.0.0.1", 21)
    ftp.login
    ftp.read_timeout = READ_BUDGET

    ftp.define_singleton_method(:makeport) { server }

    high_port, low_port = server.port.divmod(256)
    port_command = "PORT 127,0,0,1,#{high_port},#{low_port}\r\n"

    [ftp, control, data, server, port_command]
  end
end
