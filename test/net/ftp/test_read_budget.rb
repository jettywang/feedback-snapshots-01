# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "tmpdir"

#
# Exercises the optional Net::FTP read budget on block (binary) and text
# (line) retrieval.
#
# The sandbox forbids binding TCP ports, so no real listening server is used.
# The control connection is one end of a Socket.pair; the server side is a
# small scripted peer.  For each RETR the peer hands the client a fresh
# in-memory Socket.pair as the data connection (passive mode), so the real
# transfercmd / RETR / final-reply machinery is exercised end to end.
#
class FTPReadBudgetTest < Test::Unit::TestCase
  BLOCKSIZE = 4

  # A line-oriented control socket with no read-ahead, so each readline
  # corresponds to exactly one server reply.
  class QueuedControl
    def initialize(io)
      @io = io
      @queue = Queue.new
      @reader = Thread.start do
        until io.closed?
          line = io.gets
          break if line.nil?
          @queue.push(line)
        end
      rescue IOError
        # peer closed
      ensure
        @queue.close
      end
    end

    def readline
      line = @queue.pop
      raise EOFError, "end of file reached" if line.nil?
      line
    end

    def write(message)
      @io.write(message)
    end

    attr_accessor :read_timeout

    def close
      @io.close
    end

    def closed?
      @io.closed?
    end

    def shutdown(*args)
      @io.shutdown(*args)
    end

    def send(message, _flags, _dest = nil)
      @io.write(message)
    end
  end

  # Minimal stand-in for the bare socket's remote address (parse227).
  class StubAddress
    def remote_address
      address = Object.new
      def address.ipv4?
        true
      end

      def address.ip_address
        "127.0.0.1"
      end
      address
    end
  end

  # A scripted FTP peer.  Each download is described by a Download:
  #   content:  bytes offered on the data connection
  #   text:     when true the bytes are served as CRLF lines
  #   drop_after: close the data connection after this many bytes (optional)
  #   final_reply: reply sent after the data connection ends
  Download = Struct.new(:content, :text, :drop_after, :final_reply,
                        :abort_silent, keyword_init: true)

  class FakeFtpPeer
    attr_reader :commands

    def initialize(download)
      @download = download
      @commands = []
      @data_endpoints = Queue.new
      @server_data_end = nil
      @retr_done = false
      @control_pair = Socket.pair(:UNIX, :STREAM)
      @client_control = @control_pair[0]
      @server_control = @control_pair[1]
      @thread = Thread.start { run }
    end

    def client
      peer = self
      ftp = Net::FTP.new
      ftp.read_timeout = 2
      ftp.passive = true
      ftp.set_socket(QueuedControl.new(@client_control), true)
      ftp.instance_variable_set(:@bare_sock, StubAddress.new)
      ftp.define_singleton_method(:open_socket) do |_host, _port|
        peer.take_data_endpoint
      end
      ftp.login("user", "pass")
      ftp
    end

    # The client end of the data connection prepared at PASV.
    def take_data_endpoint
      @data_endpoints.pop
    end

    def join
      @thread.join
    end

    def close
      @server_control.close unless @server_control.closed?
      @client_control.close unless @client_control.closed?
    end

    private

    def run
      sock = @server_control
      sock.write("220 fake ftp ready.\r\n")
      loop do
        line = sock.gets
        raise EOFError if line.nil?
        line = line.chomp
        @commands << line
        case line
        when /\AUSER /
          sock.write("331 need password.\r\n")
        when /\APASS /
          sock.write("230 logged in.\r\n")
        when /\ATYPE /
          sock.write("200 type set.\r\n")
        when /\APASV(?:\s|\z)/
          client_end, server_end = Socket.pair(:UNIX, :STREAM)
          @server_data_end = server_end
          @data_endpoints.push(client_end)
          sock.write("227 Entering Passive Mode (127,0,0,1,12,34).\r\n")
        when /\ARETR /
          sock.write("150 opening data connection.\r\n")
          stream_data(@server_data_end)
          @server_data_end = nil
          @retr_done = true
        when /\AABOR(?:\s|\z)/
          unless @retr_done
            # Not in a transfer; report that there is nothing to abort.
            sock.write("225 no transfer to abort.\r\n")
            next
          end
          @retr_done = false
          if @download.abort_silent
            # Drop the control connection without answering.
            @server_control.close rescue nil
            return
          end
          sock.write("426 connection closed; transfer aborted.\r\n")
          sock.write("226 abort successful.\r\n")
        when /\ANOOP(?:\s|\z)/
          sock.write("200 noop ok.\r\n")
        else
          sock.write("500 unknown command.\r\n")
        end
      end
    rescue EOFError, IOError, Errno::ENOTCONN, Errno::EPIPE
      # Client went away.
    ensure
      sock.close rescue nil
    end

    def stream_data(server_end)
      return if server_end.nil?
      bytes = @download.content.b
      if @download.text
        bytes = bytes.gsub(/\n/, "\r\n") unless bytes.include?("\r\n")
      end
      served = if @download.drop_after
                 bytes.byteslice(0, @download.drop_after)
               else
                 bytes
               end
      begin
        server_end.write(served)
      rescue Errno::EPIPE, IOError
        # The client stopped reading (budget exhausted).
      end
      server_end.shutdown(Socket::SHUT_WR) rescue nil
      server_end.close rescue nil
      if @download.final_reply
        @server_control.write(@download.final_reply)
      end
    end
  end

  def setup
    @peers = []
  end

  def teardown
    @peers.each do |peer|
      peer.close rescue nil
      peer.join rescue nil
    end
  end

  def peer(download)
    peer = FakeFtpPeer.new(download)
    @peers << peer
    peer
  end

  def binary_content
    (0..15).map { |i| (i + 0xa0).chr }.join.b
  end

  def text_content
    "alpha\nbeta\ngamma\n"
  end

  # --- binary, within budget -------------------------------------------------

  def test_binary_within_budget_is_complete_and_control_stays_usable
    content = binary_content
    download = Download.new(content: content, text: false,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    chunks = []
    result = ftp.retrbinary("RETR report.bin", BLOCKSIZE,
                            read_budget: content.bytesize + 10) do |chunk|
      chunks << chunk
    end

    assert_equal(content, chunks.join.b)
    assert_equal(content.bytesize, result.bytes_read)
    assert(result.data_complete?)
    refute(result.truncated?)
    assert(result.control_connection_usable?)
    assert_equal("226", result.final_response_code)
    assert_match(/\A226/, result.final_response)
    assert_equal(:complete, result.reason)

    # The next ordinary command still works.
    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
    assert(p.commands.include?("NOOP"))
  ensure
    ftp&.close
  end

  # --- binary, exactly the budget -------------------------------------------

  def test_binary_exact_budget_is_complete
    content = binary_content
    download = Download.new(content: content, text: false,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    chunks = []
    result = ftp.retrbinary("RETR report.bin", BLOCKSIZE,
                            read_budget: content.bytesize) do |chunk|
      chunks << chunk
    end

    assert_equal(content.bytesize, result.bytes_read)
    assert_equal(content, chunks.join.b)
    assert(result.data_complete?)
    assert(result.control_connection_usable?)
    assert_equal("226", result.final_response_code)

    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  # --- binary, stopped early ------------------------------------------------

  def test_binary_early_stop_truncates_but_control_stays_usable
    content = binary_content
    budget = 8
    download = Download.new(content: content, text: false,
                            final_reply: nil)
    p = peer(download)
    ftp = p.client
    chunks = []
    result = ftp.retrbinary("RETR report.bin", BLOCKSIZE,
                            read_budget: budget) do |chunk|
      chunks << chunk
    end

    assert_equal(budget, result.bytes_read)
    assert_equal(content.byteslice(0, budget), chunks.join.b)
    refute(result.data_complete?)
    assert(result.truncated?)
    # The client aborted, so the final reply is the abort acknowledgement.
    assert_equal("226", result.final_response_code)
    assert_match(/\A226/, result.final_response)
    assert(result.control_connection_usable?)

    # ABOR was issued; the following NOOP still runs over the same control
    # connection.
    assert(p.commands.any? { |c| c.start_with?("ABOR") })
    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  # --- binary file helper, stopped early ------------------------------------

  def test_getbinaryfile_early_stop_leaves_partial_file
    content = binary_content
    budget = 5
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.bin")
      download = Download.new(content: content, text: false,
                             final_reply: nil)
      p = peer(download)
      ftp = p.client
      result = ftp.getbinaryfile("report.bin", path, BLOCKSIZE,
                                 read_budget: budget)

      assert(result.truncated?)
      assert_equal(budget, result.bytes_read)
      assert_equal(content.byteslice(0, budget), File.binread(path))
      refute_equal(content.bytesize, File.size(path))

      assert_nothing_raised { ftp.noop }
      assert_equal("200 noop ok.", ftp.last_response.chomp)
    ensure
      ftp&.close
    end
  end

  # --- text, within budget ---------------------------------------------------

  def test_text_within_budget_is_complete_and_control_stays_usable
    raw = text_content
    text_bytes = raw.gsub(/\n/, "\r\n")
    download = Download.new(content: text_bytes, text: true,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    lines = []
    result = ftp.retrlines("RETR report.txt",
                           read_budget: text_bytes.bytesize + 10) do |line|
      lines << line
    end

    assert_equal(["alpha", "beta", "gamma"], lines)
    assert_equal(text_bytes.bytesize, result.bytes_read)
    assert(result.data_complete?)
    assert(result.control_connection_usable?)
    assert_equal("226", result.final_response_code)

    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  # --- text, exactly the budget ---------------------------------------------

  def test_text_exact_budget_is_complete
    text_bytes = text_content.gsub(/\n/, "\r\n")
    download = Download.new(content: text_bytes, text: true,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    lines = []
    result = ftp.retrlines("RETR report.txt",
                           read_budget: text_bytes.bytesize) do |line|
      lines << line
    end

    assert_equal(["alpha", "beta", "gamma"], lines)
    assert_equal(text_bytes.bytesize, result.bytes_read)
    assert(result.data_complete?)
    assert(result.control_connection_usable?)
    assert_equal("226", result.final_response_code)

    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  # --- text, stopped early ---------------------------------------------------

  def test_text_early_stop_truncates_whole_lines_and_control_stays_usable
    text_bytes = text_content.gsub(/\n/, "\r\n")
    # Room for "alpha\r\n" and "beta\r\n" (13 bytes) but not "gamma\r\n".
    budget = 13
    download = Download.new(content: text_bytes, text: true,
                            final_reply: nil)
    p = peer(download)
    ftp = p.client
    lines = []
    result = ftp.retrlines("RETR report.txt", read_budget: budget) do |line|
      lines << line
    end

    # Only whole lines are delivered; the line that would not fit is not
    # split.
    assert_equal(["alpha", "beta"], lines)
    assert_equal(budget, result.bytes_read)
    refute(result.data_complete?)
    assert(result.truncated?)
    assert_equal("226", result.final_response_code)
    assert(result.control_connection_usable?)

    assert(p.commands.any? { |c| c.start_with?("ABOR") })
    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  # --- text file helper, stopped early --------------------------------------

  def test_gettextfile_early_stop_leaves_partial_file
    text_bytes = text_content.gsub(/\n/, "\r\n")
    budget = 13
    Dir.mktmpdir do |dir|
      path = File.join(dir, "report.txt")
      download = Download.new(content: text_bytes, text: true,
                              final_reply: nil)
      p = peer(download)
      ftp = p.client
      result = ftp.gettextfile("report.txt", path, read_budget: budget)

      assert(result.truncated?)
      assert_equal(budget, result.bytes_read)
      assert_equal("alpha\nbeta\n", File.read(path))

      assert_nothing_raised { ftp.noop }
      assert_equal("200 noop ok.", ftp.last_response.chomp)
    ensure
      ftp&.close
    end
  end


  # --- zero budget -----------------------------------------------------------

  def test_zero_budget_delivers_nothing_and_truncates
    content = binary_content
    download = Download.new(content: content, text: false,
                            final_reply: nil)
    p = peer(download)
    ftp = p.client
    chunks = []
    result = ftp.retrbinary("RETR report.bin", BLOCKSIZE, read_budget: 0) do |chunk|
      chunks << chunk
    end

    assert_equal(0, result.bytes_read)
    assert_equal([], chunks)
    refute(result.data_complete?)
    assert(result.truncated?)
    assert(result.control_connection_usable?)

    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  # --- no budget keeps the legacy return value ------------------------------

  def test_without_budget_retrbinary_returns_nil
    content = binary_content
    download = Download.new(content: content, text: false,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    chunks = []
    result = ftp.retrbinary("RETR report.bin", BLOCKSIZE) do |chunk|
      chunks << chunk
    end

    assert_nil(result)
    assert_equal(content, chunks.join.b)
    assert_equal("226 transfer complete.", ftp.last_response.chomp)

    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  def test_without_budget_getbinaryfile_returns_data
    content = binary_content
    download = Download.new(content: content, text: false,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    data = ftp.getbinaryfile("report.bin", nil, BLOCKSIZE)

    assert_kind_of(String, data)
    assert_equal(content, data)
  ensure
    ftp&.close
  end


  def test_without_budget_retrlines_yields_all_lines
    text = text_content.gsub(/\n/, "\r\n")
    download = Download.new(content: text, text: true,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    lines = []
    result = ftp.retrlines("RETR report.txt") { |line| lines << line }

    assert_nil(result)
    assert_equal(["alpha", "beta", "gamma"], lines)
    # The transfer's 226 is consumed inside retrlines; restoring binary
    # mode afterwards leaves the TYPE reply as the last response on the
    # connection.  A following command still runs normally.
    assert_nothing_raised { ftp.noop }
    assert_equal("200 noop ok.", ftp.last_response.chomp)
  ensure
    ftp&.close
  end

  def test_without_budget_gettextfile_returns_data
    text = text_content.gsub(/\n/, "\r\n")
    download = Download.new(content: text, text: true,
                            final_reply: "226 transfer complete.\r\n")
    p = peer(download)
    ftp = p.client
    data = ftp.gettextfile("report.txt", nil)

    assert_equal(text_content, data)
  ensure
    ftp&.close
  end


  # --- invalid budget --------------------------------------------------------

  def test_negative_or_non_integer_budget_is_rejected
    ftp = Net::FTP.new
    assert_raise(ArgumentError) do
      ftp.retrbinary("RETR x", BLOCKSIZE, read_budget: -1) {}
    end
    assert_raise(ArgumentError) do
      ftp.retrlines("RETR x", read_budget: "4") {}
    end
    assert_raise(ArgumentError) do
      ftp.retrbinary("RETR x", BLOCKSIZE, read_budget: 1.5) {}
    end
  end

  # --- control reply unavailable on an early stop ---------------------------

  def test_early_stop_without_abort_reply_reports_unusable_control
    content = binary_content
    # The peer ends the data connection but sends no final reply and drops
    # the control connection, simulating a lost control channel.
    download = Download.new(content: content, text: false,
                            final_reply: nil, abort_silent: true)
    p = peer(download)
    ftp = p.client
    chunks = []
    result = ftp.retrbinary("RETR report.bin", BLOCKSIZE,
                            read_budget: 4) do |chunk|
      chunks << chunk
    end

    assert_equal(4, result.bytes_read)
    refute(result.data_complete?)
    refute(result.control_connection_usable?)
    assert_nil(result.final_response_code)

    # With the control channel gone the next command cannot run normally.
    assert_raise(Errno::EPIPE) { ftp.noop }
  ensure
    ftp&.close
  end
end
