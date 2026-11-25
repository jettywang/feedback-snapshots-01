# frozen_string_literal: true

require "net/ftp"
require "test/unit"
require "digest"
require "json"
require "ostruct"
require "tmpdir"

#
# Exercises the optional Net::FTP::TransferReceipt resumable download flow.
#
# The sandbox forbids binding TCP ports, so neither a real listening server
# nor real data sockets are used.  Both the control connection and every data
# connection are in-memory Socket.pair endpoints.
#
# The control endpoint is wrapped in QueuedControl, which returns exactly one
# reply line per readline so the strict FTP request/response ordering stays
# correct over a zero-latency pair (BufferedIO would otherwise pre-buffer
# several replies).  Data connections use the ordinary
# Net::FTP::BufferedSocket; the client runs in passive mode and its
# open_socket is redirected to the endpoint the fake server prepared at PASV,
# keeping the real transfercmd/REST/RETR machinery exercised end to end.
#
class FTPResumeReceiptTest < Test::Unit::TestCase
  BLOCKSIZE = 8

  # Line-oriented control socket with no read-ahead.  A reader thread pulls
  # one reply line at a time into a queue, so each readline corresponds to
  # exactly one server reply.
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
        @queue.push(:eof)
      end
    end

    def readline
      line = @queue.pop
      raise EOFError, "end of file reached" if line == :eof
      line
    end

    def write(message)
      @io.write(message)
    end

    def read_timeout=(value)
      @read_timeout = value
    end

    def close
      @io.close
    end

    def closed?
      @io.closed?
    end

    def shutdown(*args)
      @io.shutdown(*args)
    end
  end

  # A scripted, in-memory FTP peer.
  class FakeFtpPeer
    # An attempt descriptor:
    #   content:      bytes offered on the data connection
    #   drop_after:   close the data connection after this many bytes
    #                 (nil => deliver everything and half-close cleanly)
    #   final_reply:  control reply sent after the data connection ends
    #                 (nil => drop the control connection instead)
    #   facts:        version facts advertised for this attempt
    Attempt = Struct.new(:content, :drop_after, :final_reply, :facts,
                         keyword_init: true)

    attr_reader :rest_offsets, :commands

    def initialize(attempts)
      @attempts = attempts
      @rest_offsets = []
      @commands = []
      @data_pairs = Queue.new
      @streamers = []
      @control_pair = Socket.pair(:UNIX, :STREAM)
      @client_control = @control_pair[0]
      @server_control = @control_pair[1]
      @thread = Thread.start { run }
    end

    # Builds a passive-mode FTP client whose sockets are the fake endpoints.
    # A normal login handshake is performed up front.
    def client
      peer = self
      ftp = Net::FTP.new
      ftp.read_timeout = 2
      ftp.passive = true
      # get_greeting = true drains the 220 greeting before login.
      ftp.set_socket(QueuedControl.new(@client_control), true)
      ftp.instance_variable_set(:@bare_sock, StubAddress.new)
      ftp.define_singleton_method(:open_socket) do |_host, _port|
        peer.take_data_endpoint
      end
      ftp.login("user", "pass")
      return ftp
    end

    # The data endpoint prepared by the server at PASV.
    def take_data_endpoint
      return @data_pairs.pop
    end

    # The REST offsets observed, captured by wrapping the resume setter path
    # via the recorded REST commands on the server.
    def join
      @thread.join
      @streamers.each(&:join)
    end

    def close
      @server_control.close unless @server_control.closed?
      @client_control.close unless @client_control.closed?
    end

    private

    # Minimal stand-in for a bare socket's remote address, used by parse227.
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

    def run
      sock = @server_control
      sock.write("220 fake ftp ready.\r\n")

      attempt_index = 0
      facts = @attempts[attempt_index].facts
      pending_data_end = nil
      rest_offset = 0

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
        when /\ASIZE /
          if facts.size.nil?
            sock.write("550 no size fact.\r\n")
          else
            sock.write("213 #{facts.size}\r\n")
          end
        when /\AMDTM /
          if facts.mtime.nil?
            sock.write("550 no mdtm fact.\r\n")
          else
            sock.write("213 #{facts.mtime}\r\n")
          end
        when /\AMLST /
          if facts.unique.nil?
            sock.write("550 no mlst fact.\r\n")
          else
            path = line.sub(/\AMLST /, "")
            sock.write("250-Listing\r\n")
            sock.write(" unique=#{facts.unique}; #{path}\r\n")
            sock.write("250 End\r\n")
          end
        when /\APASV(?:\s|\z)/
          client_end, server_end = Socket.pair(:UNIX, :STREAM)
          pending_data_end = server_end
          @data_pairs.push(client_end)
          sock.write("227 Entering Passive Mode (127,0,0,1,12,34).\r\n")
        when /\AREST /
          rest_offset = line.split.last.to_i
          @rest_offsets << rest_offset
          sock.write("350 rest at #{rest_offset}.\r\n")
        when /\ARETR /
          data_end = pending_data_end
          pending_data_end = nil
          stream_data(data_end, @attempts[attempt_index], rest_offset)
          rest_offset = 0
          sock.write("150 opening data connection.\r\n")
          if @attempts[attempt_index].final_reply
            sock.write(@attempts[attempt_index].final_reply)
          else
            # All bytes delivered, but the control end never confirms: drop it.
            @server_control.close rescue nil
            return
          end
          attempt_index += 1
          return if attempt_index >= @attempts.size
          facts = @attempts[attempt_index].facts
        else
          sock.write("500 unknown command.\r\n")
        end
      end
    rescue EOFError, IOError, Errno::ENOTCONN, Errno::EPIPE
      # Client went away (e.g. control drop) - nothing more to script.
    ensure
      sock.close rescue nil
    end

    # Streams one attempt's bytes on its own thread so the control thread
    # stays free to handle the post-transfer exchange.  Honors +rest_offset+
    # by serving only the bytes from that absolute offset onward.
    def stream_data(server_end, attempt, rest_offset)
      @streamers << Thread.start do
        begin
          bytes = attempt.content.b.byteslice(rest_offset,
                                              attempt.content.bytesize - rest_offset)
          if attempt.drop_after
            server_end.write(bytes.byteslice(0, attempt.drop_after))
            # Abrupt drop: close without a write shutdown so the client sees a
            # truncated connection.
          else
            server_end.write(bytes)
            server_end.shutdown(Socket::SHUT_WR) rescue nil
          end
        rescue IOError, Errno::EPIPE, Errno::ENOTCONN
          # client closed early
        ensure
          server_end.close rescue nil
        end
      end
    end
  end

  def facts(size:, mtime: nil, unique: nil)
    OpenStruct.new(size: size, mtime: mtime, unique: unique)
  end

  def receipt_for(localfile, remotefile = "archive.bin")
    Net::FTP::TransferReceipt.new(localfile: localfile,
                                  remotefile: remotefile)
  end

  def sha256(string)
    Digest::SHA256.hexdigest(string)
  end

  # Two same-size but byte-distinct revisions.
  def revision_a
    ("A" * 8) + ("1" * 8) + ("a" * 8)
  end

  def revision_b
    ("B" * 8) + ("2" * 8) + ("b" * 8)
  end

  def prefix_len
    10
  end

  # Writes the prefix bytes of an interrupted first attempt plus the matching
  # sidecar receipt, as if a previous process had died mid-transfer.
  def seed_interrupted(dir, content, version_facts, state: :interrupted)
    part = File.join(dir, "archive.bin.part")
    sidecar = File.join(dir, "archive.bin.ftp-receipt")
    prefix = content.byteslice(0, prefix_len)
    File.binwrite(part, prefix)
    receipt = Net::FTP::TransferReceipt.new(
      localfile: File.join(dir, "archive.bin"),
      remotefile: "archive.bin",
    )
    receipt.mark_attempt!(state: :receiving,
                          rest_offset: 0,
                          version_facts: Net::FTP::VersionFacts.new(
                            size: version_facts.size,
                            mtime: version_facts.mtime,
                            unique: version_facts.unique,
                          ),
                          version_status: :fresh)
    prefix_len.times { receipt.add_received!(1) }
    receipt.mark_data_end!
    receipt.record_prefix!(prefix.bytesize, sha256(prefix))
    receipt.instance_variable_set(:@state, state)
    receipt.persist!(sidecar)
    [part, sidecar, prefix]
  end

  # Scenario 1: same-size replacement, server cannot distinguish versions.
  def test_same_size_replacement_without_version_facts_keeps_candidate
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        old_content = revision_a
        new_content = revision_b
        assert_equal(old_content.bytesize, new_content.bytesize)
        part, _sidecar, saved_prefix =
          seed_interrupted(dir, old_content, facts(size: old_content.bytesize))

        peer = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: new_content,
            drop_after: nil,
            final_reply: "226 transfer complete.\r\n",
            facts: facts(size: new_content.bytesize),
          ),
        ])
        ftp = peer.client
        receipt = receipt_for(File.join(dir, "archive.bin"))
        chunks = []
        error = assert_raise(Net::FTPResumeVersionError) do
          ftp.getbinaryfile("archive.bin", File.join(dir, "archive.bin"),
                            BLOCKSIZE, receipt: receipt) { |c| chunks << c }
        end
        assert_same(receipt, error.receipt)

        # The prefix cannot be verified: retained as a candidate and no REST
        # is ever issued, so no byte range is appended to the rejected prefix.
        assert(receipt.candidate?)
        assert_equal(:indeterminate, receipt.version_status)
        assert_match(/cannot be distinguished/, receipt.candidate_reason)
        assert_equal([], peer.rest_offsets)
        candidate = File.join(dir, "archive.bin.candidate")
        assert(File.file?(candidate))
        assert_equal(saved_prefix, File.binread(candidate))
        refute(File.file?(part))
        refute(File.file?(File.join(dir, "archive.bin")))
        # The chunk callback is not invoked once the prefix is rejected.
        assert_equal([], chunks)
        # The sidecar round-trips and still describes the saved prefix.
        persisted = Net::FTP::TransferReceipt.load(
          File.join(dir, "archive.bin.ftp-receipt"))
        assert_equal(:candidate, persisted.state)
        assert_equal(:indeterminate, persisted.version_status)
        assert_equal(sha256(saved_prefix), persisted.prefix_digest)
        assert_equal(prefix_len, persisted.prefix_bytes)
      ensure
        ftp&.close
        peer.close
        peer.join
      end
    end
  end

  # Scenario 2: versions stay distinguishable and consistent; resume works,
  # then a further attempt loses the final control reply.
  def test_verified_resume_then_data_complete_without_final_reply
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        content = revision_a
        consistent = facts(size: content.bytesize,
                           mtime: "20260101000000",
                           unique: "abcd-efgh")
        part, sidecar, saved_prefix =
          seed_interrupted(dir, content, consistent)

        # First live connection verifies the prefix and resumes to completion.
        first = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: content,
            drop_after: nil,
            final_reply: "226 transfer complete.\r\n",
            facts: consistent,
          ),
        ])
        ftp = first.client
        receipt = receipt_for(File.join(dir, "archive.bin"))
        chunks = []
        ftp.getbinaryfile("archive.bin", File.join(dir, "archive.bin"),
                          BLOCKSIZE, receipt: receipt) { |c| chunks << c }

        # Local prefix digest is checked against the sidecar.
        assert_equal(sha256(saved_prefix), receipt.prefix_digest)
        # The verified resume starts exactly at the saved prefix length.
        assert_equal([prefix_len], first.rest_offsets)
        # Only the back half is received during this attempt.
        back_half = content.byteslice(prefix_len,
                                      content.bytesize - prefix_len)
        assert_equal(back_half, chunks.join.b)
        assert_equal(back_half.bytesize, receipt.received_bytes)
        assert_equal((prefix_len)...(content.bytesize),
                     receipt.received_range)
        # Confirmed on the control channel, then archived.
        assert_equal(:archived, receipt.state)
        assert(receipt.archivable?)
        assert_equal("226", receipt.last_response_code)
        assert_equal(content, File.binread(File.join(dir, "archive.bin")))
        refute(File.file?(part))
        refute(File.file?(sidecar))
        ftp.close
        first.close
        first.join

        # A new connection that finishes all bytes but never gets the control
        # confirmation stays staged and is separately marked.
        second = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: content,
            drop_after: nil,
            final_reply: nil,
            facts: consistent,
          ),
        ])
        ftp2 = second.client
        part2 = File.join(dir, "archive.bin.part")
        sidecar2 = File.join(dir, "archive.bin.ftp-receipt")
        receipt2 = receipt_for(File.join(dir, "archive.bin"))
        assert_raise(EOFError) do
          ftp2.getbinaryfile("archive.bin", File.join(dir, "archive.bin"),
                             BLOCKSIZE, receipt: receipt2)
        end
        assert(receipt2.data_complete?)
        refute(receipt2.archivable?)
        assert_equal(:data_complete, receipt2.state)
        assert(File.file?(part2))
        assert_equal(content, File.binread(part2))
        # The earlier archived file is left untouched (no premature archive).
        assert_equal(content, File.binread(File.join(dir, "archive.bin")))
        saved = JSON.parse(File.binread(sidecar2))
        assert_equal("data_complete", saved["state"])
      ensure
        ftp2&.close
        second&.close
        second&.join
      end
    end
  end

  # Mid-transfer disconnect leaves an interrupted prefix attributed to the
  # attempt; the next reception (on a new connection) resumes at the saved
  # offset.
  def test_interrupted_prefix_records_attempt_and_resume_offset
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        content = revision_a
        consistent = facts(size: content.bytesize,
                           mtime: "20260101000000",
                           unique: "abcd-efgh")

        # First connection dies halfway, persisting a prefix + sidecar.
        first = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: content,
            drop_after: prefix_len,
            final_reply: nil,
            facts: consistent,
          ),
        ])
        ftp = first.client
        receipt = receipt_for(File.join(dir, "archive.bin"))
        assert_raise(EOFError) do
          ftp.getbinaryfile("archive.bin", File.join(dir, "archive.bin"),
                            BLOCKSIZE, receipt: receipt)
        end
        assert(receipt.interrupted?)
        assert_equal(1, receipt.attempt_count)
        assert_equal(1, receipt.prefix_attempt)
        assert_equal(prefix_len, receipt.prefix_bytes)
        assert_equal(sha256(content.byteslice(0, prefix_len)),
                     receipt.prefix_digest)
        sidecar = File.join(dir, "archive.bin.ftp-receipt")
        assert(File.file?(sidecar))
        ftp.close
        first.close
        first.join

        # A fresh connection verifies the prefix and resumes at its length.
        second = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: content,
            drop_after: nil,
            final_reply: "226 transfer complete.\r\n",
            facts: consistent,
          ),
        ])
        ftp2 = second.client
        receipt2 = receipt_for(File.join(dir, "archive.bin"))
        ftp2.getbinaryfile("archive.bin", File.join(dir, "archive.bin"),
                           BLOCKSIZE, receipt: receipt2)
        assert_equal([prefix_len], second.rest_offsets)
        assert_equal(:archived, receipt2.state)
        assert_equal(content, File.binread(File.join(dir, "archive.bin")))
      ensure
        ftp2&.close
        second&.close
        second&.join
      end
    end
  end

  # A provably different (distinguishable) revision is reported as a mismatch.
  def test_distinguishable_revision_change_is_mismatch
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        old_content = revision_a
        new_content = revision_b
        old_facts = facts(size: old_content.bytesize,
                          mtime: "20260101000000",
                          unique: "old-id")
        new_facts = facts(size: new_content.bytesize,
                          mtime: "20260202000000",
                          unique: "new-id")
        seed_interrupted(dir, old_content, old_facts)

        peer = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: new_content,
            drop_after: nil,
            final_reply: "226 transfer complete.\r\n",
            facts: new_facts,
          ),
        ])
        ftp = peer.client
        receipt = receipt_for(File.join(dir, "archive.bin"))
        assert_raise(Net::FTPResumeVersionError) do
          ftp.getbinaryfile("archive.bin", File.join(dir, "archive.bin"),
                            BLOCKSIZE, receipt: receipt)
        end
        assert_equal(:mismatch, receipt.version_status)
        assert_match(/version changed/, receipt.candidate_reason)
        assert(receipt.candidate?)
        assert(File.file?(File.join(dir, "archive.bin.candidate")))
      ensure
        ftp&.close
        peer.close
        peer.join
      end
    end
  end

  # A clean download with no prior prefix archives immediately and keeps the
  # per-chunk callback working throughout.
  def test_fresh_download_archives_and_invokes_callback
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        content = revision_a
        peer = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: content,
            drop_after: nil,
            final_reply: "226 transfer complete.\r\n",
            facts: facts(size: content.bytesize,
                         mtime: "20260101000000",
                         unique: "id"),
          ),
        ])
        ftp = peer.client
        receipt = receipt_for(File.join(dir, "archive.bin"))
        chunks = []
        result = ftp.getbinaryfile("archive.bin",
                                   File.join(dir, "archive.bin"),
                                   BLOCKSIZE,
                                   receipt: receipt) { |c| chunks << c }
        assert_nil(result)
        assert_equal(:archived, receipt.state)
        assert_equal(content, chunks.join.b)
        assert_equal(content, File.binread(File.join(dir, "archive.bin")))
        # A fresh reception starts at offset zero.
        assert_equal([0], peer.rest_offsets)
        refute(File.file?(File.join(dir, "archive.bin.ftp-receipt")))
      ensure
        ftp&.close
        peer.close
        peer.join
      end
    end
  end

  # Without a receipt the legacy behavior is unchanged: the file is written
  # directly to its destination and no staging/sidecar/candidate artifacts are
  # created, and no version-fact or REST commands are issued.
  def test_legacy_getbinaryfile_without_receipt_is_unchanged
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        content = revision_a
        peer = FakeFtpPeer.new([
          FakeFtpPeer::Attempt.new(
            content: content,
            drop_after: nil,
            final_reply: "226 transfer complete.\r\n",
            facts: facts(size: content.bytesize),
          ),
        ])
        ftp = peer.client
        chunks = []
        ftp.getbinaryfile("archive.bin", File.join(dir, "out.bin"),
                          BLOCKSIZE) { |c| chunks << c }

        assert_equal(content, File.binread(File.join(dir, "out.bin")))
        assert_equal(content, chunks.join.b)
        refute(File.file?(File.join(dir, "out.bin.part")))
        refute(File.file?(File.join(dir, "out.bin.ftp-receipt")))
        refute(File.file?(File.join(dir, "out.bin.candidate")))
        # Legacy path never asks for version facts and never issues REST.
        assert_equal([], peer.rest_offsets)
        fact_commands = peer.commands.grep(/\A(?:SIZE|MDTM|MLST|REST)/)
        assert_equal([], fact_commands)
      ensure
        ftp&.close
        peer.close
        peer.join
      end
    end
  end
end
