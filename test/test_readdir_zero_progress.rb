require 'common'

# Zero-progress safety tests for directory enumeration. A server that keeps
# answering READDIR with empty FXP_NAME packets must not make the client
# send READDIR forever, and the end-of-listing rules (STATUS EOF before
# protocol v6, empty FXP_NAME as of v6) must stay scoped to the directory
# they were received on.
class ReaddirZeroProgressSessionTest < Net::SFTP::TestCase
  def test_v6_readdir_bang_treats_empty_name_packet_as_end_of_listing
    expect_sftp_session :server_version => 6 do |channel|
      channel.sends_packet(FXP_READDIR, :long, 0, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 0, :long, 0)
    end

    assert_scripted_command do
      assert_nil sftp.readdir!("handle")
    end
  end

  def test_v3_readdir_bang_reports_empty_batch_without_ending_listing
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_READDIR, :long, 0, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 0, :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 1)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      assert_equal [], sftp.readdir!("handle")
      assert_nil sftp.readdir!("handle")
      assert_equal 2, counts["handle"]
    end
  end

  def test_v6_dir_entries_stops_at_empty_name_packet
    expect_sftp_session :server_version => 6 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/dir")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 1, :long, 2,
        :string, "a", :long, 0, :byte, 1,
        :string, "b", :long, 0, :byte, 1)
      channel.sends_packet(FXP_READDIR, :long, 2, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 2, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      assert_equal %w(a b), sftp.dir.entries("/dir").map { |e| e.name }
      assert_equal 2, counts["handle"]
    end
  end

  def test_v3_dir_entries_read_multiple_batches_until_status_eof
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/dir")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 1, :long, 2,
        :string, "a", :string, "long a", :long, 0,
        :string, "b", :string, "long b", :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 2, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 2, :long, 1,
        :string, "c", :string, "long c", :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 1)
      channel.sends_packet(FXP_CLOSE, :long, 4, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      assert_equal %w(a b c), sftp.dir.entries("/dir").map { |e| e.name }
      assert_equal 3, counts["handle"]
    end
  end

  def test_v3_empty_name_storm_aborts_instead_of_looping_forever
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/dir")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      3.times do |i|
        channel.sends_packet(FXP_READDIR, :long, 1 + i, :string, "handle")
        channel.gets_packet(FXP_NAME, :long, 1 + i, :long, 0)
      end
      channel.sends_packet(FXP_CLOSE, :long, 4, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      error = assert_raises(Net::SFTP::Exception) { sftp.dir.entries("/dir") }
      assert_match(/empty batches/, error.message)
      assert_equal 3, counts["handle"]
    end
  end

  def test_v3_empty_batch_budget_resets_when_progress_is_made
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/dir")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 1, :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 2, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 2, :long, 1, :string, "a", :string, "long a", :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 3, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 3, :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 4, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 4, :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 5, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 5, :long, 1, :string, "b", :string, "long b", :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 6, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 6, :long, 1)
      channel.sends_packet(FXP_CLOSE, :long, 7, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 7, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      assert_equal %w(a b), sftp.dir.entries("/dir").map { |e| e.name }
      assert_equal 6, counts["handle"]
    end
  end

  def test_v3_readdir_error_status_aborts_enumeration
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/dir")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 3, :string, "Permission denied", :string, "en")
      channel.sends_packet(FXP_CLOSE, :long, 2, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      error = assert_raises(Net::SFTP::StatusException) { sftp.dir.entries("/dir") }
      assert_equal 3, error.code
      assert_equal 1, counts["handle"]
    end
  end

  def test_v3_truncated_name_packet_aborts_enumeration
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/dir")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_READDIR, :long, 1, :string, "handle")
      channel.gets_packet(FXP_NAME, :long, 1, :long, 5, :string, "a", :string, "long a", :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 2, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      error = assert_raises(Net::SFTP::Exception) { sftp.dir.entries("/dir") }
      assert_match(/only \d+ bytes/, error.message)
      assert_equal 1, counts["handle"]
    end
  end

  def test_interleaved_directories_are_enumerated_independently
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/a")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle-a")
      channel.sends_packet(FXP_OPENDIR, :long, 1, :string, "/b")
      channel.gets_packet(FXP_HANDLE, :long, 1, :string, "handle-b")

      channel.sends_packet(FXP_READDIR, :long, 2, :string, "handle-a")
      channel.gets_packet(FXP_NAME, :long, 2, :long, 1, :string, "a1", :string, "long a1", :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 3, :string, "handle-b")
      channel.gets_packet(FXP_NAME, :long, 3, :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 4, :string, "handle-a")
      channel.gets_packet(FXP_NAME, :long, 4, :long, 1, :string, "a2", :string, "long a2", :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 5, :string, "handle-b")
      channel.gets_packet(FXP_STATUS, :long, 5, :long, 3, :string, "denied", :string, "en")
      channel.sends_packet(FXP_READDIR, :long, 6, :string, "handle-a")
      channel.gets_packet(FXP_STATUS, :long, 6, :long, 1)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      handle_a = sftp.opendir!("/a")
      handle_b = sftp.opendir!("/b")

      a_batches = []
      a_batches << sftp.readdir!(handle_a).map { |n| n.name }
      assert_equal [], sftp.readdir!(handle_b)
      a_batches << sftp.readdir!(handle_a).map { |n| n.name }

      error = assert_raises(Net::SFTP::StatusException) { sftp.readdir!(handle_b) }
      assert_equal 3, error.code

      assert_nil sftp.readdir!(handle_a)

      assert_equal [%w(a1), %w(a2)], a_batches
      assert_equal 3, counts["handle-a"]
      assert_equal 2, counts["handle-b"]
    end
  end

  def test_v6_interleaved_empty_name_ends_only_its_own_listing
    expect_sftp_session :server_version => 6 do |channel|
      channel.sends_packet(FXP_OPENDIR, :long, 0, :string, "/a")
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle-a")
      channel.sends_packet(FXP_OPENDIR, :long, 1, :string, "/b")
      channel.gets_packet(FXP_HANDLE, :long, 1, :string, "handle-b")

      channel.sends_packet(FXP_READDIR, :long, 2, :string, "handle-a")
      channel.gets_packet(FXP_NAME, :long, 2, :long, 1, :string, "a1", :long, 0, :byte, 1)
      channel.sends_packet(FXP_READDIR, :long, 3, :string, "handle-b")
      channel.gets_packet(FXP_NAME, :long, 3, :long, 1, :string, "b1", :long, 0, :byte, 1)
      channel.sends_packet(FXP_READDIR, :long, 4, :string, "handle-a")
      channel.gets_packet(FXP_NAME, :long, 4, :long, 0)
      channel.sends_packet(FXP_READDIR, :long, 5, :string, "handle-b")
      channel.gets_packet(FXP_NAME, :long, 5, :long, 1, :string, "b2", :long, 0, :byte, 1)
      channel.sends_packet(FXP_READDIR, :long, 6, :string, "handle-b")
      channel.gets_packet(FXP_NAME, :long, 6, :long, 0)
    end

    assert_scripted_command do
      counts = count_readdir_requests
      handle_a = sftp.opendir!("/a")
      handle_b = sftp.opendir!("/b")

      assert_equal %w(a1), sftp.readdir!(handle_a).map { |n| n.name }
      assert_equal %w(b1), sftp.readdir!(handle_b).map { |n| n.name }
      assert_nil sftp.readdir!(handle_a)
      assert_equal %w(b2), sftp.readdir!(handle_b).map { |n| n.name }
      assert_nil sftp.readdir!(handle_b)

      assert_equal 2, counts["handle-a"]
      assert_equal 3, counts["handle-b"]
    end
  end

  private

    # Counts READDIR requests per handle by wrapping the live protocol
    # driver, so tests can assert exactly how many requests each directory
    # enumeration caused.
    def count_readdir_requests
      counts = Hash.new(0)
      protocol = sftp.protocol
      original = protocol.method(:readdir)
      protocol.define_singleton_method(:readdir) do |handle|
        counts[handle] += 1
        original.call(handle)
      end
      counts
    end
end

class ReaddirZeroProgressDirTest < Net::SFTP::TestCase
  def setup
    @sftp = mock("sftp")
    @dir = Net::SFTP::Operations::Dir.new(@sftp)
  end

  def test_foreach_aborts_after_too_many_consecutive_empty_batches
    @sftp.expects(:opendir!).with("/d").returns("handle")
    @sftp.expects(:readdir!).with("handle").returns([], [], []).times(3)
    @sftp.expects(:close!).with("handle")

    error = assert_raises(Net::SFTP::Exception) { @dir.foreach("/d") { |e| flunk "unexpected entry #{e}" } }
    assert_match(/empty batches/, error.message)
  end

  def test_foreach_tolerates_empty_batches_up_to_budget
    @sftp.expects(:opendir!).with("/d").returns("handle")
    @sftp.expects(:readdir!).with("handle").returns([], [:e1], [], [], [:e2], nil).times(6)
    @sftp.expects(:close!).with("handle")

    entries = []
    @dir.foreach("/d") { |entry| entries << entry }
    assert_equal [:e1, :e2], entries
  end

  def test_foreach_empty_batch_budget_is_scoped_per_enumeration
    2.times do
      @sftp.expects(:opendir!).with("/d").returns("handle")
      @sftp.expects(:readdir!).with("handle").returns([], [], [:e], nil).times(4)
      @sftp.expects(:close!).with("handle")
    end

    2.times do
      entries = []
      @dir.foreach("/d") { |entry| entries << entry }
      assert_equal [:e], entries
    end
  end
end
