require "common"

class ConfirmedUploadTest < Net::SFTP::TestCase
  POSIX_RENAME = "posix-rename@openssh.com"
  FSYNC = "fsync@openssh.com"

  EXTENSIONS = { POSIX_RENAME => "1", FSYNC => "1" }.freeze

  def test_successful_upload_switches_the_final_path_only_after_write_close_and_verification
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abc")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_WRITE, :long, 2, :string, "handle", :int64, 3, :string, "def")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 3, :string, FSYNC, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 4, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 4, :long, 0)
      channel.sends_packet(FXP_STAT, :long, 5, :string, "/remote/staging")
      channel.gets_packet(FXP_ATTRS, :long, 5, :long, 0x1, :int64, 6)
      channel.sends_packet(FXP_EXTENDED, :long, 6, :string, POSIX_RENAME,
                           :string, "/remote/staging", :string, "/remote/file")
      channel.gets_packet(FXP_STATUS, :long, 6, :long, 0)
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging",
                                       :read_size => 3)
    end

    assert_equal :published, result.state
    assert result.published?
    assert result.content_confirmed?
    assert result.all_writes_confirmed?
    assert result.verified?
    assert_equal 6, result.bytes_from_source
    assert_equal 6, result.bytes_confirmed
    assert_equal 2, result.writes_sent
    assert_equal 2, result.writes_confirmed
    assert_equal :confirmed, result.fsync
    assert_equal :file_data_flushed, result.durability
    assert_equal :unknown, result.directory_entry_durability
    assert_equal :confirmed, result.close
    assert_equal :size_confirmed, result.verification
    assert_equal :confirmed, result.rename
    assert_equal :renamed, result.staging_cleanup
    assert_match(/^published at \/remote\/file/, result.notification)
    assert_match(/directory entry durability is unknown/, result.notification)
  end

  def test_write_failure_keeps_the_final_path_and_reports_only_acknowledged_bytes
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abc")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_WRITE, :long, 2, :string, "handle", :int64, 3, :string, "def")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 4, :string, "No space left on device", :string, "")
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging",
                                       :read_size => 3)
    end

    assert_equal :partial, result.state
    refute result.published?
    refute result.content_confirmed?
    refute result.all_writes_confirmed?
    assert_equal 6, result.bytes_from_source
    assert_equal 3, result.bytes_confirmed
    assert_equal 2, result.writes_sent
    assert_equal 1, result.writes_confirmed
    assert_equal :confirmed, result.close
    assert_equal :not_attempted, result.fsync
    assert_equal :not_attempted, result.verification
    assert_equal :not_attempted, result.rename
    assert_equal :unknown, result.durability
    assert_equal :retained, result.staging_cleanup
    assert_equal 4, result.write_error.code
    assert_match(/^not published; transfer incomplete/, result.notification)
    assert_match(/3\/6 bytes acknowledged/, result.notification)
  end

  def test_close_failure_stops_before_verification_and_rename
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abcdef")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, FSYNC, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 4, :string, "close failed", :string, "")
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging")
    end

    assert_equal :partial, result.state
    refute result.published?
    refute result.content_confirmed?
    assert result.all_writes_confirmed?
    refute result.verified?
    assert_equal :not_attempted, result.verification
    assert_equal :failed, result.close
    assert_equal :confirmed, result.fsync
    assert_equal :file_data_flushed, result.durability
    assert_equal :not_attempted, result.rename
    assert_equal :retained, result.staging_cleanup
    assert_equal 4, result.close_error.code
    assert_match(/^not published; transfer incomplete/, result.notification)
  end

  def test_missing_posix_rename_leaves_a_verified_staging_file
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abcdef")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 2, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_STAT, :long, 3, :string, "/remote/staging")
      channel.gets_packet(FXP_ATTRS, :long, 3, :long, 0x1, :int64, 6)
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging")
    end

    assert_equal :staged, result.state
    refute result.published?
    assert result.content_confirmed?
    assert_equal :fsync_unsupported, result.fsync
    assert_equal :fsync_unsupported, result.durability
    assert_equal :unsupported, result.rename
    assert_equal :retained, result.staging_cleanup
    assert_match(/^not published; verified staging file retained at \/remote\/staging/, result.notification)
  end

  def test_fsync_failure_blocks_the_final_path_switch
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abcdef")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, FSYNC, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 4, :string, "fsync failed", :string, "")
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging")
    end

    assert_equal :partial, result.state
    refute result.published?
    refute result.file_data_flushed?
    assert_equal :failed, result.fsync
    assert_equal :fsync_failed, result.durability
    assert_equal :not_attempted, result.rename
    assert_equal 4, result.fsync_error.code
  end

  def test_readback_digest_confirms_the_bytes_returned_through_sftp
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abcdef")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, FSYNC, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.sends_packet(FXP_OPEN, :long, 4, :string, "/remote/staging", :long, 0x1, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 4, :string, "read")
      channel.sends_packet(FXP_READ, :long, 5, :string, "read", :int64, 0, :long, 32_000)
      channel.gets_packet(FXP_DATA, :long, 5, :string, "abcdef")
      channel.sends_packet(FXP_READ, :long, 6, :string, "read", :int64, 6, :long, 32_000)
      channel.gets_packet(FXP_STATUS, :long, 6, :long, 1)
      channel.sends_packet(FXP_CLOSE, :long, 7, :string, "read")
      channel.gets_packet(FXP_STATUS, :long, 7, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 8, :string, POSIX_RENAME,
                           :string, "/remote/staging", :string, "/remote/file")
      channel.gets_packet(FXP_STATUS, :long, 8, :long, 0)
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging",
                                       :verify => :readback)
    end

    assert_equal :published, result.state
    assert result.content_confirmed?
    assert result.verified?
    assert_equal :digest_confirmed, result.verification
    assert_equal Digest::SHA256.hexdigest("abcdef"), result.source_digest
    assert_equal result.source_digest, result.remote_digest
  end

  def test_missing_bound_handle_is_not_reported_as_delivered
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_STATUS, :long, 0, :long, 3, :string, "Permission denied", :string, "")
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging")
    end

    assert_equal :failed, result.state
    refute result.published?
    assert_equal :failed, result.open
    assert_equal 3, result.open_error.code
    assert_equal 0, result.bytes_confirmed
    assert_equal :not_attempted, result.close
  end

  def test_lost_rename_reply_is_unknown_not_failed_or_published
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abcdef")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, FSYNC, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
      channel.sends_packet(FXP_STAT, :long, 4, :string, "/remote/staging")
      channel.gets_packet(FXP_ATTRS, :long, 4, :long, 0x1, :int64, 6)
      channel.sends_packet(FXP_EXTENDED, :long, 5, :string, POSIX_RENAME,
                           :string, "/remote/staging", :string, "/remote/file")
      channel.gets_close
      channel.sends_close
    end

    result = nil
    assert_scripted do
      sftp.connect!
      Timeout.timeout(5) do
        result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                         :staging_path => "/remote/staging")
      end
      flush_channel_close
    end

    assert_equal :unknown, result.state
    refute result.published?
    assert_equal :failed, result.rename
    assert_equal :unknown, result.durability
    assert_match(/^outcome unknown/, result.notification)
  end

  def test_lost_close_reply_is_unknown_and_does_not_publish
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abcdef")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 0)
      channel.sends_packet(FXP_EXTENDED, :long, 2, :string, FSYNC, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_CLOSE, :long, 3, :string, "handle")
      channel.gets_close
      channel.sends_close
    end

    result = nil
    assert_scripted do
      sftp.connect!
      Timeout.timeout(5) do
        result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                         :staging_path => "/remote/staging")
      end
      flush_channel_close
    end

    assert_equal :partial, result.state
    refute result.published?
    assert_equal :unknown, result.close
    assert_equal :not_attempted, result.verification
    assert_equal :not_attempted, result.rename
    assert_equal :unknown, result.durability
  end

  def test_cleanup_on_failure_removes_the_staging_file
    expect_sftp_session :server_version => 3, :extensions => EXTENSIONS do |channel|
      channel.sends_packet(FXP_OPEN, :long, 0, :string, "/remote/staging", :long, 0x2A, :long, 0)
      channel.gets_packet(FXP_HANDLE, :long, 0, :string, "handle")
      channel.sends_packet(FXP_WRITE, :long, 1, :string, "handle", :int64, 0, :string, "abc")
      channel.gets_packet(FXP_STATUS, :long, 1, :long, 4, :string, "No space left on device", :string, "")
      channel.sends_packet(FXP_CLOSE, :long, 2, :string, "handle")
      channel.gets_packet(FXP_STATUS, :long, 2, :long, 0)
      channel.sends_packet(FXP_REMOVE, :long, 3, :string, "/remote/staging")
      channel.gets_packet(FXP_STATUS, :long, 3, :long, 0)
    end

    result = nil
    assert_scripted do
      sftp.connect!
      result = sftp.confirmed_upload!(StringIO.new("abcdef"), "/remote/file",
                                       :staging_path => "/remote/staging",
                                       :read_size => 3,
                                       :cleanup => :on_failure)
    end

    assert_equal :failed, result.state
    assert_equal :removed, result.staging_cleanup
    assert_equal 0, result.bytes_confirmed
    assert_match(/^not published; the transfer failed/, result.notification)
  end
end
