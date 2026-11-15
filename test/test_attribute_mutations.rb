require 'common'

# A short, protocol-aware corpus of ATTRS and FXP_NAME responses. Each sample
# differs from a normal response for the same protocol version in one flag,
# length or field, while the request id and outer packet framing stay valid.
#
# The samples are fed through a real Net::SFTP::Session so the assertions cover
# response dispatch and the API a caller sees, not just the attribute parser.
class AttributeMutationTest < Net::SFTP::TestCase
  include Net::SFTP::Constants
  include Net::SFTP::Constants::PacketTypes

  VERSIONS = [3, 4, 6].freeze

  # v3 flag bits.
  F_SIZE        = 0x00000001
  F_UIDGID      = 0x00000002
  F_PERMISSIONS = 0x00000004
  F_ACMODTIME   = 0x00000008
  F_EXTENDED    = 0x80000000

  # v4 and v6 flag bits. F_ACMODTIME is split into F_ACCESSTIME and
  # F_MODIFYTIME in these versions.
  F_ACCESSTIME  = 0x00000008
  F_CREATETIME  = 0x00000010
  F_MODIFYTIME  = 0x00000020
  F_ACL         = 0x00000040
  F_OWNERGROUP  = 0x00000080
  F_SUBSECOND   = 0x00000100

  # v6-only flag bits.
  F_BITS              = 0x00000200
  F_ALLOCATION        = 0x00000400
  F_TEXT_HINT         = 0x00000800
  F_MIME_TYPE         = 0x00001000
  F_LINK_COUNT        = 0x00002000
  F_UNTRANSLATED_NAME = 0x00004000
  F_CTIME             = 0x00008000

  V3_FULL_FLAGS = F_SIZE | F_UIDGID | F_PERMISSIONS | F_ACMODTIME | F_EXTENDED
  V4_FULL_FLAGS = F_SIZE | F_PERMISSIONS | F_ACCESSTIME | F_CREATETIME |
                  F_MODIFYTIME | F_ACL | F_OWNERGROUP | F_SUBSECOND | F_EXTENDED
  V6_FULL_FLAGS = V4_FULL_FLAGS | F_BITS | F_ALLOCATION | F_TEXT_HINT |
                  F_MIME_TYPE | F_LINK_COUNT | F_UNTRANSLATED_NAME | F_CTIME

  # ---------------------------------------------------------------------------
  # Normal cross-version controls
  # ---------------------------------------------------------------------------

  def test_normal_attributes_are_parsed_through_the_session
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, full_attrs(version))

      assert_nil error, "v#{version} normal attributes should parse"
      assert_equal 1234, attributes.size, "v#{version} size"
      assert_equal 0755, attributes.permissions, "v#{version} permissions"
      assert_equal({ "k" => "v" }, attributes.extended, "v#{version} extended")
    end
  end

  def test_normal_attributes_expose_version_specific_fields
    attributes, = fetch_attrs(3, full_attrs(3))
    assert_equal 11, attributes.uid
    assert_equal 22, attributes.gid

    attributes, = fetch_attrs(4, full_attrs(4))
    assert_equal "owner", attributes.owner
    assert_equal 100, attributes.atime
    assert_equal 110, attributes.createtime
    assert_equal 120, attributes.mtime
    assert_equal 1, attributes.acl.length

    attributes, = fetch_attrs(6, full_attrs(6))
    assert_equal 4321, attributes.allocation_size
    assert_equal 130, attributes.ctime
    assert_equal "text/plain", attributes.mime_type
    assert_equal 3, attributes.link_count
    assert_equal "pre", attributes.untranslated_name
  end

  def test_normal_name_entries_are_parsed_through_the_session
    VERSIONS.each do |version|
      names, error = fetch_names(version, full_names(version))

      assert_nil error, "v#{version} normal names should parse"
      assert_equal %w(dir file), names.map(&:name), "v#{version} names"
      assert names.first.directory?, "v#{version} dir type"
      refute names.last.directory?, "v#{version} file type"
      assert_equal 0644, names.last.attributes.permissions, "v#{version} file perms"
      assert_equal({ "k" => "v" }, names.last.attributes.extended, "v#{version} nested extended")
    end
  end

  # ---------------------------------------------------------------------------
  # Legal empty attributes
  # ---------------------------------------------------------------------------

  def test_empty_attributes_are_accepted_and_are_not_mistaken_for_permissions
    { 3 => raw(:long, 0), 4 => raw(:long, 0, :byte, 1), 6 => raw(:long, 0, :byte, 1) }.each do |version, body|
      attributes, error = fetch_attrs(version, body)

      assert_nil error, "v#{version} empty attributes are legal"
      assert_nil attributes.size, "v#{version} empty size"
      assert_nil attributes.permissions, "v#{version} empty permissions"
      refute_equal 0644, attributes.permissions, "v#{version} empty must not look like 0644"
    end
  end

  def test_empty_extended_hash_is_accepted
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, empty_extended_attrs(version))

      assert_nil error, "v#{version} zero extended pairs are legal"
      assert_equal({}, attributes.extended, "v#{version} empty extended")
      assert_nil attributes.permissions, "v#{version} no permissions were sent"
    end
  end

  # ---------------------------------------------------------------------------
  # Flag mutations
  # ---------------------------------------------------------------------------

  def test_unknown_flags_are_rejected_instead_of_shifting_the_fields
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, unknown_flag_attrs(version))

      assert_nil attributes, "v#{version} unknown flags must not yield attributes"
      assert_instance_of Net::SFTP::UnsupportedAttributeFlagsError, error, "v#{version} unknown flags"
    end
  end

  def test_flags_from_a_later_version_are_unknown_to_an_older_protocol
    _, error = fetch_attrs(3, raw(:long, F_ACL, :long, 0))
    assert_instance_of Net::SFTP::UnsupportedAttributeFlagsError, error, "v3 must not accept a v4 ACL flag"

    _, error = fetch_attrs(4, raw(:long, F_ALLOCATION, :byte, 1, :int64, 99))
    assert_instance_of Net::SFTP::UnsupportedAttributeFlagsError, error, "v4 must not accept a v6 allocation flag"
  end

  def test_flags_defined_by_the_protocol_version_are_accepted
    attributes, error = fetch_attrs(6, raw(:long, F_ALLOCATION, :byte, 1, :int64, 99))

    assert_nil error
    assert_equal 99, attributes.allocation_size
    assert_nil attributes.size
  end

  def test_subsecond_flag_without_a_timestamp_is_rejected_as_misplaced_bytes
    [4, 6].each do |version|
      body = raw(:long, F_SUBSECOND, :byte, 1, :long, 5)
      attributes, error = fetch_attrs(version, body)

      assert_nil attributes, "v#{version} subsecond flag alone must not parse"
      assert_instance_of Net::SFTP::MalformedPacketError, error, "v#{version} nseconds without a time"
    end
  end

  # ---------------------------------------------------------------------------
  # Length and field mutations
  # ---------------------------------------------------------------------------

  def test_size_field_shorter_than_int64_is_rejected
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, truncated_size_attrs(version))

      assert_nil attributes, "v#{version} truncated size must not yield attributes"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} truncated size"
    end
  end

  def test_permissions_field_shorter_than_long_is_rejected
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, truncated_permissions_attrs(version))

      assert_nil attributes, "v#{version} truncated permissions must not yield attributes"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} truncated permissions"
    end
  end

  def test_string_length_larger_than_the_packet_is_rejected
    [4, 6].each do |version|
      body = raw(:long, F_OWNERGROUP, :byte, 1, :long, 50, :raw, "abc")
      attributes, error = fetch_attrs(version, body)

      assert_nil attributes, "v#{version} overlong owner string must not parse"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} overlong owner string"
    end
  end

  def test_mime_type_length_larger_than_the_packet_is_rejected
    body = raw(:long, F_MIME_TYPE, :byte, 1, :long, 40, :raw, "abc")
    attributes, error = fetch_attrs(6, body)

    assert_nil attributes
    assert_instance_of Net::SFTP::TruncatedPacketError, error
  end

  def test_fields_supplied_out_of_order_are_rejected
    [4, 6].each do |version|
      # permissions (a long) is placed where the owner string belongs, so the
      # 0755 is read as a string length instead of being accepted as a mode.
      body = raw(:long, F_OWNERGROUP | F_PERMISSIONS, :byte, 1, :long, 0755)
      attributes, error = fetch_attrs(version, body)

      assert_nil attributes, "v#{version} out-of-order fields must not parse"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} out-of-order fields"
    end
  end

  def test_truncated_ctime_nseconds_is_rejected
    body = raw(:long, F_CTIME | F_SUBSECOND, :byte, 1, :int64, 130, :raw, "\x00\x00")
    attributes, error = fetch_attrs(6, body)

    assert_nil attributes
    assert_instance_of Net::SFTP::TruncatedPacketError, error
  end

  def test_trailing_bytes_after_the_attributes_are_rejected
    { 3 => raw(:long, 0, :raw, "\x00"),
      4 => raw(:long, 0, :byte, 1, :raw, "\x00"),
      6 => raw(:long, 0, :byte, 1, :raw, "\x00") }.each do |version, body|
      attributes, error = fetch_attrs(version, body)

      assert_nil attributes, "v#{version} trailing bytes must not parse"
      assert_instance_of Net::SFTP::MalformedPacketError, error, "v#{version} trailing bytes"
    end
  end

  # ---------------------------------------------------------------------------
  # Extended attribute boundaries
  # ---------------------------------------------------------------------------

  def test_extended_count_without_a_count_field_is_rejected
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, missing_extended_count_attrs(version))

      assert_nil attributes, "v#{version} missing extended count must not parse"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} missing extended count"
    end
  end

  def test_extended_count_larger_than_the_packet_is_rejected
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, overrun_extended_count_attrs(version))

      assert_nil attributes, "v#{version} oversized extended count must not parse"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} oversized extended count"
    end
  end

  def test_extended_pair_with_a_missing_value_is_rejected
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, truncated_extended_pair_attrs(version))

      assert_nil attributes, "v#{version} half pair must not parse"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} half pair"
    end
  end

  # ---------------------------------------------------------------------------
  # FXP_NAME: nested attributes must stay inside their own directory entry
  # ---------------------------------------------------------------------------

  def test_name_entry_truncation_is_rejected
    VERSIONS.each do |version|
      body = raw(:long, 1, :long, 100, :raw, "abc")
      names, error = fetch_names(version, body)

      assert_nil names, "v#{version} truncated filename must not yield names"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} truncated filename"
    end
  end

  def test_name_entry_trailing_bytes_are_rejected
    { 3 => raw(:long, 1, :string, "a", :string, "l", :long, 0, :raw, "\x00"),
      4 => raw(:long, 1, :string, "a", :long, 0, :byte, 1, :raw, "\x00"),
      6 => raw(:long, 1, :string, "a", :long, 0, :byte, 1, :raw, "\x00") }.each do |version, body|
      names, error = fetch_names(version, body)

      assert_nil names, "v#{version} trailing bytes in a name entry must not parse"
      assert_instance_of Net::SFTP::MalformedPacketError, error, "v#{version} name trailing bytes"
    end
  end

  def test_name_nested_unknown_flags_are_rejected
    { 3 => raw(:long, 1, :string, "a", :string, "l", :long, F_SUBSECOND),
      4 => raw(:long, 1, :string, "a", :long, 0x200, :byte, 1),
      6 => raw(:long, 1, :string, "a", :long, 0x00010000, :byte, 1) }.each do |version, body|
      names, error = fetch_names(version, body)

      assert_nil names, "v#{version} unknown nested flags must not yield names"
      assert_instance_of Net::SFTP::UnsupportedAttributeFlagsError, error, "v#{version} nested unknown flags"
    end
  end

  def test_name_nested_attributes_shorter_than_their_flags_are_rejected
    { 3 => raw(:long, 1, :string, "a", :string, "l", :long, F_PERMISSIONS, :raw, "\x00\x00"),
      4 => raw(:long, 1, :string, "a", :long, F_PERMISSIONS, :byte, 1, :raw, "\x00\x00"),
      6 => raw(:long, 1, :string, "a", :long, F_PERMISSIONS, :byte, 1, :raw, "\x00\x00") }.each do |version, body|
      names, error = fetch_names(version, body)

      assert_nil names, "v#{version} truncated nested permissions must not yield names"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} nested truncated permissions"
    end
  end

  # The counterexample: without an entry boundary, the first entry's extended
  # count is satisfied by bytes that belong to the second entry. #legacy_first_
  # name_extended below reproduces the old unbounded loop on exactly the same
  # bytes the hardened parser now rejects.
  def test_without_the_entry_boundary_extended_attributes_borrow_the_next_entry
    VERSIONS.each do |version|
      body = borrowing_names(version)

      borrowed = legacy_first_name_extended(version, body)
      assert_equal ["victim"], borrowed.keys,
        "v#{version} legacy parse takes the next entry's filename as the extended name"
      assert_equal expected_borrowed_value(version), borrowed["victim"],
        "v#{version} legacy parse takes the next entry's bytes as the extended value"

      names, error = fetch_names(version, body)
      assert_nil names, "v#{version} borrowed attributes must not reach the caller"
      assert_instance_of Net::SFTP::TruncatedPacketError, error,
        "v#{version} the entry boundary must reject the borrowed pair"
    end
  end

  def expected_borrowed_value(version)
    if version == 3
      "long-victim"
    else
      # The v4+ next entry has no longname, so the value string starts at the
      # permissions flag: 0x00000004 is read as a four-byte length, and the
      # entry type byte followed by the first three bytes of the 0644 mode
      # fill it.
      "\x01\x00\x00\x01"
    end
  end

  def test_legacy_borrow_yields_a_plausible_pair_from_the_next_entry
    borrowed = legacy_first_name_extended(3, borrowing_names(3))
    assert_equal({ "victim" => "long-victim" }, borrowed)

    borrowed = legacy_first_name_extended(4, borrowing_names(4))
    assert_equal({ "victim" => "\x01\x00\x00\x01" }, borrowed)
  end

  # ---------------------------------------------------------------------------
  # A parse failure must fail the request, not hand out partial attributes
  # ---------------------------------------------------------------------------

  def test_failed_parse_does_not_invoke_the_callback_or_expose_a_response
    fresh_session!
    expect_sftp_session :server_version => 3 do |channel|
      channel.sends_packet(FXP_LSTAT, :long, 0, :string, "/bad")
      channel.gets_packet(FXP_ATTRS, :long, 0, :long, F_SIZE | F_PERMISSIONS,
        :int64, 1234, :raw, "\x00\x00")
      channel.sends_packet(FXP_STAT, :long, 1, :string, "/good")
      channel.gets_packet(FXP_ATTRS, :long, 1, :long, F_PERMISSIONS, :long, 0644)
    end

    called = false
    request = nil

    assert_scripted do
      sftp.connect!
      request = sftp.lstat("/bad") { called = true }

      error = assert_raises(Net::SFTP::TruncatedPacketError) { sftp.loop }
      assert_match(/permissions/, error.message)

      refute called, "callback must not see a partially parsed attributes object"
      refute request.pending?
      assert_nil request.response
      assert_raises(Net::SFTP::TruncatedPacketError) { request.wait }

      assert sftp.open?, "a rejected response must not close the session"
      assert_empty sftp.pending_requests

      attributes = sftp.stat!("/good")
      assert_equal 0644, attributes.permissions
      assert_nil attributes.size
    end
  end

  def test_synchronous_stat_raises_instead_of_returning_a_partial_attributes_object
    VERSIONS.each do |version|
      attributes, error = fetch_attrs(version, truncated_permissions_attrs(version))

      assert_nil attributes, "v#{version} stat! must not return attributes on a parse error"
      assert_instance_of Net::SFTP::TruncatedPacketError, error, "v#{version} stat! error class"
    end
  end

  private

    def fetch_attrs(version, body)
      attributes = nil
      error = nil

      fresh_session!
      expect_sftp_session :server_version => version do |channel|
        args = [:long, 0, :string, "/path/to/file"]
        args += [:long, V4_FULL_FLAGS] if version >= 4
        channel.sends_packet(FXP_STAT, *args)
        channel.gets_packet(FXP_ATTRS, :long, 0, :raw, body)
      end

      assert_scripted do
        sftp.connect!
        begin
          attributes = sftp.stat!("/path/to/file")
        rescue Net::SFTP::Exception => e
          error = e
        end
      end

      [attributes, error]
    end

    def fetch_names(version, body)
      names = nil
      error = nil

      fresh_session!
      expect_sftp_session :server_version => version do |channel|
        channel.sends_packet(FXP_READDIR, :long, 0, :string, "handle")
        channel.gets_packet(FXP_NAME, :long, 0, :raw, body)
      end

      assert_scripted do
        sftp.connect!
        begin
          names = sftp.readdir!("handle")
        rescue Net::SFTP::Exception => e
          error = e
        end
      end

      [names, error]
    end

    # Each sample is a separate scripted SSH session, so drop the memoized
    # socket, transport, connection and SFTP session between samples.
    def fresh_session!
      @sftp = @connection = @transport = @socket = nil
    end

    def full_attrs(version)
      case version
      when 3
        raw(:long, V3_FULL_FLAGS,
          :int64, 1234, :long, 11, :long, 22, :long, 0755,
          :long, 100, :long, 200,
          :long, 1, :string, "k", :string, "v")
      when 4
        raw(:long, V4_FULL_FLAGS,
          :byte, 1, :int64, 1234,
          :string, "owner", :string, "group", :long, 0755,
          :int64, 100, :long, 5,
          :int64, 110, :long, 6,
          :int64, 120, :long, 7,
          :string, raw(:long, 1, :long, 1, :long, 2, :long, 3, :string, "who"),
          :long, 1, :string, "k", :string, "v")
      when 6
        raw(:long, V6_FULL_FLAGS,
          :byte, 1, :int64, 1234, :int64, 4321,
          :string, "owner", :string, "group", :long, 0755,
          :int64, 100, :long, 5,
          :int64, 110, :long, 6,
          :int64, 120, :long, 7,
          :int64, 130, :long, 8,
          :string, raw(:long, 1, :long, 1, :long, 2, :long, 3, :string, "who"),
          :long, 0x1234, :long, 0x5678, :byte, 2,
          :string, "text/plain", :long, 3, :string, "pre",
          :long, 1, :string, "k", :string, "v")
      end
    end

    def full_names(version)
      if version == 3
        raw(:long, 2,
          :string, "dir", :string, "drwxr-xr-x dir", :long, F_PERMISSIONS, :long, 040755,
          :string, "file", :string, "-rw-r--r-- file", :long, F_PERMISSIONS | F_EXTENDED, :long, 0644,
            :long, 1, :string, "k", :string, "v")
      else
        raw(:long, 2,
          :string, "dir", :long, F_PERMISSIONS, :byte, 2, :long, 040755,
          :string, "file", :long, F_PERMISSIONS | F_EXTENDED, :byte, 1, :long, 0644,
            :long, 1, :string, "k", :string, "v")
      end
    end

    def empty_extended_attrs(version)
      if version == 3
        raw(:long, F_EXTENDED, :long, 0)
      else
        raw(:long, F_EXTENDED, :byte, 1, :long, 0)
      end
    end

    def unknown_flag_attrs(version)
      case version
      when 3 then raw(:long, F_SUBSECOND)
      when 4 then raw(:long, 0x200, :byte, 1)
      when 6 then raw(:long, 0x00010000, :byte, 1)
      end
    end

    def truncated_size_attrs(version)
      if version == 3
        raw(:long, F_SIZE, :long, 0)
      else
        raw(:long, F_SIZE, :byte, 1, :long, 0)
      end
    end

    def truncated_permissions_attrs(version)
      if version == 3
        raw(:long, F_SIZE | F_PERMISSIONS, :int64, 1234, :raw, "\x00\x00")
      else
        raw(:long, F_SIZE | F_PERMISSIONS, :byte, 1, :int64, 1234, :raw, "\x00\x00")
      end
    end

    def missing_extended_count_attrs(version)
      if version == 3
        raw(:long, F_EXTENDED)
      else
        raw(:long, F_EXTENDED, :byte, 1)
      end
    end

    def overrun_extended_count_attrs(version)
      if version == 3
        raw(:long, F_EXTENDED, :long, 3, :string, "k", :string, "v")
      else
        raw(:long, F_EXTENDED, :byte, 1, :long, 3, :string, "k", :string, "v")
      end
    end

    def truncated_extended_pair_attrs(version)
      if version == 3
        raw(:long, F_EXTENDED, :long, 1, :string, "k")
      else
        raw(:long, F_EXTENDED, :byte, 1, :long, 1, :string, "k")
      end
    end

    def borrowing_names(version)
      if version == 3
        raw(:long, 2,
          :string, "first", :string, "longfirst", :long, F_EXTENDED, :long, 1,
          :string, "victim", :string, "long-victim", :long, F_PERMISSIONS, :long, 0644)
      else
        raw(:long, 2,
          :string, "first", :long, F_EXTENDED, :long, 1,
          :string, "victim", :long, F_PERMISSIONS, :byte, 1, :long, 0644)
      end
    end

    # Reproduces the pre-hardening parse: the count is read from the entry, but
    # its pairs are read from the packet with no entry or structure limit.
    def legacy_first_name_extended(version, body)
      buffer = Net::SSH::Buffer.new(body)
      buffer.read_long

      if version == 3
        buffer.read_string
        buffer.read_string
      else
        buffer.read_string
      end

      flags = buffer.read_long
      return nil if flags & F_EXTENDED == 0

      extended = {}
      buffer.read_long.times do
        extended[buffer.read_string] = buffer.read_string
      end
      extended
    end
end
