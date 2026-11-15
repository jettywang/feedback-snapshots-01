require 'common'
require 'protocol/03/test_base'

class Protocol::V04::TestBase < Protocol::V03::TestBase
  def test_version
    assert_equal 4, @base.version
  end

  def test_parse_attrs_packet_should_use_correct_attributes_class
    Net::SFTP::Protocol::V04::Attributes.expects(:from_buffer).with(:packet).returns(:result)
    assert_equal({ :attrs => :result }, @base.parse_attrs_packet(:packet))
  end

  def test_parse_name_packet_should_use_correct_name_class
    packet = Net::SSH::Buffer.from(:long, 2,
      :string, "name1", :long, 0x4, :byte, 1, :long, 0755,
      :string, "name2", :long, 0x4, :byte, 1, :long, 0550)
    names = @base.parse_name_packet(packet)[:names]

    refute_nil names
    assert_equal 2, names.length
    assert_instance_of Net::SFTP::Protocol::V04::Name, names.first

    assert_equal "name1", names.first.name
    assert_equal 0755, names.first.attributes.permissions

    assert_equal "name2", names.last.name
    assert_equal 0550, names.last.attributes.permissions
  end

  def test_parse_name_packet_should_keep_an_entry_s_extended_pairs_inside_that_entry
    packet = Net::SSH::Buffer.from(:long, 2,
      :string, "first", :long, 0x80000000, :long, 1,
      :string, "victim", :long, 0x4, :byte, 1, :long, 0644)

    error = assert_raises(Net::SFTP::TruncatedPacketError) { @base.parse_name_packet(packet) }
    assert_match(/extended attribute/, error.message)
  end

  def test_parse_name_packet_should_reject_a_trailing_byte_after_the_entries
    packet = Net::SSH::Buffer.from(:long, 1, :string, "name", :long, 0, :byte, 1, :raw, "\x00")

    assert_raises(Net::SFTP::MalformedPacketError) { @base.parse_name_packet(packet) }
  end

  def test_parse_name_packet_should_reject_an_entry_whose_filename_overlaps_the_next
    packet = Net::SSH::Buffer.from(:long, 2, :string, "name1", :long, 40, :raw, "abc")

    assert_raises(Net::SFTP::TruncatedPacketError) { @base.parse_name_packet(packet) }
  end

  def test_parse_name_packet_with_only_type_attribute_should_format_longname
    packet = Net::SSH::Buffer.from(:long, 1, :string, "name1", :long, 0, :byte, 1)
    names = @base.parse_name_packet(packet)[:names]

    assert_equal "-????????? ?        ?               ?            ? name1", names.first.longname
  end

  undef test_fstat_should_ignore_flags_parameter
  undef test_lstat_should_ignore_flags_parameter
  undef test_stat_should_ignore_flags_parameter
  def test_lstat_should_send_lstat_packet
    @session.expects(:send_packet).with(FXP_LSTAT, :long, 0, :string, "/path/to/file", :long, 0x800001fd)
    assert_equal 0, @base.lstat("/path/to/file")
  end

  def test_lstat_with_custom_flags_should_send_lstat_packet_with_given_flags
    @session.expects(:send_packet).with(FXP_LSTAT, :long, 0, :string, "/path/to/file", :long, 1234)
    assert_equal 0, @base.lstat("/path/to/file", 1234)
  end

  def test_fstat_should_send_fstat_packet
    @session.expects(:send_packet).with(FXP_FSTAT, :long, 0, :string, "handle", :long, 0x800001fd)
    assert_equal 0, @base.fstat("handle")
  end

  def test_fstat_with_custom_flags_should_send_fstat_packet_with_given_flags
    @session.expects(:send_packet).with(FXP_FSTAT, :long, 0, :string, "handle", :long, 1234)
    assert_equal 0, @base.fstat("handle", 1234)
  end

  def test_stat_should_send_stat_packet
    @session.expects(:send_packet).with(FXP_STAT, :long, 0, :string, "/path/to/file", :long, 0x800001fd)
    assert_equal 0, @base.stat("/path/to/file")
  end

  def test_stat_with_custom_flags_should_send_stat_packet_with_given_flags
    @session.expects(:send_packet).with(FXP_STAT, :long, 0, :string, "/path/to/file", :long, 1234)
    assert_equal 0, @base.stat("/path/to/file", 1234)
  end

  def test_parse_name_packet_should_reject_count_larger_than_remaining_data
    packet = Net::SSH::Buffer.from(:long, 500_000, :string, "name1", :long, 0, :byte, 1)
    assert_raises(Net::SFTP::Exception) { @base.parse_name_packet(packet) }
  end

  def test_parse_name_packet_should_keep_an_entry_s_acl_inside_that_entry
    # The first entry's ACL string is eight bytes and holds only one fixed
    # field; the second entry's filename would complete it if the ACL count
    # were checked against the rest of the packet instead of the string.
    packet = Net::SSH::Buffer.from(:long, 2,
      :string, "first", :long, 0x40, :byte, 1, :string, raw(:long, 2, :long, 1, :long, 2, :long, 3, :long, 0),
      :string, "victim", :long, 0, :byte, 1)

    error = assert_raises(Net::SFTP::TruncatedPacketError) { @base.parse_name_packet(packet) }
    assert_match(/ACL/, error.message)
  end

  def test_parse_attrs_packet_should_reject_unknown_flags
    packet = Net::SSH::Buffer.from(:long, 0x00010000, :byte, 1)

    assert_raises(Net::SFTP::UnsupportedAttributeFlagsError) { @base.parse_attrs_packet(packet) }
  end

  private

    def driver
      Net::SFTP::Protocol::V04::Base
    end

    def attributes
      Net::SFTP::Protocol::V04::Attributes
    end
end
