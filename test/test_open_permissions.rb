require "common"

# Cross-version regression for the permission mapping behind
# Net::SFTP::Session#open.
#
# The same caller intent (an IO flag set or an IO#open mode string) is encoded
# differently depending on the negotiated SFTP version:
#
#   * v1-v4 send a single pflags bitmask (Constants::OpenFlags::FV1).
#   * v5-v6 send a desired-access mask (Constants::ACE::Mask) plus a separate
#     creation/disposition value (Constants::OpenFlags::FV5), optionally OR-ed
#     with FV5::APPEND_DATA.
#
# These tests assert the exact bytes handed to Session#send_packet, so a change
# that silently widens access, truncates an existing file, or drops an
# exclusive-create requirement fails here rather than reaching a server. They
# also prove that intents which cannot be represented safely raise
# ArgumentError *before* any packet is constructed or transmitted.
class OpenPermissionsTest < Net::SFTP::TestCase
  include Net::SFTP::Constants
  include Net::SFTP::Constants::PacketTypes
  include Net::SFTP::Constants::OpenFlags

  PATH = "/path/to/file".freeze

  def self.vector_name(label)
    label.gsub(/[^a-z0-9]+/i, "_").sub(/^_/, "").downcase
  end

  READ_ACCESS      = ACE::Mask::READ_DATA | ACE::Mask::READ_ATTRIBUTES
  WRITE_ACCESS     = ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES
  RDWR_ACCESS      = READ_ACCESS | WRITE_ACCESS
  APPEND_WRITE     = WRITE_ACCESS | ACE::Mask::APPEND_DATA
  APPEND_RDWR      = RDWR_ACCESS | ACE::Mask::APPEND_DATA

  # Short packet vectors: every representable intent, with the concrete
  # pflags (v3) or desired-access + disposition (v5/v6) that must appear in
  # the FXP_OPEN packet. Values come straight from the SFTP protocol
  # constants, not from assumptions about server behaviour.
  V3_VECTORS = {
    "r read-only, existing file" =>
      ["r",                                       FV1::READ],
    "r+ read-write, existing file" =>
      ["r+",                                      FV1::READ | FV1::WRITE],
    "w write-only, create and truncate" =>
      ["w",                                       FV1::WRITE | FV1::CREAT | FV1::TRUNC],
    "w+ read-write, create and truncate" =>
      ["w+",                                      FV1::READ | FV1::WRITE | FV1::CREAT | FV1::TRUNC],
    "a append, create if missing, write-only" =>
      ["a",                                       FV1::WRITE | FV1::APPEND | FV1::CREAT],
    "a+ append, create if missing, read-write" =>
      ["a+",                                      FV1::READ | FV1::WRITE | FV1::APPEND | FV1::CREAT],
    "RDONLY numeric, existing file" =>
      [IO::RDONLY,                                FV1::READ],
    "RDWR numeric, existing file" =>
      [IO::RDWR,                                  FV1::READ | FV1::WRITE],
    "WRONLY numeric, open existing, never create" =>
      [IO::WRONLY,                                FV1::WRITE],
    "exclusive create, read-write" =>
      [IO::RDWR | IO::CREAT | IO::EXCL,           FV1::READ | FV1::WRITE | FV1::CREAT | FV1::EXCL],
    "exclusive create, write-only" =>
      [IO::WRONLY | IO::CREAT | IO::EXCL,         FV1::WRITE | FV1::CREAT | FV1::EXCL],
    "read-only create, no write bit" =>
      [IO::RDONLY | IO::CREAT,                    FV1::READ | FV1::CREAT],
    "truncate existing, read-write" =>
      [IO::RDWR | IO::TRUNC,                      FV1::READ | FV1::WRITE | FV1::TRUNC],
    "append to existing file, write-only" =>
      [IO::WRONLY | IO::APPEND,                   FV1::WRITE | FV1::APPEND],
  }.freeze

  V5_VECTORS = {
    "r read-only, existing file" =>
      ["r",                                       READ_ACCESS,  FV5::OPEN_EXISTING],
    "r+ read-write, existing file" =>
      ["r+",                                      RDWR_ACCESS,  FV5::OPEN_EXISTING],
    "w write-only, create and truncate" =>
      ["w",                                       WRITE_ACCESS, FV5::CREATE_TRUNCATE],
    "w+ read-write, create and truncate" =>
      ["w+",                                      RDWR_ACCESS,  FV5::CREATE_TRUNCATE],
    "a append, create if missing, write-only" =>
      ["a",                                       APPEND_WRITE, FV5::OPEN_OR_CREATE | FV5::APPEND_DATA],
    "a+ append, create if missing, read-write" =>
      ["a+",                                      APPEND_RDWR,  FV5::OPEN_OR_CREATE | FV5::APPEND_DATA],
    "RDONLY numeric, existing file" =>
      [IO::RDONLY,                                READ_ACCESS,  FV5::OPEN_EXISTING],
    "RDWR numeric, existing file" =>
      [IO::RDWR,                                  RDWR_ACCESS,  FV5::OPEN_EXISTING],
    "WRONLY numeric, open existing, never create" =>
      [IO::WRONLY,                                WRITE_ACCESS, FV5::OPEN_EXISTING],
    "exclusive create, read-write" =>
      [IO::RDWR | IO::CREAT | IO::EXCL,           RDWR_ACCESS,  FV5::CREATE_NEW],
    "exclusive create, write-only" =>
      [IO::WRONLY | IO::CREAT | IO::EXCL,         WRITE_ACCESS, FV5::CREATE_NEW],
    "read-only create, no write bit" =>
      [IO::RDONLY | IO::CREAT,                    READ_ACCESS,  FV5::OPEN_OR_CREATE],
    "truncate existing, read-write" =>
      [IO::RDWR | IO::TRUNC,                      RDWR_ACCESS,  FV5::TRUNCATE_EXISTING],
    "append to existing file, write-only" =>
      [IO::WRONLY | IO::APPEND,                   APPEND_WRITE, FV5::OPEN_EXISTING | FV5::APPEND_DATA],
  }.freeze

  # Intents no SFTP version can represent without either dropping a safety
  # guarantee or gaining a destructive power. Each must be rejected on every
  # driver before a packet goes out.
  UNSAFE_VECTORS = {
    "exclusive flag without create loses exclusivity" =>
      IO::RDONLY | IO::EXCL,
    "write exclusive flag without create loses exclusivity" =>
      IO::WRONLY | IO::EXCL,
    "truncate without write would destroy data from a read handle" =>
      IO::RDONLY | IO::TRUNC,
  }.freeze

  def setup
    @session = stub("session", :logger => nil, :pending_requests => {})
  end

  V3_VECTORS.each do |label, (flags, pflags)|
    define_method("test_v3_#{OpenPermissionsTest.vector_name(label)}_emits_exact_pflags") do
      @session.expects(:send_packet).with(
        FXP_OPEN, :long, 0, :string, PATH, :long, pflags, :raw, attributes(3).new.to_s)
      driver(3).open(PATH, flags, {})
    end
  end

  V5_VECTORS.each do |label, (flags, access, disposition)|
    [5, 6].each do |version|
      define_method("test_v#{version}_#{OpenPermissionsTest.vector_name(label)}_emits_exact_access_and_disposition") do
        @session.expects(:send_packet).with(
          FXP_OPEN, :long, 0, :string, PATH,
          :long, access, :long, disposition, :raw, attributes(version).new.to_s)
        driver(version).open(PATH, flags, {})
      end
    end
  end

  UNSAFE_VECTORS.each do |label, flags|
    [3, 5, 6].each do |version|
      define_method("test_v#{version}_#{OpenPermissionsTest.vector_name(label)}_is_rejected_before_any_packet") do
        @session.expects(:send_packet).never
        error = assert_raises(ArgumentError) { driver(version).open(PATH, flags, {}) }
        assert_kind_of ArgumentError, error
      end
    end
  end

  def test_v3_read_only_intent_never_carries_a_write_bit
    @session.expects(:send_packet).with do |*args|
      pflags = args[6]
      assert_equal 0, pflags & (FV1::WRITE | FV1::TRUNC),
        "read-only open must not request write or truncate, got pflags=0x#{pflags.to_s(16)}"
      true
    end
    driver(3).open(PATH, "r", {})
  end

  def test_v5_read_only_intent_requests_no_write_access_and_no_truncating_disposition
    @session.expects(:send_packet).with do |*args|
      access, disposition = args[6], args[8]
      assert_equal 0, access & (ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES | ACE::Mask::APPEND_DATA),
        "read-only open must not request any write access, got 0x#{access.to_s(16)}"
      refute_equal FV5::CREATE_TRUNCATE, disposition
      refute_equal FV5::TRUNCATE_EXISTING, disposition
      true
    end
    driver(5).open(PATH, "r", {})
  end

  def test_v5_exclusive_create_takes_precedence_over_truncation_in_the_disposition
    # CREAT|EXCL|TRUNC is contradictory: an exclusive create cannot also
    # truncate an existing file. With write access present the request is
    # representable, and the v5 mapping must resolve it as CREATE_NEW (fail if
    # the file exists), never CREATE_TRUNCATE/TRUNCATE_EXISTING, which would
    # destroy an existing file and silently lose the exclusive guarantee.
    flags = IO::RDWR | IO::CREAT | IO::EXCL | IO::TRUNC
    @session.expects(:send_packet).with(
      FXP_OPEN, :long, 0, :string, PATH,
      :long, RDWR_ACCESS, :long, FV5::CREATE_NEW, :raw, attributes(5).new.to_s)
    driver(5).open(PATH, flags, {})
  end

  def test_v3_exclusive_create_keeps_excl_bit_and_cannot_be_downgraded
    @session.expects(:send_packet).with do |*args|
      pflags = args[6]
      assert(pflags & FV1::EXCL != 0, "exclusive create must retain FV1::EXCL")
      assert(pflags & FV1::CREAT != 0, "exclusive create must retain FV1::CREAT")
      true
    end
    driver(3).open(PATH, IO::RDWR | IO::CREAT | IO::EXCL, {})
  end

  def test_append_always_carries_a_write_channel_on_both_wire_formats
    @session.expects(:send_packet).with do |*args|
      pflags = args[6]
      assert(pflags & FV1::APPEND != 0)
      assert(pflags & FV1::WRITE != 0, "v3 append requires WRITE so writes are legal")
      true
    end
    driver(3).open(PATH, "a", {})

    @session.expects(:send_packet).with do |*args|
      access, disposition = args[6], args[8]
      assert(access & ACE::Mask::APPEND_DATA != 0)
      assert(disposition & FV5::APPEND_DATA != 0)
      assert(access & ACE::Mask::WRITE_DATA != 0, "v5 append still grants WRITE_DATA")
      true
    end
    driver(5).open(PATH, "a", {})
  end

  def test_same_intent_keeps_read_only_across_v3_and_v5
    # Regression anchor: a read-only caller must never gain write capability
    # merely because the server negotiated a newer protocol.
    v3 = capture_open(3, "r")
    v5 = capture_open(5, "r")
    assert_equal FV1::READ, v3
    assert_equal [READ_ACCESS, FV5::OPEN_EXISTING], v5
    assert_equal 0, v5.first & (ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES)
  end

  [[3, IO::RDONLY | IO::EXCL], [5, IO::RDONLY | IO::TRUNC], [6, IO::WRONLY | IO::EXCL]].each do |version, flags|
    define_method("test_session_open_v#{version}_rejects_unsafe_intent_without_touching_the_channel") do
      # Drive the public Net::SFTP::Session#open entry point through a fully
      # scripted SSH channel. The story contains only the handshake (init /
      # version); no FXP_OPEN is scripted as an expected send, so transmitting
      # one would fail the script. The error must surface before that point.
      expect_sftp_session :server_version => version
      Net::SSH::Test::Extensions::IO.with_test_extension do
        sftp.connect!
        assert_raises(ArgumentError) { sftp.open(PATH, flags) }
        assert_empty sftp.pending_requests
      end
    end
  end

  private

    def driver(version)
      @drivers ||= {}
      @drivers[version] ||= protocol_class(version).new(@session)
    end

    def protocol_class(version)
      Net::SFTP::Protocol.const_get("V0#{version}")::Base
    end

    def attributes(version)
      # v1-v4 share the V01 attribute encoding; v5 keeps the v4 form; v6 adds
      # its own subclass.
      klass = case version
              when 6 then 6
              when 5 then 4
              else 1
              end
      Net::SFTP::Protocol.const_get("V0#{klass}")::Attributes
    end

    def capture_open(version, flags)
      captured = nil
      @session.stubs(:send_packet).with do |*args|
        captured = version <= 4 ? args[6] : [args[6], args[8]]
        true
      end
      driver(version).open(PATH, flags, {})
      captured
    end
end
