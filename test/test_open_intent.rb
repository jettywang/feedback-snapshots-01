require 'common'

# Regression coverage for the Net::SFTP::Session#open permission mapping.
#
# The same call must not silently acquire write access, truncate an existing
# file, or lose an exclusive-create requirement just because the negotiated
# SFTP version differs. These tests drive the public Session#open path and
# decode the bytes that actually leave the client.
#
# The SFTP open request is encoded differently per version:
#
#   v1-v4: FXP_OPEN(id, path, pflags, attrs)
#          pflags is one bitfield: READ, WRITE, APPEND, CREAT, TRUNC, EXCL.
#
#   v5-v6: FXP_OPEN(id, path, desired-access, flags, attrs)
#          desired-access is an ACE mask saying what the handle may be used
#          for (READ_DATA, WRITE_DATA, APPEND_DATA, ...); flags carries a
#          mutually exclusive disposition (CREATE_NEW = 0, CREATE_TRUNCATE,
#          OPEN_EXISTING, OPEN_OR_CREATE, TRUNCATE_EXISTING) plus modifiers
#          such as APPEND_DATA and NOFOLLOW.
#
# The two encodings do not share bit values. FV5::CREATE_NEW is 0x00000000,
# while FV1::READ is 0x00000001, so a translation bug is easy to hide. The
# tests therefore assert on decoded fields, not on "it did not crash".
class OpenIntentTest < Net::SFTP::TestCase
  include Net::SFTP::Constants::PacketTypes
  include Net::SFTP::Constants

  # Versions whose FXP_OPEN layout carries a single pflags field.
  LEGACY_VERSIONS = [1, 2, 3, 4].freeze

  # Versions whose FXP_OPEN layout carries desired-access plus flags.
  MODERN_VERSIONS = [5, 6].freeze

  ALL_VERSIONS = (LEGACY_VERSIONS + MODERN_VERSIONS).freeze

  OPEN_EXISTING    = OpenFlags::FV5::OPEN_EXISTING
  OPEN_OR_CREATE   = OpenFlags::FV5::OPEN_OR_CREATE
  CREATE_NEW       = OpenFlags::FV5::CREATE_NEW
  CREATE_TRUNCATE  = OpenFlags::FV5::CREATE_TRUNCATE
  TRUNCATE_EXISTING = OpenFlags::FV5::TRUNCATE_EXISTING

  READ_BITS  = ACE::Mask::READ_DATA | ACE::Mask::READ_ATTRIBUTES
  WRITE_BITS = ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES
  APPEND_BIT = ACE::Mask::APPEND_DATA

  # Negotiates a real session at +version+, then replaces the channel's
  # +send_data+ with a recorder so the exact frame can be inspected without a
  # scripted reply. Nothing is forwarded to the mock socket, which keeps the
  # handshake script empty.
  def open_frame(version, flags, path = "/f")
    frames = []
    reset_session

    expect_sftp_session :server_version => version
    assert_scripted do
      sftp.connect!
      channel = sftp.channel
      channel.define_singleton_method(:send_data) { |data| frames << data.dup }
      sftp.open(path, flags, {})
    end

    opens = frames.select { |frame| frame.getbyte(4) == FXP_OPEN }
    assert_equal 1, opens.length,
      "expected exactly one FXP_OPEN at v#{version} for #{flags.inspect}, got #{opens.length}"
    opens.first
  end

  def decode_open(frame, version)
    length = frame.byteslice(0, 4).unpack1("N")
    assert_equal FXP_OPEN, frame.getbyte(4)
    assert_equal frame.bytesize - 4, length, "frame length prefix must match the payload"

    body = Net::SSH::Buffer.new(frame.byteslice(5, length - 1))
    fields = { id: body.read_long, path: body.read_string }
    if version >= 5
      fields[:access] = body.read_long
      fields[:flags] = body.read_long
    else
      fields[:pflags] = body.read_long
    end
    fields[:attrs] = body.read(length)
    fields
  end

  # Runs the block on a negotiated session at +version+ and asserts that no
  # FXP_OPEN reached the channel.
  def assert_open_refused(version, flags)
    frames = []
    reset_session

    expect_sftp_session :server_version => version
    error = nil
    assert_scripted do
      sftp.connect!
      channel = sftp.channel
      channel.define_singleton_method(:send_data) { |data| frames << data.dup }
      begin
        sftp.open("/f", flags, {})
      rescue StandardError => e
        error = e
      end
    end

    refute_nil error, "expected the open request to be refused at v#{version}"
    assert_empty frames,
      "refusal at v#{version} for #{flags.inspect} still wrote #{frames.length} frame(s) to the channel"
    error
  end

  def reset_session
    @sftp = nil
    @connection = nil
    @transport = nil
    @socket = nil
  end

  def sftp
    @sftp ||= Net::SFTP::Session.new(connection)
  end
end

# The same caller intent, expressed as a mode string and as numeric IO flags,
# must produce the same request on every version that can express it.
class OpenIntentMappingTest < OpenIntentTest

  # mode string => expected fields on v1-v4 and v5/v6
  INTENTS = {
    "r"  => { read: true,  write: false, pflags: OpenFlags::FV1::READ,
              access: READ_BITS, flags: OPEN_EXISTING },
    "r+" => { read: true,  write: true,  pflags: OpenFlags::FV1::READ | OpenFlags::FV1::WRITE,
              access: READ_BITS | WRITE_BITS, flags: OPEN_EXISTING },
    "w"  => { read: false, write: true,
              pflags: OpenFlags::FV1::WRITE | OpenFlags::FV1::TRUNC | OpenFlags::FV1::CREAT,
              access: WRITE_BITS, flags: CREATE_TRUNCATE },
    "w+" => { read: true,  write: true,
              pflags: OpenFlags::FV1::WRITE | OpenFlags::FV1::READ | OpenFlags::FV1::TRUNC | OpenFlags::FV1::CREAT,
              access: READ_BITS | WRITE_BITS, flags: CREATE_TRUNCATE },
    "a"  => { read: false, write: true,
              pflags: OpenFlags::FV1::APPEND | OpenFlags::FV1::WRITE | OpenFlags::FV1::CREAT,
              access: WRITE_BITS | APPEND_BIT, flags: OPEN_OR_CREATE | OpenFlags::FV5::APPEND_DATA },
    "a+" => { read: true,  write: true,
              pflags: OpenFlags::FV1::APPEND | OpenFlags::FV1::WRITE | OpenFlags::FV1::READ | OpenFlags::FV1::CREAT,
              access: READ_BITS | WRITE_BITS | APPEND_BIT, flags: OPEN_OR_CREATE | OpenFlags::FV5::APPEND_DATA }
  }.freeze

  INTENTS.each do |mode, expected|
    define_method("test_mode_#{mode.tr('+', 'plus')}_intent_is_preserved_on_every_version") do
      (1..4).each do |version|
        fields = decode_open(open_frame(version, mode), version)
        assert_equal expected[:pflags], fields[:pflags],
          "v#{version} #{mode.inspect} pflags"
        assert_equal expected[:read], (fields[:pflags] & OpenFlags::FV1::READ) != 0,
          "v#{version} #{mode.inspect} read access"
        assert_equal expected[:write], (fields[:pflags] & OpenFlags::FV1::WRITE) != 0,
          "v#{version} #{mode.inspect} write access"
      end

      [5, 6].each do |version|
        fields = decode_open(open_frame(version, mode), version)
        assert_equal expected[:access], fields[:access],
          "v#{version} #{mode.inspect} desired access"
        assert_equal expected[:flags], fields[:flags],
          "v#{version} #{mode.inspect} disposition/flags"
      end
    end
  end

  def test_mode_string_and_numeric_flags_agree
    {
      "r"  => IO::RDONLY,
      "r+" => IO::RDWR,
      "w"  => IO::WRONLY | IO::TRUNC | IO::CREAT,
      "w+" => IO::RDWR | IO::TRUNC | IO::CREAT,
      "a"  => IO::WRONLY | IO::APPEND | IO::CREAT,
      "a+" => IO::RDWR | IO::APPEND | IO::CREAT
    }.each do |mode, numeric|
      ALL_VERSIONS.each do |version|
        from_mode = decode_open(open_frame(version, mode), version)
        from_numeric = decode_open(open_frame(version, numeric), version)
        assert_equal from_mode, from_numeric,
          "v#{version}: #{mode.inspect} and #{numeric.inspect} must encode identically"
      end
    end
  end

  def test_binary_modifier_does_not_change_permissions
    ALL_VERSIONS.each do |version|
      text = decode_open(open_frame(version, "r"), version)
      binary = decode_open(open_frame(version, "rb"), version)
      assert_equal text, binary, "v#{version}: b modifier must not change the request"
    end
  end

  def test_read_only_open_never_grants_write_access
    (1..4).each do |version|
      fields = decode_open(open_frame(version, "r"), version)
      assert_equal 0, fields[:pflags] & OpenFlags::FV1::WRITE,
        "v#{version} read-only open must not set WRITE"
    end

    [5, 6].each do |version|
      fields = decode_open(open_frame(version, "r"), version)
      assert_equal 0, fields[:access] & (ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES | APPEND_BIT),
        "v#{version} read-only open must not request any write access"
    end
  end

  def test_append_open_does_not_truncate_and_requires_create
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, "a"), version)
      disposition = fields[:flags] & 0x7
      assert_equal OPEN_OR_CREATE, disposition,
        "v#{version} append must open-or-create, not truncate"
      assert_equal OpenFlags::FV5::APPEND_DATA, fields[:flags] & OpenFlags::FV5::APPEND_DATA
    end

    (1..4).each do |version|
      fields = decode_open(open_frame(version, "a"), version)
      assert_equal 0, fields[:pflags] & OpenFlags::FV1::TRUNC,
        "v#{version} append must not set TRUNC"
      assert_equal OpenFlags::FV1::CREAT, fields[:pflags] & OpenFlags::FV1::CREAT,
        "v#{version} append must create the file if absent"
    end
  end
end

# Safety properties: when a version cannot express the caller's intent
# exactly, the request must be refused before any FXP_OPEN is written. In
# particular it must not fall back to a wider permission set, nor silently
# drop an exclusive-create requirement or a no-follow requirement.
class OpenIntentSafetyTest < OpenIntentTest

  def test_exclusive_create_is_preserved_on_modern_versions
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::CREAT | IO::EXCL), version)
      assert_equal CREATE_NEW, fields[:flags] & 0x7,
        "v#{version} O_CREAT|O_EXCL must be CREATE_NEW, not an ordinary open"
      assert_equal WRITE_BITS, fields[:access],
        "v#{version} exclusive create is write-only; it must not gain read access"
    end
  end

  def test_exclusive_create_is_preserved_on_legacy_versions
    (1..4).each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::CREAT | IO::EXCL), version)
      assert_equal OpenFlags::FV1::CREAT | OpenFlags::FV1::EXCL,
        fields[:pflags] & (OpenFlags::FV1::CREAT | OpenFlags::FV1::EXCL),
        "v#{version} O_CREAT|O_EXCL must keep both CREAT and EXCL"
    end
  end

  def test_read_only_exclusive_create_does_not_gain_write_access
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::RDONLY | IO::CREAT | IO::EXCL), version)
      assert_equal CREATE_NEW, fields[:flags] & 0x7,
        "v#{version} read-only exclusive create must still be CREATE_NEW"
      assert_equal 0, fields[:access] & (ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES | APPEND_BIT),
        "v#{version} read-only exclusive create must not request write access"
    end
  end

  def test_exclusive_without_create_is_refused_on_every_version
    ALL_VERSIONS.each do |version|
      error = assert_open_refused(version, IO::WRONLY | IO::EXCL)
      assert_kind_of Net::SFTP::Protocol::OpenIntent::Unsupported, error,
        "v#{version}: O_EXCL without O_CREAT must be rejected, not silently weakened"
    end
  end

  def test_nofollow_is_refused_on_versions_without_that_flag
    skip "Ruby does not expose O_NOFOLLOW" if Net::SFTP::Protocol::OpenIntent::NOFOLLOW == 0

    (1..5).each do |version|
      error = assert_open_refused(version, IO::WRONLY | File::NOFOLLOW)
      assert_kind_of Net::SFTP::Protocol::OpenIntent::NotExpressible, error,
        "v#{version}: O_NOFOLLOW must be refused rather than dropped"
    end
  end

  def test_nofollow_is_encoded_on_version_6
    skip "Ruby does not expose O_NOFOLLOW" if Net::SFTP::Protocol::OpenIntent::NOFOLLOW == 0

    fields = decode_open(open_frame(6, IO::WRONLY | File::NOFOLLOW), 6)
    assert_equal OpenFlags::FV6::NOFOLLOW, fields[:flags] & OpenFlags::FV6::NOFOLLOW,
      "v6 defines NOFOLLOW; the request must carry it"
  end

  def test_contradictory_access_modes_are_refused
    # Ruby itself rejects O_WRONLY|O_RDWR. The library must not pick one.
    ALL_VERSIONS.each do |version|
      error = assert_open_refused(version, IO::WRONLY | IO::RDWR)
      assert_kind_of Net::SFTP::Protocol::OpenIntent::Unsupported, error
    end
  end

  def test_unsupported_read_write_mode_string_is_refused
    # "rw" is not an IO mode, even though the existing session helper scripts
    # one for a legacy test. It must not be interpreted as a write mode.
    ALL_VERSIONS.each do |version|
      error = assert_open_refused(version, "rw")
      assert_kind_of Net::SFTP::Protocol::OpenIntent::Unsupported, error
      assert_match(/unsupported flags/, error.message)
    end
  end

  def test_truncate_without_write_access_is_expressible_and_not_widened
    # O_RDONLY|O_TRUNC is unusual but exactly expressible: read access plus a
    # truncating disposition. The point of this test is that the request is
    # neither refused as unrepresentable nor widened with write access.
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::RDONLY | IO::TRUNC), version)
      assert_equal TRUNCATE_EXISTING, fields[:flags] & 0x7,
        "v#{version}: truncate must survive as TRUNCATE_EXISTING"
      assert_equal 0, fields[:access] & (ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES),
        "v#{version}: a read-only caller must not be granted write access"
    end

    LEGACY_VERSIONS.each do |version|
      fields = decode_open(open_frame(version, IO::RDONLY | IO::TRUNC), version)
      assert_equal OpenFlags::FV1::READ | OpenFlags::FV1::TRUNC, fields[:pflags],
        "v#{version}: read-only truncate must keep both READ and TRUNC"
    end
  end
end

# Short, literal packet vectors. Decoding is useful for reasoning, but these
# pin the exact bytes on the wire so a refactor that changes field order,
# field count, or disposition encoding cannot pass unnoticed.
class OpenIntentVectorTest < OpenIntentTest
  # intent label => { version => "hex of the FXP_OPEN body after the type byte" }
  # The trailing attrs bytes are the empty ATTRS structure: flags 0, plus the
  # v4+ type byte.
  VECTORS = {
    "read-only" => {
      3 => "00000000000000022f660000000100000000",
      5 => "00000000000000022f6600000081000000020000000001",
      6 => "00000000000000022f6600000081000000020000000001"
    },
    "read-write" => {
      3 => "00000000000000022f660000000300000000",
      5 => "00000000000000022f6600000183000000020000000001",
      6 => "00000000000000022f6600000183000000020000000001"
    },
    "write-truncate-create" => {
      3 => "00000000000000022f660000001a00000000",
      5 => "00000000000000022f6600000102000000010000000001",
      6 => "00000000000000022f6600000102000000010000000001"
    },
    "append-create" => {
      3 => "00000000000000022f660000000e00000000",
      5 => "00000000000000022f66000001060000000b0000000001",
      6 => "00000000000000022f66000001060000000b0000000001"
    },
    "exclusive-create" => {
      3 => "00000000000000022f660000002a00000000",
      5 => "00000000000000022f6600000102000000000000000001",
      6 => "00000000000000022f6600000102000000000000000001"
    }
  }.freeze

  FLAGS_FOR = {
    "read-only" => "r",
    "read-write" => "r+",
    "write-truncate-create" => "w",
    "append-create" => "a",
    "exclusive-create" => IO::WRONLY | IO::CREAT | IO::EXCL
  }.freeze

  VECTORS.each do |label, per_version|
    define_method("test_wire_vector_#{label.tr('-', '_')}") do
      per_version.each do |version, hex|
        frame = open_frame(version, FLAGS_FOR[label])
        # Drop the 4-byte length and 1-byte packet type, leaving the body.
        assert_equal hex, frame.byteslice(5, frame.bytesize - 5).unpack1("H*"),
          "#{label} FXP_OPEN body at v#{version} does not match the pinned vector"
      end
    end
  end

  def test_frame_length_and_type
    frame = open_frame(5, "r")
    assert_equal frame.bytesize - 4, frame.byteslice(0, 4).unpack1("N"),
      "the 4-byte length prefix must cover everything after itself"
    assert_equal FXP_OPEN, frame.getbyte(4)
  end
end

# Cross-version equivalence: for each intent that every version can express,
# the decoded request must describe the same permission set even though the
# wire encodings differ. This is the property that a "server probably does the
# right thing" argument cannot establish: the bytes themselves must agree.
class OpenIntentCrossVersionTest < OpenIntentTest
  COMMON_INTENTS = {
    "read-only" => ["r", { read: true, write: false, create: false, truncate: false, exclusive: false,
                           append: false }],
    "read-write" => ["r+", { read: true, write: true, create: false, truncate: false, exclusive: false,
                             append: false }],
    "write-truncate-create" => ["w", { read: false, write: true, create: true, truncate: true, exclusive: false,
                                       append: false }],
    "append-create" => ["a", { read: false, write: true, create: true, truncate: false, exclusive: false,
                               append: true }],
    "exclusive-create" => [IO::WRONLY | IO::CREAT | IO::EXCL,
                           { read: false, write: true, create: true, truncate: false, exclusive: true,
                             append: false }]
  }.freeze

  def intent_from_legacy(pflags)
    {
      read: (pflags & OpenFlags::FV1::READ) != 0,
      write: (pflags & OpenFlags::FV1::WRITE) != 0,
      create: (pflags & OpenFlags::FV1::CREAT) != 0,
      truncate: (pflags & OpenFlags::FV1::TRUNC) != 0,
      exclusive: (pflags & OpenFlags::FV1::EXCL) != 0,
      append: (pflags & OpenFlags::FV1::APPEND) != 0 &&
              (pflags & OpenFlags::FV1::WRITE) != 0
    }
  end

  def intent_from_modern(access, flags)
    disposition = flags & 0x7
    {
      read: (access & ACE::Mask::READ_DATA) != 0,
      write: (access & ACE::Mask::WRITE_DATA) != 0,
      create: [CREATE_NEW, CREATE_TRUNCATE, OPEN_OR_CREATE].include?(disposition),
      truncate: [CREATE_TRUNCATE, TRUNCATE_EXISTING].include?(disposition),
      exclusive: disposition == CREATE_NEW,
      append: (flags & OpenFlags::FV5::APPEND_DATA) != 0
    }
  end

  COMMON_INTENTS.each do |label, (flags, expected)|
    define_method("test_#{label.tr('-', '_')}_means_the_same_thing_on_every_version") do
      LEGACY_VERSIONS.each do |version|
        fields = decode_open(open_frame(version, flags), version)
        assert_equal expected, intent_from_legacy(fields[:pflags]),
          "v#{version} #{label}: decoded intent differs"
      end

      MODERN_VERSIONS.each do |version|
        fields = decode_open(open_frame(version, flags), version)
        assert_equal expected, intent_from_modern(fields[:access], fields[:flags]),
          "v#{version} #{label}: decoded intent differs"
      end
    end
  end
end

# Disposition boundaries that the mode-string shortcuts don't reach. These are
# where a v5/v6 translation is most likely to collapse two different requests
# into one (CREATE_TRUNCATE vs TRUNCATE_EXISTING vs OPEN_OR_CREATE).
class OpenIntentDispositionTest < OpenIntentTest
  def test_truncate_with_create_but_not_exclusive_is_create_truncate
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::TRUNC | IO::CREAT), version)
      assert_equal CREATE_TRUNCATE, fields[:flags] & 0x7,
        "v#{version}: O_TRUNC|O_CREAT without O_EXCL must not require the file to be new"
    end
  end

  def test_create_without_truncate_is_open_or_create
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::CREAT), version)
      assert_equal OPEN_OR_CREATE, fields[:flags] & 0x7,
        "v#{version}: O_CREAT alone must not truncate an existing file"
    end
  end

  def test_truncate_without_create_is_truncate_existing
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::TRUNC), version)
      assert_equal TRUNCATE_EXISTING, fields[:flags] & 0x7,
        "v#{version}: O_TRUNC alone must not create a missing file"
    end
  end

  def test_plain_open_is_open_existing
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY), version)
      assert_equal OPEN_EXISTING, fields[:flags] & 0x7,
        "v#{version}: a plain open must neither create nor truncate"
    end
  end

  def test_open_or_create_does_not_grant_exclusive_semantics
    # Guard against CREATE_NEW leaking in from the O_CREAT path: the four
    # dispositions are distinct values and must be distinguishable.
    dispositions = [OPEN_EXISTING, OPEN_OR_CREATE, CREATE_TRUNCATE, TRUNCATE_EXISTING, CREATE_NEW]
    assert_equal dispositions.uniq.length, dispositions.length,
      "the v5 dispositions used by the mapping must all be distinct"
  end
end

# One combination is redundant rather than divergent: O_TRUNC together with
# O_EXCL. An exclusive create only succeeds when the file does not exist, so
# there is never an existing file whose contents could be truncated. v1-4 can
# still set the TRUNC bit alongside EXCL; v5/v6 use the single CREATE_NEW
# disposition and have no separate truncate flag to set. Both requests mean
# "create this file only if it is absent", and neither can destroy data.
class OpenIntentRedundantTruncateTest < OpenIntentTest
  def test_truncate_with_exclusive_create_cannot_destroy_an_existing_file
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::TRUNC | IO::CREAT | IO::EXCL), version)
      assert_equal CREATE_NEW, fields[:flags] & 0x7,
        "v#{version}: O_EXCL must keep the create-new-only disposition"
      assert_equal 0, fields[:flags] & OpenFlags::FV5::APPEND_DATA
      assert_equal WRITE_BITS, fields[:access],
        "v#{version}: exclusive create must stay write-only"
    end

    LEGACY_VERSIONS.each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::TRUNC | IO::CREAT | IO::EXCL), version)
      assert_equal OpenFlags::FV1::CREAT | OpenFlags::FV1::EXCL,
        fields[:pflags] & (OpenFlags::FV1::CREAT | OpenFlags::FV1::EXCL),
        "v#{version}: exclusive create must keep CREAT and EXCL"
    end
  end

  def test_exclusive_create_never_reports_open_or_create
    # If a translation dropped EXCL and kept only CREAT, the request would
    # become OPEN_OR_CREATE and could open an existing file. Pin the
    # distinction.
    [5, 6].each do |version|
      fields = decode_open(open_frame(version, IO::WRONLY | IO::CREAT | IO::EXCL), version)
      refute_equal OPEN_OR_CREATE, fields[:flags] & 0x7,
        "v#{version}: O_EXCL must not degrade to open-or-create"
    end
  end
end
