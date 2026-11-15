module Net; module SFTP; module Protocol

  # Resolves the +flags+ argument accepted by Net::SFTP::Session#open into an
  # explicit description of what the caller actually asked for, independent of
  # the SFTP protocol version that will carry the request.
  #
  # The SFTP protocol changed the open request completely between version 4 and
  # version 5: v1-4 send a single +pflags+ bitfield, while v5/v6 send a
  # +desired-access+ ACE mask plus a separate +flags+ field that holds the
  # disposition. The bit values are not interchangeable, and one of the v5
  # dispositions (CREATE_NEW) is zero, so it is easy for a translation to
  # disappear into an unrelated field.
  #
  # OpenIntent resolves a caller's flags once, then each protocol version
  # checks that it can express every part of that intent. If a version cannot,
  # the request is refused before a packet is written. A request is never
  # quietly dropped (which would lose an exclusive-create requirement) or
  # widened (which would add write access or truncation that was not asked for).
  class OpenIntent
    # Raised when the caller's flags are self-contradictory or contain a
    # semantic that SFTP cannot express safely (for example O_EXCL without
    # O_CREAT). Nothing has been sent when this is raised.
    class Unsupported < ArgumentError; end

    # Raised when the negotiated protocol version cannot express an otherwise
    # valid intent. Nothing has been sent when this is raised.
    class NotExpressible < Unsupported; end

    # Ruby defines O_RDONLY as zero, so "read-only" and "no access mode given"
    # are the same bits. The access mode is recovered from these two bits.
    ACCESS_MASK = IO::WRONLY | IO::RDWR

    # O_NOFOLLOW has no encoding in SFTP v1-v5; only v6 defines
    # OpenFlags::FV6::NOFOLLOW. Use the platform value when Ruby exposes it.
    NOFOLLOW = defined?(::File::NOFOLLOW) ? ::File::NOFOLLOW : 0

    # Returns a new intent for the given +flags+ (an Integer of IO constants or
    # one of the mode strings that IO#open accepts).
    def self.from_flags(flags)
      new(normalize(flags))
    end

    # Converts the string form accepted by IO#open into IO constants. The
    # binary modifier does not change the permission semantics, so it is
    # stripped first.
    def self.normalize(flags)
      return flags.to_i unless String === flags

      case flags.tr("b", "")
      when "r"  then IO::RDONLY
      when "r+" then IO::RDWR
      when "w"  then IO::WRONLY | IO::TRUNC | IO::CREAT
      when "w+" then IO::RDWR | IO::TRUNC | IO::CREAT
      when "a"  then IO::APPEND | IO::CREAT | IO::WRONLY
      when "a+" then IO::APPEND | IO::CREAT | IO::RDWR
      else raise Unsupported, "unsupported flags: #{flags.inspect}"
      end
    end

    def initialize(flags)
      @flags = flags
      validate!
    end

    # True if the caller asked for read access. Note that Ruby's O_RDONLY is
    # zero, so this is the complement of write-only rather than a bit test.
    def read?
      (@flags & ACCESS_MASK) != IO::WRONLY
    end

    # True if the caller asked for write access. O_RDONLY is zero; O_WRONLY and
    # O_RDWR are the non-zero modes.
    def write?
      (@flags & ACCESS_MASK) != IO::RDONLY
    end

    # O_APPEND only means anything together with write access. Read-only
    # callers that also pass O_APPEND get no append behaviour from Ruby either,
    # so the flag is inert and is not carried into any version's encoding.
    def append?
      @flags & IO::APPEND != 0 && write?
    end

    def create?
      @flags & IO::CREAT != 0
    end

    def truncate?
      @flags & IO::TRUNC != 0
    end

    # O_EXCL only has meaning together with O_CREAT in POSIX and in the SFTP
    # drafts. Version 5 has no encoding for a bare O_EXCL, and accepting one
    # would silently turn it into an ordinary open, so bare O_EXCL is rejected
    # by #validate! instead.
    def exclusive?
      @flags & IO::EXCL != 0
    end

    # True when the caller expects the file to be created only if it does not
    # already exist.
    def exclusive_create?
      exclusive? && create?
    end

    # O_NOFOLLOW asks the server to fail rather than follow a symbolic link.
    # Only SFTP v6 has a flag for it.
    def nofollow?
      NOFOLLOW != 0 && (@flags & NOFOLLOW) != 0
    end

    # Checks that the given protocol +version+ can express every part of this
    # intent. Called before any packet is built, so an unrepresentable request
    # fails without writing anything to the server.
    #
    # O_NOFOLLOW exists only in SFTP v6 (OpenFlags::FV6::NOFOLLOW). Versions 1
    # through 5 have no field for it, and silently dropping it would turn a
    # request that refuses to follow a symlink into one that follows it.
    def assert_expressible!(version)
      if nofollow? && version < 6
        raise NotExpressible, "O_NOFOLLOW cannot be expressed by SFTP version #{version}; " \
          "only version 6 defines NOFOLLOW, and dropping it would allow a symlink to be followed"
      end

      self
    end

    private

      def validate!
        if @flags & ACCESS_MASK == ACCESS_MASK
          raise Unsupported, "flags #{@flags.inspect} request both write-only and read-write access"
        end

        if exclusive? && !create?
          # v1-4 can put EXCL in pflags, but v5/v6 have no disposition for it,
          # so the same call would fail on one server and open an existing file
          # on another. Neither meaning can be chosen for the caller.
          raise Unsupported, "O_EXCL (#{@flags.inspect}) requires O_CREAT; " \
            "v1-v4 encode the bare flag while v5/v6 cannot, so its meaning " \
            "would depend on the negotiated version"
        end

        # Bits with no SFTP meaning (O_SYNC, O_DIRECT, ...) are ignored, as they
        # always have been. O_NOFOLLOW is the exception: dropping it is a
        # security downgrade, so #assert_expressible! checks it per version.
      end
  end

end; end; end
