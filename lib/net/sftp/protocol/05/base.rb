require 'net/sftp/protocol/04/base'

module Net; module SFTP; module Protocol; module V05

  # Wraps the low-level SFTP calls for version 5 of the SFTP protocol.
  #
  # None of these protocol methods block--all of them return immediately,
  # requiring the SSH event loop to be run while the server response is
  # pending.
  #
  # You will almost certainly never need to use this driver directly. Please
  # see Net::SFTP::Session for the recommended interface.
  class Base < V04::Base
    # Returns the protocol version implemented by this driver. (5, in this
    # case)
    def version
      5
    end

    # Sends a FXP_RENAME packet to the server to request that the file or
    # directory with the given +name+ (must be a full path) be changed to
    # +new_name+ (which must also be a path). The +flags+ parameter must be
    # either +nil+ or 0 (the default), or some combination of the
    # Net::SFTP::Constants::RenameFlags constants.
    def rename(name, new_name, flags=nil)
      send_request(FXP_RENAME, :string, name, :string, new_name, :long, flags || 0)
    end

    # Sends a FXP_OPEN packet to the server and returns the packet identifier.
    # The +flags+ parameter is either an integer (in which case it must be
    # a combination of the IO constants) or a string (in which case it must
    # be one of the mode strings that IO::open accepts). The +options+
    # parameter is a hash that is used to construct a new Attribute object,
    # to pass as part of the FXP_OPEN request.
    #
    # Version 5 replaced the v1-4 +pflags+ field with two fields: a
    # +desired-access+ ACE mask, which says what the handle may be used for,
    # and a disposition/flag field, which says what happens to the file. The
    # caller's flags are resolved into an explicit intent first (see
    # Protocol::OpenIntent); a request whose disposition cannot be spelled out
    # in this version is refused before a packet is sent.
    def open(path, flags, options)
      intent = open_intent(flags)
      intent.assert_expressible!(version)

      sftp_flags = disposition_for(intent)
      sftp_flags |= FV5::APPEND_DATA if intent.append?
      sftp_flags |= nofollow_flag if intent.nofollow?

      desired_access = desired_access_for(intent)

      attributes = attribute_factory.new(options)

      send_request(FXP_OPEN, :string, path, :long, desired_access, :long, sftp_flags, :raw, attributes.to_s)
    end

    protected

      # The flag value for O_NOFOLLOW on the wire. Version 5 has no such flag;
      # v6 overrides this with OpenFlags::FV6::NOFOLLOW.
      def nofollow_flag
        raise OpenIntent::NotExpressible, "O_NOFOLLOW is not defined by SFTP version #{version}"
      end

      # Maps an intent to exactly one v5 disposition. Version 5 expresses
      # create/truncate as a mutually exclusive disposition rather than as
      # independent bits, so every combination has to be considered in order.
      # A request that cannot be represented exactly raises rather than
      # falling through to a different disposition.
      def disposition_for(intent)
        if intent.exclusive_create?
          FV5::CREATE_NEW
        elsif intent.create? && intent.truncate?
          FV5::CREATE_TRUNCATE
        elsif intent.create?
          FV5::OPEN_OR_CREATE
        elsif intent.truncate?
          # Truncate without create: the file must already exist, so neither
          # CREATE_TRUNCATE (which would also create) nor OPEN_OR_CREATE
          # (which would not truncate) is correct here.
          FV5::TRUNCATE_EXISTING
        else
          FV5::OPEN_EXISTING
        end
      end

      # Builds the v5 desired-access mask from the intent. Read access is only
      # granted when the caller asked for it; append is an additional access
      # right, not a replacement for plain write access.
      def desired_access_for(intent)
        access = 0
        if intent.write?
          access |= ACE::Mask::WRITE_DATA | ACE::Mask::WRITE_ATTRIBUTES
          access |= ACE::Mask::APPEND_DATA if intent.append?
        end
        if intent.read?
          access |= ACE::Mask::READ_DATA | ACE::Mask::READ_ATTRIBUTES
        end
        access
      end

  end

end; end; end; end
