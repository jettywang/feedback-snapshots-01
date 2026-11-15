require "ipaddr"

module OneLogin
  module RubySaml

    # Matching rules for the ``Address`` attribute of a SAML SubjectConfirmationData.
    #
    # This helper never looks at an HTTP request, socket or forwarding header. The
    # caller is responsible for deciding whether a client address is trustworthy and
    # passes it explicitly; the helper only compares that confirmed value against the
    # Address carried by a single SubjectConfirmationData node.
    #
    module SubjectConfirmationAddress
      # Policies accepted by {.normalize_policy}.
      #
      # * +:exact+    an Address that is present must match the confirmed client address;
      #               an absent Address is not by itself a failure (SAML makes it optional).
      # * +:required+ an Address must be present and must match the confirmed client address.
      POLICIES = [:exact, :required].freeze

      # Parses the caller supplied, already confirmed client address.
      #
      # @param value [String, IPAddr, nil]
      # @return [IPAddr, nil] normalized address, or nil when the caller could not confirm one
      # @raise [ArgumentError] if a value was supplied that is not a single IPv4/IPv6 address
      def self.client_address(value)
        return nil if value.nil?

        unless value.is_a?(String) || value.is_a?(IPAddr)
          raise ArgumentError.new("client_address must be a String or IPAddr, got #{value.class}")
        end

        if value.is_a?(IPAddr)
          return normalize(host_address(value, "client_address"))
        end

        text = value.strip
        raise ArgumentError.new("client_address must not be blank") if text.empty?

        normalize(parse(text, "client_address"))
      rescue IPAddr::Error => error
        raise ArgumentError.new("client_address is not a valid IPv4 or IPv6 address: #{error.message}")
      end

      # Validates the matching policy name.
      #
      # @param value [Symbol, String, nil]
      # @return [Symbol, nil]
      # @raise [ArgumentError] for an unknown policy
      def self.normalize_policy(value)
        return nil if value.nil?

        policy = value.to_sym
        unless POLICIES.include?(policy)
          raise ArgumentError.new("Unknown subject_confirmation_address_policy #{value.inspect}, expected one of #{POLICIES.inspect}")
        end
        policy
      rescue NoMethodError
        raise ArgumentError.new("subject_confirmation_address_policy must be a Symbol or String")
      end

      # Evaluates the Address of one SubjectConfirmationData node.
      #
      # A missing Address is reported as +:absent+: the node makes no statement about
      # the client address, and {POLICIES} decides whether that is acceptable. Anything
      # present must be a single host address. A malformed value, or an Address whose
      # source could not be confirmed, never matches.
      #
      # @param raw_address [String, nil] the raw Address attribute
      # @param client_address [IPAddr, nil] normalized confirmed client address
      # @return [Symbol] +:absent+, +:invalid+, +:unknown_client+, +:mismatch+ or +:match+
      def self.evaluate(raw_address, client_address)
        return :absent if raw_address.nil?

        address = begin
          parse(raw_address.to_s.strip, "SubjectConfirmationData Address")
        rescue IPAddr::Error
          nil
        end
        return :invalid unless address

        return :unknown_client if client_address.nil?
        return :mismatch unless comparable?(address, client_address)

        address == client_address ? :match : :mismatch
      end

      # @param address [IPAddr]
      # @return [IPAddr]
      def self.normalize(address)
        if address.ipv6? && address.respond_to?(:ipv4_mapped?) && address.ipv4_mapped?
          address.native
        else
          address
        end
      end

      # Parses a single host address, rejecting CIDR notation and zone identifiers.
      # Both are ranges/scoped values rather than one address, so treating them as
      # equal to a client address would widen the trust decision.
      #
      # @param text [String]
      # @param label [String]
      # @return [IPAddr]
      # @raise [IPAddr::Error]
      def self.parse(text, label)
        if text.include?("/")
          raise IPAddr::InvalidAddressError.new("#{label} must be a single address without a prefix length")
        end
        if text.include?("%")
          raise IPAddr::InvalidAddressError.new("#{label} must not contain a zone identifier")
        end

        normalize(IPAddr.new(text))
      end

      # Rejects IPAddr instances that describe a range or a scoped address.
      #
      # @param address [IPAddr]
      # @param label [String]
      # @return [IPAddr]
      # @raise [IPAddr::Error]
      def self.host_address(address, label)
        full_prefix = address.ipv6? ? 128 : 32
        if address.prefix != full_prefix
          raise IPAddr::InvalidAddressError.new("#{label} must be a single address without a prefix length")
        end
        if address.to_s.include?("%")
          raise IPAddr::InvalidAddressError.new("#{label} must not contain a zone identifier")
        end

        address
      end

      # @param left [IPAddr]
      # @param right [IPAddr]
      # @return [Boolean]
      def self.comparable?(left, right)
        # IPAddr#== includes the family flag, so the same native address written
        # as IPv4 or as an IPv4-mapped IPv6 value is not equal. Require both
        # normalized values to report the same family and then compare them.
        (left.ipv4? && right.ipv4?) || (left.ipv6? && right.ipv6?)
      end
    end
  end
end
