module RubySMB
  # Contains the methods for handling packet signing
  module Signing
    # The NTLM Session Key used for signing
    # @!attribute [rw] session_key
    #   @return [String]
    attr_accessor :session_key

    # Take an SMB1 packet and sign it. This version is an instance method that
    # accesses the necessary values from the object instance.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @return [RubySMB::GenericPacket] the signed packet
    def smb1_sign(packet)
      packet = Signing::smb1_sign(packet, @session_key, @sequence_counter)
      @sequence_counter += 1

      packet
    end

    # Take an SMB1 packet and sign it. This version is a module function that
    # requires the necessary values to be explicitly passed to it.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @param [String] session_key The key to use for signing.
    # @param [Integer] sequence_counter The sequence counter of packet to be sent.
    # @return [RubySMB::GenericPacket] the signed packet
    def self.smb1_sign(packet, session_key, sequence_counter)
      # Pack the Sequence counter into a int64le
      packed_sequence_counter = [sequence_counter].pack('Q<')
      packet.smb_header.security_features = packed_sequence_counter
      signature = OpenSSL::Digest::MD5.digest(session_key + packet.to_binary_s)[0, 8]
      packet.smb_header.security_features = signature

      packet
    end

    # Verify the signature of a raw SMB1 packet. The signature is the first
    # 8 bytes of the MD5 digest of the session key concatenated with the
    # packet, where the security features field (offset 14 in the SMB
    # header) holds the little-endian sequence counter of the packet.
    #
    # @param [String] raw_packet The raw binary packet to verify.
    # @param [String] session_key The key to verify the signature with.
    # @param [Integer] sequence_counter The sequence counter of the packet.
    # @return [Boolean] true if the signature is valid
    def self.smb1_verify(raw_packet, session_key, sequence_counter)
      # The security features field ends at offset 22 in the SMB1 header
      return false if raw_packet.nil? || raw_packet.length < 22

      signature = raw_packet[14, 8]
      data = raw_packet.dup
      data[14, 8] = [sequence_counter].pack('Q<')
      expected_signature = OpenSSL::Digest::MD5.digest(session_key + data)[0, 8]

      signature == expected_signature
    end

    # Take an SMB2 packet and sign it. This version is an instance method that
    # accesses the necessary values from the object instance.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @return [RubySMB::GenericPacket] the signed packet
    def smb2_sign(packet)
      Signing::smb2_sign(packet, @session_key)
    end

    # Take an SMB2 packet and sign it. This version is a module function that
    # requires the necessary values to be explicitly passed to it.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @param [String] session_key The key to use for signing.
    # @return [RubySMB::GenericPacket] the signed packet
    def self.smb2_sign(packet, session_key)
      packet.smb2_header.flags.signed = 1
      packet.smb2_header.signature = "\x00" * 16
      # OpenSSL 3 raises exceptions if the session key is an empty string
      session_key = session_key == '' ? ("\x00" * 16).b : session_key
      hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), session_key, packet.to_binary_s)
      packet.smb2_header.signature = hmac[0, 16]

      packet
    end

    # Verify the signature of a raw SMB2 packet. The signature is the first
    # 16 bytes of the HMAC-SHA256 of the packet with the signature field
    # (offset 48 in the SMB2 header) zeroed out.
    #
    # @param [String] raw_packet The raw binary packet to verify.
    # @param [String] session_key The key to verify the signature with.
    # @return [Boolean] true if the signature is valid
    def self.smb2_verify(raw_packet, session_key)
      data = smb2_signature_data(raw_packet)
      return false if data.nil?

      signature = data[48, 16]
      data[48, 16] = "\x00" * 16
      # OpenSSL 3 raises exceptions if the session key is an empty string
      session_key = session_key == '' ? ("\x00" * 16).b : session_key
      expected_signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), session_key, data)[0, 16]

      signature == expected_signature
    end

    # Take an SMB3 packet and sign it. This version is an instance method that
    # accesses the necessary values from the object instance.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @return [RubySMB::GenericPacket] the signed packet
    def smb3_sign(packet)
      Signing::smb3_sign(packet, @session_key, @dialect, @preauth_integrity_hash_value)
    end

    # Take an SMB3 packet and sign it. This version is a module function that
    # requires the necessary values to be explicitly passed to it.
    #
    # @param [RubySMB::GenericPacket] packet The packet to sign.
    # @param [String] session_key The key to use for signing.
    # @param [String] dialect The SMB3 dialect to sign for.
    # @param [String] preauth_integrity_hash The preauth integrity hash as
    #   required by the 3.1.1 dialect.
    # @return [RubySMB::GenericPacket] the signed packet
    def self.smb3_sign(packet, session_key, dialect, preauth_integrity_hash=nil)
      case dialect
      when '0x0300', '0x0302'
        signing_key = Crypto::KDF.counter_mode(session_key, "SMB2AESCMAC\x00", "SmbSign\x00")
      when '0x0311'
        raise ArgumentError.new('the preauth integrity hash is required for the specified dialect') if preauth_integrity_hash.nil?
        signing_key = Crypto::KDF.counter_mode(session_key, "SMBSigningKey\x00", preauth_integrity_hash)
      else
        raise Error::SigningError.new("Dialect #{dialect.inspect} is incompatible with SMBv3 signing")
      end

      packet.smb2_header.flags.signed = 1
      packet.smb2_header.signature = "\x00" * 16
      hmac = OpenSSL::CMAC.digest('AES', signing_key, packet.to_binary_s)
      packet.smb2_header.signature = hmac[0, 16]

      packet
    end

    # Verify the signature of a raw SMB3 packet. The signature is the first
    # 16 bytes of the AES-CMAC of the packet with the signature field
    # (offset 48 in the SMB2 header) zeroed out.
    #
    # @param [String] raw_packet The raw binary packet to verify.
    # @param [String] session_key The key to verify the signature with.
    # @param [String] dialect The SMB3 dialect to verify for.
    # @param [String] preauth_integrity_hash The preauth integrity hash as
    #   required by the 3.1.1 dialect.
    # @return [Boolean] true if the signature is valid
    def self.smb3_verify(raw_packet, session_key, dialect, preauth_integrity_hash=nil)
      case dialect
      when '0x0300', '0x0302'
        signing_key = Crypto::KDF.counter_mode(session_key, "SMB2AESCMAC\x00", "SmbSign\x00")
      when '0x0311'
        raise ArgumentError.new('the preauth integrity hash is required for the specified dialect') if preauth_integrity_hash.nil?
        signing_key = Crypto::KDF.counter_mode(session_key, "SMBSigningKey\x00", preauth_integrity_hash)
      else
        raise Error::SigningError.new("Dialect #{dialect.inspect} is incompatible with SMBv3 signing")
      end

      data = smb2_signature_data(raw_packet)
      return false if data.nil?

      signature = data[48, 16]
      data[48, 16] = "\x00" * 16
      expected_signature = OpenSSL::CMAC.digest('AES', signing_key, data)[0, 16]

      signature == expected_signature
    end

    # Extract a mutable copy of a raw SMB2/3 packet for signature
    # verification. Returns nil if the packet is too short to contain an
    # SMB2 header (64 bytes, with the 16-byte signature at offset 48).
    #
    # @param [String] raw_packet The raw binary packet.
    # @return [String, nil] a copy of the packet, or nil if it is malformed
    def self.smb2_signature_data(raw_packet)
      return nil if raw_packet.nil? || raw_packet.length < 64

      raw_packet.dup
    end
  end
end
