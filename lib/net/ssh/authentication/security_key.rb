require 'net/ssh/errors'
require 'net/ssh/authentication/pub_key_fingerprint'

module Net
  module SSH
    module Authentication
      # FIDO/U2F security keys held by ssh-agent. The agent does the signing (incl. user
      # presence); net-ssh only parses and re-serialises the public key blob (see PROTOCOL.u2f).
      module SecurityKey
        SK_ECDSA_SHA2_NISTP256 = "sk-ecdsa-sha2-nistp256@openssh.com"
        SK_SSH_ED25519 = "sk-ssh-ed25519@openssh.com"
        TYPES = [SK_ECDSA_SHA2_NISTP256, SK_SSH_ED25519].freeze

        # The only curve defined for sk-ecdsa keys, and the fixed sizes from
        # PROTOCOL.u2f. These are structural checks only; the server verifies
        # the signature against the key.
        ECDSA_CURVE = "nistp256"
        ECDSA_POINT_BYTES = 65
        ED25519_KEY_BYTES = 32
        ED25519_SIGNATURE_BYTES = 64
        APPLICATION_PREFIX = "ssh:"

        # Bits in the FIDO signature's flags byte. UP/UV are assertions made by
        # the authenticator (via the agent); only the server can verify them.
        # Other authData bits are token-specific and are preserved, not rejected.
        SSH_SK_USER_PRESENCE_REQUIRED = 0x01
        SSH_SK_USER_VERIFICATION_REQUIRED = 0x04

        # Raised for a malformed sk-* public key. It is an UnsupportedKeyType so
        # Agent#identities skips the key, as it does for other unusable blobs.
        class InvalidPublicKey < Net::SSH::UnsupportedKeyType; end

        # Raised for a malformed or non-sk-* signature blob. A plain
        # ssh-ed25519/ecdsa-sha2-* signature must never be accepted for an sk-*
        # identity.
        class SignatureError < Net::SSH::Exception; end

        def self.understands?(type)
          TYPES.include?(type)
        end

        # Parsed signature returned by ssh-agent for an sk-* key. +signature+ is
        # the algorithm-specific body: a 64-byte Ed25519 signature, or for
        # sk-ecdsa, string r followed by string s as encoded by OpenSSH.
        class Signature
          attr_reader :algorithm, :signature, :flags, :counter

          def self.read(blob, expected_algorithm: nil)
            require 'net/ssh/buffer'
            buffer = Net::SSH::Buffer.new(blob)
            algorithm = buffer.read_string
            unless SecurityKey.understands?(algorithm)
              raise SignatureError, "unexpected signature algorithm `#{algorithm.inspect}'"
            end
            if expected_algorithm && algorithm != expected_algorithm
              raise SignatureError,
                    "signature algorithm `#{algorithm}' does not match key type `#{expected_algorithm}'"
            end

            signature = buffer.read_string
            flags = buffer.read_byte
            counter = buffer.read_long
            if signature.nil? || flags.nil? || counter.nil?
              raise SignatureError, "truncated #{algorithm} signature"
            end
            unless buffer.eof?
              raise SignatureError, "trailing data after #{algorithm} signature"
            end

            new(algorithm, signature, flags, counter)
          end

          def initialize(algorithm, signature, flags, counter)
            @algorithm = algorithm
            @signature = signature
            @flags = flags
            @counter = counter
          end

          def user_presence?
            (flags & SSH_SK_USER_PRESENCE_REQUIRED) != 0
          end

          def user_verification?
            (flags & SSH_SK_USER_VERIFICATION_REQUIRED) != 0
          end

          # Structural validation only. UP/UV are claims by the agent and token;
          # the server checks them against the key's certificate/authorized_keys
          # policy. This does not turn them into verified facts.
          def validate!
            if algorithm == SK_SSH_ED25519
              unless signature.bytesize == ED25519_SIGNATURE_BYTES
                raise SignatureError, "invalid #{algorithm} signature length #{signature.bytesize}"
              end
            else
              body = Net::SSH::Buffer.new(signature)
              r = body.read_string
              s = body.read_string
              if r.nil? || s.nil? || !body.eof? || r.empty? || s.empty?
                raise SignatureError, "invalid #{algorithm} signature encoding"
              end
            end

            self
          end

          def to_blob
            Net::SSH::Buffer.from(:string, algorithm, :string, signature,
                                  :byte, flags, :long, counter).to_s
          end
        end

        # Public key of an agent-held security key; signing is delegated to the agent.
        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          attr_reader :ssh_type, :curve, :public_key_data, :application

          # Wire formats:
          #   sk-ecdsa-sha2-nistp256@openssh.com: string curve, string Q, string application
          #   sk-ssh-ed25519@openssh.com:         string public_key, string application
          def self.read_keyblob(type, buffer)
            case type
            when SK_ECDSA_SHA2_NISTP256
              curve = buffer.read_string
              public_key_data = buffer.read_string
              application = buffer.read_string
              new(type, public_key_data, application, curve: curve)
            when SK_SSH_ED25519
              public_key_data = buffer.read_string
              application = buffer.read_string
              new(type, public_key_data, application)
            else
              raise Net::SSH::UnsupportedKeyType, "unsupported security key type `#{type}'"
            end
          end

          def initialize(ssh_type, public_key_data, application, curve: nil)
            @ssh_type = ssh_type
            @public_key_data = public_key_data
            @application = application
            @curve = curve
            validate!
          end

          def to_blob
            buffer = Net::SSH::Buffer.new
            buffer.write_string(ssh_type)
            buffer.write_string(curve) if curve
            buffer.write_string(public_key_data)
            buffer.write_string(application)
            buffer.to_s
          end

          def ssh_signature_type
            ssh_type
          end

          # parse_agent_signature is deliberately narrow: an sk-* key only
          # accepts an sk-* signature of its own algorithm with the FIDO
          # flags/counter trailer. Other signature formats are rejected rather
          # than parsed as plain Ed25519/ECDSA.
          def parse_agent_signature(blob)
            Signature.read(blob, expected_algorithm: ssh_type).validate!
          end

          # Only used to de-duplicate identities, so a stable key-specific string suffices.
          # to_blob includes the application, so the same key bytes registered for
          # two FIDO applications remain two distinct identities.
          def to_pem
            "#{ssh_type} #{[to_blob].pack('m0')}"
          end

          private

          def validate!
            raise InvalidPublicKey, "unsupported security key type `#{ssh_type}'" unless SecurityKey.understands?(ssh_type)

            unless application.is_a?(String) && application.start_with?(APPLICATION_PREFIX)
              raise InvalidPublicKey, "security key application must start with `#{APPLICATION_PREFIX}'"
            end

            case ssh_type
            when SK_ECDSA_SHA2_NISTP256
              raise InvalidPublicKey, "invalid sk-ecdsa curve `#{curve}'" unless curve == ECDSA_CURVE
              unless public_key_data.is_a?(String) && public_key_data.bytesize == ECDSA_POINT_BYTES &&
                     public_key_data.getbyte(0) == 0x04
                raise InvalidPublicKey, "invalid sk-ecdsa public key"
              end
            when SK_SSH_ED25519
              unless public_key_data.is_a?(String) && public_key_data.bytesize == ED25519_KEY_BYTES
                raise InvalidPublicKey, "invalid sk-ssh-ed25519 public key"
              end
            end
          end
        end
      end
    end
  end
end
