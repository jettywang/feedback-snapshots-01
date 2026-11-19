require 'openssl'
require 'net/ssh/buffer'
require 'net/ssh/transport/cipher_factory'
require 'net/ssh/authentication/pub_key_fingerprint'

module Net
  module SSH
    module Authentication
      module ED25519
        ALGORITHM = "ED25519"
        KEY_BYTES = 32
        PRIVATE_KEY_BYTES = 64

        class UnsupportedError < StandardError; end

        def self.ensure_supported!
          unless OpenSSL::PKey.respond_to?(:new_raw_public_key) && OpenSSL::PKey.respond_to?(:new_raw_private_key)
            raise UnsupportedError, "OpenSSL::PKey raw public/private key APIs are unavailable"
          end

          key = new_private_key("\x00" * KEY_BYTES)
          signature = sign(key, "")
          public_key = new_public_key(key.raw_public_key)
          raise UnsupportedError, "OpenSSL Ed25519 signature verification failed" unless verify(public_key, signature, "")
        rescue OpenSSL::PKey::PKeyError => e
          raise UnsupportedError, e.message
        end

        def self.new_public_key(key)
          validate_key_bytes!(key, "public key", KEY_BYTES)
          OpenSSL::PKey.new_raw_public_key(ALGORITHM, binary_string(key))
        end

        def self.new_private_key(key)
          validate_key_bytes!(key, "private key", KEY_BYTES)
          OpenSSL::PKey.new_raw_private_key(ALGORITHM, binary_string(key))
        end

        def self.sign(key, data)
          key.sign(nil, data)
        end

        def self.verify(key, signature, data)
          key.verify(nil, signature, data)
        end

        def self.validate_key_bytes!(key, label, expected_bytes)
          raise ArgumentError, "invalid Ed25519 #{label}" unless key.respond_to?(:bytesize) && key.bytesize == expected_bytes
        end

        def self.binary_string(string)
          string.dup.force_encoding('BINARY')
        end
        private_class_method :binary_string

        class OpenSSHPrivateKeyLoader
          CipherFactory = Net::SSH::Transport::CipherFactory

          MBEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
          MEND = "-----END OPENSSH PRIVATE KEY-----"
          MAGIC = "openssh-key-v1"

          # Default limit, matching OpenSSH; bcrypt_pbkdf with 2**32 rounds would
          # run for months (GHSA-rpq3-v334-f5pm). It can be lowered per load via
          # the :max_kdf_rounds option to bound the work a server is willing to do.
          DEFAULT_MAX_KDF_ROUNDS = 1 << 20
          # Backwards-compatible alias; the constant used to carry the single limit.
          MAX_KDF_ROUNDS = DEFAULT_MAX_KDF_ROUNDS

          # Base class for every failure while parsing an OpenSSH private key
          # container. It is an ArgumentError so existing callers that rescue
          # ArgumentError keep working, but the subclasses let the key factory
          # tell structural problems apart from a wrong passphrase.
          #
          # Messages deliberately describe what is wrong without echoing any
          # private key material.
          class KeyParseError < ArgumentError
            # Structural, unsupported or over-budget inputs are never fixed by
            # asking for another passphrase, so they are not retryable.
            def retryable?
              false
            end
          end

          # The container names a cipher, KDF or inner key type that Net::SSH
          # does not understand, or the PEM framing is not an OpenSSH key.
          class UnsupportedFormatError < KeyParseError; end

          # The container is recognizably OpenSSH but its fields do not parse:
          # truncated data, bad lengths, multiple keys, trailing bytes, or a
          # decoded private section that does not describe a valid key.
          class MalformedKeyError < KeyParseError; end

          # The KDF asks for more bcrypt rounds than the configured budget.
          # Raised before any expensive key derivation runs.
          class KdfBudgetError < KeyParseError
            attr_reader :rounds, :limit

            def initialize(rounds, limit)
              @rounds = rounds
              @limit = limit
              super("Private key bcrypt rounds #{rounds} exceeds the configured limit of #{limit}")
            end
          end

          # The key is encrypted and the passphrase was missing or wrong, or the
          # underlying cipher rejected the data. This is the only failure that
          # warrants prompting again.
          class DecryptError < ArgumentError
            def initialize(message, encrypted_key: false)
              super(message)
              @encrypted_key = encrypted_key
            end

            def encrypted_key?
              return @encrypted_key
            end

            # A decrypt failure on an encrypted key may be resolved by trying
            # another passphrase; every other parse error is not.
            def retryable?
              @encrypted_key
            end
          end

          def self.read(datafull, password, max_kdf_rounds: DEFAULT_MAX_KDF_ROUNDS)
            datafull = datafull.strip.encode(universal_newline: true)
            raise UnsupportedFormatError.new("Expected #{MBEGIN} at start of private key") unless datafull.start_with?(MBEGIN)
            raise UnsupportedFormatError.new("Expected #{MEND} at end of private key") unless datafull.end_with?(MEND)

            datab64 = datafull[MBEGIN.size...-MEND.size]
            data = datab64.unpack1("m")
            raise MalformedKeyError.new("Expected #{MAGIC} at start of decoded private key") unless data.start_with?(MAGIC)

            buffer = Net::SSH::Buffer.new(data[(MAGIC.size + 1)..-1])

            ciphername = require_string!(buffer, "cipher name")
            cipher_supported =
              begin
                CipherFactory.supported?(ciphername)
              rescue NotImplementedError
                false
              end
            raise UnsupportedFormatError.new("#{ciphername} in private key is not supported") unless cipher_supported

            kdfname = require_string!(buffer, "KDF name")
            raise UnsupportedFormatError.new("Expected #{kdfname} to be or none or bcrypt") unless %w[none bcrypt].include?(kdfname)

            kdfopts = Net::SSH::Buffer.new(require_string!(buffer, "KDF options"))
            num_keys = buffer.read_long
            raise MalformedKeyError.new("Only 1 key is supported in ssh keys #{num_keys} was in private key") unless num_keys == 1

            _pubkey = require_string!(buffer, "public key")

            if kdfname == 'bcrypt'
              salt = require_string!(kdfopts, "KDF salt")
              rounds = kdfopts.read_long
              raise MalformedKeyError.new("Private key is missing its bcrypt round count") if rounds.nil?
              # Enforce the budget before any expensive bcrypt_pbkdf derivation
              # (and before touching the encrypted section).
              raise KdfBudgetError.new(rounds, max_kdf_rounds) if rounds > max_kdf_rounds
            end

            len = buffer.read_long
            raise MalformedKeyError.new("Private key section length is missing") if len.nil?
            encrypted_private = buffer.read(len)

            keylen, blocksize, ivlen = CipherFactory.get_lengths(ciphername, iv_len: true)
            raise MalformedKeyError.new("Private key len:#{len} is not a multiple of #{blocksize}") if
              (len < blocksize) || ((blocksize > 0) && (len % blocksize) != 0)

            raise MalformedKeyError.new("Private key len:#{len} exceeds available data") unless encrypted_private.bytesize == len

            authlen = CipherFactory.auth_length(ciphername)
            auth_tag = authlen > 0 ? buffer.read(authlen) : nil
            raise MalformedKeyError.new("Private key is missing its #{authlen}-byte authentication tag") if authlen > 0 && auth_tag.nil?

            if kdfname == 'bcrypt'
              key = bcrypt_pbkdf_key(password, salt, keylen + ivlen, rounds)
            else
              key = "\x00" * (keylen + ivlen)
            end

            decoded = decrypt_private_key(
              ciphername,
              encrypted_private,
              auth_tag,
              key: key[0...keylen],
              iv: key[keylen...(keylen + ivlen)],
              encrypted_key: kdfname == 'bcrypt'
            )

            decoded = Net::SSH::Buffer.new(decoded)
            check1 = decoded.read_long
            check2 = decoded.read_long

            checkints_missing = check1.nil? || check2.nil?
            raise DecryptError.new("Decrypt failed on private key", encrypted_key: kdfname == 'bcrypt') if
              checkints_missing || (check1 != check2)

            type_name = decoded.read_string
            raise MalformedKeyError.new("Decoded private key is missing its key type") if type_name.nil?
            build_private_key(type_name, decoded)
          end

          def self.require_string!(buffer, field)
            value = buffer.read_string
            raise MalformedKeyError.new("Private key is missing or truncated: #{field}") if value.nil?
            value
          end

          def self.build_private_key(type_name, decoded)
            # Raise outside the rescues below: UnsupportedFormatError is itself an
            # ArgumentError and must not be reclassified as a malformed key.
            raise UnsupportedFormatError.new("Private key type #{type_name} is not supported") unless
              type_name == "ssh-ed25519" || type_name == "ssh-rsa" || type_name.start_with?("ecdsa-sha2-")

            begin
              case type_name
              when "ssh-ed25519"
                PrivKey.new(decoded)
              else
                decoded.read_private_keyblob(type_name)
              end
            rescue Net::SSH::Exception => e
              raise UnsupportedFormatError, e.message
            rescue OpenSSL::PKey::PKeyError, ArgumentError => e
              raise MalformedKeyError, "Decoded private key of type #{type_name} is not valid: #{e.message}"
            end
          end

          def self.bcrypt_pbkdf_key(password, salt, length, rounds)
            begin
              require_bcrypt_pbkdf
            rescue LoadError
              raise DecryptError.new("bcrypt_pbkdf is required to decrypt bcrypt-encrypted OpenSSH private keys")
            end
            raise DecryptError.new("Passphrase required for encrypted private key", encrypted_key: true) if password.nil? || password.empty?

            key = BCryptPbkdf::key(password, salt, length, rounds)
            raise DecryptError.new("BCryptPbkdf failed", encrypted_key: true) unless key

            key
          end

          def self.require_bcrypt_pbkdf
            require 'bcrypt_pbkdf'
          end

          def self.decrypt_private_key(ciphername, encrypted_private, auth_tag, options)
            if auth_tag
              return CipherFactory.decrypt_private_key(
                ciphername,
                encrypted_private,
                auth_tag,
                options[:key],
                options[:iv]
              )
            end

            cipher = CipherFactory.get(ciphername, key: options[:key], iv: options[:iv], decrypt: true)
            decoded = cipher.update(encrypted_private)
            decoded << cipher.final
          rescue Net::SSH::Exception, OpenSSL::Cipher::CipherError
            raise DecryptError.new("Decrypt failed on private key", encrypted_key: options[:encrypted_key])
          end
        end

        class PubKey
          include Net::SSH::Authentication::PubKeyFingerprint

          def initialize(data)
            ED25519.validate_key_bytes!(data, "public key", KEY_BYTES)
            @public_key_bytes = data.dup.force_encoding('BINARY')
          end

          def self.read_keyblob(buffer)
            PubKey.new(buffer.read_string)
          end

          def to_blob
            Net::SSH::Buffer.from(:mstring, "ssh-ed25519".dup, :string, public_key_bytes).to_s
          end

          def ssh_type
            "ssh-ed25519"
          end

          def ssh_signature_type
            ssh_type
          end

          def ssh_do_verify(sig, data, options = {})
            ED25519.verify(verify_key, sig, data)
          end

          def to_pem
            # TODO this is not pem
            ssh_type + [public_key_bytes].pack("m")
          end

          def public_key_bytes
            @public_key_bytes.dup
          end

          def verify_key
            @verify_key ||= ED25519.new_public_key(@public_key_bytes)
          end
        end

        class PrivKey
          CipherFactory = Net::SSH::Transport::CipherFactory

          attr_reader :sign_key

          def initialize(buffer)
            pk = buffer.read_string
            sk = buffer.read_string
            _comment = buffer.read_string

            ED25519.validate_key_bytes!(pk, "public key", KEY_BYTES)
            ED25519.validate_key_bytes!(sk, "private key field", PRIVATE_KEY_BYTES)

            private_key_bytes = sk[0, KEY_BYTES]
            raise ArgumentError, "Ed25519 private key does not include matching public key" unless sk[KEY_BYTES, KEY_BYTES] == pk

            @sign_key = ED25519.new_private_key(private_key_bytes)
            raise ArgumentError, "Ed25519 public key does not match private key" unless @sign_key.raw_public_key == pk

            @public_key_bytes = pk.dup.force_encoding('BINARY')
            @private_key_bytes = private_key_bytes.dup.force_encoding('BINARY')
          end

          def to_blob
            public_key.to_blob
          end

          def ssh_type
            "ssh-ed25519"
          end

          def ssh_signature_type
            ssh_type
          end

          def public_key
            PubKey.new(public_key_bytes)
          end

          def ssh_do_sign(data, sig_alg = nil)
            ED25519.sign(@sign_key, data)
          end

          def public_key_bytes
            @public_key_bytes.dup
          end

          def private_key_bytes
            @private_key_bytes.dup
          end

          def private_key_bytes_for_agent
            private_key_bytes + public_key_bytes
          end

          def self.read(data, password, **options)
            OpenSSHPrivateKeyLoader.read(data, password, **options)
          end
        end
      end
    end
  end
end
