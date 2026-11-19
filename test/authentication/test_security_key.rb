# encoding: ASCII-8BIT
# frozen_string_literal: false

require_relative '../common'
require 'net/ssh/buffer'
require 'net/ssh/authentication/security_key'

module Authentication
  class TestSecurityKey < NetSSHTest
    SK_ECDSA = Net::SSH::Authentication::SecurityKey::SK_ECDSA_SHA2_NISTP256
    SK_ED25519 = Net::SSH::Authentication::SecurityKey::SK_SSH_ED25519

    # 65-byte uncompressed NIST P-256 point (0x04 || X || Y).
    ECDSA_POINT = "\x04#{"\x11" * 64}".b
    ED25519_POINT = ("\x22" * 32).b

    # Fixed public key vectors; fingerprints match `ssh-keygen -lf` output.
    ECDSA_KEY_B64 = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBKoqiTnbbceOXTHddiPfT6F1W2zgnGZmj0QtNS8JEfmZbLWmxZjU+8XgJ91cqMWkrNVb48+YcKV6jgwKte45WNcAAAAEc3NoOg==".freeze
    ED25519_KEY_B64 = "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIB3EAkD0aWTMZBn0rMaYZO7wh/2h9yPe7dXShspyBI0WAAAABHNzaDo=".freeze

    def ecdsa_key
      @ecdsa_key ||= Net::SSH::Buffer.new(ECDSA_KEY_B64.unpack1("m")).read_key
    end

    def ed25519_key
      @ed25519_key ||= Net::SSH::Buffer.new(ED25519_KEY_B64.unpack1("m")).read_key
    end

    def sk_ecdsa_blob(application = "ssh:")
      Net::SSH::Buffer.from(:string, SK_ECDSA, :string, "nistp256",
                            :string, ECDSA_POINT, :string, application).to_s
    end

    def sk_ed25519_blob(application = "ssh:")
      Net::SSH::Buffer.from(:string, SK_ED25519, :string, ED25519_POINT,
                            :string, application).to_s
    end

    def test_buffer_read_key_returns_security_key_pubkey_for_sk_ecdsa
      key = Net::SSH::Buffer.new(sk_ecdsa_blob).read_key
      assert_instance_of Net::SSH::Authentication::SecurityKey::PubKey, key
      assert_equal SK_ECDSA, key.ssh_type
      assert_equal "nistp256", key.curve
      assert_equal ECDSA_POINT, key.public_key_data
      assert_equal "ssh:", key.application
    end

    def test_buffer_read_key_returns_security_key_pubkey_for_sk_ed25519
      key = Net::SSH::Buffer.new(sk_ed25519_blob).read_key
      assert_instance_of Net::SSH::Authentication::SecurityKey::PubKey, key
      assert_equal SK_ED25519, key.ssh_type
      assert_nil key.curve
      assert_equal ED25519_POINT, key.public_key_data
      assert_equal "ssh:", key.application
    end

    def test_to_blob_round_trips_sk_ecdsa
      blob = sk_ecdsa_blob
      assert_equal blob, Net::SSH::Buffer.new(blob).read_key.to_blob
    end

    def test_to_blob_round_trips_sk_ed25519
      blob = sk_ed25519_blob
      assert_equal blob, Net::SSH::Buffer.new(blob).read_key.to_blob
    end

    def test_fingerprint_uses_openssh_sha256_format
      blob = sk_ecdsa_blob
      key = Net::SSH::Buffer.new(blob).read_key
      expected = "SHA256:#{[OpenSSL::Digest.digest('SHA256', blob)].pack('m').chomp.delete('=')}"
      assert_equal expected, key.fingerprint('SHA256')
    end

    def test_ssh_signature_type_is_key_type
      key = Net::SSH::Buffer.new(sk_ed25519_blob).read_key
      assert_equal SK_ED25519, key.ssh_signature_type
    end

    def test_understands_only_known_sk_types
      assert Net::SSH::Authentication::SecurityKey.understands?(SK_ECDSA)
      assert Net::SSH::Authentication::SecurityKey.understands?(SK_ED25519)
      refute Net::SSH::Authentication::SecurityKey.understands?("ssh-ed25519")
      refute Net::SSH::Authentication::SecurityKey.understands?("ecdsa-sha2-nistp256")
    end

    def test_unknown_type_still_raises
      blob = Net::SSH::Buffer.from(:string, "totally-unknown", :string, "x").to_s
      assert_raises(Net::SSH::UnsupportedKeyType) { Net::SSH::Buffer.new(blob).read_key }
    end

    def test_pub_key_read_keyblob_rejects_unknown_sk_type
      buffer = Net::SSH::Buffer.from(:string, "x", :string, "ssh:")
      error = assert_raises(Net::SSH::UnsupportedKeyType) do
        Net::SSH::Authentication::SecurityKey::PubKey.read_keyblob("sk-unknown@openssh.com", buffer)
      end
      assert_equal "unsupported security key type `sk-unknown@openssh.com'", error.message
    end

    def test_same_public_key_bytes_with_different_application_are_distinct_identities
      first = Net::SSH::Buffer.new(sk_ed25519_blob("ssh:first")).read_key
      second = Net::SSH::Buffer.new(sk_ed25519_blob("ssh:second")).read_key

      assert_equal ED25519_POINT, first.public_key_data
      assert_equal ED25519_POINT, second.public_key_data
      refute_equal first.to_blob, second.to_blob
      refute_equal first.to_pem, second.to_pem
      refute_equal first.fingerprint("SHA256"), second.fingerprint("SHA256")
    end

    def test_same_public_key_bytes_and_application_are_the_same_identity
      first = Net::SSH::Buffer.new(sk_ed25519_blob("ssh:first")).read_key
      second = Net::SSH::Buffer.new(sk_ed25519_blob("ssh:first")).read_key

      assert_equal first.to_blob, second.to_blob
      assert_equal first.to_pem, second.to_pem
      assert_equal first.fingerprint("SHA256"), second.fingerprint("SHA256")
    end

    def test_application_must_start_with_ssh
      blob = sk_ed25519_blob("https://example.com")
      error = assert_raises(Net::SSH::Authentication::SecurityKey::InvalidPublicKey) do
        Net::SSH::Buffer.new(blob).read_key
      end
      assert_equal "security key application must start with `ssh:'", error.message
    end

    def test_ecdsa_curve_must_be_nistp256
      blob = Net::SSH::Buffer.from(:string, SK_ECDSA, :string, "nistp384",
                                   :string, ECDSA_POINT, :string, "ssh:").to_s
      error = assert_raises(Net::SSH::Authentication::SecurityKey::InvalidPublicKey) do
        Net::SSH::Buffer.new(blob).read_key
      end
      assert_equal "invalid sk-ecdsa curve `nistp384'", error.message
    end

    def test_ecdsa_point_must_be_an_uncompressed_p256_point
      [("x" * 64).b, "\x02#{"\x11" * 64}".b, "\x04#{"\x11" * 63}".b].each do |point|
        blob = Net::SSH::Buffer.from(:string, SK_ECDSA, :string, "nistp256",
                                     :string, point, :string, "ssh:").to_s
        assert_raises(Net::SSH::Authentication::SecurityKey::InvalidPublicKey, point.inspect) do
          Net::SSH::Buffer.new(blob).read_key
        end
      end
    end

    def test_ed25519_public_key_must_be_32_bytes
      blob = Net::SSH::Buffer.from(:string, SK_ED25519, :string, "x" * 31,
                                   :string, "ssh:").to_s
      assert_raises(Net::SSH::Authentication::SecurityKey::InvalidPublicKey) do
        Net::SSH::Buffer.new(blob).read_key
      end
    end

    def test_standalone_public_key_rejects_trailing_bytes
      blob = sk_ed25519_blob + "extra"
      error = assert_raises(Net::SSH::Authentication::SecurityKey::InvalidPublicKey) do
        Net::SSH::Buffer.new(blob).read_key
      end
      assert_equal "trailing data after #{SK_ED25519} public key", error.message
    end

    def test_fixed_vectors_keep_their_openssh_fingerprints
      assert_equal "SHA256:ndD+3s351AVTSHGXmwN8KG46k38xvz3y/5NBNDvaRr0", ecdsa_key.fingerprint("SHA256")
      assert_equal "SHA256:n1tKMhw1/usLdyMTVdX7V5lnr/UDVmVJZncNA0ipvYk", ed25519_key.fingerprint("SHA256")
    end

    def test_sk_ed25519_signature_records_up_and_uv_as_structured_claims
      blob = Net::SSH::Buffer.from(:string, SK_ED25519, :string, "s" * 64,
                                   :byte, 0x05, :long, 3).to_s
      signature = ed25519_key.parse_agent_signature(blob)

      assert_equal SK_ED25519, signature.algorithm
      assert_equal 3, signature.counter
      assert signature.user_presence?
      assert signature.user_verification?
      assert_equal blob, signature.to_blob
    end

    def test_sk_ecdsa_signature_is_an_openssh_ecdsa_signature_body
      body = Net::SSH::Buffer.from(:string, "\x01".b, :string, "\x02".b).to_s
      blob = Net::SSH::Buffer.from(:string, SK_ECDSA, :string, body,
                                   :byte, 0x01, :long, 0).to_s
      signature = ecdsa_key.parse_agent_signature(blob)

      assert_equal SK_ECDSA, signature.algorithm
      assert signature.user_presence?
      refute signature.user_verification?
      assert_equal body, signature.signature
    end

    def test_sk_ed25519_rejects_a_plain_ed25519_signature
      blob = Net::SSH::Buffer.from(:string, "ssh-ed25519", :string, "s" * 64).to_s
      error = assert_raises(Net::SSH::Authentication::SecurityKey::SignatureError) do
        ed25519_key.parse_agent_signature(blob)
      end
      assert_equal "unexpected signature algorithm `\"ssh-ed25519\"'", error.message
    end

    def test_sk_signature_rejects_algorithm_mismatch
      blob = Net::SSH::Buffer.from(:string, SK_ECDSA, :string, "s" * 64,
                                   :byte, 0x01, :long, 0).to_s
      error = assert_raises(Net::SSH::Authentication::SecurityKey::SignatureError) do
        ed25519_key.parse_agent_signature(blob)
      end
      assert_equal "signature algorithm `#{SK_ECDSA}' does not match key type `#{SK_ED25519}'", error.message
    end

    def test_sk_signature_rejects_truncated_trailer_and_trailing_data
      no_counter = Net::SSH::Buffer.from(:string, SK_ED25519, :string, "s" * 64,
                                         :byte, 0x01).to_s
      trailing = Net::SSH::Buffer.from(:string, SK_ED25519, :string, "s" * 64,
                                       :byte, 0x01, :long, 0, :raw, "x").to_s

      assert_raises(Net::SSH::Authentication::SecurityKey::SignatureError) do
        ed25519_key.parse_agent_signature(no_counter)
      end
      assert_raises(Net::SSH::Authentication::SecurityKey::SignatureError) do
        ed25519_key.parse_agent_signature(trailing)
      end
    end

    def test_sk_signature_preserves_unrecognised_auth_data_bits
      # UP/UV are the bits net-ssh reports; other authData bits are
      # token-specific and must round-trip rather than make the signature
      # unusable.
      blob = Net::SSH::Buffer.from(:string, SK_ED25519, :string, "s" * 64,
                                   :byte, 0x41, :long, 0).to_s
      signature = ed25519_key.parse_agent_signature(blob)

      assert signature.user_presence?
      refute signature.user_verification?
      assert_equal 0x41, signature.flags
      assert_equal blob, signature.to_blob
    end

    def test_sk_signature_rejects_wrong_ed25519_length
      blob = Net::SSH::Buffer.from(:string, SK_ED25519, :string, "s" * 63,
                                   :byte, 0x01, :long, 0).to_s
      assert_raises(Net::SSH::Authentication::SecurityKey::SignatureError) do
        ed25519_key.parse_agent_signature(blob)
      end
    end
  end
end
