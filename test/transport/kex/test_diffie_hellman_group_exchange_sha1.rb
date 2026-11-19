require 'common'
require 'transport/kex/test_diffie_hellman_group1_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group_exchange_sha1'
require 'net/ssh/transport/kex/diffie_hellman_group14_sha1'

module Transport
  module Kex
    class TestDiffieHellmanGroupExchangeSHA1 < TestDiffieHellmanGroup1SHA1
      KEXDH_GEX_GROUP   = 31
      KEXDH_GEX_INIT    = 32
      KEXDH_GEX_REPLY   = 33
      KEXDH_GEX_REQUEST = 34

      # A fixed 2048-bit prime that IS prime but is NOT a safe prime: its
      # (p-1)/2 companion is composite. Used to prove that merely being prime,
      # or having an in-range bit length, is never accepted as a trustworthy
      # group. Generated once with OpenSSL::BN.generate_prime(2048, false).
      NON_SAFE_PRIME_HEX =
        'F7EEF34A16F140A63644EFFCB3A43F08F69140ECFE38E6754241116738C4FD7CEA073F3016FEC2B8502C5AD7AF7DA14E54A90CD4EFB8E3D3019A7E2963DDB4AB9829AF5378AD732171D50ABE9A2E026F4B463ABEA8571688688CB3529B9766228A9D25CDC8ADE5206DF7002A2D4A6E1C47036E5FC46AC1E145966C1FAD6EBBE143FFCA24BF959F9D87079C5D72FC32D1A37D0888626EA032DF0B5B79F0B66E6429FFE5C63A308A431723B556C4D244F64CCC30E170ADF08A75E09EEAC0A2EA21B8F23B7F74998FFD7EC32A05AD3662A8F088553CB91E9AF0DD6FC62D76FAAC2B60347629D6B542B8471CC337D2ECC5C9D4BB028DDF0C78782A40EFAB7D50655D'

      def test_request_sizes_follow_openssh_estimate
        { 8 => 2048, 14 => 2048, 16 => 3072, 24 => 7680, 32 => 8192, 64 => 8192 }.each do |need_bytes, need_bits|
          setup
          dh_options need_bytes: need_bytes
          assert_nothing_raised { exchange! }
          assert_equal [2048, need_bits, 8192], @request
        end
      end

      def test_minimum_dh_bits_raises_requested_sizes
        dh_options need_bytes: 8, minimum_dh_bits: 4096
        assert_nothing_raised { exchange! p: modulus(4096) }
        assert_equal [4096, 4096, 8192], @request
      end

      def test_cisco_server_caps_preferred_size
        packet_data[:server_version_string] = "SSH-2.0-Cisco-1.25"
        dh_options need_bytes: 32
        assert_nothing_raised { exchange! p: modulus(4096) }
        assert_equal [2048, 4096, 8192], @request
      end

      def test_non_cisco_server_preferred_size_is_not_capped
        packet_data[:server_version_string] = "SSH-2.0-OpenSSH_9.6 Cisco-1.25"
        dh_options need_bytes: 32
        assert_nothing_raised { exchange! }
        assert_equal [2048, 8192, 8192], @request
      end

      def test_cisco_server_preferred_size_stays_at_minimum_dh_bits
        packet_data[:server_version_string] = "SSH-2.0-Cisco-1.25"
        dh_options need_bytes: 32, minimum_dh_bits: 6144
        assert_nothing_raised { exchange! p: modulus(6144) }
        assert_equal [6144, 6144, 8192], @request
      end

      def test_minimum_dh_bits_below_default_accepts_legacy_group
        dh_options minimum_dh_bits: 1024
        assert_nothing_raised { exchange! p: legacy_p }
        assert_equal [1024, 7680, 8192], @request
        assert_equal legacy_p, dh.dh.p
      end

      def test_group_below_minimum_should_raise_exception_naming_opt_out
        error = assert_raises(Net::SSH::Exception) { exchange! p: legacy_p }
        assert_equal "server's DH group is 1024 bits, below the minimum of 2048; pass minimum_dh_bits: 1024 to allow it",
                     error.message
      end

      def test_group_below_custom_minimum_should_raise_exception
        dh_options minimum_dh_bits: 3072
        error = assert_raises(Net::SSH::Exception) { exchange! }
        assert_match(/2048 bits, below the minimum of 3072/, error.message)
      end

      def test_group_above_maximum_should_raise_exception
        error = assert_raises(Net::SSH::Exception) { exchange! p: modulus(8193) }
        assert_equal "server's DH group is 8193 bits, above the maximum of 8192", error.message
      end

      def test_invalid_generator_should_raise_exception
        [0, 1, default_p - 1, default_p].each do |g|
          setup
          error = assert_raises(Net::SSH::Exception) { exchange! g: g }
          assert_equal "server's DH group generator is invalid", error.message
        end
      end

      def test_that_p_and_g_are_provided_by_the_server
        assert_nothing_raised { exchange! p: default_p + 2, g: 3 }
        assert_equal default_p + 2, dh.dh.p
        assert_equal 3, dh.dh.g
      end

      def test_exchange_hash_matches_independent_vector_with_a_real_safe_prime
        # End-to-end run against the fixed RFC 3526 group14 safe prime with no
        # primality stubbing: the exchange hash must match a hash built from
        # the independently derived shared secret.
        result = exchange!(stub_primality: false)
        assert_equal session_id, result[:session_id]
        assert_equal shared_secret, result[:shared_secret]
      end

      def test_legacy_safe_prime_passes_real_cryptographic_validation
        dh_options minimum_dh_bits: 1024
        result = exchange!(p: legacy_p, stub_primality: false)
        assert_equal legacy_p, dh.dh.p
        assert_equal session_id, result[:session_id]
      end

      def test_valid_group_runs_exactly_two_bounded_primality_checks
        OpenSSL::BN.any_instance.expects(:prime?).with(subject::PRIMALITY_CHECKS).twice.returns(true)
        assert_nothing_raised { exchange!(stub_primality: false) }
      end

      def test_range_failure_never_reaches_primality_or_expensive_work
        OpenSSL::BN.any_instance.expects(:prime?).never
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: legacy_p) }
        assert_match(/below the minimum of 2048/, error.message)
      end

      def test_structure_failure_never_reaches_primality_or_expensive_work
        OpenSSL::BN.any_instance.expects(:prime?).never
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: default_p, g: 1) }
        assert_equal "server's DH group generator is invalid", error.message
      end

      def test_in_range_odd_composite_fails_cryptographic_validation
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: odd_composite, stub_primality: false) }
        assert_equal "server's DH group prime failed primality validation", error.message
      end

      def test_in_range_even_composite_is_rejected_without_running_primality
        OpenSSL::BN.any_instance.expects(:prime?).never
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: even_composite, stub_primality: false) }
        assert_equal "server's DH group prime failed primality validation", error.message
      end

      def test_in_range_prime_that_is_not_safe_is_rejected
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: non_safe_prime, stub_primality: false) }
        assert_equal "server's DH group prime is not a safe prime", error.message
      end

      def test_zero_prime_is_a_structural_error
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: OpenSSL::BN.new(0), g: 2) }
        assert_equal "server's DH group prime must be a positive integer", error.message
      end

      def test_prime_at_lower_bit_boundary_is_accepted
        assert_nothing_raised { exchange!(p: boundary_prime(2048)) }
        assert_equal 2048, dh.dh.p.num_bits
      end

      def test_prime_just_below_lower_boundary_is_rejected
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: boundary_prime(2047)) }
        assert_match(/2047 bits, below the minimum of 2048/, error.message)
      end

      def test_prime_at_upper_bit_boundary_is_accepted
        assert_nothing_raised { exchange!(p: boundary_prime(8192)) }
        assert_equal 8192, dh.dh.p.num_bits
      end

      def test_prime_just_above_upper_boundary_is_rejected
        expect_no_group_key_generation
        error = assert_raises(Net::SSH::Exception) { exchange!(p: boundary_prime(8193)) }
        assert_match(/8193 bits, above the maximum of 8192/, error.message)
      end

      def test_oversized_prime_is_refused_before_any_bignum_is_parsed
        # The encoded prime alone is far larger than the negotiated maximum; it
        # must be rejected from its declared length, so no oversized integer is
        # ever allocated and no DH key generation happens.
        expect_no_group_key_generation
        connection.expect do |transport, buffer|
          assert_equal KEXDH_GEX_REQUEST, buffer.type
          transport.return(KEXDH_GEX_GROUP, :bignum, OpenSSL::BN.new(1) << 100_000, :bignum, OpenSSL::BN.new(2))
        end

        error = assert_raises(Net::SSH::Exception) { dh.exchange_keys }
        assert_match(/exceeds the limit of \d+ bytes/, error.message)
      end

      def test_truncated_group_payload_is_a_structural_error
        expect_no_group_key_generation
        packet = Net::SSH::Buffer.from(:byte, KEXDH_GEX_GROUP, :long, 64)
        connection.expect do |transport, buffer|
          assert_equal KEXDH_GEX_REQUEST, buffer.type
          transport.queue << Net::SSH::Packet.new(packet)
        end

        error = assert_raises(Net::SSH::Exception) { dh.exchange_keys }
        assert_match(/only 0 bytes remain/, error.message)
      end

      private

      def group_p
        default_p
      end

      def default_p
        OpenSSL::BN.new(Net::SSH::Transport::Kex::DiffieHellmanGroup14SHA1::P_s, 16)
      end

      # 1024-bit group, as offered by legacy servers
      def legacy_p
        @legacy_p ||= OpenSSL::BN.new("142326151570335518660743995281621698377057354949884468943021767573608899048361360422513557553514790045512299468953431585300812548859419857171094366358158903433167915517332113861059747425408670144201099811846875730766487278261498262568348338476437200556998366087779709990807518291581860338635288400119315130179")
      end

      def non_safe_prime
        @non_safe_prime ||= OpenSSL::BN.new(NON_SAFE_PRIME_HEX, 16)
      end

      # An odd, in-range, 2048-bit composite (the group14 prime plus two).
      def odd_composite
        @odd_composite ||= default_p + 2
      end

      # An even, in-range, 2048-bit composite (the odd group14 prime plus one).
      def even_composite
        @even_composite ||= default_p + 1
      end

      def boundary_prime(bits)
        OpenSSL::BN.new((1 << (bits - 1)) + 0xFFFF_FFFF)
      end

      def modulus(bits)
        boundary_prime(bits)
      end

      def expect_no_group_key_generation
        OpenSSL::PKey::DH.any_instance.expects(:compute_key).never
        if OpenSSL::PKey.respond_to?(:generate_key)
          OpenSSL::PKey.expects(:generate_key).never
        else
          OpenSSL::PKey::DH.any_instance.expects(:generate_key!).never
        end
      end

      # Plumbing tests use fixed, non-prime modulus() values for speed, so the
      # bounded Miller-Rabin checks are stubbed by default. The group crosses
      # the mocked transport as an SSH2 bignum and is parsed back into a fresh
      # OpenSSL::BN instance, so expectations are installed on the class. Tests
      # that exercise the real validation pass stub_primality: false.
      def stub_group_primality
        OpenSSL::BN.any_instance.stubs(:prime?).with(subject::PRIMALITY_CHECKS).returns(true)
      end

      def exchange!(options = {})
        prime = options[:p] || default_p
        stub_group_primality if options.fetch(:stub_primality, true)

        connection.expect do |t, buffer|
          assert_equal KEXDH_GEX_REQUEST, buffer.type
          @request = [buffer.read_long, buffer.read_long, buffer.read_long]
          t.return(KEXDH_GEX_GROUP, :bignum, prime, :bignum, OpenSSL::BN.new(options[:g] || 2))
          t.expect do |t2, buffer2|
            assert_equal KEXDH_GEX_INIT, buffer2.type
            assert_equal dh.dh.pub_key, buffer2.read_bignum
            t2.return(KEXDH_GEX_REPLY, :string, options[:server_key_blob] || b(:key, server_key), :bignum, server_dh_pubkey, :string, b(:string, options[:key_type] || "ssh-rsa", :string, signature))
            t2.expect do |t3, buffer3|
              assert_equal NEWKEYS, buffer3.type
              t3.return(NEWKEYS)
            end
          end
        end

        dh.exchange_keys
      end

      def subject
        Net::SSH::Transport::Kex::DiffieHellmanGroupExchangeSHA1
      end

      def digest_type
        OpenSSL::Digest::SHA1
      end

      def session_id
        @session_id ||= begin
          buffer = Net::SSH::Buffer.from(:string, packet_data[:client_version_string],
                                         :string, packet_data[:server_version_string],
                                         :string, packet_data[:client_algorithm_packet],
                                         :string, packet_data[:server_algorithm_packet],
                                         :string, Net::SSH::Buffer.from(:key, server_key),
                                         :long,   @request[0],
                                         :long,   @request[1],
                                         :long,   @request[2],
                                         :bignum, dh.dh.p,
                                         :bignum, dh.dh.g,
                                         :bignum, dh.dh.pub_key,
                                         :bignum, server_dh_pubkey,
                                         :bignum, shared_secret)
          digest_type.digest(buffer.to_s)
        end
      end
    end
  end
end
