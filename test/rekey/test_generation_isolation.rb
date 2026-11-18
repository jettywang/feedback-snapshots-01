# frozen_string_literal: true

require 'openssl'
require_relative '../common'
require_relative 'crypto'

# Unit tests for the harness framing/key-derivation primitives. These pin the
# generation-isolation guarantees the end-to-end regression relies on: frames
# protected by one generation must fail HMAC verification under another
# generation's keys, and each generation must derive distinct key material from
# its own exchange hash while keeping the session id fixed.
module Rekey
  class TestGenerationIsolation < NetSSHTest
    def setup
      @digester = OpenSSL::Digest::SHA256
      @session_id = 'S' * 32
      @hash_one = 'H' * 32
      @hash_two = 'T' * 32
      @shared = OpenSSL::BN.new(0x0123_4567_89ab_cdef).to_ssh
      @cipher = 'aes256-ctr'
      @hmac = 'hmac-sha2-256'
    end

    def test_distinct_generations_derive_distinct_keys
      gen_one = Net::SSH::Rekey::Direction.new(
        :server_send, @shared, @hash_one, @session_id, @digester, @cipher, @hmac
      )
      gen_two = Net::SSH::Rekey::Direction.new(
        :server_send, @shared, @hash_two, @session_id, @digester, @cipher, @hmac
      )

      refute_equal gen_one.cipher_key, gen_two.cipher_key
      refute_equal gen_one.iv, gen_two.iv
    end

    def test_same_inputs_reproduce_identical_keys
      a = Net::SSH::Rekey::Direction.new(
        :server_recv, @shared, @hash_one, @session_id, @digester, @cipher, @hmac, 7
      )
      b = Net::SSH::Rekey::Direction.new(
        :server_recv, @shared, @hash_one, @session_id, @digester, @cipher, @hmac, 7
      )

      assert_equal a.cipher_key, b.cipher_key
      assert_equal a.iv, b.iv
      assert_equal a.sequence_number, b.sequence_number
    end

    def test_frame_protected_by_one_generation_fails_under_another
      sender = self_decoding_codec(@hash_one)
      frame, = sender.encode(Net::SSH::Buffer.from(:byte, 21).to_s)

      # A fresh codec built from the *next* generation's keys must reject the
      # frame rather than silently decrypt it.
      wrong_generation = self_decoding_codec(@hash_two)
      error = assert_raises(Net::SSH::Exception) do
        wrong_generation.decode(frame)
      end
      assert_match(/hmac|packet length/, error.message.downcase)
    end

    def test_frame_round_trips_under_matching_generation
      codec = self_decoding_codec(@hash_one)
      payload = Net::SSH::Buffer.from(:byte, 94, :long, 0, :string, 'round-trip').to_s
      frame, = codec.encode(payload)
      packets = codec.decode(frame)

      assert_equal 1, packets.size
      packets.first.reset!
      assert_equal 94, packets.first.read_byte
      packets.first.read_long
      assert_equal 'round-trip', packets.first.read_string
    end

    def test_sequence_number_is_carried_into_new_generation
      first = codec(:server_send, :server_recv, @hash_one)
      3.times { first.encode(Net::SSH::Buffer.from(:byte, 21).to_s) }
      assert_equal 3, first.send_dir.sequence_number

      rotated = Net::SSH::Rekey::FrameCodec.new(
        Net::SSH::Rekey::Direction.new(:server_send, @shared, @hash_two, @session_id,
                                       @digester, @cipher, @hmac, first.send_dir.sequence_number),
        Net::SSH::Rekey::Direction.new(:server_recv, @shared, @hash_two, @session_id,
                                       @digester, @cipher, @hmac, first.recv_dir.sequence_number)
      )
      assert_equal 3, rotated.send_dir.sequence_number
    end

    def test_salt_directions_are_reversed_for_server_and_client
      # A/C/E protect client->server; the server's receive direction must use
      # those same salts, while its send direction uses B/D/F.
      server_recv = Net::SSH::Rekey::Direction.new(
        :server_recv, @shared, @hash_one, @session_id, @digester, @cipher, @hmac
      )
      client_send = Net::SSH::Rekey::Direction.new(
        :encrypt, @shared, @hash_one, @session_id, @digester, @cipher, @hmac
      )

      assert_equal server_recv.cipher_key, client_send.cipher_key
      assert_equal server_recv.iv, client_send.iv
    end

    private

    # A codec whose send and receive directions share one SSH key stream (the
    # A/C/E salts) but use opposite cipher directions. This models a single
    # endpoint protecting and then validating its own frame, which is what the
    # generation-isolation checks need. The real server crosses salt pairs
    # instead (covered by test_salt_directions_are_reversed_for_server_and_client).
    def self_decoding_codec(hash)
      codec(:self_send, :self_recv, hash)
    end

    def codec(send_role, recv_role, hash)
      send_dir = Net::SSH::Rekey::Direction.new(
        send_role, @shared, hash, @session_id, @digester, @cipher, @hmac
      )
      recv_dir = Net::SSH::Rekey::Direction.new(
        recv_role, @shared, hash, @session_id, @digester, @cipher, @hmac
      )
      Net::SSH::Rekey::FrameCodec.new(send_dir, recv_dir)
    end
  end
end
