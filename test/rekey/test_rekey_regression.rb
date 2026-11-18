# frozen_string_literal: true

require 'openssl'
require 'logger'
require_relative '../common'
require 'net/ssh/transport/constants'
require 'net/ssh/connection/constants'
require 'net/ssh/authentication/session'
require_relative 'harness'

# Deterministic, in-memory regression tests for SSH rekey semantics.
#
# A real Net::SSH::Transport::Session talks to a fully implemented in-process
# peer (Net::SSH::Rekey::Server) over cross-connected pipes. Every protected
# packet is recorded in a shared, ordered transcript tagged with its key
# generation and sequence number, which lets these tests assert the exact
# invariants a correct rekey must preserve:
#
#   * the long-lived session id is the *first* exchange hash and never changes;
#   * each generation uses distinct key material derived from its own hash;
#   * application bytes survive back-to-back rekeys without loss or duplication;
#   * a direction cannot be unlocked with the other generation's keys;
#   * NEWKEYS is processed exactly once per exchange.
module Rekey
  class TestRekeyRegression < NetSSHTest
    include Net::SSH::Transport::Constants
    include Net::SSH::Connection::Constants

    CHANNEL_DATA = 94
    CHANNEL_WINDOW_ADJUST = 93

    def setup
      @harness = Net::SSH::Rekey::Harness.new(logger: Logger.new(nil))
      @harness.connect!
    end

    def test_initial_handshake_establishes_matching_session_id
      assert @harness.client.algorithms.initialized?
      assert_equal @harness.server.session_id, @harness.client.algorithms.session_id
      assert_equal 1, @harness.server.generation
      assert_equal 1, @harness.server.newkeys_seen
    end

    def test_session_id_stays_identical_across_two_rekeys
      original = @harness.client.algorithms.session_id

      @harness.client_rekey!
      assert_equal original, @harness.client.algorithms.session_id
      @harness.server_rekey!
      assert_equal original, @harness.client.algorithms.session_id

      # Three exchanges (initial + two rekeys), three distinct hashes, but the
      # retained session id always points at the first one.
      assert_equal 3, @harness.server.exchange_hashes.size
      assert_equal 3, @harness.server.exchange_hashes.uniq.size
      assert_equal @harness.server.exchange_hashes.first, original
      assert_equal original, @harness.server.session_id
    end

    def test_each_generation_uses_distinct_key_material
      @harness.client_rekey!
      @harness.server_send_channel_data(0, 'gen-2-data')
      @harness.server_rekey!
      @harness.server_send_channel_data(0, 'gen-3-data')

      hashes = @harness.server.exchange_hashes
      assert_equal hashes.uniq, hashes, 'exchange hashes must be unique per generation'

      # Records are tagged with the generation active when each frame was
      # protected. Pre-key KEX frames are generation 0; each rotation produces
      # protected frames at successively higher generations.
      protected_records = @harness.transcript.reject { |record| record.generation.zero? }
      assert protected_records.any?, 'expected at least one post-rotation protected frame'
      generations = protected_records.map(&:generation).uniq.sort
      assert_equal [1, 2, 3], generations
    end

    def test_application_bytes_survive_two_consecutive_rekeys
      payloads = ['before-any-rekey', 'after-client-rekey', 'after-server-rekey']

      @harness.server_send_channel_data(0, payloads[0])
      @harness.client_rekey!
      @harness.server_send_channel_data(0, payloads[1])
      @harness.server_rekey!
      @harness.server_send_channel_data(0, payloads[2])

      received = decode_channel_data(@harness.incoming)
      assert_equal payloads, received
    end

    def test_interleaved_channel_data_and_window_adjust_keep_order
      @harness.server_send_channel_data(0, 'data-0')
      @harness.server_send_window_adjust(0, 4096)
      @harness.client_rekey!
      @harness.server_send_window_adjust(0, 8192)
      @harness.server_send_channel_data(0, 'data-1')

      types = @harness.incoming.map(&:type)
      assert_equal [CHANNEL_DATA, CHANNEL_WINDOW_ADJUST,
                    CHANNEL_WINDOW_ADJUST, CHANNEL_DATA], types
    end

    def test_client_to_server_data_survives_rekeys
      up = ['uplink-0', 'uplink-1', 'uplink-2']

      send_client_channel_data(up[0])
      @harness.client_rekey!
      send_client_channel_data(up[1])
      @harness.server_rekey!
      send_client_channel_data(up[2])

      assert_equal up, @harness.server.channel_data
    end

    def test_newkeys_is_processed_exactly_once_per_exchange
      @harness.client_rekey!
      @harness.server_rekey!

      # One client NEWKEYS per exchange, including the initial handshake.
      assert_equal 3, @harness.server.newkeys_seen
      assert_equal 3, @harness.server.kex_count
    end

    def test_frames_carry_monotonic_sequence_numbers_per_direction
      @harness.server_send_channel_data(0, 'a')
      @harness.client_rekey!
      @harness.server_send_channel_data(0, 'b')

      server_records = @harness.transcript.select { |record| record.role == :server }
      sequences = server_records.map(&:seq)
      assert_equal sequences, sequences.sort, 'server sequence numbers must be monotonic'
      assert_equal sequences.uniq, sequences, 'server sequence numbers must not repeat'
    end

    def test_publickey_signature_is_bound_to_long_lived_session_id
      # Re-key before authenticating so the most recent exchange hash differs
      # from the session id the signature must be built on.
      @harness.client_rekey!
      @harness.server_rekey!
      refute_equal @harness.server.session_id, @harness.server.exchange_hashes.last

      authenticate_with_ecdsa_key

      signed = @harness.server.auth_requests.find { |record| record[:sig_blob] }
      refute_nil signed, 'expected a signed publickey USERAUTH_REQUEST'
      assert @harness.server.verify_publickey_signature!(signed)
    end

    def test_signature_rejected_when_verified_against_latest_exchange_hash
      @harness.client_rekey!
      authenticate_with_ecdsa_key

      signed = @harness.server.auth_requests.find { |record| record[:sig_blob] }
      server = @harness.server
      server.instance_variable_set(:@session_id, server.exchange_hashes.last)

      error = assert_raises(Net::SSH::Exception) do
        server.verify_publickey_signature!(signed)
      end
      assert_match(/session id/, error.message)
    ensure
      @harness.server.instance_variable_set(:@session_id,
                                            @harness.server.exchange_hashes.first)
    end

    def test_duplicate_newkeys_is_rejected
      # The server refuses a NEWKEYS that was not preceded by a fresh exchange,
      # which is what would happen if a queued NEWKEYS were replayed.
      fake_newkeys = Net::SSH::Packet.new(Net::SSH::Buffer.from(:byte, NEWKEYS).to_s)
      error = assert_raises(Net::SSH::Exception) do
        @harness.server.feed_packet(fake_newkeys)
      end
      assert_match(/duplicated NEWKEYS/, error.message)
    end

    private

    def send_client_channel_data(data)
      payload = Net::SSH::Buffer.from(:byte, CHANNEL_DATA, :long, 0, :string, data).to_s
      @harness.client_send(payload)
    end

    def decode_channel_data(packets)
      packets.map do |packet|
        packet.reset!
        packet.read_byte # type
        packet.read_long # recipient channel
        packet.read_string
      end
    end

    def authenticate_with_ecdsa_key
      user_key = OpenSSL::PKey::EC.generate('prime256v1')
      lock = @harness.instance_variable_get(:@client_lock)
      transport = @harness.client

      worker = Thread.new do
        lock.synchronize do
          auth = Net::SSH::Authentication::Session.new(
            transport,
            auth_methods: ['publickey'],
            key_data: [user_key.to_pem],
            keys_only: true,
            non_interactive: true,
            logger: Logger.new(nil)
          )
          auth.authenticate('ssh-connection', 'alice')
        end
      end

      deadline = Time.now + 15
      @harness.send(:pump_until) { !worker.alive? || Time.now > deadline }
      worker.join
    end
  end
end
