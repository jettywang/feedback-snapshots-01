# frozen_string_literal: true

# Self-contained, offline test for versioned TLS trust rotation. It does not
# rely on the full test_helper (which stands up Redis/Toxiproxy servers); a fake
# driver + raw connection record the exact TLS parameters/version each
# connection is negotiated with so pool selection can be asserted without I/O.
require "redis_client"
require "minitest/autorun"

class RedisClient
  class TLSRotationTest < Minitest::Test
    class FakeRawConnection
      include ConnectionMixin

      attr_reader :connects

      attr_accessor :connect_timeout, :read_timeout, :write_timeout

      def initialize(config, connect_timeout:, read_timeout:, write_timeout:)
        super(config)
        @connect_timeout = connect_timeout
        @read_timeout = read_timeout
        @write_timeout = write_timeout
        @closed = false
        @connects = []
        connect
      end

      def connect
        @closed = false
        @server_key = @config.server_key
        # Record the trust version + ssl_params this connection was built with.
        @connects << {
          version: @config.tls_version,
          ssl_params: @config.trust_registry.current.ssl_params.dup,
        }
      end

      def reconnect
        close
        connect
      end

      def close
        @closed = true
        super
      end

      def connected?
        !@closed
      end

      def write(_command); end

      def write_multi(_commands); end

      # Low-level response read. @pending_reads accounting is owned entirely by
      # ConnectionMixin#call/#call_pipelined (increment before, decrement after
      # read), so this double must not touch it — otherwise it double-counts.
      def read(_timeout = nil)
        "OK"
      end
    end

    module FakeDriver
      def self.ssl_context(ssl_params)
        params = ssl_params || {}
        raise OpenSSL::SSL::SSLError, "invalid TLS configuration" if params[:ca_file] == "BOGUS_CA"

        [:fake_context, params].freeze
      end

      def self.new(config, **kwargs)
        FakeRawConnection.new(config, **kwargs)
      end
    end

    def setup
      RedisClient.register_driver(:tls_fake) { FakeDriver }
    end

    def base_params(version, ca)
      { version: version, ssl_params: { ca_file: ca, verify_mode: OpenSSL::SSL::VERIFY_PEER } }
    end

    def build_pool(retain:, size: 2)
      config = RedisClient::Config.new(
        host: "example.test",
        port: 6379,
        driver: :tls_fake,
        tls: [base_params(:v1, "ca-v1")],
        tls_retain: retain,
      )
      [config, config.new_pool(size: size, timeout: 1)]
    end

    def raw_connection(client)
      client.instance_variable_get(:@raw_connection)
    end

    def test_tls_flag_and_single_hash_shorthand
      config = RedisClient::Config.new(
        host: "example.test", port: 6379, driver: :tls_fake,
        tls: base_params(:only, "ca"),
      )
      assert_predicate config, :ssl?
      assert_predicate config, :versioned_tls?
      assert_equal :only, config.tls_version
      assert_equal [:only], config.tls_versions
    end

    def test_invalid_retain_policy_is_rejected
      error = assert_raises(ArgumentError) do
        RedisClient::Config.new(
          host: "example.test", port: 6379, driver: :tls_fake,
          tls: [base_params(:v1, "ca")], tls_retain: :nope,
        )
      end
      assert_includes error.message, "Unknown TLS retain policy"
    end

    def test_invalid_initial_tls_config_never_becomes_approved
      assert_raises(OpenSSL::SSL::SSLError) do
        RedisClient::Config.new(
          host: "example.test", port: 6379, driver: :tls_fake,
          tls: [base_params(:v1, "BOGUS_CA")],
        )
      end
    end

    def test_duplicate_initial_versions_are_rejected
      error = assert_raises(ArgumentError) do
        RedisClient::Config.new(
          host: "example.test", port: 6379, driver: :tls_fake,
          tls: [base_params(:v1, "ca-a"), base_params(:v1, "ca-b")],
        )
      end
      assert_includes error.message, "Duplicate TLS version"
    end

    def test_rotation_requires_versioned_tls
      config = RedisClient::Config.new(host: "example.test", port: 6379, driver: :tls_fake)
      assert_raises(ArgumentError) do
        config.rotate_tls!(**base_params(:v2, "ca-v2"))
      end
    end

    def test_rotating_to_an_existing_version_is_rejected
      config, _pool = build_pool(retain: :in_flight)
      error = assert_raises(ArgumentError) do
        config.rotate_tls!(**base_params(:v1, "ca-again"))
      end
      assert_includes error.message, "Duplicate TLS version"
      assert_equal :v1, config.tls_version
    end

    def test_failed_rotation_does_not_pollute_approved_instances
      _config, pool = build_pool(retain: :in_flight)
      pool.with { |c| c.call("PING") }

      assert_raises(OpenSSL::SSL::SSLError) do
        pool.rotate_tls!(**base_params(:bad, "BOGUS_CA"))
      end

      assert_equal :v1, pool.tls_version
      assert_equal [:v1], pool.tls_versions
      pool.with do |client|
        assert_equal :v1, client.connection_tls_version
      end
    end

    def test_in_flight_lets_old_request_finish_then_reconnects_after_return
      config, pool = build_pool(retain: :in_flight)

      old_client = pool.with { |c| c.call("PING"); c }
      old_raw = raw_connection(old_client)
      assert_equal :v1, old_raw.tls_version

      # Rotate during the borrowed connection's lifetime (mid-command window).
      config.rotate_tls!(**base_params(:v2, "ca-v2"))
      assert_equal :v2, config.tls_version

      # The already checked-out connection is allowed to finish its work.
      assert config.tls_version_borrowable?(:v1, checked_out: true)
      assert_equal "OK", old_raw.call(["PING"], nil)
      assert_equal :v1, old_raw.tls_version

      # Once returned, re-borrowing the stale idle connection replaces its raw
      # connection with a fresh one negotiated against the current version.
      pool.with do |client|
        assert_same old_client, client
        refute_same old_raw, raw_connection(client)
        assert_equal :v2, client.connection_tls_version
        assert_equal [[:v2]], raw_connection(client).connects.map { |c| [c[:version]] }
      end
    end

    def test_in_flight_new_borrow_uses_current_version
      config, pool = build_pool(retain: :in_flight)
      pool.with { |c| c.call("PING") } # establish + return a v1 connection

      config.rotate_tls!(**base_params(:v2, "ca-v2"))

      pool.with do |client|
        assert_equal :v2, client.connection_tls_version
        recorded = raw_connection(client).connects.last
        assert_equal :v2, recorded[:version]
        assert_equal "ca-v2", recorded[:ssl_params][:ca_file]
      end
    end

    def test_none_policy_reconnects_every_borrow_after_rotation
      config, pool = build_pool(retain: :none)
      pool.with { |c| c.call("PING") }

      config.rotate_tls!(**base_params(:v2, "ca-v2"))
      refute config.tls_version_borrowable?(:v1, checked_out: true)

      pool.with do |client|
        assert_equal :v2, client.connection_tls_version
      end
    end

    def test_idle_policy_keeps_reusing_returned_connections
      config, pool = build_pool(retain: :idle)
      pool.with { |c| c.call("PING") } # a v1 connection now sits idle in the pool

      config.rotate_tls!(**base_params(:v2, "ca-v2"))
      assert config.tls_version_borrowable?(:v1)

      pool.with do |client|
        # The idle v1 connection is still selected; no reconnect happened.
        assert_equal :v1, client.connection_tls_version
        assert_equal 1, raw_connection(client).connects.size
      end
    end

    def test_new_connection_after_idle_rotation_uses_current_version
      config, pool = build_pool(retain: :idle, size: 1)
      pool.with { |c| c.call("PING") }
      config.rotate_tls!(**base_params(:v2, "ca-v2"))

      # Close the pooled client's raw connection; the replacement must
      # negotiate the current (v2) trust version on the next borrow.
      pool.with(&:close)
      pool.with do |client|
        assert_equal :v2, client.connection_tls_version
      end
    end

    def test_connection_records_tls_params_it_was_built_with
      _config, pool = build_pool(retain: :in_flight)
      pool.with do |client|
        client.call("PING")
        recorded = raw_connection(client).connects.first
        assert_equal :v1, recorded[:version]
        assert_equal "ca-v1", recorded[:ssl_params][:ca_file]
        assert_equal OpenSSL::SSL::VERIFY_PEER, recorded[:ssl_params][:verify_mode]
      end
    end
  end
end
