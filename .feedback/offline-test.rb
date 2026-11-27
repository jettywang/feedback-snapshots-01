# Exercises the local client without opening a connection.
require "redis_client"
require "minitest/autorun"

class OfflineConfigTest < Minitest::Test
  def test_tls_and_database_from_url
    config = RedisClient::Config.new(url: "rediss://example.test/4")
    assert_equal "example.test", config.host
    assert config.ssl?
    assert_equal 4, config.db
  end

  def test_credentials_are_included_in_handshake
    config = RedisClient::Config.new(
      protocol: 3, url: "redis://reader:fixture@example.test/0"
    )
    assert_includes config.connection_prelude, ["HELLO", "3", "AUTH", "reader", "fixture"]
  end

  def test_invalid_url_error_filters_credential
    error = assert_raises(ArgumentError) do
      RedisClient::Config.new(url: "http://:fixture@example.test")
    end
    refute_includes error.message, "fixture"
  end
end

# A driver that never opens a socket. Every instantiation is counted so the tests
# can prove that an out-of-range candidate is rejected before a connection attempt.
class OfflineRedisDriver
  include RedisClient::ConnectionMixin

  class << self
    attr_accessor :instances, :role
  end
  self.instances = []
  self.role = "master"

  def self.reset!
    instances.clear
    self.role = "master"
  end

  def initialize(config, connect_timeout:, read_timeout:, write_timeout:)
    super(config)
    self.class.instances << self
  end

  def connected?
    true
  end

  def close
  end

  def write(_command)
  end

  def write_multi(_commands)
  end

  def read(_timeout = nil)
    [self.class.role]
  end
end

# Scripted Sentinel that answers from canned responses without a network.
class OfflineSentinelClient
  def initialize(responses)
    @responses = responses
  end

  def call_v(command, &block)
    response = @responses.fetch(command.first(2)).shift
    raise "unexpected command or exhausted responses: #{command.inspect}" if response.nil?

    block ? block.call(response) : response
  end

  def close
  end
end

class OfflineSentinelPolicyTest < Minitest::Test
  DISCOVERY_RANGE = "10.0.0.0/24"
  NODE_RANGE = "192.168.0.0/16"
  SENTINEL_HOST = "10.0.0.10"
  MASTER_HOST = "192.168.1.5"
  FOREIGN_HOST = "203.0.113.9"

  def setup
    OfflineRedisDriver.reset!
  end

  def test_allowed_master_is_queried_resolved_and_connected
    config = build_config
    stub_sentinel(config, master_responses(MASTER_HOST))

    assert_equal ["master"], config.new_client.call("PING")

    recorder = config.recorder
    assert_equal [[SENTINEL_HOST, 26_379]],
      recorder.sentinel_queries.map { |event| [event[:host], event[:port]] }
    assert_equal [{ host: MASTER_HOST, port: 6379, role: "master" }], recorder.candidates
    assert_equal [{ host: MASTER_HOST, port: 6379 }], recorder.connections
    assert_equal MASTER_HOST, recorder.last_connection[:host]
    assert_empty recorder.rejections
    assert_equal 1, OfflineRedisDriver.instances.size
  end

  def test_out_of_range_node_is_rejected_without_connecting
    config = build_config
    stub_sentinel(config, master_responses(FOREIGN_HOST))

    error = assert_raises(RedisClient::AddressNotAllowedError) do
      config.new_client.call("PING")
    end

    assert_includes error.message, FOREIGN_HOST
    recorder = config.recorder
    assert_equal 1, recorder.sentinel_queries.size
    assert_equal [{ host: FOREIGN_HOST, port: 6379, role: "master" }], recorder.candidates
    assert_equal "address_not_allowed", recorder.rejections.first[:reason]
    assert_empty recorder.connections
    assert_nil recorder.last_connection
    assert_empty OfflineRedisDriver.instances
  end

  def test_sentinel_outside_discovery_range_is_rejected
    config = build_config(sentinels: [{ host: FOREIGN_HOST, port: 26_379 }])

    assert_raises(RedisClient::AddressNotAllowedError) do
      config.new_client.call("PING")
    end

    assert_empty config.recorder.connections
    assert_empty OfflineRedisDriver.instances
  end

  def test_failover_re_checks_policy_instead_of_reusing_approval
    config = build_config
    responses = {
      ["SENTINEL", "get-master-addr-by-name"] =>
        [[MASTER_HOST, "6379"], [FOREIGN_HOST, "6379"]],
      ["SENTINEL", "sentinels"] => [[], []],
    }
    stub_sentinel(config, responses)

    client = config.new_client
    client.call("PING")
    assert_equal MASTER_HOST, config.recorder.last_connection[:host]

    config.reset
    error = assert_raises(RedisClient::AddressNotAllowedError) { client.call("PING") }
    assert_includes error.message, FOREIGN_HOST

    assert_equal [MASTER_HOST, FOREIGN_HOST], config.recorder.candidates.map { |c| c[:host] }
    assert_equal FOREIGN_HOST, config.recorder.rejections.first[:host]
    # The new node is never reached, so the last connection stays the original one.
    assert_equal MASTER_HOST, config.recorder.last_connection[:host]
    assert_equal 1, OfflineRedisDriver.instances.size
  end

  def test_replica_role_is_checked_against_node_range
    OfflineRedisDriver.role = "slave"
    config = build_config(role: :replica)
    responses = {
      ["SENTINEL", "replicas"] =>
        [[{ "ip" => MASTER_HOST, "port" => "6380", "flags" => "slave" }]],
    }
    stub_sentinel(config, responses)

    config.new_client.call("PING")

    assert_equal [{ host: MASTER_HOST, port: 6380, role: "replica" }], config.recorder.candidates
    assert_equal MASTER_HOST, config.recorder.last_connection[:host]
  end

  def test_without_allowlists_all_addresses_are_permitted
    config = RedisClient.sentinel(
      name: "cache",
      sentinels: [{ host: SENTINEL_HOST, port: 26_379 }],
      driver: OfflineRedisDriver,
      reconnect_attempts: 0,
    )
    stub_sentinel(config, master_responses(FOREIGN_HOST))

    config.new_client.call("PING")

    assert_empty config.recorder.rejections
    assert_equal FOREIGN_HOST, config.recorder.last_connection[:host]
  end

  private

  def build_config(role: :master, sentinels: nil)
    RedisClient.sentinel(
      name: "cache",
      role: role,
      sentinels: sentinels || [{ host: SENTINEL_HOST, port: 26_379 }],
      driver: OfflineRedisDriver,
      reconnect_attempts: 0,
      allowed_sentinel_addresses: [DISCOVERY_RANGE],
      allowed_node_addresses: [NODE_RANGE],
    )
  end

  def stub_sentinel(config, responses)
    client = OfflineSentinelClient.new(responses)
    config.define_singleton_method(:sentinel_client) { |_sentinel_config| client }
  end

  def master_responses(host)
    {
      ["SENTINEL", "get-master-addr-by-name"] => [[host, "6379"]],
      ["SENTINEL", "sentinels"] => [[]],
    }
  end
end
