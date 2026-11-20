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
