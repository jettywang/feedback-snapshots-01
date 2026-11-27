# frozen_string_literal: true

class RedisClient
  class SentinelConfig
    include Config::Common

    SENTINEL_DELAY = 0.25
    DEFAULT_RECONNECT_ATTEMPTS = 2

    attr_reader :name, :recorder, :sentinel_address_policy, :node_address_policy

    def initialize(
      sentinels:,
      sentinel_password: nil,
      sentinel_username: nil,
      role: :master,
      name: nil,
      url: nil,
      allowed_sentinel_addresses: nil,
      allowed_node_addresses: nil,
      recorder: nil,
      **client_config
    )
      unless %i(master replica slave).include?(role.to_sym)
        raise ArgumentError, "Expected role to be either :master or :replica, got: #{role.inspect}"
      end

      # Track whether SSL was explicitly provided by user
      ssl_explicitly_set = client_config.key?(:ssl)

      if url
        url_config = URLConfig.new(url)
        client_config = {
          username: url_config.username,
          password: url_config.password,
          db: url_config.db,
          ssl: url_config.ssl?,
        }.compact.merge(client_config)
        name ||= url_config.host
      end

      @name = name
      unless @name
        raise ArgumentError, "RedisClient::SentinelConfig requires either a name or an url with a host"
      end

      @to_list_of_hash = @to_hash = nil
      password = if sentinel_password && !sentinel_password.respond_to?(:call)
        ->(_) { sentinel_password }
      else
        sentinel_password
      end
      @extra_config = {
        username: sentinel_username,
        password: password,
        db: nil,
      }
      if client_config[:protocol] == 2
        @extra_config[:protocol] = client_config[:protocol]
        @to_list_of_hash = lambda do |may_be_a_list|
          if may_be_a_list.is_a?(Array)
            may_be_a_list.map { |l| l.each_slice(2).to_h }
          else
            may_be_a_list
          end
        end
      end

      @sentinels = {}.compare_by_identity
      @role = role.to_sym
      @mutex = Mutex.new
      @config = nil

      @sentinel_address_policy = AddressPolicy.new(Array(allowed_sentinel_addresses))
      @node_address_policy = AddressPolicy.new(Array(allowed_node_addresses))
      @recorder = recorder || DiscoveryRecorder.new

      client_config[:reconnect_attempts] ||= DEFAULT_RECONNECT_ATTEMPTS
      @client_config = client_config || {}
      @sentinel_client_config = @client_config.dup
      # Only remove SSL from sentinel config if it was derived from URL,
      # not if explicitly set by user.
      @sentinel_client_config.delete(:ssl) unless ssl_explicitly_set
      super(**client_config)
      @sentinel_configs = sentinels_to_configs(sentinels)
    end

    def sentinels
      @mutex.synchronize do
        @sentinel_configs.dup
      end
    end

    def reset
      @mutex.synchronize do
        @config = nil
      end
    end

    def server_key
      config.server_key
    end

    def host
      config.host
    end

    def port
      config.port
    end

    def path
      nil
    end

    def retry_connecting?(attempt, error)
      reset unless error.is_a?(TimeoutError)
      super
    end

    def sentinel?
      true
    end

    def check_role!(role)
      unless role.is_a?(String)
        raise TypeError, "Expected role to be a string, got: #{role.inspect}"
      end

      if @role == :master
        unless role == "master"
          sleep SENTINEL_DELAY
          raise FailoverError, "Expected to connect to a master, but the server is a replica"
        end
      else
        unless role == "slave"
          sleep SENTINEL_DELAY
          raise FailoverError, "Expected to connect to a replica, but the server is a master"
        end
      end
    end

    def resolved?
      @mutex.synchronize do
        !!@config
      end
    end

    # Invoked by the client immediately before opening a socket to the resolved
    # Redis node, so an offline driver can observe the final connection target.
    def record_connection
      @recorder.record_connection(host, port)
    end

    private

    def sentinels_to_configs(sentinels)
      sentinels.map do |sentinel|
        case sentinel
        when String
          Config.new(**@sentinel_client_config, **@extra_config, url: sentinel)
        else
          Config.new(**@sentinel_client_config, **@extra_config, **sentinel)
        end
      end
    end

    def config
      @mutex.synchronize do
        @config ||= if @role == :master
          resolve_master
        else
          resolve_replica
        end
      end
    end

    def resolve_master
      each_sentinel do |sentinel_client|
        host, port = sentinel_client.call_v(["SENTINEL", "get-master-addr-by-name", @name])
        next unless host && port

        refresh_sentinels(sentinel_client)

        approve_node!(host, Integer(port), "master")

        return Config.new(host: host, port: Integer(port), **@client_config)
      end
    rescue AddressNotAllowedError
      raise
    rescue ConnectionError
      raise ConnectionError, "No sentinels available"
    else
      raise ConnectionError, "Couldn't locate a replica for role: #{@name}"
    end

    def sentinel_client(sentinel_config)
      @sentinels[sentinel_config] ||= sentinel_config.new_client
    end

    def resolve_replica
      each_sentinel do |sentinel_client|
        replicas = sentinel_client.call_v(["SENTINEL", "replicas", @name], &@to_list_of_hash)
        replicas.reject! do |r|
          flags = r["flags"].to_s.split(",")
          flags.include?("s_down") || flags.include?("o_down")
        end
        next if replicas.empty?

        replica = replicas.sample
        host = replica["ip"]
        port = Integer(replica["port"])
        approve_node!(host, port, "replica")

        return Config.new(host: host, port: port, **@client_config)
      end
    rescue AddressNotAllowedError
      raise
    rescue ConnectionError
      raise ConnectionError, "No sentinels available"
    else
      raise ConnectionError, "Couldn't locate a replica for role: #{@name}"
    end

    # A candidate is only serviceable when its origin (network range), role and
    # approval region all agree. The check is run for every resolution so a
    # failover never inherits the approval granted to the previous connection.
    # An out-of-range candidate is recorded and rejected before any connection
    # is opened to it.
    def approve_node!(host, port, role)
      @recorder.record_candidate(host, port, role)
      return if @node_address_policy.allowed?(host, port)

      @recorder.record_rejection(host, port, role, "address_not_allowed")
      raise AddressNotAllowedError,
        "#{role.capitalize} node #{host}:#{port} is outside of the configured allowed node ranges"
    end

    def each_sentinel
      last_error = nil

      @sentinel_configs.dup.each do |sentinel_config|
        @sentinel_address_policy.check!(sentinel_config.host, sentinel_config.port, "Sentinel")
        sentinel_client = sentinel_client(sentinel_config)
        success = true
        begin
          @recorder.record_sentinel(sentinel_config.host, sentinel_config.port, sentinel_command)
          yield sentinel_client, sentinel_config
        rescue RedisClient::Error => error
          last_error = error
          success = false
          sleep SENTINEL_DELAY
        ensure
          if success
            @sentinel_configs.unshift(@sentinel_configs.delete(sentinel_config))
          end
          # Redis Sentinels may be configured to have a lower maxclients setting than
          # the Redis nodes. Close the connection to the Sentinel node to avoid using
          # a connection.
          sentinel_client.close
        end
      end

      raise last_error if last_error
    end

    def sentinel_command
      @role == :master ? ["SENTINEL", "get-master-addr-by-name", @name] : ["SENTINEL", "replicas", @name]
    end

    def refresh_sentinels(sentinel_client)
      sentinel_response = sentinel_client.call_v(["SENTINEL", "sentinels", @name], &@to_list_of_hash)
      sentinels = sentinel_response.map do |sentinel|
        { host: sentinel.fetch("ip"), port: Integer(sentinel.fetch("port")) }
      end
      new_sentinels = sentinels.select do |sentinel|
        @sentinel_configs.none? do |sentinel_config|
          sentinel_config.host == sentinel.fetch(:host) && sentinel_config.port == sentinel.fetch(:port)
        end
      end

      approved_sentinels = new_sentinels.select do |sentinel|
        host = sentinel.fetch(:host)
        port = sentinel.fetch(:port)
        if @sentinel_address_policy.allowed?(host, port)
          true
        else
          @recorder.record_rejection(host, port, "sentinel", "address_not_allowed")
          false
        end
      end

      @sentinel_configs.concat sentinels_to_configs(approved_sentinels)
    end
  end
end
