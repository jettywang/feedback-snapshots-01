# frozen_string_literal: true

require "ipaddr"

class RedisClient
  class SentinelConfig
    # Immutable set of network ranges that an endpoint is allowed to belong to.
    # A policy without any range is permissive and approves every address, which
    # preserves the historical behaviour when no allow-list is configured.
    class AddressPolicy
      def initialize(ranges)
        @ranges = ranges.map { |range| range.is_a?(IPAddr) ? range : IPAddr.new(range.to_s) }.freeze
      end

      def allowed?(host, port)
        return true if @ranges.empty?

        address = IPAddr.new(host.to_s)
        @ranges.any? { |range| range.include?(address) }
      rescue IPAddr::InvalidAddressError
        false
      end

      def check!(host, port, kind)
        return if allowed?(host, port)

        raise AddressNotAllowedError,
          "#{kind} address #{host}:#{port} is outside of the configured allowed ranges"
      end
    end

    # Records the discovery decisions made by a SentinelConfig. It is deliberately
    # connection free so that an offline driver can assert what was queried, which
    # candidates were considered and whether a connection was ever attempted.
    class DiscoveryRecorder
      attr_reader :sentinel_queries, :candidates, :connections

      def initialize
        @sentinel_queries = []
        @candidates = []
        @rejections = []
        @connections = []
      end

      def record_sentinel(host, port, command)
        @sentinel_queries << { host: host, port: port, command: command.dup.freeze }.freeze
      end

      def record_candidate(host, port, role)
        @candidates << { host: host, port: port, role: role }.freeze
      end

      def record_rejection(host, port, role, reason)
        @rejections << { host: host, port: port, role: role, reason: reason }.freeze
      end

      def record_connection(host, port)
        @connections << { host: host, port: port }.freeze
      end

      def rejections
        @rejections.dup
      end

      def last_connection
        @connections.last
      end
    end
  end
end
