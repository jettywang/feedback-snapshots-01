# frozen_string_literal: true

class RedisClient
  # A versioned set of TLS/SSL parameters.
  #
  # Each +TLSConfig+ is identified by an immutable +version+ and carries the
  # +ssl_params+ used to build the underlying +OpenSSL::SSL::SSLContext+. The
  # SSL context is built eagerly so that an invalid certificate configuration
  # raises while the object is constructed, i.e. *before* it can be promoted to
  # an approved trust version.
  class TLSConfig
    attr_reader :version, :ssl_params, :ssl_context

    def initialize(version:, ssl_params:, driver:)
      @version = version
      @ssl_params = ssl_params.dup
      # Eagerly build the context. An invalid cert/key/CA raises here rather
      # than later, so a broken configuration can never become an approved
      # instance.
      @ssl_context = driver.ssl_context(@ssl_params)
    end
  end

  # Holds the currently approved trust versions and decides which existing
  # connections are still allowed to be borrowed after a rotation.
  #
  # +retain+ controls how long connections established against a previous trust
  # version may keep being reused:
  #
  # - +:none+      – every borrow after a rotation reconnects to the current
  #                  approved version.
  # - +:in_flight+ – a connection already checked out when the rotation happens
  #                  may finish its current command, but once returned to the
  #                  pool it must reconnect on the next borrow.
  # - +:idle+      – connections sitting idle in the pool keep being reused
  #                  (across borrows) until the pool is closed/drained.
  class TrustRegistry
    RETAIN_POLICIES = %i[none in_flight idle].freeze

    attr_reader :retain

    def initialize(tls_configs, retain: :in_flight)
      unless RETAIN_POLICIES.include?(retain)
        raise ArgumentError,
          "Unknown TLS retain policy #{retain.inspect}, expected one of: #{RETAIN_POLICIES.map(&:inspect).join(', ')}"
      end

      @retain = retain
      @mutex = Mutex.new
      @configs = {}
      tls_configs.each { |entry| put(entry) }
      if @configs.empty?
        raise ArgumentError, "At least one TLS configuration is required"
      end
      @current_version = @configs.keys.last
    end

    # The version newly established connections must use.
    def current_version
      @mutex.synchronize { @current_version }
    end

    def current
      @mutex.synchronize { @configs.fetch(@current_version) }
    end

    # Every version still held by the registry (including superseded ones kept
    # for reuse depending on the retain policy).
    def versions
      @mutex.synchronize { @configs.keys.dup }
    end

    def ssl_context(version = nil)
      @mutex.synchronize do
        entry = @configs.fetch(version || @current_version)
        entry.ssl_context
      end
    end

    # Promotes +entry+ to the current approved version.
    #
    # The +entry+ is constructed (and therefore validated) by the caller before
    # this method runs, so a failure while building its SSL context never
    # mutates the approved state.
    def rotate(entry)
      @mutex.synchronize do
        put(entry)
        @current_version = entry.version
        entry.version
      end
    end

    # Whether a connection established against +version+ may be borrowed now.
    #
    # +checked_out+ indicates whether the calling thread currently holds the
    # connection. Under +:in_flight+ an in-use connection is allowed to finish
    # even though it is no longer the current version.
    def borrowable?(version, checked_out: false)
      @mutex.synchronize do
        next false unless @configs.key?(version)

        case @retain
        when :none
          version == @current_version
        when :in_flight
          version == @current_version || checked_out
        when :idle
          true
        else
          false
        end
      end
    end

    private

    def put(entry)
      if @configs.key?(entry.version)
        raise ArgumentError, "Duplicate TLS version #{entry.version.inspect}"
      end
      @configs[entry.version] = entry
    end
  end
end
