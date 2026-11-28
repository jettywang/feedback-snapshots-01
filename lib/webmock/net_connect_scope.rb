# frozen_string_literal: true

module WebMock
  # An isolated set of net-connect permissions, independent of the global
  # WebMock::Config. A scope keeps its own allow/deny rules, so tests running
  # concurrently in the same process cannot reset or widen each other's
  # permissions. Which scope applies is tracked per thread on an activation
  # stack; scopes activated by other threads are never consulted.
  class NetConnectScope
    attr_reader :allow_net_connect
    attr_reader :allow_localhost
    attr_reader :allow
    attr_reader :net_http_connect_on_start

    def initialize(allow_net_connect:, allow_localhost: nil, allow: nil,
                   net_http_connect_on_start: nil)
      @allow_net_connect = allow_net_connect
      @allow_localhost = allow_localhost
      @allow = allow
      @net_http_connect_on_start = net_http_connect_on_start
      @closed = false
    end

    def open?
      !@closed
    end

    def closed?
      @closed
    end

    def close
      return if closed?

      @closed = true
      WebMock::NetConnectScopeRegistry.instance.closed(self)
    end

    # Runs the block with this scope as the active scope for the current
    # thread. The previous scope is restored afterwards and the scope is
    # closed automatically.
    def activate
      registry = WebMock::NetConnectScopeRegistry.instance
      @closed = false
      registry.register(self)
      registry.push_scope(self)
      begin
        yield self
      ensure
        registry.pop_scope(self)
        close
      end
    end

    def net_connect_allowed?(uri = nil)
      return false unless open?
      return !!@allow_net_connect if uri.nil?

      if uri.is_a?(String)
        uri = WebMock::Util::URI.normalize_uri(uri)
      end

      !!(
        @allow_net_connect ||
        (@allow_localhost && WebMock::Util::URI.is_uri_localhost?(uri)) ||
        (@allow && WebMock.net_connect_explicit_allowed?(@allow, uri))
      )
    end

    def net_http_connect_on_start?(uri)
      return false unless open?

      allowed = @net_http_connect_on_start || false

      if [true, false].include?(allowed)
        allowed
      else
        WebMock.net_connect_explicit_allowed?(allowed, uri)
      end
    end
  end

  # Holds every open scope and the per-thread activation stack. The shared
  # scope list lets a scope be closed from any thread, while the thread-local
  # stack keeps concurrent tests isolated from each other.
  class NetConnectScopeRegistry
    include Singleton

    def initialize
      @scopes = []
      @mutex = Mutex.new
    end

    def register(scope)
      @mutex.synchronize { @scopes << scope unless @scopes.include?(scope) }
      scope
    end

    def unregister(scope)
      @mutex.synchronize { @scopes.delete(scope) }
    end

    # Called by NetConnectScope#close from any thread.
    def closed(scope)
      unregister(scope)
      activation_stack.delete(scope)
    end

    def push_scope(scope)
      activation_stack.push(scope)
    end

    def pop_scope(scope)
      activation_stack.delete(scope)
    end

    def reset!
      @mutex.synchronize do
        @scopes.each { |scope| scope.instance_variable_set(:@closed, true) }
        @scopes.clear
      end
      Thread.current[:webmock_net_connect_scopes] = nil
    end

    def current
      activation_stack.reverse_each.find(&:open?)
    end

    def net_connect_allowed?(uri = nil)
      if (scope = current)
        scope.net_connect_allowed?(uri)
      else
        global_net_connect_allowed?(uri)
      end
    end

    def net_http_connect_on_start?(uri)
      if (scope = current)
        scope.net_http_connect_on_start?(uri)
      else
        global_connect_on_start?(uri)
      end
    end

    private

    def activation_stack
      Thread.current[:webmock_net_connect_scopes] ||= []
    end

    def global_net_connect_allowed?(uri)
      config = WebMock::Config.instance
      return !!config.allow_net_connect if uri.nil?

      if uri.is_a?(String)
        uri = WebMock::Util::URI.normalize_uri(uri)
      end

      !!(
        config.allow_net_connect ||
        (config.allow_localhost && WebMock::Util::URI.is_uri_localhost?(uri)) ||
        (config.allow && WebMock.net_connect_explicit_allowed?(config.allow, uri))
      )
    end

    def global_connect_on_start?(uri)
      allowed = WebMock::Config.instance.net_http_connect_on_start || false
      return allowed if [true, false].include?(allowed)

      WebMock.net_connect_explicit_allowed?(allowed, uri)
    end
  end
end
