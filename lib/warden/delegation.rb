# encoding: utf-8
# frozen_string_literal: true

module Warden
  # Base class for all errors raised by a scope-restricted context.
  class DelegationError < StandardError; end

  # Raised when a restricted context is asked for a scope it was not granted.
  class ScopeNotGranted < DelegationError; end

  # Raised when a restricted context is asked for an operation it was not granted.
  class CapabilityNotGranted < DelegationError; end

  # Raised when a restricted context is used after its call has finished.
  class DelegationExpired < DelegationError; end

  # Raised when a restricted context is used outside its own delegation frame,
  # for example an outer handle while a narrower inner context is active.
  class DelegationNotActive < DelegationError; end

  # Raised when a nested context asks for more than its parent granted.
  class DelegationEscalation < DelegationError; end

  # Raised when a restricted context tries to obtain a writable session.
  class WritableSessionNotGranted < DelegationError; end

  # A read-only view of a session (or scoped session) hash.
  #
  # Reads return deeply copied values so a caller cannot mutate the backing
  # session through the returned object or through a nested value. Every
  # mutating Hash method raises Warden::WritableSessionNotGranted.
  class ReadOnlySession
    include Enumerable

    MUTATORS = %i[
      []= store delete delete_if keep_if reject! select! filter! clear
      merge! update replace shift pop compact! transform_values!
      transform_keys! deep_merge! rehash default= default_proc=
      compare_by_identity
    ].freeze

    def initialize(hash, scope = nil)
      @hash = hash || {}
      @scope = scope
    end

    def [](key)
      self.class.copy(@hash[key])
    end

    def fetch(*args, &block)
      self.class.copy(@hash.fetch(*args, &block))
    end

    def dig(*keys)
      self.class.copy(@hash.dig(*keys))
    end

    def key?(key)
      @hash.key?(key)
    end
    alias has_key? key?
    alias include? key?
    alias member? key?

    def each(&block)
      return enum_for(:each) unless block

      @hash.each { |key, value| block.call(key, self.class.copy(value)) }
      self
    end
    alias each_pair each

    def keys
      @hash.keys
    end

    def values
      @hash.values.map { |value| self.class.copy(value) }
    end

    def each_value
      return enum_for(:each_value) unless block_given?

      @hash.each_value { |value| yield self.class.copy(value) }
      self
    end

    def each_key
      return enum_for(:each_key) unless block_given?

      @hash.each_key { |key| yield key }
      self
    end

    def values_at(*keys)
      self.class.copy(@hash.values_at(*keys))
    end

    def size
      @hash.size
    end
    alias length size

    def empty?
      @hash.empty?
    end

    def to_h
      self.class.copy(@hash)
    end
    alias to_hash to_h

    def inspect
      "#<Warden::ReadOnlySession scope=#{@scope.inspect} #{@hash.inspect}>"
    end
    alias to_s inspect

    def ==(other)
      to_h == (other.respond_to?(:to_h) ? other.to_h : other)
    end

    def method_missing(name, *args, &block)
      if MUTATORS.include?(name)
        raise WritableSessionNotGranted,
              "session for scope #{@scope.inspect} is read-only inside a restricted context"
      elsif @hash.respond_to?(name)
        self.class.copy(@hash.public_send(name, *args, &block))
      else
        super
      end
    end

    def respond_to_missing?(name, include_private = false)
      MUTATORS.include?(name) || @hash.respond_to?(name, include_private) || super
    end

    # Deep copy hashes and arrays so callers cannot reach the real session.
    def self.copy(value)
      case value
      when Hash
        value.each_with_object({}) { |(key, item), copy| copy[key] = self.copy(item) }.freeze
      when Array
        value.map { |item| self.copy(item) }.freeze
      else
        value
      end
    end
  end

  # A read-only view over a Warden::SessionSerializer. It can fetch identities
  # but cannot store or delete them.
  class ReadOnlySessionSerializer
    def initialize(serializer)
      @serializer = serializer
    end

    def key_for(scope)
      @serializer.key_for(scope)
    end

    # Fetch an identity without the stale-key cleanup the real serializer does,
    # so a read inside a restricted context never mutates the session.
    def fetch(scope)
      key = @serializer.session[key_for(scope)]
      return nil unless key

      method_name = "#{scope}_deserialize"
      if @serializer.respond_to?(method_name)
        @serializer.send(method_name, key)
      else
        @serializer.deserialize(key)
      end
    end

    def stored?(scope)
      @serializer.stored?(scope)
    end

    def session
      Warden::ReadOnlySession.new(@serializer.session, :serializer)
    end

    def serialize(_user)
      raise WritableSessionNotGranted,
            "the session serializer is read-only inside a restricted context"
    end

    def deserialize(key)
      @serializer.deserialize(key)
    end

    def store(_user, _scope)
      raise WritableSessionNotGranted,
            "the session serializer is read-only inside a restricted context"
    end

    def delete(_scope, _user = nil)
      raise WritableSessionNotGranted,
            "the session serializer is read-only inside a restricted context"
    end
  end

  # The handle yielded to a Warden::Proxy#delegate block.
  #
  # It can read an already resolved identity and scoped session data, and it
  # can perform only the operations the caller explicitly delegated. The
  # handle is revoked when the block returns and cannot be used afterwards.
  class RestrictedContext
    CAPABILITIES = %i[read set_user logout authenticate].freeze

    attr_reader :scopes, :capabilities

    def initialize(proxy, scopes:, capabilities:, parent: nil)
      @proxy = proxy
      @scopes = normalize_list(scopes).freeze
      @capabilities = normalize_capabilities(capabilities).freeze
      @active = true

      validate_subset!(parent) if parent
    end

    # Read an already resolved identity. This never runs a strategy.
    def user(scope = nil)
      ensure_active!
      @proxy.user(scope)
    end
    alias principal user

    def authenticated?(scope = nil, &block)
      ensure_active!
      @proxy.authenticated?(scope, &block)
    end

    def unauthenticated?(scope = nil, &block)
      ensure_active!
      @proxy.unauthenticated?(scope, &block)
    end

    # Returns a read-only view of the scoped session data.
    def session(scope = nil)
      ensure_active!
      @proxy.session(scope.nil? ? @proxy.config.default_scope : scope)
    end

    # The raw session is deliberately not exposed to a plugin: it would reveal
    # keys belonging to scopes that were not granted. Use #session instead.
    def raw_session
      ensure_active!
      raise CapabilityNotGranted,
            "the raw session is not exposed inside a restricted context"
    end

    # Explicitly delegated write operations. The proxy enforces the grant and
    # raises Warden::CapabilityNotGranted / Warden::ScopeNotGranted otherwise.
    def set_user(user, opts = {})
      ensure_active!
      @proxy.set_user(user, opts)
    end

    def logout(*scopes)
      ensure_active!
      @proxy.logout(*scopes)
    end

    def authenticate(*args)
      ensure_active!
      @proxy.authenticate(*args)
    end

    def authenticate?(*args, &block)
      ensure_active!
      @proxy.authenticate?(*args, &block)
    end

    def authenticate!(*args)
      ensure_active!
      @proxy.authenticate!(*args)
    end

    def granted_scope?(scope)
      @scopes.include?(normalize(scope))
    end

    def granted_capability?(capability)
      @capabilities.include?(normalize(capability))
    end

    def active?
      !!@active
    end

    # A restricted handle is tied to exactly one call. Copying it would create
    # a second reference that could outlive revocation, so copying is refused.
    def initialize_copy(_other)
      raise DelegationError, "restricted contexts cannot be copied"
    end

    def expired?
      !active?
    end

    # Called by the proxy when the delegation block ends.
    # :api: private
    def revoke!
      @active = false
      self
    end

    def inspect
      "#<Warden::RestrictedContext scopes=#{@scopes.inspect} " \
        "capabilities=#{@capabilities.inspect} #{active? ? 'active' : 'revoked'}>"
    end
    alias to_s inspect

    private

    def ensure_active!
      raise DelegationExpired, "this restricted context has been revoked" unless active?

      unless @proxy.current_delegation.equal?(self)
        raise DelegationNotActive,
              "this restricted context is not the active delegation frame"
      end
    end

    def normalize_list(values)
      Array(values).map { |value| normalize(value) }.uniq
    end

    # Reading an already resolved identity is the baseline grant. Granting
    # :authenticate also implies :read, because authentication looks up a
    # resolved identity before deciding whether to run a strategy.
    def normalize_capabilities(values)
      capabilities = normalize_list(values)
      unknown = capabilities - CAPABILITIES
      unless unknown.empty?
        raise ArgumentError, "unknown delegated capabilities: #{unknown.inspect}"
      end

      capabilities << :read if capabilities.include?(:authenticate)
      (capabilities << :read).uniq
    end

    def normalize(value)
      value.respond_to?(:to_sym) ? value.to_sym : value
    end

    def validate_subset!(parent)
      extra_scopes = @scopes - parent.scopes
      unless extra_scopes.empty?
        raise DelegationEscalation,
              "nested context cannot grant scopes the outer context lacks: #{extra_scopes.inspect}"
      end

      extra_capabilities = @capabilities - parent.capabilities
      unless extra_capabilities.empty?
        raise DelegationEscalation,
              "nested context cannot grant capabilities the outer context lacks: " \
              "#{extra_capabilities.inspect}"
      end
    end
  end
end
