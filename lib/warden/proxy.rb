# encoding: utf-8
# frozen_string_literal: true

module Warden
  class UserNotSet < RuntimeError; end

  class Proxy
    # An accessor to the winning strategy
    # :api: private
    attr_accessor :winning_strategy

    # An accessor to the rack env hash, the proxy owner and its config
    # :api: public
    attr_reader :env, :manager, :config, :winning_strategies

    extend ::Forwardable
    include ::Warden::Mixins::Common

    ENV_WARDEN_ERRORS = 'warden.errors'.freeze
    ENV_SESSION_OPTIONS = 'rack.session.options'.freeze

    # :api: private
    def_delegators :winning_strategy, :headers, :status, :custom_response

    # :api: public
    def_delegators :config, :default_strategies

    def initialize(env, manager) #:nodoc:
      @env, @users, @winning_strategies, @locked = env, {}, {}, false
      @manager, @config = manager, manager.config.dup
      @strategies = Hash.new { |h,k| h[k] = {} }
      @delegation_stack = []
    end

    # Runs a block with a scope-restricted context suitable for handing to a
    # plugin. The context can always read already resolved identities from the
    # allowed scopes; writes and strategy execution happen only for explicitly
    # delegated capabilities.
    #
    # The grant lives only for the duration of the block. When the block
    # returns or raises, the context is revoked and the proxy returns to its
    # normal behaviour, so the main request keeps managing the session through
    # the ordinary Warden API.
    #
    # Parameters:
    #   scopes       - scopes the plugin may inspect. Defaults to the default scope.
    #   capabilities - explicitly delegated operations. Supported values are
    #                  :read, :set_user, :logout and :authenticate. :read is
    #                  always available. Granting :authenticate also grants :read.
    #
    # Example:
    #   env['warden'].delegate(:scopes => [:reports]) do |ctx|
    #     ctx.user                # resolved identity, never runs a strategy
    #     ctx.session[:filters]   # read-only view of the scoped session
    #   end
    #
    #   env['warden'].delegate(:scopes => [:default], :capabilities => [:set_user]) do |ctx|
    #     ctx.set_user(user)      # explicit, short-lived delegated write
    #   end
    #
    # :api: public
    def delegate(*args, scopes: nil, capabilities: [:read], &block)
      options = args.last.is_a?(Hash) ? args.pop : {}
      if args.length > 1
        raise ArgumentError, "expected at most one positional scope list, got #{args.inspect}"
      end

      scopes = args.first unless args.empty?
      scopes = options[:scopes] if options.key?(:scopes)
      capabilities = options[:capabilities] if options.key?(:capabilities)

      raise ArgumentError, "a block is required to delegate a restricted context" unless block

      parent = @delegation_stack.last
      context = RestrictedContext.new(
        self,
        :scopes => scopes.nil? ? [@config.default_scope] : scopes,
        :capabilities => capabilities,
        :parent => parent
      )

      @delegation_stack.push(context)
      begin
        block.call(context)
      ensure
        context.revoke!
        @delegation_stack.pop
      end
    end
    alias restricted_context delegate

    # The innermost active restricted context, if any.
    # :api: private
    def current_delegation
      @delegation_stack.last
    end

    def delegating?
      !@delegation_stack.empty?
    end

    # Run the on_request callbacks
    # :api: private
    def on_request
      manager._run_callbacks(:on_request, self)
    end

    # Lazily initiate errors object in session.
    # :api: public
    def errors
      @env[ENV_WARDEN_ERRORS] ||= Errors.new
    end

    # Points to a SessionSerializer instance responsible for handling
    # everything related with storing, fetching and removing the user
    # session.
    #
    # Inside a restricted context this is a read-only wrapper, so a plugin
    # cannot store or delete identities through it.
    # :api: public
    def session_serializer
      return ReadOnlySessionSerializer.new(_session_serializer) if delegating?
      _session_serializer
    end

    # Clear the cache of performed strategies so far. Warden runs each
    # strategy just once during the request lifecycle. You can clear the
    # strategies cache if you want to allow a strategy to be run more than
    # once.
    #
    # This method has the same API as authenticate, allowing you to clear
    # specific strategies for given scope:
    #
    # Parameters:
    #   args - a list of symbols (labels) that name the strategies to attempt
    #   opts - an options hash that contains the :scope of the user to check
    #
    # Example:
    #   # Clear all strategies for the configured default_scope
    #   env['warden'].clear_strategies_cache!
    #
    #   # Clear all strategies for the :admin scope
    #   env['warden'].clear_strategies_cache!(:scope => :admin)
    #
    #   # Clear password strategy for the :admin scope
    #   env['warden'].clear_strategies_cache!(:password, :scope => :admin)
    #
    # :api: public
    def clear_strategies_cache!(*args)
      if delegating?
        raise CapabilityNotGranted,
              "the strategy cache cannot be cleared inside a restricted context"
      end

      scope, _opts = _retrieve_scope_and_opts(args)

      @winning_strategies.delete(scope)
      @strategies[scope].each do |k, v|
        v.clear! if args.empty? || args.include?(k)
      end
    end

    # Locks the proxy so new users cannot authenticate during the
    # request lifecycle. This is useful when the request cannot
    # be verified (for example, using a CSRF verification token).
    # Notice that already authenticated users are kept as so.
    #
    # :api: public
    def lock!
      if delegating?
        raise CapabilityNotGranted,
              "the proxy cannot be locked inside a restricted context"
      end
      @locked = true
    end

    # Run the authentication strategies for the given strategies.
    # If there is already a user logged in for a given scope, the strategies are not run
    # This does not halt the flow of control and is a passive attempt to authenticate only
    # When scope is not specified, the default_scope is assumed.
    #
    # Parameters:
    #   args - a list of symbols (labels) that name the strategies to attempt
    #   opts - an options hash that contains the :scope of the user to check
    #
    # Example:
    #   env['warden'].authenticate(:password, :basic, :scope => :sudo)
    #
    # :api: public
    def authenticate(*args)
      _guard_authentication!(args)
      user, _opts = _perform_authentication(*args)
      user
    end

    # Same API as authenticate, but returns a boolean instead of a user.
    # The difference between this method (authenticate?) and authenticated?
    # is that the former will run strategies if the user has not yet been
    # authenticated, and the second relies on already performed ones.
    # :api: public
    def authenticate?(*args)
      result = !!authenticate(*args)
      yield if result && block_given?
      result
    end

    # The same as +authenticate+ except on failure it will throw a :warden symbol causing the request to be halted
    # and rendered through the +failure_app+
    #
    # Example
    #   env['warden'].authenticate!(:password, :scope => :publisher) # throws if it cannot authenticate
    #
    # :api: public
    def authenticate!(*args)
      _guard_authentication!(args)
      user, opts = _perform_authentication(*args)
      throw(:warden, opts) unless user
      user
    end

    # Check to see if there is an authenticated user for the given scope.
    # This brings the user from the session, but does not run strategies before doing so.
    # If you want strategies to be run, please check authenticate?.
    #
    # Parameters:
    #   scope - the scope to check for authentication. Defaults to default_scope
    #
    # Example:
    #   env['warden'].authenticated?(:admin)
    #
    # :api: public
    def authenticated?(scope = @config.default_scope)
      result = !!user(scope)
      yield if block_given? && result
      result
    end

    # Same API as authenticated?, but returns false when authenticated.
    # :api: public
    def unauthenticated?(scope = @config.default_scope)
      result = !authenticated?(scope)
      yield if block_given? && result
      result
    end

    # Manually set the user into the session and auth proxy
    #
    # Parameters:
    #   user - An object that has been setup to serialize into and out of the session.
    #   opts - An options hash.  Use the :scope option to set the scope of the user, set the :store option to false to skip serializing into the session, set the :run_callbacks to false to skip running the callbacks (the default is true).
    #
    # :api: public
    def set_user(user, opts = {})
      if delegating?
        _assert_capability!(:set_user)
        _assert_scope!(opts[:scope] || @config.default_scope)
      end
      _set_user(user, opts)
    end

    # Provides access to the user object in a given scope for a request.
    # Will be nil if not logged in. Please notice that this method does not
    # perform strategies.
    #
    # Example:
    #   # without scope (default user)
    #   env['warden'].user
    #
    #   # with scope
    #   env['warden'].user(:admin)
    #
    #   # as a Hash
    #   env['warden'].user(:scope => :admin)
    #
    #   # with default scope and run_callbacks option
    #   env['warden'].user(:run_callbacks => false)
    #
    #  # with a scope and run_callbacks option
    #  env['warden'].user(:scope => :admin, :run_callbacks => true)
    #
    # :api: public
    def user(argument = {})
      opts  = argument.is_a?(Hash) ? argument : { :scope => argument }
      scope = (opts[:scope] ||= @config.default_scope)
      _assert_scope!(scope) if delegating?
      _user(opts)
    end

    # Provides a scoped session data for authenticated users.
    # Warden manages clearing out this data when a user logs out
    #
    # Example
    #  # default scope
    #  env['warden'].session[:foo] = "bar"
    #
    #  # :sudo scope
    #  env['warden'].session(:sudo)[:foo] = "bar"
    #
    # :api: public
    def session(scope = @config.default_scope)
      if delegating?
        _assert_scope!(scope)
        raise NotAuthenticated, "#{scope.inspect} user is not logged in" unless authenticated?(scope)
        return ReadOnlySession.new(_raw_session["warden.user.#{scope}.session"] || {}, scope)
      end

      raise NotAuthenticated, "#{scope.inspect} user is not logged in" unless authenticated?(scope)
      raw_session["warden.user.#{scope}.session"] ||= {}
    end

    # The raw session is not exposed inside a restricted context. A plugin
    # should use the delegated, scoped #session view instead.
    def raw_session
      if delegating?
        raise CapabilityNotGranted,
              "the raw session is not exposed inside a restricted context"
      end
      _raw_session
    end

    # Provides logout functionality.
    # The logout also manages any authenticated data storage and clears it when a user logs out.
    #
    # Parameters:
    #   scopes - a list of scopes to logout
    #
    # Example:
    #  # Logout everyone and clear the session
    #  env['warden'].logout
    #
    #  # Logout the default user but leave the rest of the session alone
    #  env['warden'].logout(:default)
    #
    #  # Logout the :publisher and :admin user
    #  env['warden'].logout(:publisher, :admin)
    #
    # :api: public
    def logout(*scopes)
      if delegating?
        _assert_capability!(:logout)
        if scopes.empty?
          raise ScopeNotGranted,
                "an explicit scope is required when logging out inside a restricted context"
        end
        scopes.each { |scope| _assert_scope!(scope) }
      end
      _logout(*scopes)
    end

    # proxy methods through to the winning strategy
    # :api: private
    def result # :nodoc:
      winning_strategy && winning_strategy.result
    end

    # Proxy through to the authentication strategy to find out the message that was generated.
    # :api: public
    def message
      winning_strategy && winning_strategy.message
    end

    # Provides a way to return a 401 without warden deferring to the failure app
    # The result is a direct passthrough of your own response
    # :api: public
    def custom_failure!
      @custom_failure = true
    end

    # Check to see if the custom failure flag has been set
    # :api: public
    def custom_failure?
      if instance_variable_defined?(:@custom_failure)
        !!@custom_failure
      else
        false
      end
    end

    # Check to see if this is an asset request
    # :api: public
    def asset_request?
      ::Warden::asset_paths.any? { |r| env['PATH_INFO'].to_s.match(r) }
    end

    def inspect(*args)
      "Warden::Proxy:#{object_id} @config=#{@config.inspect}"
    end

    def to_s(*args)
      inspect(*args)
    end

    private

    def _perform_authentication(*args)
      scope, opts = _retrieve_scope_and_opts(args)
      user = nil

      # Look for an existing user in the session for this scope.
      # If there was no user in the session, see if we can get one from the request.
      return user, opts if user = _user(opts.merge(:scope => scope))
      _run_strategies_for(scope, args)

      if winning_strategy && winning_strategy.successful?
        opts[:store] = opts.fetch(:store, winning_strategy.store?)
        _set_user(winning_strategy.user, opts.merge!(:event => :authentication))
      end

      [@users[scope], opts]
    end

    # Checks capability and scope for a strategy-running authentication call.
    def _guard_authentication!(args)
      return unless delegating?

      opts = args.last.is_a?(Hash) ? args.last : {}
      _assert_capability!(:authenticate)
      _assert_scope!(opts[:scope] || @config.default_scope)
    end

    # Raises unless the innermost restricted context delegated the capability.
    def _assert_capability!(capability)
      context = current_delegation
      return if context && context.granted_capability?(capability)

      raise CapabilityNotGranted,
            "capability #{capability.inspect} was not delegated to this restricted context"
    end

    # Raises unless the innermost restricted context grants the scope.
    def _assert_scope!(scope)
      context = current_delegation
      return if context && context.granted_scope?(scope)

      raise ScopeNotGranted,
            "scope #{scope.inspect} was not delegated to this restricted context"
    end

    # The real Rack session, bypassing the restricted read-only view.
    def _raw_session
      @env['rack.session']
    end

    def _session_serializer
      @session_serializer ||= Warden::SessionSerializer.new(@env)
    end

    def _set_user(user, opts = {})
      scope = (opts[:scope] ||= @config.default_scope)

      # Get the default options from the master configuration for the given scope
      opts = (@config[:scope_defaults][scope] || {}).merge(opts)
      opts[:event] ||= :set_user
      @users[scope] = user

      if opts[:store] != false && opts[:event] != :fetch
        options = env[ENV_SESSION_OPTIONS]
        if options
          if options.frozen?
            env[ENV_SESSION_OPTIONS] = options.merge(:renew => true).freeze
          else
            options[:renew] = true
          end
        end
        _session_serializer.store(user, scope)
      end

      run_callbacks = opts.fetch(:run_callbacks, true)
      manager._run_callbacks(:after_set_user, user, self, opts) if run_callbacks

      @users[scope]
    end

    def _user(opts = {})
      scope = (opts[:scope] ||= @config.default_scope)

      if @users.has_key?(scope)
        @users[scope]
      else
        # Inside a restricted context a read must not clean up stale keys.
        serializer = delegating? ? session_serializer : _session_serializer
        unless user = serializer.fetch(scope)
          run_callbacks = opts.fetch(:run_callbacks, true)
          manager._run_callbacks(:after_failed_fetch, user, self, :scope => scope) if run_callbacks
        end

        @users[scope] = user ? _set_user(user, opts.merge(:event => :fetch)) : nil
      end
    end

    def _logout(*scopes)
      if scopes.empty?
        scopes = @users.keys
        reset_session = true
      end

      scopes.each do |scope|
        user = @users.delete(scope)
        manager._run_callbacks(:before_logout, user, self, :scope => scope)

        session = _raw_session
        session.delete("warden.user.#{scope}.session") unless session.nil?
        _session_serializer.delete(scope, user)
      end

      reset_session! if reset_session
    end

    def _retrieve_scope_and_opts(args) #:nodoc:
      opts  = args.last.is_a?(Hash) ? args.pop : {}
      scope = opts[:scope] || @config.default_scope
      opts  = (@config[:scope_defaults][scope] || {}).merge(opts)
      [scope, opts]
    end

    # Run the strategies for a given scope
    def _run_strategies_for(scope, args) #:nodoc:
      self.winning_strategy = @winning_strategies[scope]
      return if winning_strategy && winning_strategy.halted?

      # Do not run any strategy if locked
      return if @locked

      if args.empty?
        defaults   = @config[:default_strategies]
        strategies = defaults[scope] || defaults[:_all]
      end

      (strategies || args).each do |name|
        strategy = _fetch_strategy(name, scope)
        next unless strategy && !strategy.performed? && strategy.valid?
        catch(:warden) do
          _update_winning_strategy(strategy, scope)
        end

        strategy._run!
        _update_winning_strategy(strategy, scope)
        break if strategy.halted?
      end
    end

    # Fetches strategies and keep them in a hash cache.
    def _fetch_strategy(name, scope)
      @strategies[scope][name] ||= if klass = Warden::Strategies[name]
        klass.new(@env, scope)
      elsif @config.silence_missing_strategies?
        nil
      else
        raise "Invalid strategy #{name}"
      end
    end

    # Updates the winning strategy for a given scope
    def _update_winning_strategy(strategy, scope)
      self.winning_strategy = @winning_strategies[scope] = strategy
    end
  end # Proxy

end # Warden
