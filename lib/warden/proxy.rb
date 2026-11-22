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
      @levels = {}
      @manager, @config = manager, manager.config.dup
      @strategies = Hash.new { |h,k| h[k] = {} }
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
    # :api: public
    def session_serializer
      @session_serializer ||= Warden::SessionSerializer.new(@env)
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
      @locked = true
    end

    # Run the authentication strategies for the given strategies.
    # If there is already a user logged in for a given scope, the strategies are not run
    # This does not halt the flow of control and is a passive attempt to authenticate only
    # When scope is not specified, the default_scope is assumed.
    #
    # Parameters:
    #   args - a list of symbols (labels) that name the strategies to attempt
    #   opts - an options hash that contains the :scope of the user to check.
    #          Use :min_level to require a minimum authentication level. When an
    #          existing session is below that level the strategies are run to
    #          elevate it; if elevation does not reach the level the existing
    #          session is left untouched and nil is returned.
    #
    # Example:
    #   env['warden'].authenticate(:password, :basic, :scope => :sudo)
    #   env['warden'].authenticate(:password, :min_level => 2)
    #
    # :api: public
    def authenticate(*args)
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
    #   env['warden'].authenticate!(:password, :min_level => 2)     # throws unless level 2 was verified
    #
    # :api: public
    def authenticate!(*args)
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
    #   opts - optional hash accepting :min_level, the minimum authentication
    #          level the loaded session must carry. Sessions written before
    #          levels existed are treated as level 0 and never satisfy a
    #          positive minimum.
    #
    # Example:
    #   env['warden'].authenticated?(:admin)
    #   env['warden'].authenticated?(:admin, :min_level => 2)
    #
    # :api: public
    def authenticated?(scope = @config.default_scope, opts = {})
      if scope.is_a?(Hash)
        opts = scope
        scope = opts[:scope] || @config.default_scope
      end

      result = !!user(opts.merge(:scope => scope))
      yield if block_given? && result
      result
    end

    # Same API as authenticated?, but returns false when authenticated.
    # :api: public
    def unauthenticated?(scope = @config.default_scope, opts = {})
      if scope.is_a?(Hash)
        opts = scope
        scope = opts[:scope] || @config.default_scope
      end

      result = !authenticated?(scope, opts)
      yield if block_given? && result
      result
    end

    # The authentication level currently associated with the scope, or nil
    # when no user is loaded. Sessions written before levels existed report
    # Warden::UNKNOWN_AUTHENTICATION_LEVEL (0).
    #
    # :api: public
    def authentication_level(scope = @config.default_scope)
      scope = (scope[:scope] || @config.default_scope) if scope.is_a?(Hash)
      user(scope)
      @levels[scope]
    end

    # Manually set the user into the session and auth proxy
    #
    # Parameters:
    #   user - An object that has been setup to serialize into and out of the session.
    #   opts - An options hash. Use the :scope option to set the scope of the user,
    #          set the :store option to false to skip serializing into the session,
    #          set the :run_callbacks to false to skip running the callbacks
    #          (the default is true), and use :level to record the authentication
    #          level that produced this user (defaults to the scope's existing
    #          level for fetches, otherwise DEFAULT_AUTHENTICATION_LEVEL).
    #
    # :api: public
    def set_user(user, opts = {})
      scope = (opts[:scope] ||= @config.default_scope)

      # Get the default options from the master configuration for the given scope
      opts = (@config[:scope_defaults][scope] || {}).merge(opts)
      opts[:event] ||= :set_user
      @users[scope] = user

      # An explicit :level is authoritative (it is also how a fetched session
      # reports the level it was stored with). Otherwise a manual set_user is
      # an ordinary login and starts at the default level; it must not inherit
      # a previous elevation, which could belong to a different user.
      level = if opts.key?(:level)
        Warden.coerce_authentication_level(opts[:level])
      else
        Warden::DEFAULT_AUTHENTICATION_LEVEL
      end

      if user
        level ||= Warden::DEFAULT_AUTHENTICATION_LEVEL
        @levels[scope] = level
      else
        @levels.delete(scope)
      end

      if opts[:store] != false && opts[:event] != :fetch && user
        options = env[ENV_SESSION_OPTIONS]
        if options
          if options.frozen?
            env[ENV_SESSION_OPTIONS] = options.merge(:renew => true).freeze
          else
            options[:renew] = true
          end
        end
        session_serializer.store(user, scope)
        session_serializer.store_level(scope, level)
      end

      run_callbacks = opts.fetch(:run_callbacks, true)
      manager._run_callbacks(:after_set_user, user, self, opts) if run_callbacks

      @users[scope]
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
    #  # require a minimum authentication level on the loaded session
    #  env['warden'].user(:scope => :admin, :min_level => 2)
    #
    # When :min_level is given and the session's recorded level is lower, nil
    # is returned. A session written before levels existed reports level 0 and
    # therefore fails any positive minimum.
    #
    # :api: public
    def user(argument = {})
      opts  = argument.is_a?(Hash) ? argument : { :scope => argument }
      scope = (opts[:scope] ||= @config.default_scope)

      if @users.has_key?(scope)
        loaded = @users[scope]
      else
        unless user = session_serializer.fetch(scope)
          run_callbacks = opts.fetch(:run_callbacks, true)
          manager._run_callbacks(:after_failed_fetch, user, self, :scope => scope) if run_callbacks
        end

        if user
          opts = opts.merge(:event => :fetch,
                            :level => session_serializer.fetch_level(scope))
        end
        @users[scope] = loaded = user ? set_user(user, opts) : nil
      end

      min_level = Warden.coerce_authentication_level(opts[:min_level])
      return loaded if min_level.nil?
      return nil unless loaded

      level = @levels[scope]
      level && level >= min_level ? loaded : nil
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
      raise NotAuthenticated, "#{scope.inspect} user is not logged in" unless authenticated?(scope)
      raw_session["warden.user.#{scope}.session"] ||= {}
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
      if scopes.empty?
        scopes = @users.keys
        reset_session = true
      end

      scopes.each do |scope|
        user = @users.delete(scope)
        manager._run_callbacks(:before_logout, user, self, :scope => scope)

        @levels.delete(scope)
        raw_session.delete("warden.user.#{scope}.session") unless raw_session.nil?
        raw_session.delete("warden.user.#{scope}.level") unless raw_session.nil?
        session_serializer.delete(scope, user)
      end

      reset_session! if reset_session
    end

    # proxy methods through to the winning strategy
    # :api: private
    def result # :nodoc:
      winning_strategy && winning_strategy.result
    end

    # Proxy through to the authentication strategy to find out the message that was generated.
    # When a level requirement could not be met, a message explaining the
    # shortfall takes precedence.
    # :api: public
    def message
      @level_failure_message || (winning_strategy && winning_strategy.message)
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
      min_level = Warden.coerce_authentication_level(opts[:min_level])
      @level_failure_message = nil

      # Look for an existing user in the session for this scope.
      # If the loaded session already satisfies the requested level, there is
      # nothing left to verify.
      if current = user(:scope => scope, :run_callbacks => opts.fetch(:run_callbacks, true))
        return current, opts if min_level.nil? || authentication_level(scope) >= min_level

        # The session exists but is below the requested level: allow the
        # strategies for this scope to run again to elevate it.
        clear_strategies_cache!(:scope => scope)
      end

      _run_strategies_for(scope, args)

      if winning_strategy && winning_strategy.successful?
        verified_level = winning_strategy.level

        if min_level && verified_level < min_level
          # The strategy succeeded without verifying enough for this action.
          # Leave any existing session untouched instead of replacing it with
          # a weaker one, and report failure to the caller.
          @level_failure_message =
            "Authentication level #{verified_level} is below the required level #{min_level}"
          return nil, opts
        end

        opts[:store] = opts.fetch(:store, winning_strategy.store?)
        opts[:level] = verified_level
        set_user(winning_strategy.user, opts.merge!(:event => :authentication))
      end

      authenticated_user = @users[scope]
      if min_level && (authenticated_user.nil? || (authentication_level(scope) || 0) < min_level)
        # Keep a strategy's own failure/redirect message when there is one;
        # otherwise explain the level shortfall so callers can report it.
        unless winning_strategy && winning_strategy.message
          @level_failure_message =
            "Authentication level #{authentication_level(scope) || Warden::UNKNOWN_AUTHENTICATION_LEVEL} is below the required level #{min_level}"
        end
        return nil, opts
      end

      @level_failure_message = nil
      [authenticated_user, opts]
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
