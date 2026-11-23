# encoding: utf-8
# frozen_string_literal: true
require 'warden/hooks'
require 'warden/config'
require 'warden/callback_registry'

module Warden
  # The middleware for Rack Authentication
  # The middleware requires that there is a session upstream
  # The middleware injects an authentication object into
  # the rack environment hash
  class Manager
    extend Warden::Hooks

    attr_accessor :config

    # Callbacks registered for this application only. Global callbacks
    # registered directly on Warden::Manager stay shared across applications.
    attr_reader :callbacks

    # The callback kinds warden knows how to dispatch during a request.
    CALLBACK_KINDS = %i(on_request after_set_user after_failed_fetch
                        before_logout before_failure).freeze

    # Initialize the middleware. If a block is given, a Warden::Config is yielded so you can properly
    # configure the Warden::Manager.
    # :api: public
    def initialize(app, options={})
      default_strategies = options.delete(:default_strategies)

      @app, @config = app, Warden::Config.new(options)
      @config.manager = self
      @callbacks = Warden::CallbackRegistry.new
      @config.default_strategies(*default_strategies) if default_strategies
      yield @config if block_given?
    end

    # Invoke the application guarding for throw :warden.
    # If this is downstream from another warden instance, don't do anything.
    # :api: private
    def call(env) # :nodoc:
      return @app.call(env) if env['warden'] && env['warden'].manager != self

      env['warden'] = Proxy.new(env, self)
      result = catch(:warden) do
        env['warden'].on_request
        @app.call(env)
      end

      result ||= {}
      case result
      when Array
        handle_chain_result(result.first, result, env)
      when Hash
        process_unauthenticated(env, result)
      when Rack::Response
        handle_chain_result(result.status, result, env)
      end
    end

    # Runs the callbacks of +kind+ for the current request. The effective
    # chain is captured (frozen) when the request starts and always runs the
    # globally registered, shared callbacks first followed by the callbacks
    # local to this application - each in their order of declaration.
    # Keeping this method on the manager preserves the public contract used by
    # Warden::Proxy and existing integrations.
    # :api: private
    def _run_callbacks(kind, *args) #:nodoc:
      proxy = current_proxy(kind, args)
      chain = proxy ? proxy.callback_chain(kind) : callback_chain(kind)
      @callbacks._run_callback_chain(chain, args)
    end

    # Builds the effective callback chain for +kind+ outside of a request
    # context: global (shared) callbacks first, then this application's own.
    # :api: private
    def callback_chain(kind) #:nodoc:
      self.class.public_send("_#{kind}") + @callbacks.snapshot(kind)
    end

    class << self
      # The global, cross-application callback registry. Only callbacks
      # declared here (the historical Warden::Manager registration) are shared
      # between mounted applications; an application cannot promote its own
      # callbacks into the shared set. Treat anything registered here as
      # explicitly approved for cross-application use.
      def shared_callbacks
        self
      end

      # Prepares the user to serialize into the session.
      # Any object that can be serialized into the session in some way can be used as a "user" object
      # Generally however complex object should not be stored in the session.
      # If possible store only a "key" of the user object that will allow you to reconstitute it.
      #
      # You can supply different methods of serialization for different scopes by passing a scope symbol
      #
      # Example:
      #   Warden::Manager.serialize_into_session{ |user| user.id }
      #   # With Scope:
      #   Warden::Manager.serialize_into_session(:admin) { |user| user.id }
      #
      # :api: public
      def serialize_into_session(scope = nil, &block)
        method_name = scope.nil? ? :serialize : "#{scope}_serialize"
        Warden::SessionSerializer.send :define_method, method_name, &block
      end

      # Reconstitutes the user from the session.
      # Use the results of user_session_key to reconstitute the user from the session on requests after the initial login
      # You can supply different methods of de-serialization for different scopes by passing a scope symbol
      #
      # Example:
      #   Warden::Manager.serialize_from_session{ |id| User.get(id) }
      #   # With Scope:
      #   Warden::Manager.serialize_from_session(:admin) { |id| AdminUser.get(id) }
      #
      # :api: public
      def serialize_from_session(scope = nil, &block)
        method_name = scope.nil? ? :deserialize : "#{scope}_deserialize"

        if Warden::SessionSerializer.method_defined? method_name
          Warden::SessionSerializer.send :remove_method, method_name
        end

        Warden::SessionSerializer.send :define_method, method_name, &block
      end
    end

  private

    # Resolves the proxy whose frozen callback chains should be used. The
    # proxy is always one of the callback arguments, except for before_failure
    # where only the rack env is available. When no proxy can be found (for
    # example a direct call outside of a request) a fresh chain is built.
    def current_proxy(kind, args)
      if kind == :before_failure
        env = args.first
        proxy = env && env['warden']
        proxy.is_a?(Proxy) ? proxy : nil
      else
        args.find { |arg| arg.is_a?(Proxy) }
      end
    end

    def handle_chain_result(status, result, env)
      if status == 401 && intercept_401?(env)
        process_unauthenticated(env)
      else
        result
      end
    end

    def intercept_401?(env)
      config[:intercept_401] && !env['warden'].custom_failure?
    end

    # When a request is unauthenticated, here's where the processing occurs.
    # It looks at the result of the proxy to see if it's been executed and what action to take.
    # :api: private
    def process_unauthenticated(env, options={})
      options[:action] ||= begin
        opts = config[:scope_defaults][config.default_scope] || {}
        opts[:action] || 'unauthenticated'
      end

      proxy  = env['warden']
      result = options[:result] || proxy.result

      case result
      when :redirect
        body = proxy.message || "You are being redirected to #{proxy.headers['Location']}"
        [proxy.status, proxy.headers, [body]]
      when :custom
        proxy.custom_response
      else
        options[:message] ||= proxy.message
        call_failure_app(env, options)
      end
    end

    # Calls the failure app.
    # The before_failure hooks are run on each failure
    # :api: private
    def call_failure_app(env, options = {})
      if config.failure_app
        options.merge!(:attempted_path => ::Rack::Request.new(env).fullpath)
        env["PATH_INFO"] = "/#{options[:action]}"
        env["warden.options"] = options

        _run_callbacks(:before_failure, env, options)
        config.failure_app.call(env).to_a
      else
        raise "No Failure App provided"
      end
    end # call_failure_app
  end
end # Warden
