# frozen_string_literal: true

require 'rack/protection'

module Rack
  module Protection
    ##
    # Selects one of several pre-built Rack::Protection stacks ("profiles")
    # for each request, using a finite set of caller-declared path and
    # method rules.
    #
    # The typical use case is a mounted Rack backend that serves both
    # browser pages and non-browser webhook endpoints: browsers need the
    # full default protections, while webhook senders cannot provide
    # Origin/Referer headers or CSRF tokens, so the browser-specific
    # checks would only produce false positives there.
    #
    #   use Rack::Protection::ProfileSelector,
    #     { reaction: :drop_session },                      # default profile
    #     webhooks: {                                       # named profile
    #       paths:   %w[/webhooks/stripe /webhooks/github], # exact paths
    #       methods: %w[POST],                              # optional method list
    #       options: { except: %i[http_origin remote_token json_csrf] }
    #     }
    #
    # The same setup is available through Rack::Protection.new:
    #
    #   use Rack::Protection, reaction: :drop_session, profiles: { ... }
    #
    # == Selection contract
    #
    # Rules are matched against the literal +PATH_INFO+ and
    # +REQUEST_METHOD+ of the request as seen at this point of the
    # middleware stack -- the same values the downstream router routes on:
    #
    # * Declare paths exactly as the router sees them. When the app is
    #   mounted under a prefix with +map+, the prefix is already stripped
    #   from +PATH_INFO+, so declare paths relative to the mount point.
    # * No decoding or normalization is applied. Percent-encoded variants
    #   (e.g. +/webhooks/%73tripe+) never match a declared path and fall
    #   through to the default profile, so the boundary cannot be crossed
    #   with encoded paths.
    # * When Rack::MethodOverride (or similar) sits upstream, the
    #   effective (overridden) method is matched, exactly like the router.
    #   Override headers or parameters cannot smuggle a request into a
    #   profile the router would not route it to.
    # * The first matching profile wins. Requests matching no rule use the
    #   default profile built from the top-level options.
    #
    # All stacks are built once when the middleware is created and the
    # compiled rules are frozen; selection itself is stateless, so a
    # request can never observe or affect another request's configuration.
    #
    # == This is not authentication
    #
    # Profiles only choose which protections apply to a request. Endpoints
    # with relaxed protections (e.g. webhooks) must still authenticate
    # callers themselves, for example by verifying a request signature.
    # Never treat matching a profile as proof of identity.
    class ProfileSelector
      RULE_KEYS = %i[paths methods options].freeze

      def initialize(app, default_options = {}, profiles = nil)
        unless default_options.is_a?(Hash)
          raise ArgumentError, 'default options must be a Hash of Rack::Protection options'
        end

        default_options = default_options.dup
        default_options.delete(:profiles)
        isolate_options(default_options)

        @default_stack = build_stack(app, default_options)
        @profiles      = compile_profiles(app, default_options, profiles)

        freeze
      end

      def call(env)
        select_stack(env).call(env)
      end

      private

      def select_stack(env)
        path = env['PATH_INFO']
        path = '/' if path.nil? || path.empty?
        method = env['REQUEST_METHOD']

        @profiles.each do |paths, methods, stack|
          next unless methods.nil? || methods.include?(method)

          return stack if paths.include?(path)
        end

        @default_stack
      end

      def build_stack(app, options)
        ::Rack::Protection.new(app, options)
      end

      def compile_profiles(app, default_options, profiles)
        unless profiles.is_a?(Hash) && !profiles.empty?
          raise ArgumentError, 'profiles must be a non-empty Hash of name => rule'
        end

        profiles.map do |name, rule|
          paths, methods, options = compile_rule(name, rule)
          [paths, methods, build_stack(app, default_options.merge(options))].freeze
        end.freeze
      end

      def compile_rule(name, rule)
        unless rule.is_a?(Hash)
          raise ArgumentError, "profile #{name.inspect}: rule must be a Hash with keys #{RULE_KEYS.inspect}"
        end

        unknown = rule.keys - RULE_KEYS
        unless unknown.empty?
          raise ArgumentError, "profile #{name.inspect}: unknown rule keys #{unknown.inspect}"
        end

        options = rule[:options] || {}
        unless options.is_a?(Hash)
          raise ArgumentError, "profile #{name.inspect}: :options must be a Hash of Rack::Protection options"
        end
        if options.key?(:profiles)
          raise ArgumentError, "profile #{name.inspect}: :options must not nest :profiles"
        end

        options = options.dup
        isolate_options(options)

        [compile_paths(name, rule[:paths]), compile_methods(name, rule[:methods]), options]
      end

      def compile_paths(name, paths)
        unless paths.is_a?(Array) && !paths.empty? && paths.all? { |p| p.is_a?(String) && p.start_with?('/') }
          raise ArgumentError,
                "profile #{name.inspect}: :paths must be a non-empty Array of absolute path Strings"
        end

        paths.map { |p| p.dup.freeze }.freeze
      end

      def compile_methods(name, methods)
        return if methods.nil?

        unless methods.is_a?(Array) && !methods.empty? && methods.all? { |m| m.is_a?(String) || m.is_a?(Symbol) }
          raise ArgumentError, "profile #{name.inspect}: :methods must be an Array of HTTP method names"
        end

        methods.map { |m| m.to_s.upcase.freeze }.freeze
      end

      # Detach mutable option values from the caller's copies so the
      # configuration cannot change after the stacks have been built.
      def isolate_options(options)
        %i[except use].each do |key|
          value = options[key]
          options[key] = value.dup.freeze if value.is_a?(Array)
        end
        options
      end
    end
  end
end
