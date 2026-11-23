# encoding: utf-8
# frozen_string_literal: true
require 'stringio'

module Warden
  # An immutable, allowlisted description of an authentication failure for
  # failure applications that are maintained outside the trusted application
  # boundary (for example a public login-failure page).
  #
  # The trusted side keeps using +env["warden.options"]+ and the
  # +before_failure+ callbacks. Those still see the complete Rack environment
  # and the complete options hash. A restricted failure application instead
  # receives a fresh environment containing only the Rack keys needed to build
  # a response and this context under +ENV_KEY+.
  #
  # Only three values cross the boundary:
  #
  # * +action+      - the failure action chosen by Warden or the application
  # * +category+    - a conservative classification of the failure. A
  #                   +before_failure+ callback may replace it with a safe
  #                   identifier (for example <tt>:account_locked</tt>).
  # * +return_to+   - an approved, same-site path derived from +return_to+ or
  #                   +attempted_path+. Query strings, fragments, absolute
  #                   URLs and protocol-relative URLs are discarded.
  #
  # Anything else placed in the options hash by a callback is intentionally
  # not copied.
  class FailureContext
    # Key used to expose the context to a restricted failure application.
    ENV_KEY = 'warden.failure'.freeze

    PUBLIC_KEYS = %i[action category return_to].freeze

    DEFAULT_ACTION = :unauthenticated
    DEFAULT_CATEGORY = :authentication_failed

    IDENTIFIER = /\A[a-z][a-z0-9_]*\z/
    ACTION = /\A[A-Za-z0-9_\-]+\z/
    UNSAFE_CHARACTERS = /[\x00-\x1f\x7f]/

    attr_reader :action, :category, :return_to

    class << self
      # Builds a context from the trusted options hash.
      #
      # +result+ is the value returned by the proxy when the options hash does
      # not already carry a result. It is only used to pick the default
      # category; it is never exposed verbatim unless it is a safe identifier.
      def build(options, config = nil, result = nil)
        new(
          :action => extract_action(options),
          :category => extract_category(options, result),
          :return_to => extract_return_to(options, config)
        )
      end

      # Returns a new Rack environment carrying only response-building Rack
      # metadata and the filtered failure context. The original environment is
      # never mutated or exposed.
      def public_env(env, context)
        https = env['rack.url_scheme'] == 'https'
        {
          'REQUEST_METHOD' => copy_string(env['REQUEST_METHOD'] || 'GET'),
          'SCRIPT_NAME' => copy_string(env['SCRIPT_NAME']),
          'PATH_INFO' => "/#{context.action}",
          'QUERY_STRING' => '',
          'SERVER_NAME' => copy_string(env['SERVER_NAME'] || 'localhost'),
          'SERVER_PORT' => copy_string(env['SERVER_PORT'] || (https ? '443' : '80')),
          'SERVER_PROTOCOL' => copy_string(env['SERVER_PROTOCOL'] || 'HTTP/1.1'),
          'rack.url_scheme' => https ? 'https' : 'http',
          'rack.input' => StringIO.new(''),
          'rack.errors' => env['rack.errors'] || $stderr,
          'rack.multithread' => !!env['rack.multithread'],
          'rack.multiprocess' => !!env['rack.multiprocess'],
          'rack.run_once' => !!env['rack.run_once'],
          ENV_KEY => context
        }
      end

      # Returns the context attached to a restricted failure environment, if
      # one is present.
      def from_env(env)
        env[ENV_KEY]
      end

      private

      def extract_action(options)
        value = options[:action]
        case value
        when Symbol
          value.to_s.match?(ACTION) ? value : DEFAULT_ACTION
        when String
          value.match?(ACTION) ? value.to_sym : DEFAULT_ACTION
        else
          DEFAULT_ACTION
        end
      end

      def extract_category(options, result)
        if (identifier = normalize_identifier(options[:failure_category]))
          return identifier
        end

        normalize_category(result || options[:result])
      end

      def normalize_category(result)
        case result
        when nil, :failure, :success
          DEFAULT_CATEGORY
        when :custom
          :custom_response
        when :redirect
          :redirect
        else
          normalize_identifier(result) || DEFAULT_CATEGORY
        end
      end

      def normalize_identifier(value)
        case value
        when Symbol
          value if value.to_s.match?(IDENTIFIER)
        when String
          value.to_sym if value.match?(IDENTIFIER)
        end
      end

      def extract_return_to(options, config)
        candidate = options.key?(:return_to) ? options[:return_to] : options[:attempted_path]
        sanitize_return_to(candidate, config)
      end

      def sanitize_return_to(value, config)
        return nil if value.nil?

        path = value.to_s.split('#', 2).first.to_s.split('?', 2).first.to_s
        return nil if path.empty?
        return nil unless path.valid_encoding?
        return nil unless path.start_with?('/')
        return nil if path.start_with?('//')
        return nil if path.include?('\\') || path.match?(UNSAFE_CHARACTERS)

        decoded = begin
          ::Rack::Utils.unescape_path(path)
        rescue StandardError
          return nil
        end

        return nil unless decoded.valid_encoding?
        return nil if decoded.start_with?('//')
        return nil if decoded.include?('://') || decoded.include?('\\')
        return nil if decoded.include?('?') || decoded.include?('#')
        return nil if decoded.match?(UNSAFE_CHARACTERS)
        return nil if decoded.split('/').any? { |segment| segment == '..' || segment == '.' }
        # Refuse doubly-encoded input rather than letting a downstream decoder
        # turn it into a protocol-relative or traversal path.
        return nil if decoded.match?(/%[0-9A-Fa-f]{2}/)
        return nil unless approved_return_path?(path, config)

        copy_string(path)
      end

      def approved_return_path?(path, config)
        approved = config && config[:approved_return_paths]
        return true if approved.nil?

        if approved.respond_to?(:call) && !approved.is_a?(Regexp)
          approved = approved.call(path)
          return true if approved == true

          return false unless approved.is_a?(Array)
        end

        Array(approved).any? { |entry| approved_entry?(entry, path) }
      end

      def approved_entry?(entry, path)
        return entry.match?(path) if entry.is_a?(Regexp)

        prefix = entry.to_s
        return false if prefix.empty?

        prefix = prefix.chomp('/')
        return path.start_with?('/') if prefix.empty?

        path == prefix || path.start_with?("#{prefix}/")
      end

      def copy_string(value)
        value.to_s.dup.freeze
      end
    end

    def initialize(action:, category:, return_to:)
      @action = action
      @category = category
      @return_to = return_to
      freeze
    end

    def [](key)
      key = key.to_sym if key.respond_to?(:to_sym)
      to_h[key] if PUBLIC_KEYS.include?(key)
    end

    def fetch(key, *defaults, &block)
      key = key.to_sym if key.respond_to?(:to_sym)
      return to_h[key] if PUBLIC_KEYS.include?(key)
      return yield(key) if block
      return defaults.first unless defaults.empty?

      raise KeyError, "key not found: #{key.inspect}"
    end

    def key?(key)
      key = key.to_sym if key.respond_to?(:to_sym)
      PUBLIC_KEYS.include?(key)
    end
    alias has_key? key?
    alias include? key?

    def to_h
      {
        :action => @action,
        :category => @category,
        :return_to => @return_to
      }
    end
    alias to_hash to_h

    def inspect
      "#<Warden::FailureContext action=#{@action.inspect} " \
        "category=#{@category.inspect} return_to=#{@return_to.inspect}>"
    end
    alias to_s inspect
  end
end
