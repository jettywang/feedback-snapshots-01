# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2024, by Samuel Williams.

require 'json'
require 'securerandom'

require 'rack/request'
require 'rack/response'
require 'rack/utils'

require_relative 'constants'

module Rack
  module Session
    # Rack::Session::SingleSession enforces a hard boundary between data that
    # is allowed to live on the client and data that must stay on the server.
    #
    # Two cookies are emitted, neither of which ever carries authorization:
    #
    # * The session cookie holds an opaque, random session id. The id is the
    #   only pointer the client has to the server-side record.
    # * The preference cookie holds a JSON document of ordinary user
    #   preferences (theme, language, ...). These round-trip through the client
    #   because they are non-sensitive.
    #
    # Authorization data is stored exclusively in the configured backend, keyed
    # by the session id. Decoding either cookie can therefore never yield a
    # permission: when the backend record is missing, rejected or unwritable,
    # the session simply has no authorization.
    #
    # The backend is any object responding to:
    #
    #   backend.create_record(session_id)            -> record (Hash)
    #   backend.read_record(session_id)              -> record or nil
    #   backend.write_record(session_id, record)     -> true on success,
    #                                                   false/nil on failure
    #   backend.destroy_record(session_id)           -> void
    #
    # A simple in-memory HashBackend is provided for tests and single-process
    # applications.
    class SingleSession
      # The keys the client is allowed to store. Everything else is treated as
      # internal authorization data and is kept on the server.
      PREFERENCE_KEYS = %w[theme language timezone].freeze

      DEFAULT_OPTIONS = {
        key: RACK_SESSION,
        preference_key: 'rack.session.preferences',
        path: '/',
        domain: nil,
        expire_after: nil,
        secure: false,
        httponly: true,
        same_site: :lax,
        sidbits: 128,
        secure_random: ::SecureRandom,
      }.freeze

      # Minimal in-memory backend. A real deployment would swap this for a
      # Redis, database or memcached adapter implementing the same four methods.
      class HashBackend
        def initialize(records = {})
          @records = records
          @mutex = Mutex.new
        end

        def create_record(session_id)
          @mutex.synchronize do
            @records[session_id] ||= {}
          end
        end

        def read_record(session_id)
          @mutex.synchronize do
            record = @records[session_id]
            record && record.dup
          end
        end

        def write_record(session_id, record)
          @mutex.synchronize do
            @records[session_id] = record
            true
          end
        end

        def destroy_record(session_id)
          @mutex.synchronize do
            @records.delete(session_id)
          end
        end

        # Test helper: drop every record, simulating server-side expiry or
        # eviction while leaving the client's cookies intact.
        def evict!
          @mutex.synchronize { @records.clear }
        end

        def size
          @mutex.synchronize { @records.size }
        end
      end

      # The unified, hash-like object handed to the application at
      # <tt>env['rack.session']</tt>. Preferences and authorization share one
      # interface even though they are persisted in different places.
      class Accessor
        include Enumerable

        def initialize(middleware, preferences, server_record, session_id)
          @middleware = middleware
          @preferences = preferences
          @server_record = server_record
          @session_id = session_id
          @dirty = false
        end

        attr_reader :session_id, :preferences, :server_record

        # Ordinary preferences are readable and writable like any hash entry.
        def [](key)
          key = key.to_s
          if @middleware.preference?(key)
            @preferences[key]
          else
            @server_record[key]
          end
        end

        def []=(key, value)
          key = key.to_s
          if @middleware.preference?(key)
            @preferences[key] = value
          else
            @server_record[key] = value
            @dirty = true
          end
        end

        def fetch(key, *default, &block)
          key = key.to_s
          source = @middleware.preference?(key) ? @preferences : @server_record
          source.fetch(key, *default, &block)
        end

        def key?(key)
          key = key.to_s
          source = @middleware.preference?(key) ? @preferences : @server_record
          source.key?(key)
        end
        alias has_key? key?
        alias include? key?

        def delete(key)
          key = key.to_s
          if @middleware.preference?(key)
            @preferences.delete(key)
          else
            @server_record.delete(key)
            @dirty = true
          end
        end

        def each(&block)
          @preferences.each(&block)
          @server_record.each(&block)
        end

        def keys
          @preferences.keys + @server_record.keys
        end

        def to_hash
          @preferences.merge(@server_record)
        end
        alias to_h to_hash

        def empty?
          @preferences.empty? && @server_record.empty?
        end

        # Explicit authorization entry point. Permissions can only be granted
        # server-side; a value placed in a cookie never reaches this store.
        def grant!(name)
          @server_record['permissions'] ||= []
          @server_record['permissions'] |= [name.to_s]
          @dirty = true
        end

        def permitted?(name)
          Array(@server_record['permissions']).include?(name.to_s)
        end

        def revoke!(name)
          return unless @server_record['permissions']
          @server_record['permissions'].delete(name.to_s)
          @dirty = true
        end

        def destroy!
          @middleware.destroy(@session_id)
          @server_record.clear
          @session_id = nil
          @dirty = false
        end

        # Whether authorization data changed and therefore needs to be written
        # back to the backend.
        def dirty?
          @dirty
        end
      end

      attr_reader :key, :preference_key, :default_options

      def initialize(app, options = {})
        @app = app
        @backend = options.delete(:backend) || HashBackend.new
        @default_options = DEFAULT_OPTIONS.merge(options)
        @key = @default_options[:key]
        @preference_key = @default_options[:preference_key]
        @sidbits = @default_options[:sidbits]
        @sid_length = @sidbits / 4
        @secure_random = @default_options[:secure_random]
      end

      def call(env)
        request = Rack::Request.new(env)

        preferences = load_preferences(request)
        session_id = request.cookies[@key]

        # Look up the server-side record. A missing or evicted record means the
        # client holds an id that no longer authorizes anything.
        server_record = session_id && @backend.read_record(session_id)

        if session_id.nil? || server_record.nil?
          # Missing server record (first visit, or eviction): mint a fresh,
          # empty session. No authorization is carried over from the cookie.
          session_id = generate_sid
          server_record = @backend.create_record(session_id)
          new_session = true
        end

        accessor = Accessor.new(self, preferences, server_record, session_id)
        env[RACK_SESSION] = accessor
        env[RACK_SESSION_OPTIONS] = @default_options.dup

        status, headers, body = @app.call(env)
        response = Rack::Response::Raw.new(status, headers)

        commit(request, response, accessor, new_session)

        [status, headers, body]
      end

      # Called by Accessor#destroy!; exposed so the accessor does not need to
      # touch the backend directly.
      def destroy(session_id)
        @backend.destroy_record(session_id) if session_id
      end

      def preference?(key)
        PREFERENCE_KEYS.include?(key.to_s)
      end

      private

      def generate_sid
        @secure_random.hex(@sid_length)
      end

      def load_preferences(request)
        raw = request.cookies[@preference_key]
        return {} if raw.nil? || raw.empty?

        decoded = JSON.parse(raw)
        decoded.is_a?(Hash) ? filter_preferences(decoded) : {}
      rescue JSON::ParserError
        # A malformed preference cookie must never break the request.
        {}
      end

      # Only approved preference keys are accepted from the client. Anything
      # else (including forged permissions) is discarded at the boundary.
      def filter_preferences(hash)
        hash.each_with_object({}) do |(key, value), filtered|
          filtered[key.to_s] = value if preference?(key)
        end
      end

      def commit(request, response, accessor, new_session)
        saved = true

        if accessor.dirty?
          # Persist authorization server-side. A backend failure means the
          # permission change does not take effect; the request still completes
          # using the in-memory view only.
          saved = !!@backend.write_record(accessor.session_id, accessor.server_record)

          unless saved
            (request.get_header(RACK_ERRORS) || $stderr).puts(
              "Warning! #{self.class.name} backend rejected the session update; " \
              "authorization changes were not persisted."
            )
          end
        end

        cookie_options = base_cookie_options(request)

        # A brand new session always needs its id cookie. For an existing
        # session we only re-issue it when the backend accepted the update, so
        # a rejected write cannot silently rotate the client's id.
        if new_session || saved
          set_cookie(response, @key, accessor.session_id, cookie_options)
        end

        set_cookie(response, @preference_key, JSON.generate(accessor.preferences), cookie_options)
      end

      def base_cookie_options(request)
        options = {
          path: @default_options[:path],
          domain: @default_options[:domain],
          secure: @default_options[:secure],
          HttpOnly: @default_options[:httponly],
          SameSite: @default_options[:same_site],
        }

        if (expire_after = @default_options[:expire_after])
          options[:expires] = Time.now + expire_after
        end

        options
      end

      def set_cookie(response, name, value, options)
        Rack::Utils.set_cookie_header!(response.headers, name, options.merge(value: value))
      end
    end
  end
end
