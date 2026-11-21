# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.
# Copyright, 2022, by Jeremy Evans.

require 'time'
require 'securerandom'
require 'digest/sha2'

require 'rack/constants'
require 'rack/request'
require 'rack/response'

require_relative '../constants'
require_relative '../commit_policy'

module Rack

  module Session

    class SessionId
      ID_VERSION = 2

      attr_reader :public_id

      def initialize(public_id)
        @public_id = public_id
      end

      def private_id
        "#{ID_VERSION}::#{hash_sid(public_id)}"
      end

      alias :cookie_value :public_id
      alias :to_s :public_id

      def empty?; false; end
      def inspect; public_id.inspect; end

      private

      def hash_sid(sid)
        Digest::SHA256.hexdigest(sid)
      end
    end

    module Abstract
      # SessionHash is responsible to lazily load the session from store.

      class SessionHash
        include Enumerable
        attr_writer :id

        Unspecified = Object.new

        def self.find(req)
          req.get_header RACK_SESSION
        end

        def self.set(req, session)
          req.set_header RACK_SESSION, session
        end

        def self.set_options(req, options)
          req.set_header RACK_SESSION_OPTIONS, options.dup
        end

        def initialize(store, req)
          @store = store
          @req = req
          @loaded = false
        end

        def id
          return @id if @loaded or instance_variable_defined?(:@id)
          @id = @store.send(:extract_session_id, @req)
        end

        def options
          @req.session_options
        end

        def each(&block)
          load_for_read!
          @data.each(&block)
        end

        def [](key)
          load_for_read!
          @data[key.to_s]
        end

        def dig(key, *keys)
          load_for_read!
          @data.dig(key.to_s, *keys)
        end

        def fetch(key, default = Unspecified, &block)
          load_for_read!
          if default == Unspecified
            @data.fetch(key.to_s, &block)
          else
            @data.fetch(key.to_s, default, &block)
          end
        end

        def has_key?(key)
          load_for_read!
          @data.has_key?(key.to_s)
        end
        alias :key? :has_key?
        alias :include? :has_key?

        def []=(key, value)
          load_for_write!
          @data[key.to_s] = value
        end
        alias :store :[]=

        def clear
          load_for_write!
          @data.clear
        end

        def destroy
          if @store.respond_to?(:defer_session_destroy?) && @store.defer_session_destroy?(@req)
            # With a commit policy, destroying is a pending change: the store
            # entry is only removed if the policy allows the commit. This
            # prevents a failed business response from deleting an existing
            # session.
            load_for_write!
            @destroyed_session_id = id
            @pending_destroy = true
            @data.clear
            @id
          else
            clear
            @id = @store.send(:delete_session, @req, id, options)
          end
        end

        def pending_destroy?
          !!@pending_destroy
        end

        def apply_pending_destroy!
          return unless @pending_destroy

          @pending_destroy = false
          session_id = @destroyed_session_id
          @destroyed_session_id = nil
          @id = @store.send(:delete_session, @req, session_id || @store.send(:generate_sid), options)
        end

        def cancel_pending_destroy!
          return unless @pending_destroy

          @pending_destroy = false
          @id = @destroyed_session_id
          @destroyed_session_id = nil
          nil
        end

        def to_hash
          load_for_read!
          @data.dup
        end

        def update(hash)
          load_for_write!
          @data.update(stringify_keys(hash))
        end
        alias :merge! :update

        def replace(hash)
          load_for_write!
          @data.replace(stringify_keys(hash))
        end

        def delete(key)
          load_for_write!
          @data.delete(key.to_s)
        end

        def inspect
          if loaded?
            @data.inspect
          else
            "#<#{self.class}:0x#{self.object_id.to_s(16)} not yet loaded>"
          end
        end

        def exists?
          return @exists if instance_variable_defined?(:@exists)
          @data = {}
          @exists = @store.send(:session_exists?, @req)
        end

        def loaded?
          @loaded
        end

        def empty?
          load_for_read!
          @data.empty?
        end

        def keys
          load_for_read!
          @data.keys
        end

        def values
          load_for_read!
          @data.values
        end

      private

        def load_for_read!
          load! if !loaded? && exists?
        end

        def load_for_write!
          load! unless loaded?
        end

        def load!
          @id, session = @store.send(:load_session, @req)
          @data = stringify_keys(session)
          @loaded = true
        end

        def stringify_keys(other)
          # Use transform_keys after dropping Ruby 2.4 support
          hash = {}
          other.to_hash.each do |key, value|
            hash[key.to_s] = value
          end
          hash
        end
      end

      # ID sets up a basic framework for implementing an id based sessioning
      # service. Cookies sent to the client for maintaining sessions will only
      # contain an id reference. Only #find_session, #write_session and
      # #delete_session are required to be overwritten.
      #
      # All parameters are optional.
      # * :key determines the name of the cookie, by default it is
      #   'rack.session'
      # * :path, :domain, :expire_after, :secure, :httponly, :partitioned and :same_site set
      #   the related cookie options as by Rack::Response#set_cookie
      # * :skip will not a set a cookie in the response nor update the session state
      # * :defer will not set a cookie in the response but still update the session
      #   state if it is used with a backend
      # * :renew (implementation dependent) will prompt the generation of a new
      #   session id, and migration of data to be referenced at the new id. If
      #   :defer is set, it will be overridden and the cookie will be set.
      # * :sidbits sets the number of bits in length that a generated session
      #   id will be.
      #
      # These options can be set on a per request basis, at the location of
      # <tt>env['rack.session.options']</tt>. Additionally the id of the
      # session can be found within the options hash at the key :id. It is
      # highly not recommended to change its value.
      #
      # Is Rack::Utils::Context compatible.
      #
      # Not included by default; you must require 'rack/session/abstract/id'
      # to use.

      class Persisted
        DEFAULT_OPTIONS = {
          key: RACK_SESSION,
          path: '/',
          domain: nil,
          expire_after: nil,
          secure: false,
          httponly: true,
          partitioned: false,
          defer: false,
          renew: false,
          sidbits: 128,
          cookie_only: true,
          secure_random: ::SecureRandom
        }.freeze

        attr_reader :key, :default_options, :sid_secure, :same_site, :commit_policy

        def initialize(app, options = {})
          @app = app
          @default_options = self.class::DEFAULT_OPTIONS.merge(options)
          @key = @default_options.delete(:key)
          @assume_ssl = @default_options.delete(:assume_ssl)
          @cookie_only = @default_options.delete(:cookie_only)
          @same_site = @default_options.delete(:same_site)
          @commit_policy = @default_options.delete(:commit_policy)
          @commit_policy = @default_options.delete(:commit_on) if @commit_policy.nil?
          initialize_sid
        end

        def call(env)
          context(env)
        end

        def context(env, app = @app)
          req = make_request env
          prepare_session(req)
          status, headers, body = app.call(req.env)
          res = Rack::Response::Raw.new status, headers

          if commit_enabled?(req)
            policy = commit_policy_for(req)

            if CommitPolicy.defer_streaming?(policy) && deferrable_body?(body)
              # For a streaming body, the response has not been fully delivered
              # yet. Defer the commit until the body is closed successfully, so
              # a stream (or stream close) error does not persist staged data.
              result = build_commit_result(req, res, policy, body)
              commit = lambda { commit_session(req, res, result: result) }
              error = lambda { |exception| fail_deferred_commit(req, result, exception) }
              body = CommitBody.new(body, commit, error)
            else
              commit_session(req, res)
            end
          else
            # No policy was requested: preserve the historical behaviour
            # exactly, including the return value and the absence of any
            # additional environment keys.
            commit_session(req, res)
          end

          [status, headers, body]
        end

        private

        def make_request(env)
          Rack::Request.new env
        end

        def initialize_sid
          @sidbits = @default_options[:sidbits]
          @sid_secure = @default_options[:secure_random]
          @sid_length = @sidbits / 4
        end

        # Returns the effective commit policy for the request. A policy may be
        # configured globally, overridden through session options, or provided
        # directly in the environment.
        def commit_policy_for(req)
          options = req.get_header(RACK_SESSION_OPTIONS)
          if options.respond_to?(:key?) && options.key?(:commit_policy)
            return options[:commit_policy]
          end

          if req.env.key?(RACK_SESSION_COMMIT_POLICY)
            return req.get_header(RACK_SESSION_COMMIT_POLICY)
          end

          @commit_policy
        end

        def policy_configured?(policy)
          !policy.nil?
        end

        # A policy is considered enabled when it is configured globally, set
        # per request, or when the caller supplied an explicit commit decision.
        def commit_enabled?(req)
          policy = commit_policy_for(req)
          return true if policy_configured?(policy)

          options = req.get_header(RACK_SESSION_OPTIONS)
          !CommitPolicy.resolve_explicit_decision(req.env, options).nil?
        end

        # Whether the store should defer a SessionHash#destroy until commit
        # time, so the policy can veto destructive changes.
        def defer_session_destroy?(req)
          commit_enabled?(req)
        end
        public :defer_session_destroy?

        # Only bodies which are not already buffered need to be wrapped so
        # that we can observe the end of the stream.
        def deferrable_body?(body)
          return false if body.nil?
          return false if body.is_a?(Array)
          return false if body.respond_to?(:to_str)

          true
        end

        def commit_context(req, res, session, options, policy, body = nil)
          CommitContext.new(
            env: req.env,
            status: res.status,
            headers: res.headers,
            body: body,
            session: session,
            options: options,
            policy: policy
          )
        end

        def build_commit_result(req, res, policy = nil, body = nil)
          session = req.get_header RACK_SESSION
          options = session.respond_to?(:options) ? session.options : req.get_header(RACK_SESSION_OPTIONS) || {}
          context = commit_context(req, res, session, options, policy, body)

          CommitResult.new(
            status: res.status,
            family: context.family,
            business_success: context.business_success?
          )
        end

        # Record the commit outcome in the environment and session options,
        # keeping business success and persistence success independent.
        def store_commit_result(req, session, result)
          env = req.env
          env[RACK_SESSION_COMMIT_RESULT] = result
          env[RACK_SESSION_COMMITTED] = result.committed?
          env[RACK_SESSION_PERSISTED] = result.persisted?
          env[RACK_SESSION_COMMIT_STATUS] = result.reason
          env[RACK_SESSION_COMMIT_ERROR] = result.error

          options = session.respond_to?(:options) ? session.options : req.get_header(RACK_SESSION_OPTIONS)
          if options
            options[:commit_result] = result
            options[:commit_status] = result.reason
            options[:committed] = result.committed?
            options[:persisted] = result.persisted?
            options[:business_success] = result.business_success?
          end

          result
        end

        def fail_deferred_commit(req, result, exception)
          result.fail_stream!(exception)

          session = req.get_header RACK_SESSION
          store_commit_result(req, session, result)

          if errors = req.get_header(RACK_ERRORS)
            errors.puts("Warning! #{self.class.name} did not save session after response stream error: #{exception.message}")
          end
        end

        # Generate a new session id using Ruby #rand.  The size of the
        # session id is controlled by the :sidbits option.
        # Monkey patch this to use custom methods for session id generation.

        def generate_sid(secure = @sid_secure)
          if secure
            secure.hex(@sid_length)
          else
            "%0#{@sid_length}x" % Kernel.rand(2**@sidbits - 1)
          end
        rescue NotImplementedError
          generate_sid(false)
        end

        # Sets the lazy session at 'rack.session' and places options and session
        # metadata into 'rack.session.options'.

        def prepare_session(req)
          session_was               = req.get_header RACK_SESSION
          session                   = session_class.new(self, req)
          req.set_header RACK_SESSION, session
          req.set_header RACK_SESSION_OPTIONS, @default_options.dup
          session.merge! session_was if session_was
        end

        # Extracts the session id from provided cookies and passes it and the
        # environment to #find_session.

        def load_session(req)
          sid = current_session_id(req)
          sid, session = find_session(req, sid)
          [sid, session || {}]
        end

        # Extract session id from request object.

        def extract_session_id(request)
          sid = request.cookies[@key]
          sid ||= request.params[@key] unless @cookie_only
          sid
        end

        # Returns the current session id from the SessionHash.

        def current_session_id(req)
          req.get_header(RACK_SESSION).id
        end

        # Check if the session exists or not.

        def session_exists?(req)
          value = current_session_id(req)
          value && !value.empty?
        end

        # Session should be committed if it was loaded, any of specific options like :renew, :drop
        # or :expire_after was given and the security permissions match. Skips if skip is given.
        #
        # When a commit policy is configured, the policy decides whether the
        # staged data is eligible. The policy is evaluated even when the
        # session would not otherwise be committed, so callers can observe the
        # decision.

        def commit_session?(req, session, options)
          if options[:skip]
            false
          else
            has_session = loaded_session?(session) || forced_session_update?(session, options)
            has_session && security_matches?(req, options)
          end
        end

        # Apply the configured commit policy (if any) for this request.
        #
        # Returns true when the policy allows the commit. A request-specific
        # policy in the session options takes precedence over the middleware
        # policy, and an explicit `env['rack.session.commit']` decision takes
        # precedence over both.
        def commit_policy_allows?(req, session, options, res = nil, body = nil)
          policy = commit_policy_for(req)
          explicit = CommitPolicy.resolve_explicit_decision(req.env, options)
          return explicit unless explicit.nil?
          return true unless policy_configured?(policy)

          context = commit_context(req, res, session, options, policy, body)
          CommitPolicy.resolve(policy, context)
        end

        def loaded_session?(session)
          !session.is_a?(session_class) || session.loaded?
        end

        def forced_session_update?(session, options)
          force_options?(options) && session && !session.empty?
        end

        def force_options?(options)
          options.values_at(:max_age, :renew, :drop, :defer, :expire_after).any?
        end

        def security_matches?(request, options)
          return true unless options[:secure]
          request.ssl? || @assume_ssl == true
        end

        # Acquires the session from the environment and the session id from
        # the session options and passes them to #write_session. If successful
        # and the :defer option is not true, a cookie will be added to the
        # response with the session's id.
        #
        # When a commit policy is enabled, the policy is consulted first and
        # the outcome is returned as a CommitResult. Without a policy, the
        # historical implementation and return value are used unchanged.

        def commit_session(req, res, result: nil, body: nil)
          return legacy_commit_session(req, res) unless commit_enabled?(req)

          session = req.get_header RACK_SESSION
          options = session.options

          result ||= build_commit_result(req, res, commit_policy_for(req), body)

          # The policy is consulted before any destructive operation so a
          # business failure cannot delete or renew staged session state.
          allowed = commit_policy_allows?(req, session, options, res, body)
          destructive = false

          if session.respond_to?(:pending_destroy?) && session.pending_destroy?
            if allowed
              session.apply_pending_destroy!
              destructive = true
            else
              session.cancel_pending_destroy!
            end
          end

          unless allowed
            result.skip!(:policy)
            return finish_commit(req, session, result)
          end

          if options[:drop] || options[:renew]
            session_id = delete_session(req, session.id || generate_sid, options)
            destructive = true

            unless session_id
              result.commit!(persisted: true, session_id: nil, reason: :dropped)
              return finish_commit(req, session, result)
            end
          end

          unless commit_session?(req, session, options)
            if destructive
              result.commit!(persisted: true, session_id: session_id, reason: :destroyed)
            else
              result.skip!(options[:skip] ? :skip : :not_loaded)
            end

            return finish_commit(req, session, result)
          end

          session.send(:load!) unless loaded_session?(session)
          session_id ||= session.id
          session_data = session.to_hash.delete_if { |k, v| v.nil? }

          begin
            data = write_session(req, session_id, session_data, options)
          rescue => exception
            result.fail_write!(exception)
            store_commit_result(req, session, result)

            if errors = req.get_header(RACK_ERRORS)
              errors.puts("Warning! #{self.class.name} failed to save session: #{exception.class}: #{exception.message}")
            end

            return finish_commit(req, session, result)
          end

          if not data
            result.fail_write!(nil)
            store_commit_result(req, session, result)
            req.get_header(RACK_ERRORS).puts("Warning! #{self.class.name} failed to save session. Content dropped.")
          elsif options[:defer] and not options[:renew]
            result.commit!(persisted: true, session_id: session_id)
            store_commit_result(req, session, result)
            req.get_header(RACK_ERRORS).puts("Deferring cookie for #{session_id}") if $VERBOSE
          else
            commit_cookie(req, res, data, session_id, options)
            result.commit!(persisted: true, session_id: session_id)
            store_commit_result(req, session, result)
          end

          finish_commit(req, session, result)
        end
        public :commit_session

        # Store the result for observation and return it. This path is only
        # used when a commit policy or explicit decision is enabled; without
        # one, #legacy_commit_session preserves the historical return value.
        def finish_commit(req, session, result)
          store_commit_result(req, session, result)
          result
        end

        # The historical commit implementation, used verbatim when no commit
        # policy is enabled. Keep this in sync with the old behaviour so that
        # existing applications are unaffected.
        def legacy_commit_session(req, res)
          session = req.get_header RACK_SESSION
          options = session.options

          if options[:drop] || options[:renew]
            session_id = delete_session(req, session.id || generate_sid, options)
            return unless session_id
          end

          return unless commit_session?(req, session, options)

          session.send(:load!) unless loaded_session?(session)
          session_id ||= session.id
          session_data = session.to_hash.delete_if { |k, v| v.nil? }

          if not data = write_session(req, session_id, session_data, options)
            req.get_header(RACK_ERRORS).puts("Warning! #{self.class.name} failed to save session. Content dropped.")
          elsif options[:defer] and not options[:renew]
            req.get_header(RACK_ERRORS).puts("Deferring cookie for #{session_id}") if $VERBOSE
          else
            commit_cookie(req, res, data, session_id, options)
          end
        end
        private :legacy_commit_session

        def commit_cookie(req, res, data, session_id, options)
          cookie = Hash.new
          cookie[:value] = cookie_value(data)
          cookie[:expires] = Time.now + options[:expire_after] if options[:expire_after]
          cookie[:expires] = Time.now + options[:max_age] if options[:max_age]

          if @same_site.respond_to? :call
            cookie[:same_site] = @same_site.call(req, res)
          else
            cookie[:same_site] = @same_site
          end
          set_cookie(req, res, cookie.merge!(options))
        end

        def cookie_value(data)
          data
        end

        # Sets the cookie back to the client with session id. We skip the cookie
        # setting if the value didn't change (sid is the same) or expires was given.

        def set_cookie(request, response, cookie)
          if request.cookies[@key] != cookie[:value] || cookie[:expires]
            response.set_cookie(@key, cookie)
          end
        end

        # Allow subclasses to prepare_session for different Session classes

        def session_class
          SessionHash
        end

        # All thread safety and session retrieval procedures should occur here.
        # Should return [session_id, session].
        # If nil is provided as the session id, generation of a new valid id
        # should occur within.

        def find_session(env, sid)
          raise '#find_session not implemented.'
        end

        # All thread safety and session storage procedures should occur here.
        # Must return the session id if the session was saved successfully, or
        # false if the session could not be saved.

        def write_session(req, sid, session, options)
          raise '#write_session not implemented.'
        end

        # All thread safety and session destroy procedures should occur here.
        # Should return a new session id or nil if options[:drop]

        def delete_session(req, sid, options)
          raise '#delete_session not implemented'
        end
      end

      class PersistedSecure < Persisted
        class SecureSessionHash < SessionHash
          def [](key)
            if key == "session_id"
              load_for_read!
              case id
              when SessionId
                id.public_id
              else
                id
              end
            else
              super
            end
          end
        end

        def generate_sid(*)
          public_id = super

          SessionId.new(public_id)
        end

        def extract_session_id(*)
          public_id = super
          public_id && SessionId.new(public_id)
        end

        private

        def session_class
          SecureSessionHash
        end

        def cookie_value(data)
          data.cookie_value
        end
      end

      class ID < Persisted
        def self.inherited(klass)
          k = klass.ancestors.find { |kl| kl.respond_to?(:superclass) && kl.superclass == ID }
          unless k.instance_variable_defined?(:"@_rack_warned")
            warn "#{klass} is inheriting from #{ID}.  Inheriting from #{ID} is deprecated, please inherit from #{Persisted} instead" if $VERBOSE
            k.instance_variable_set(:"@_rack_warned", true)
          end
          super
        end

        # All thread safety and session retrieval procedures should occur here.
        # Should return [session_id, session].
        # If nil is provided as the session id, generation of a new valid id
        # should occur within.

        def find_session(req, sid)
          get_session req.env, sid
        end

        # All thread safety and session storage procedures should occur here.
        # Must return the session id if the session was saved successfully, or
        # false if the session could not be saved.

        def write_session(req, sid, session, options)
          set_session req.env, sid, session, options
        end

        # All thread safety and session destroy procedures should occur here.
        # Should return a new session id or nil if options[:drop]

        def delete_session(req, sid, options)
          destroy_session req.env, sid, options
        end
      end
    end
  end
end
