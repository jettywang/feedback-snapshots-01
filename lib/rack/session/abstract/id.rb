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

        # Internal keys are part of the persisted representation and are not
        # exposed through the public session hash.
        INTERNAL_KEYS = [RACK_SESSION_PARTITION_DATA].freeze

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
          clear
          @id = @store.send(:delete_session, @req, id, options)
        end

        # Expire (clear) the session belonging to a partition. Without an
        # argument the current request's partition is cleared; a Symbol or
        # String selects a different partition explicitly. This removes the
        # persisted state and expires only that partition's cookie, leaving
        # sessions in other partitions untouched.
        #
        #   env['rack.session'].expire!            # clear the current partition
        #   env['rack.session'].expire!(:embedded) # clear only the embedded one

        def expire!(partition = Unspecified)
          options[:expire] =
            partition == Unspecified ? true : partition.to_sym
        end
        alias :expire_session! :expire!

        # The partition this session belongs to, or nil for the ordinary,
        # unpartitioned session.
        def partition
          options[:partition]
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
          INTERNAL_KEYS.each { |key| @data.delete(key) }
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
      # * :partition selects an optional session partitioning strategy. It may
      #   be a Symbol naming a fixed partition, or a callable receiving the
      #   request and returning a partition name. A nil partition means the
      #   ordinary, unpartitioned session. Partitioning is disabled by default.
      # * :partitions declares per-partition cookie options, for example
      #   <tt>{embedded: {partitioned: true, secure: true, same_site: :none}}</tt>.
      #   A named partition without a declaration defaults to a partitioned,
      #   secure cookie. Declared partitions may also override the cookie
      #   :key, so each partition can keep its own client-side session.
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
          partition: nil,
          partitions: {},
          defer: false,
          renew: false,
          sidbits: 128,
          cookie_only: true,
          secure_random: ::SecureRandom
        }.freeze

        attr_reader :key, :default_options, :sid_secure, :same_site

        def initialize(app, options = {})
          @app = app
          @default_options = self.class::DEFAULT_OPTIONS.merge(options)
          @key = @default_options.delete(:key)
          @assume_ssl = @default_options.delete(:assume_ssl)
          @cookie_only = @default_options.delete(:cookie_only)
          @same_site = @default_options.delete(:same_site)
          @partition = @default_options.delete(:partition)
          @partitions = normalize_partitions(@default_options.delete(:partitions))
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
          commit_session(req, res)
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

        # Normalize <tt>:partitions</tt> into a hash keyed by partition name,
        # with Symbol keys in the per-partition options.

        def normalize_partitions(partitions)
          (partitions || {}).each_with_object({}) do |(name, options), normalized|
            normalized[name.to_sym] =
              case options
              when nil
                {}
              when Hash
                options.each_with_object({}) { |(key, value), hash| hash[key.to_sym] = value }
              else
                raise ArgumentError, "partition options must be a Hash: #{options.inspect}"
              end
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
          resolve_partition(req)
          req.set_header RACK_SESSION, session
          req.set_header RACK_SESSION_OPTIONS, session_options_for(req)
          session.merge! session_was if session_was
        end

        # The partition selected for the current request. The explicit
        # <tt>rack.session.partition</tt> request header wins, then the
        # configured :partition strategy, then the ordinary (nil) partition.
        # An :auto strategy only selects a named partition when the request is
        # marked as embedded in a third-party page.

        def resolve_partition(req)
          explicit = req.get_header(RACK_SESSION_PARTITION)
          partition = if explicit
            explicit
          elsif @partition.respond_to?(:call)
            @partition.call(req)
          elsif @partition == :auto
            embedded_request?(req) ? :embedded : nil
          else
            @partition
          end

          partition = partition&.to_sym
          req.set_header(RACK_SESSION_PARTITION_CURRENT, partition)
          partition
        end

        # Whether the request reports that it is embedded in a third-party
        # document. +:auto+ only treats a cross-site request as embedded; the
        # same site's own pages keep the ordinary session.

        def embedded_request?(req)
          sec_fetch_site = req.get_header('HTTP_SEC_FETCH_SITE')
          return true if sec_fetch_site && sec_fetch_site.downcase == 'cross-site'

          req.get_header('HTTP_SEC_FETCH_DEST') == 'iframe' &&
            req.get_header('HTTP_SEC_FETCH_MODE') == 'navigate'
        end

        # The cookie name used for +partition+. Every named partition gets its
        # own cookie, so an embedded session and a direct session never
        # overwrite each other in the browser.

        def cookie_key_for(partition)
          cookie_key = partition && (@partitions[partition] || {})[:key]
          cookie_key ||= @key if partition.nil?
          cookie_key || "#{@key}.#{partition}"
        end

        # The cookie attributes for +partition+. Named partitions default to a
        # partitioned, secure cookie; only the ordinary session may be
        # unpartitioned unless the integrator explicitly says otherwise. The
        # Partitioned attribute requires Secure, so Secure is enforced whenever
        # Partitioned is in effect.

        def cookie_options_for(partition)
          options = {}
          options.merge!(@partitions[partition]) if partition && @partitions[partition]
          options.delete(:key)

          if partition
            options[:partitioned] = true unless options.key?(:partitioned)
            options[:secure] = true unless options.key?(:secure)
            options[:same_site] = :none unless options.key?(:same_site)
            options[:secure] = true if options[:partitioned]
          end

          options
        end

        # The effective session options for the current request, including the
        # partition-specific cookie key and attributes.

        def session_options_for(req)
          options = @default_options.dup
          partition = req.get_header(RACK_SESSION_PARTITION_CURRENT)

          if partition
            options[:partition] = partition
            options.merge!(cookie_options_for(partition))
          end

          options[:key] = cookie_key_for(partition)
          options
        end

        # Whether a persisted session may be presented as +partition+. An
        # ordinary session (without a marker) can only be presented as the
        # ordinary partition; a marked session only as its own partition. This
        # keeps the unpartitioned cookie from granting a named partition.

        def session_usable_for_partition?(session, partition)
          recorded = session[RACK_SESSION_PARTITION_DATA]
          recorded = recorded&.to_sym

          if session.key?(RACK_SESSION_PARTITION_DATA)
            recorded == partition
          else
            partition.nil?
          end
        end

        # Extracts the session id from provided cookies and passes it and the
        # environment to #find_session.

        def load_session(req)
          presented_id = current_session_id(req)
          sid, session = find_session(req, presented_id)
          session ||= {}
          partition = req.get_header(RACK_SESSION_PARTITION_CURRENT)

          if presented_id && session.is_a?(Hash) && !session_usable_for_partition?(session, partition)
            # A cookie was presented but its session belongs to another
            # partition (or lacks a partition marker and is therefore only valid
            # for the ordinary session). Start a fresh session instead of
            # reusing it.
            sid, session = discard_session(req)
          end

          [sid, session]
        end

        # Abandon a session that does not belong to the current partition and
        # start a fresh one. Backends that keep server-side records must ensure
        # the new session id resolves to an empty record.

        def discard_session(req)
          sid = generate_sid
          prepare_session_record(req, sid, req.session_options)
          [sid, {}]
        end

        # Persist the record for a freshly generated session id, so server-side
        # stores have somewhere to write when a request starts over (for
        # example because a cookie belonged to another partition). Stateless
        # stores have nothing to prepare.

        def prepare_session_record(req, sid, options)
        end

        # Extract session id from request object.

        def extract_session_id(request)
          extract_session_id_for(request, request.session_options[:key])
        end

        # Extract the session id stored under an explicit cookie +key+. Used to
        # address a partition other than the one selected for the request.

        def extract_session_id_for(request, key)
          sid = request.cookies[key]
          sid ||= request.params[key] unless @cookie_only
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

        def commit_session?(req, session, options)
          if options[:skip]
            false
          else
            has_session = loaded_session?(session) || forced_session_update?(session, options)
            has_session && security_matches?(req, options)
          end
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

        def commit_session(req, res)
          session = req.get_header RACK_SESSION
          options = session.options

          if options.key?(:expire)
            expired_current = expire_partition(req, res, session, options.delete(:expire))
            # Expiring the current partition ends the session for this request;
            # never re-issue it from any staged data.
            return if expired_current
          end

          if options[:drop] || options[:renew]
            session_id = delete_session(req, session.id || generate_sid, options)
            return unless session_id
          end

          return unless commit_session?(req, session, options)

          session.send(:load!) unless loaded_session?(session)
          session_id ||= session.id
          session_data = session.to_hash.delete_if { |k, v| v.nil? }

          if (partition = options[:partition])
            session_data[RACK_SESSION_PARTITION_DATA] = partition.to_s
          end

          if not data = write_session(req, session_id, session_data, options)
            req.get_header(RACK_ERRORS).puts("Warning! #{self.class.name} failed to save session. Content dropped.")
          elsif options[:defer] and not options[:renew]
            req.get_header(RACK_ERRORS).puts("Deferring cookie for #{session_id}") if $VERBOSE
          else
            cookie = Hash.new
            cookie[:value] = cookie_value(data)
            cookie[:expires] = Time.now + options[:expire_after] if options[:expire_after]
            cookie[:expires] = Time.now + options[:max_age] if options[:max_age]

            if @same_site.respond_to? :call
              cookie[:same_site] = @same_site.call(req, res)
            else
              cookie[:same_site] = @same_site
            end

            cookie[:same_site] = options[:same_site] if options.key?(:same_site)
            set_cookie(req, res, cookie.merge!(options))
          end
        end
        public :commit_session

        def cookie_value(data)
          data
        end

        # Sets the cookie back to the client with session id. We skip the cookie
        # setting if the value didn't change (sid is the same) or expires was given.

        def set_cookie(request, response, cookie)
          key = cookie[:key] || request.session_options[:key] || @key

          if request.cookies[key] != cookie[:value] || cookie[:expires]
            response.set_cookie(key, cookie)
          end
        end

        # Expire the session for +partition+ (nil for the ordinary session).
        # The persisted state of that partition is removed and its cookie is
        # expired. Returns true when the expired partition is the one the
        # request is currently using.

        def expire_partition(req, res, session, partition)
          current = req.get_header(RACK_SESSION_PARTITION_CURRENT)
          partition = current if partition == true
          partition = partition&.to_sym

          if partition == current
            session_id = session.id
          else
            # Another partition was named explicitly: address its cookie
            # directly so its server-side record can be removed as well.
            session_id = extract_session_id_for(req, cookie_key_for(partition))
          end

          if session_id && !session_id.to_s.empty?
            options = @default_options.merge(
              partition: partition,
              key: cookie_key_for(partition),
              drop: true
            )
            delete_session(req, session_id, options)
          end

          delete_session_cookie(req, res, partition)
          partition == current
        end

        # Expire the cookie for +partition+ on the response. The cookie is
        # expired with the same path, domain and partitioning attributes it was
        # issued with, so browsers remove exactly that session.

        def delete_session_cookie(req, response, partition)
          key = cookie_key_for(partition)
          attributes = cookie_options_for(partition)
          attributes[:path] = @default_options[:path]
          attributes[:domain] = @default_options[:domain] if @default_options[:domain]

          # Rack::Response::Raw does not implement #delete_cookie, so expire
          # the cookie directly with the same attributes it was issued with.
          response.set_cookie(key, attributes.merge(value: '', max_age: 0, expires: Time.at(0)))
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
