# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026.

require_relative 'constants'

module Rack
  module Session
    # The outcome of evaluating the commit policy for a single request.
    #
    # `business_success` describes the application's response (or an explicit
    # business marker), while `persisted` describes whether the session store
    # accepted the staged session data. The two are deliberately independent:
    # a request can be a business success even when the session could not be
    # persisted, and a business failure can still be a successful no-op.
    class CommitResult
      attr_reader :status, :family, :business_success, :committed, :persisted,
        :error, :reason, :session_id

      def initialize(status: nil, family: nil, business_success: false)
        @status = status
        @family = family
        @business_success = !!business_success
        @committed = false
        @persisted = false
        @error = nil
        @reason = nil
        @session_id = nil
      end

      def business_success?
        @business_success
      end

      def business_success=(value)
        @business_success = !!value
      end

      def business_failure?
        !@business_success
      end

      # Whether the middleware decided to attempt a session write. Note that
      # a write attempt can still fail; use #persisted? to determine whether
      # the staged data is durable.
      def committed?
        @committed
      end
      alias :attempted? :committed?

      # Whether the session store accepted the write. This is the only value
      # which indicates that the staged data is durable.
      def persisted?
        @persisted
      end

      def stored?
        @persisted
      end
      alias :persistence_success? :persisted?
      alias :persisted_successfully? :persisted?

      # Whether the business outcome was a success, independent of whether the
      # session was persisted.
      alias :business_ok? :business_success?

      # Business success, kept as an alias for callers which think of the
      # response status or marker as "success".
      def success?
        @business_success
      end

      # The commit was not attempted because the policy (or the legacy
      # :skip/:drop rules) did not allow it.
      def skipped?
        !@committed && !@persisted
      end

      def commit!(persisted: false, session_id: nil, reason: nil)
        @committed = true
        @persisted = !!persisted
        @session_id = session_id
        @reason = reason || (persisted ? :persisted : :write_failed)
        self
      end

      def skip!(reason = :skipped)
        @committed = false
        @persisted = false
        @reason = reason
        self
      end

      def fail_stream!(error)
        @committed = false
        @persisted = false
        @error = error
        @reason = :stream_error
        self
      end

      def fail_write!(error)
        @committed = true
        @persisted = false
        @error = error
        @reason = :write_error
        self
      end

      def to_h
        {
          status: status,
          family: family,
          business_success: business_success?,
          committed: committed?,
          persisted: persisted?,
          skipped: skipped?,
          reason: reason,
          error: error,
          session_id: session_id
        }
      end

      def inspect
        "#<#{self.class} status=#{status.inspect} family=#{family.inspect} " \
          "business_success=#{business_success?} committed=#{committed?} " \
          "persisted=#{persisted?} reason=#{reason.inspect}>"
      end
    end

    # Describes the request/response being considered for a session commit.
    #
    # Policies can either receive this object (the one-argument form) or the
    # pieces they need (the multi-argument forms), see CommitPolicy.resolve.
    class CommitContext
      attr_reader :env, :status, :headers, :body, :session, :options, :policy

      def initialize(env: {}, status: nil, headers: nil, body: nil, session: nil, options: nil, policy: nil)
        @env = env || {}
        @status = status && status.to_i
        @headers = headers
        @body = body
        @session = session
        @options = options || {}
        @policy = policy
      end

      def family
        CommitPolicy.family_for(@status)
      end
      alias :response_family :family

      def business_success?
        value = business_marker
        value.nil? ? CommitPolicy.successful_status?(@status) : value
      end

      def business_marker
        CommitPolicy.resolve_business_marker(@env, @session, @options, @policy, @headers)
      end

      # A per-request explicit decision, if one was provided. Returns nil when
      # the caller did not supply an override.
      def explicit_decision
        CommitPolicy.resolve_explicit_decision(@env, @options)
      end

      def response_headers
        @headers
      end

      def request
        @env
      end

      def [](key)
        case key
        when :env, "env" then @env
        when :status, "status" then @status
        when :headers, "headers" then @headers
        when :body, "body" then @body
        when :session, "session" then @session
        when :options, "options" then @options
        when :family, "family" then family
        when :business_success, "business_success", :business_success?, "business_success?" then business_success?
        else @env ? @env[key] : nil
        end
      end

      def to_h
        {
          env: env,
          status: status,
          headers: headers,
          body: body,
          session: session,
          options: options,
          family: family,
          business_success: business_success?
        }
      end
    end

    # A configurable decision describing whether staged session data should be
    # committed.
    #
    # The decision normally depends on two independent inputs:
    #
    # 1. The response family, e.g. only `:success` and `:redirect` responses.
    # 2. An optional business marker, e.g.
    #    `env['rack.session.business_success'] = true`.
    #
    # Examples:
    #
    #   # Only successful and redirect responses.
    #   Rack::Session::Pool.new(app, commit_policy: Rack::Session::CommitPolicy.new(:success, :redirect))
    #
    #   # Require an explicit business marker, and only commit 2xx responses.
    #   Rack::Session::Pool.new(app,
    #     commit_policy: {on: :success, require_business: true})
    #
    #   # A custom callable. It receives a CommitContext.
    #   Rack::Session::Pool.new(app, commit_policy: ->(context) {
    #     context.status.between?(200, 299) && context.business_success?
    #   })
    #
    # A policy may also be supplied per request:
    #
    #   env['rack.session.options'][:commit_policy] = ...
    #   env['rack.session.commit_policy'] = ...
    class CommitPolicy
      FAMILY_RANGES = {
        informational: 100...200,
        success: 200...300,
        redirect: 300...400,
        client_error: 400...500,
        server_error: 500...600
      }.freeze

      FAMILY_ALIASES = {
        informational: :informational,
        info: :informational,
        :"1xx" => :informational,
        success: :success,
        successful: :success,
        ok: :success,
        :"2xx" => :success,
        redirect: :redirect,
        redirection: :redirect,
        :"3xx" => :redirect,
        client_error: :client_error,
        client: :client_error,
        :"4xx" => :client_error,
        server_error: :server_error,
        server: :server_error,
        :"5xx" => :server_error
      }.freeze

      attr_reader :families, :statuses, :status_ranges, :business_key,
        :require_business, :check_business, :defer_streaming

      def self.family_for(status)
        return :unknown if status.nil?

        status = status.to_i
        FAMILY_RANGES.each do |family, range|
          return family if range.cover?(status)
        end

        :unknown
      end

      def self.successful_status?(status)
        return false unless status

        status = status.to_i
        status >= 200 && status < 400
      end

      def self.resolve_business_marker(env, session, options, policy = nil, headers = nil)
        keys = []
        keys << policy.business_key if policy.respond_to?(:business_key) && policy.business_key

        keys.concat([
          RACK_SESSION_BUSINESS_SUCCESS,
          :business_success
        ])

        keys.each do |key|
          next if key.nil?

          value, present = lookup(env, session, options, key)
          return truthy?(value) if present
        end

        failure_keys = [RACK_SESSION_BUSINESS_FAILURE, :business_failure]
        failure_keys.each do |key|
          value, present = lookup(env, session, options, key)
          return false if present && truthy?(value)
        end

        if headers
          header = headers[RACK_SESSION_BUSINESS_SUCCESS_HEADER]
          return truthy?(header) unless header.nil?
        end

        nil
      end

      # Look up a marker in the request environment or session options.
      #
      # The session hash itself is intentionally not consulted: reading it
      # would load a lazy session as a side effect of evaluating the policy,
      # changing whether it gets committed.
      def self.lookup(env, session, options, key)
        if env.respond_to?(:key?) && env.key?(key)
          [env[key], true]
        elsif env.respond_to?(:key?) && key.is_a?(String) && env.key?(key.to_sym)
          [env[key.to_sym], true]
        elsif options.respond_to?(:key?) && options.key?(key.to_sym)
          [options[key.to_sym], true]
        elsif options.respond_to?(:key?) && options.key?(key.to_s)
          [options[key.to_s], true]
        else
          [nil, false]
        end
      end

      def self.truthy?(value)
        case value
        when false, nil
          false
        when :failure, "failure", :failed, "failed", :error, "error"
          false
        when "false", "0", "no", "off"
          false
        when Integer
          value != 0
        else
          true
        end
      end

      def self.resolve_explicit_decision(env, options)
        keys = [RACK_SESSION_COMMIT, RACK_SESSION_COMMIT_MARKER, :commit, :commit?]

        keys.each do |key|
          if env.respond_to?(:key?) && env.key?(key)
            return truthy?(env[key])
          end

          if env.respond_to?(:key?) && key.is_a?(String) && env.key?(key.to_sym)
            return truthy?(env[key.to_sym])
          end

          if options.respond_to?(:key?) && options.key?(key)
            return truthy?(options[key])
          end

          if options.respond_to?(:key?) && key.is_a?(String) && options.key?(key.to_sym)
            return truthy?(options[key.to_sym])
          end
        end

        nil
      end

      # Evaluate a policy. Supports:
      # * nil/true/false
      # * a symbol such as :success, :error, :all, :none
      # * an array/range/integer selection
      # * a hash of CommitPolicy options
      # * a CommitPolicy
      # * a callable or an object responding to #commit?
      def self.resolve(policy, context)
        explicit = context.explicit_decision
        return explicit unless explicit.nil?

        case policy
        when nil
          new.decide(context)
        when true
          true
        when false
          false
        else
          resolve_non_trivial(policy, context)
        end
      end

      def self.resolve_non_trivial(policy, context)
        case policy
        when Symbol, Array, Range, Integer
          new(policy).decide(context)
        when Hash
          options = {}
          policy.each do |key, value|
            if key.is_a?(String) || key.is_a?(Symbol)
              options[key.to_sym] = value
            end
          end

          # A hash of family booleans is also accepted, e.g.
          # {success: true, redirect: false}.
          if options.keys.any? { |key| FAMILY_ALIASES.key?(key) }
            selected = options.select { |key, value| value && FAMILY_ALIASES.key?(key) }.keys
            new(selected).decide(context)
          else
            new(**options).decide(context)
          end
        else
          if policy.respond_to?(:decide)
            policy.decide(context)
          elsif policy.respond_to?(:commit?)
            normalize(invoke(policy.method(:commit?), context))
          elsif policy.respond_to?(:call)
            normalize(invoke(policy, context))
          else
            !!policy
          end
        end
      end

      def self.normalize(value)
        case value
        when false, nil, :skip, "skip", :deny, "deny", :none
          false
        when true, :commit, "commit", :persist, "persist"
          true
        else
          !!value
        end
      end

      def self.invoke(callable, context)
        arity = if callable.respond_to?(:arity)
          callable.arity
        else
          callable.method(:call).arity
        end

        parameters = callable.respond_to?(:parameters) ? callable.parameters : []

        case arity
        when 0
          callable.call
        when 1
          name = parameters.first && parameters.first[1]
          case name
          when :status, :code then callable.call(context.status)
          when :env, :request, :req then callable.call(context.env)
          else callable.call(context)
          end
        when 2
          callable.call(context.env, context.status)
        when 3
          callable.call(context.env, context.status, context.headers)
        when 4
          callable.call(context.env, context.status, context.headers, context.body)
        when 5
          callable.call(context.env, context.status, context.headers, context.body, context.session)
        else
          callable.call(context.env, context.status, context.headers, context.body, context.session, context.options)
        end
      end

      def self.defer_streaming?(policy)
        case policy
        when CommitPolicy
          policy.defer_streaming?
        when Hash
          policy.fetch(:defer_streaming, true) != false
        else
          true
        end
      end

      def initialize(*selection, on: nil, families: nil, statuses: nil, status: nil,
        business: true, business_key: nil, require_business: false,
        defer_streaming: true, **options)

        if selection.empty?
          selection = on
          selection = families if selection.nil?
          selection = status if selection.nil?
          selection = statuses if selection.nil?
        else
          selection = selection.length == 1 ? selection.first : selection
        end

        provided = !selection.nil?
        @families = []
        @statuses = []
        @status_ranges = []
        @business_key = business_key
        @require_business = !!require_business
        @check_business = business != false
        @defer_streaming = defer_streaming != false

        add_selection(selection) unless selection.nil?
        add_selection(options[:select]) unless options[:select].nil?
        add_selection(options[:statuses]) unless options[:statuses].nil?
        add_selection(options[:families]) unless options[:families].nil?

        # An explicit but empty selection means "commit nothing". With no
        # explicit selection, only successful (2xx) and redirect (3xx)
        # responses are considered success. The business marker can still veto
        # a commit for those responses.
        if @families.empty? && @statuses.empty? && @status_ranges.empty?
          @families << (provided ? :none : :success)
          @families << :redirect unless provided
        end
      end

      def defer_streaming?
        @defer_streaming
      end

      def families=(value)
        @families = []
        add_selection(value)
      end

      def statuses=(value)
        @statuses = []
        add_selection(value)
      end

      def add_selection(selection)
        case selection
        when Array
          selection.each { |item| add_selection(item) }
        when Range
          @status_ranges << selection
        when Integer
          @statuses << selection.to_i
        when String
          add_family(selection.to_sym)
        when Symbol
          add_family(selection)
        when nil
          nil
        else
          if selection.respond_to?(:to_a)
            selection.to_a.each { |item| add_selection(item) }
          else
            add_family(selection)
          end
        end

        self
      end

      def add_family(family)
        key = family.to_sym
        aliased = FAMILY_ALIASES[key] || key

        case aliased
        when :all, :any
          @families << :all
        when :none
          @families.clear
          @statuses.clear
          @status_ranges.clear
          @families << :none
        when :error, :errors
          @families << :client_error << :server_error
        else
          @families << aliased
        end
      end

      def family_allowed?(status)
        return true if @families.include?(:all)
        return false if @families.include?(:none)

        status = status.to_i
        return true if @statuses.include?(status)
        return true if @status_ranges.any? { |range| range.cover?(status) }

        family = self.class.family_for(status)
        @families.include?(family)
      end

      def business_allowed?(context)
        return true unless @check_business

        marker = context.business_marker
        return !@require_business if marker.nil?

        marker
      end

      def decide(context)
        explicit = context.explicit_decision
        return explicit unless explicit.nil?

        family_allowed?(context.status) && business_allowed?(context)
      end
      alias :call :decide
      alias :commit? :decide
    end

    # Wraps a Rack response body so that a deferred session commit only runs
    # after the body has been fully delivered and closed without error.
    #
    # If enumerating the body, streaming it, or closing it raises, the commit
    # is suppressed and the error is reported (then re-raised).
    class CommitBody
      def initialize(body, commit = nil, error = nil, &block)
        @body = body
        @commit = commit || block
        @error = error
        @stream_error = nil
        @reported = false
        @closed = false

        # Preserve the body's interface: only expose #each or #call if the
        # wrapped body supports it.
        if body.respond_to?(:each)
          define_singleton_method(:each) do |&block|
            return enum_for(:each) unless block

            begin
              body.each(&block)
            rescue => exception
              fail_stream(exception)
              raise
            end
          end
        end

        if body.respond_to?(:call)
          define_singleton_method(:call) do |stream|
            begin
              body.call(stream)
            rescue => exception
              fail_stream(exception)
              raise
            end
          end
        end
      end

      def close
        return if @closed
        @closed = true

        begin
          @body.close if @body.respond_to?(:close)
        rescue => exception
          fail_stream(exception)
          raise
        end

        if @stream_error
          report_stream_error(@stream_error)
        else
          @commit&.call
        end
      end

      def closed?
        @closed
      end

      def respond_to_missing?(name, include_all = false)
        @body.respond_to?(name, include_all) || super
      end

      def method_missing(name, *args, &block)
        @body.__send__(name, *args, &block)
      end
      ruby2_keywords(:method_missing) if respond_to?(:ruby2_keywords, true)

      def inspect
        "#<#{self.class} body=#{@body.class} closed=#{closed?}>"
      end

      private

      def fail_stream(exception)
        @stream_error ||= exception
        report_stream_error(@stream_error)
      end

      def report_stream_error(exception)
        return if @reported

        @reported = true
        @error&.call(exception)
      end
    end
  end
end
