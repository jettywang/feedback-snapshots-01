require "flipper"
require "flipper/adapters/wrapper"

module Flipper
  module Adapters
    # Public: Adapter that wraps another adapter and authorizes writes by
    # principal, action and feature. Reads always pass through, so applications
    # (and Flipper::UI) keep seeing exactly what the wrapped adapter holds.
    #
    # Policies deny by default, including when no principal is set. Every
    # denied write raises NotAuthorized and instruments a "write_denied.flipper"
    # event so denials can be audited.
    #
    # Examples:
    #
    #   policy = Flipper::Adapters::WriteAuthorization::Policy.new(
    #     on_call: { "checkout" => [:disable, :clear] },
    #     security: :all
    #   )
    #   adapter = Flipper::Adapters::WriteAuthorization.new(memory, policy: policy)
    #   flipper = Flipper.new(adapter)
    #
    #   # Reads need no principal and never raise.
    #   flipper[:checkout].enabled?
    #
    #   Flipper::Adapters::WriteAuthorization.with_principal(:on_call) do
    #     flipper[:checkout].disable_actor(actor) # allowed
    #     flipper[:checkout].enable               # raises NotAuthorized
    #   end
    #
    #   Flipper::Adapters::WriteAuthorization.with_principal(:security) do
    #     flipper[:checkout].enable               # allowed
    #   end
    #
    # Feature#enable and Feature#disable call Adapter#add before changing a
    # gate. Adding an existing feature changes nothing, so that prerequisite is
    # always allowed and the real gate change is authorized and reported on its
    # own. Creating a new feature is a write of its own and requires :add.
    class WriteAuthorization < Wrapper
      # Public: The name of the instrumentation event emitted for denied writes.
      DenialInstrumentationName = "write_denied.#{InstrumentationNamespace}".freeze

      # Public: Actions that change adapter state.
      WRITE_ACTIONS = %i[import add remove clear enable disable sync_version=].freeze

      # Public: The wildcard for principals, actions and features.
      ALL = :all

      # Public: Raised when a principal attempts a write the policy does not
      # allow. The denial instrumentation event carries the same information.
      class NotAuthorized < Flipper::Error
        attr_reader :principal, :action, :feature, :gate, :thing, :reason

        def initialize(principal:, action:, feature: nil, gate: nil, thing: nil, reason: nil)
          @principal = principal
          @action = action
          @feature = feature
          @gate = gate
          @thing = thing
          @reason = reason
          super(build_message)
        end

        private

        def build_message
          subject = feature ? " feature #{feature.key.inspect}" : ""

          if principal.nil?
            "write authorization requires a principal to #{action}#{subject}; " \
              "use Flipper::Adapters::WriteAuthorization.with_principal"
          else
            "#{principal.inspect} is not authorized to #{action}#{subject}"
          end
        end
      end

      # Public: A set of allow/deny rules checked by WriteAuthorization.
      #
      # Rules match on principal, action and feature. Explicit deny rules win
      # over allow rules, and anything not allowed is denied.
      #
      # Configure with #allow/#deny:
      #
      #   policy = Policy.new
      #   policy.allow :on_call, [:disable, :clear], features: %w[checkout]
      #   policy.allow :security, :all
      #
      # Or with a Hash:
      #
      #   Policy.new(
      #     on_call: { "checkout" => [:disable, :clear] },
      #     security: :all
      #   )
      #
      # Hash values can be:
      #   - :all                         => every action on every feature
      #   - :disable or [:disable, ...]  => those actions on every feature
      #   - { actions: [...], features: [...] } => actions/features pair
      #   - { "feature" => actions }     => actions restricted to each feature
      class Policy
        Rule = Struct.new(:effect, :principal, :actions, :features, keyword_init: true)

        WILDCARDS = [:all, :*, "all", "*"].freeze

        # Public: The configured rules.
        attr_reader :rules

        # Public: Build a policy from a Policy, Hash or nothing. A block, if
        # given, can add rules with #allow/#deny, including on a passed-in
        # policy or Hash.
        def self.build(source = nil, &block)
          policy = case source
          when nil
            new
          when self
            source
          when Hash
            new(source)
          else
            raise ArgumentError, "policy must be a #{self} or Hash, got #{source.inspect}"
          end

          yield policy if block_given?
          policy
        end

        def initialize(config = nil, &block)
          @rules = []
          configure(config) if config
          yield self if block_given?
        end

        # Public: Allow a principal to perform actions on features.
        #
        # principal - The Symbol/String identity the rule applies to.
        # actions   - An action, Array of actions, or :all.
        # features  - A feature name, Array of names, or :all.
        #
        # Returns self, so rules can be chained.
        def allow(principal, actions = ALL, features: ALL)
          add_rule(:allow, principal, actions, features)
        end

        # Public: Deny a principal actions on features. Deny rules win over
        # allow rules.
        #
        # Returns self, so rules can be chained.
        def deny(principal, actions = ALL, features: ALL)
          add_rule(:deny, principal, actions, features)
        end

        # Public: Does this policy allow the principal to perform action on
        # feature?
        #
        # feature can be a Flipper::Feature, a String/Symbol feature name, or
        # nil for adapter-wide actions such as import.
        def allowed?(principal, action, feature = nil)
          return false if principal.nil?

          action = action.to_sym

          !denied?(principal, action, feature) &&
            match_rule?(:allow, principal, action, feature)
        end

        # Public: The actions the principal may perform on feature. Adapter-wide
        # actions are not included; they are only allowed with a nil feature.
        def allowed_actions(principal, feature)
          return [] if principal.nil?

          WRITE_ACTIONS.select { |action| allowed?(principal, action, feature) }
        end

        private

        def add_rule(effect, principal, actions, features)
          @rules << Rule.new(
            effect: effect,
            principal: principal,
            actions: list(actions),
            features: list(features)
          )
          self
        end

        def configure(config)
          unless config.is_a?(Hash)
            raise ArgumentError, "policy configuration must be a Hash, got #{config.inspect}"
          end

          config.each { |principal, permissions| configure_principal(principal, permissions) }
          self
        end

        def configure_principal(principal, permissions)
          case permissions
          when Hash
            if permission_options?(permissions)
              allow(
                principal,
                option(permissions, :actions) || ALL,
                features: option(permissions, :features) || ALL
              )
            else
              permissions.each do |feature, actions|
                allow(principal, actions, features: feature)
              end
            end
          when Array, Symbol, String
            allow(principal, permissions)
          else
            raise ArgumentError, "permissions for #{principal.inspect} must be an action, " \
              "Array, Hash or :all, got #{permissions.inspect}"
          end
        end

        def permission_options?(permissions)
          permissions.key?(:actions) || permissions.key?("actions") ||
            permissions.key?(:features) || permissions.key?("features")
        end

        def option(hash, key)
          hash.key?(key) ? hash[key] : hash[key.to_s]
        end

        def denied?(principal, action, feature)
          match_rule?(:deny, principal, action, feature)
        end

        def match_rule?(effect, principal, action, feature)
          @rules.any? do |rule|
            rule.effect == effect &&
              principal_matches?(rule.principal, principal) &&
              list_matches?(rule.actions, action, :action) &&
              list_matches?(rule.features, feature, :feature)
          end
        end

        def principal_matches?(pattern, principal)
          return true if wildcard?(pattern)
          return pattern.to_s == principal.to_s if stringish?(pattern) && stringish?(principal)

          pattern == principal
        end

        def list_matches?(patterns, value, type)
          patterns.any? do |pattern|
            if pattern.is_a?(Array)
              list_matches?(pattern, value, type)
            elsif type == :action
              wildcard?(pattern) || pattern.to_sym == value
            else
              feature_matches?(pattern, value)
            end
          end
        end

        def feature_matches?(pattern, feature)
          return true if wildcard?(pattern)
          return false if feature.nil?

          if pattern.is_a?(Regexp)
            pattern.match?(feature_key(feature))
          else
            pattern.to_s == feature_key(feature)
          end
        end

        def feature_key(feature)
          feature.respond_to?(:key) ? feature.key.to_s : feature.to_s
        end

        def stringish?(value)
          value.is_a?(String) || value.is_a?(Symbol)
        end

        def wildcard?(value)
          WILDCARDS.include?(value)
        end

        def list(value)
          value.is_a?(Array) ? value.flatten : [value]
        end
      end

      # Public: The policy checked for writes.
      attr_reader :policy

      # Public: What is used to instrument denied writes.
      attr_reader :instrumenter

      # Public: Build a new WriteAuthorization adapter.
      #
      # adapter   - The adapter to wrap.
      # options   - Hash of options:
      #             :policy       - A Policy, a Hash of policy rules, or nil.
      #             :principal    - Optional default principal used when no
      #                             principal is set for the current thread.
      #             :instrumenter - What to use to instrument denied writes.
      # block     - Optional block yielding a new Policy to configure.
      def initialize(adapter, options = {}, &block)
        super(adapter)
        @policy = Policy.build(options[:policy], &block)
        @default_principal = options[:principal]
        @instrumenter = options.fetch(:instrumenter, Instrumenters::Noop)
      end

      class << self
        # Public: The principal for the current thread, or nil.
        def principal
          Thread.current[:flipper_write_authorization_principal]
        end

        # Public: Set the principal for the current thread.
        def principal=(value)
          Thread.current[:flipper_write_authorization_principal] = value
        end

        # Public: Run the block with principal as the identity used for
        # writes. The previous principal is restored afterwards, including
        # when the block raises.
        def with_principal(principal)
          previous = self.principal
          self.principal = principal
          yield
        ensure
          self.principal = previous
        end
      end

      # Public: Run the block with principal, scoped to this adapter.
      def with_principal(principal, &block)
        self.class.with_principal(principal, &block)
      end

      # Public: The principal writes use. The thread's principal wins over the
      # adapter's default.
      def principal
        self.class.principal || @default_principal
      end

      # Public: Would the current principal be allowed to perform action on
      # feature? Reads are never checked, so this is useful for deciding which
      # write controls to show.
      #
      # feature can be a Flipper::Feature, a String/Symbol feature name, or nil.
      def authorized?(action, feature = nil)
        policy.allowed?(principal, action, feature)
      end
      alias_method :write_allowed?, :authorized?

      # Public: The actions the current principal may perform on feature.
      def allowed_actions(feature = nil)
        policy.allowed_actions(principal, feature)
      end

      private

      def wrap(method, *args, **kwargs)
        if method == :add
          authorize_add(args.first)
        elsif WRITE_ACTIONS.include?(method)
          authorize_write(method, *args)
        end

        yield
      end

      # Internal: Feature#enable/disable call add first. A no-op add of an
      # existing feature is allowed so the real action decides the outcome.
      # Only look the feature up when :add was not granted; otherwise the
      # common path costs no extra storage read.
      def authorize_add(feature)
        return if policy.allowed?(principal, :add, feature)
        return if feature_exists?(feature)

        authorize!(:add, feature)
      end

      def feature_exists?(feature)
        @adapter.features.include?(feature.key)
      end

      def authorize_write(action, *args)
        case action
        when :enable, :disable
          feature, gate, thing = args
          authorize!(action, feature, gate: gate, thing: thing)
        when :import, :sync_version=
          authorize!(action, nil)
        when :add, :remove, :clear
          authorize!(action, args.first)
        end
      end

      def authorize!(action, feature, gate: nil, thing: nil)
        actor = principal
        return if policy.allowed?(actor, action, feature)

        error = NotAuthorized.new(
          principal: actor,
          action: action,
          feature: feature,
          gate: gate,
          thing: thing,
          reason: actor.nil? ? :missing_principal : :policy_denied
        )

        denied(error)
      end

      def denied(error)
        payload = {
          adapter_name: name,
          principal: error.principal,
          operation: error.action,
          feature_name: error.feature && error.feature.name,
          gate_name: error.gate && error.gate.name,
          thing_value: thing_value(error.thing),
          reason: error.reason,
          exception: [error.class.name, error.message],
          exception_object: error,
        }

        instrumenter.instrument(DenialInstrumentationName, payload)
        raise error
      end

      def thing_value(thing)
        thing.value if thing.respond_to?(:value)
      end
    end
  end
end
