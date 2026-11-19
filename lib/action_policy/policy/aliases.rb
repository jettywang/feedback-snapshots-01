# frozen_string_literal: true

require "action_policy/policy/rule_resolution"

module ActionPolicy
  module Policy
    # Adds rules aliases support and ability to specify
    # the default rule.
    #
    #   class ApplicationPolicy
    #     include ActionPolicy::Policy::Core
    #     include ActionPolicy::Policy::Aliases
    #
    #     # define which rule to use if `authorize!` called with
    #     # unknown rule
    #     default_rule :manage?
    #
    #     alias_rule :publish?, :unpublish?, to: :update?
    #   end
    #
    # Aliases are used only during `authorize!` call (and do not act like _real_ aliases).
    #
    # Aliases useful when combined with `CachedApply` (since we can cache only the target rule).
    module Aliases
      DEFAULT = :__default__

      class << self
        def included(base)
          base.extend ClassMethods

          # Make contract inspection available for every aliases-aware policy,
          # without changing the default resolution behavior (enforcement is
          # opt-in). If `Contract` is loaded later, it is included on demand
          # from `ClassMethods#contract_config`.
          if defined?(ActionPolicy::Policy::Contract) &&
              !base.ancestors.include?(ActionPolicy::Policy::Contract)
            base.include(ActionPolicy::Policy::Contract)
          end
        end
      end

      def resolve_rule(activity)
        resolution = self.class.resolve_rule_resolution(activity)

        if resolution.cycle? || resolution.too_long?
          raise CircularRule.new(self, activity, resolution.chain)
        end

        # Preserve the legacy ordering: the predicate naming check runs after
        # aliases (and concrete methods) but before the default rule.
        if ActionPolicy.enforce_predicate_rules_naming &&
            !respond_to?(activity) &&
            !self.class.lookup_alias(activity)
          check_rule_naming(activity)
        end

        enforce_contract(activity, resolution)

        if resolution.resolved?
          resolution.target
        elsif resolution.alias_used? || resolution.default_used?
          # Preserve the legacy behavior: aliases and default rules win over the
          # naming check, and a missing target is returned as-is (the caller
          # gets a clear error on invocation).
          resolution.chain.last
        else
          # Preserve the regular resolution flow when there is no alias or
          # default rule.
          super
        end
      end

      # Runs the opt-in contract enforcement (no-op unless the policy includes
      # `Policy::Contract` and enforcement has been explicitly enabled).
      private def enforce_contract(activity, resolution)
        return unless self.class.respond_to?(:contract_enforced?)
        return unless self.class.contract_enforced?

        self.class.validate_rule_contract!(activity, resolution, resolution.target)
      end

      # Returns the full alias resolution chain for the given activity
      # without invoking any rules.
      #
      # Unlike `resolve_rule`, this method never raises on cycles and preserves
      # every intermediate alias, so it can be used to audit policy contracts:
      #
      #   PostPolicy.resolve_rule_chain(:publish?)
      #   #=> [:publish?, :update?]
      #
      # The last element is the activity that would actually be applied: either
      # a concrete rule, an alias target or the default rule. If nothing
      # matches, the chain contains only the activity itself.
      def resolve_rule_chain(activity)
        self.class.resolve_rule_chain(activity)
      end

      private def check_rule_naming(activity)
        unless activity[-1] == "?"
          raise NonPredicateRule.new(self, activity)
        end
        nil
      end

      module ClassMethods # :nodoc:
        def default_rule(val)
          rules_aliases[DEFAULT] = val
        end

        def alias_rule(*rules, to:)
          rules.each do |rule|
            rules_aliases[rule] = to
          end
        end

        def lookup_alias(rule) = rules_aliases[rule]

        def lookup_default_rule() = rules_aliases[DEFAULT]

        # Returns a `RuleResolution` for the activity (see `#resolve_rule_chain`).
        def resolve_rule_resolution(activity)
          RuleResolution.call(self, activity)
        end

        def resolve_rule_chain(activity)
          resolve_rule_resolution(activity).chain
        end

        # Returns the rules alias registry (including the default rule under
        # the `DEFAULT` key) without copying or normalizing it.
        #
        # This is the low-level entry used by `ActionPolicy::Policy::Contract`;
        # prefer the contract API when you need to inspect resolution results.
        def rules_aliases
          return @rules_aliases if instance_variable_defined?(:@rules_aliases)

          @rules_aliases = if superclass.respond_to?(:rules_aliases)
            superclass.rules_aliases.dup
          else
            {}
          end
        end

        def method_added(name)
          rules_aliases.delete(name) if public_method_defined?(name)
        end
      end
    end
  end
end
