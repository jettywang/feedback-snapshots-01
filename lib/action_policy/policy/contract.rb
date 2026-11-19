# frozen_string_literal: true

require "action_policy/policy/rule_resolution"

module ActionPolicy
  # Raised by `ActionPolicy::Policy::Contract.validate!` when a policy contract
  # has violations.
  #
  # The error keeps the policy class and the full report, so callers can
  # locate both the policy and the exact rule(s) that failed.
  class PolicyContractError < (defined?(ActionPolicy::Error) ? ActionPolicy::Error : StandardError)
    attr_reader :policy, :report

    def initialize(report)
      @report = report
      @policy = report.policy

      super(format(
        "%s has policy contract violations:\n%s",
        report.policy_name,
        report.violations.map { |violation| "  - #{violation.message}" }.join("\n")
      ))
    end

    def violations = report.violations
  end

  module Policy
    # Opt-in policy contract inspection.
    #
    # Policy contracts answer a question that regular rule resolution cannot:
    # *where* would an action end up? This is especially useful while renaming
    # actions: old names may stay as aliases, aliases may be chained, and an
    # action mistakenly not registered anywhere silently falls back to the
    # +default_rule+.
    #
    #   class PostPolicy < ActionPolicy::Base
    #     alias_rule :publish?, :unpublish?, to: :update?
    #
    #     # Sensitive actions must resolve to a real rule (directly or through
    #     # aliases); falling back to the default rule is a contract violation.
    #     sensitive_rule :destroy?, :publish?
    #   end
    #
    #   report = PostPolicy.contract
    #   report.valid? #=> false
    #   report.violations
    #   #=> [#<ActionPolicy::Policy::Contract::Violation ...>]
    #
    #   report.resolve(:publish?) #=> :update?
    #   report.resolve(:archive?) #=> :manage? (default fallback)
    #
    # The contract check is purely inspectable: including this module does not
    # change +resolve_rule+ or any other existing entry point. Use
    # +validate_contract!+ (or +ActionPolicy::Policy::Contract.validate!+) when
    # you want to fail fast at boot/test time.
    module Contract
      class << self
        def included(base)
          base.extend ClassMethods
        end

        # Builds a report for a policy class (or a policy instance).
        def check(policy)
          Checker.new(policy).report
        end
        alias audit check
        alias report check
        alias verify check
        alias call check
        alias for check

        # Builds a report and raises `ActionPolicy::PolicyContractError` when
        # the contract is not valid.
        def validate!(policy)
          report = check(policy)
          raise PolicyContractError, report unless report.valid?
          report
        end
        alias validate validate!
        alias check! validate!
        alias verify! validate!

        def valid?(policy) = check(policy).valid?
        def violations(policy) = check(policy).violations
        def aliases(policy) = check(policy).aliases
        def resolve(policy, rule) = check(policy).resolve(rule)

        # Returns the violation for a single resolution entry, if any.
        def violation_for(entry)
          if entry.cycle?
            Violation.new(:cycle, entry)
          elsif entry.too_long?
            Violation.new(:chain_too_long, entry)
          elsif entry.missing?
            if entry.sensitive?
              Violation.new(:missing_sensitive_target, entry)
            elsif entry.alias?
              Violation.new(:missing_alias_target, entry)
            end
          elsif entry.sensitive? && entry.fallback?
            Violation.new(:sensitive_default_fallback, entry)
          end
        end

        def new(policy)
          Checker.new(policy)
        end
      end

      # The contract configuration for a single policy class.
      class Config
        def initialize(sensitive_rules = [])
          @sensitive_rules = sensitive_rules
        end

        # Marks the provided rules as sensitive.
        def sensitive(*rules)
          rules.flatten.each do |rule|
            @sensitive_rules << rule.to_sym unless @sensitive_rules.include?(rule.to_sym)
          end
          self
        end
        alias sensitive_rule sensitive
        alias register_sensitive_rule sensitive

        # A convenient block-friendly alias:
        #
        #   contract do
        #     rule :destroy?, sensitive: true
        #   end
        def rule(*rules, sensitive: true)
          self.sensitive(*rules) if sensitive
          self
        end

        def sensitive_rules = @sensitive_rules.dup

        def initialize_copy(other)
          super
          @sensitive_rules = other.sensitive_rules
        end
      end

      # A single resolution entry (a queried action and its final destination).
      class Entry
        attr_reader :rule, :policy, :chain, :status, :target, :policy_class

        def initialize(policy:, rule:, chain:, status:, target:, sensitive:, alias_used:, default_used:)
          @policy = policy
          @policy_class = policy
          @rule = rule
          @chain = chain.freeze
          @status = status
          @target = target
          @sensitive = sensitive
          @alias_used = alias_used
          @default_used = default_used
        end

        def sensitive? = @sensitive

        # True when the action went through at least one alias.
        def alias? = @alias_used

        # True when the action ended up using the default rule.
        def fallback? = status == :default

        def cycle? = status == :cycle

        def too_long? = status == :too_long

        def missing? = status == :missing

        # True when a real rule (or alias target) was resolved.
        def resolved? = !target.nil?

        # The rule that will actually be called, or nil when unresolved.
        def resolved_rule = target

        def policy_name
          policy.name || policy.inspect
        end

        def to_h
          {
            rule: rule,
            policy: policy,
            chain: chain,
            status: status,
            target: target,
            sensitive: sensitive?,
            alias: alias?,
            fallback: fallback?,
            cycle: cycle?,
            resolved: resolved?
          }
        end

        def inspect
          "#<#{self.class} policy=#{policy_name} rule=#{rule.inspect} " \
            "chain=#{chain.inspect} status=#{status.inspect}>"
        end
      end

      # A contract violation. Carries the policy class, rule and resolution
      # chain so that error output can always be traced back to the policy.
      class Violation
        TYPES = {
          cycle: "circular alias reference",
          chain_too_long: "alias chain exceeds the safety limit",
          missing_alias_target: "alias points to a rule that does not exist",
          missing_sensitive_target: "sensitive rule does not resolve to a rule",
          sensitive_default_fallback: "sensitive rule falls back to the default rule"
        }.freeze

        attr_reader :type, :policy, :rule, :chain, :target, :entry, :policy_class

        def initialize(type, entry)
          @type = type
          @entry = entry
          @policy = entry.policy
          @policy_class = entry.policy
          @rule = entry.rule
          @chain = entry.chain
          @target = entry.target
        end

        def message
          prefix = "#{entry.policy_name}##{rule}"

          case type
          when :cycle
            "#{prefix}: circular alias reference (#{chain.map(&:inspect).join(" -> ")})"
          when :chain_too_long
            "#{prefix}: alias chain exceeds the safety limit " \
              "(#{chain.length} entries)"
          when :missing_alias_target
            "#{prefix}: alias points to an undefined rule " \
              "(#{chain.map(&:inspect).join(" -> ")})"
          when :missing_sensitive_target
            "#{prefix}: sensitive rule does not resolve to a rule " \
              "(#{chain.map(&:inspect).join(" -> ")})"
          when :sensitive_default_fallback
            "#{prefix}: sensitive rule falls back to the default rule " \
              "#{target.inspect} (#{chain.map(&:inspect).join(" -> ")})"
          else
            "#{prefix}: #{TYPES.fetch(type, type.to_s.tr("_", " "))}"
          end
        end
        alias to_s message

        def to_h
          {type: type, policy: policy, rule: rule, chain: chain, target: target, message: message}
        end

        def inspect
          "#<#{self.class} type=#{type.inspect} policy=#{entry.policy_name} " \
            "rule=#{rule.inspect} message=#{message.inspect}>"
        end
      end

      # A complete contract report for a policy class.
      class Report
        include Enumerable

        attr_reader :policy, :policy_class, :entries, :violations

        def initialize(policy, entries, violations, default_rule: nil, sensitive_rules: [])
          @policy = policy
          @policy_class = policy
          @entries = entries.freeze
          @violations = violations.freeze
          @default_rule = default_rule
          @sensitive_rules = sensitive_rules.freeze
          @lookup = entries.each_with_object({}) { |entry, acc| acc[entry.rule] = entry }
        end

        def each(&block) = entries.each(&block)

        def valid? = violations.empty?
        alias success? valid?
        alias ok? valid?

        # Actions that have at least one violation.
        def invalid_rules = violations.map(&:rule).uniq

        # Returns the resolution entry for an action. Actions not included in
        # the report are resolved on demand, so ad-hoc lookups still work.
        def entry(rule)
          key = rule.to_sym
          @lookup[key] ||= policy.resolve_rule_contract(key)
        end
        alias [] entry
        alias rule_for entry

        # Returns the rule that would actually be called.
        def resolve(rule) = entry(rule)&.target
        alias resolved_rule resolve

        def alias?(rule) = !!entry(rule)&.alias?
        def fallback?(rule) = !!entry(rule)&.fallback?
        def cycle?(rule) = !!entry(rule)&.cycle?
        def missing?(rule) = !!entry(rule)&.missing?
        def sensitive?(rule) = !!entry(rule)&.sensitive?

        # The status for an action: :rule, :alias, :default, :missing, :cycle,
        # or :too_long (when the chain exceeds the safety limit).
        def status(rule) = entry(rule)&.status

        # The complete resolution chain for an action.
        def chain(rule) = entry(rule)&.chain

        # A rule => final target map for all resolved aliases.
        def aliases
          entries.select { |entry| entry.alias? && entry.resolved? }.each_with_object({}) do |entry, acc|
            acc[entry.rule] = entry.target
          end
        end
        alias alias_map aliases
        alias rule_aliases aliases

        # Actions that ended up in the default rule (including those that are
        # intentionally aliased to it).
        def fallbacks
          entries.select(&:fallback?)
        end
        alias defaulted fallbacks

        # Actions whose aliases form a cycle.
        def cycles
          entries.select(&:cycle?)
        end

        # Actions whose alias chains exceed the safety limit.
        def too_long
          entries.select(&:too_long?)
        end

        # True when the given action falls through to the default rule.
        def default_fallback?(rule) = fallback?(rule)

        def default_rule = @default_rule
        def sensitive_rules = @sensitive_rules

        def policy_name = policy.name || policy.inspect

        def rules = entries

        def to_h
          {
            policy: policy,
            default_rule: default_rule,
            sensitive_rules: sensitive_rules,
            rules: entries.map(&:to_h),
            violations: violations.map(&:to_h),
            valid: valid?
          }
        end

        def inspect
          "#<#{self.class} policy=#{policy_name} valid=#{valid?} " \
            "violations=#{violations.size}>"
        end
      end

      # Performs the actual resolution and report building. It never mutates
      # the policy and never calls a rule.
      class Checker
        attr_reader :policy

        def initialize(policy)
          @policy =
            if policy.is_a?(Module)
              policy
            else
              policy.class
            end

          validate_policy!
        end

        def report
          entries = actions.map { |rule| build_entry(rule) }
          violations = entries.flat_map { |entry| violations_for(entry) }

          Report.new(
            policy,
            entries,
            violations,
            default_rule: policy.lookup_default_rule,
            sensitive_rules: sensitive_rules
          )
        end
        alias call report
        alias check report

        private

        def validate_policy!
          return if policy.respond_to?(:rules_aliases) && policy.respond_to?(:lookup_default_rule)

          raise ArgumentError,
            "#{policy} must include ActionPolicy::Policy::Aliases to be contract-checked"
        end

        def sensitive_rules
          return policy.sensitive_rules if policy.respond_to?(:sensitive_rules)

          []
        end

        def actions
          rules = []
          rules.concat(sensitive_rules)
          rules.concat(policy.rules_aliases.keys.reject { |rule| rule == Aliases::DEFAULT })
          rules.concat(policy_rule_methods)

          rules.map(&:to_sym).uniq
        end

        def policy_rule_methods
          (policy.public_instance_methods - Object.public_instance_methods)
            .select { |name| name.to_s.end_with?("?") }
            .reject { |name| action_policy_helper?(name) }
        end

        # Excludes helper predicates provided by Action Policy core/behaviour
        # modules (e.g. `check?`); rules defined by policy classes and rule
        # modules (including `ActionPolicy::Policy::Defaults`) are kept.
        def action_policy_helper?(name)
          owner = policy.instance_method(name).owner
          return false unless owner.is_a?(Module) && !owner.is_a?(Class)

          owner_name = owner.name.to_s
          owner_name == "ActionPolicy::Policy::Core" ||
            owner_name.start_with?("ActionPolicy::Behaviours") ||
            owner_name == "ActionPolicy::Policy::Aliases" ||
            owner_name == "ActionPolicy::Policy::Authorization" ||
            owner_name == "ActionPolicy::Policy::Reasons"
        rescue NameError
          false
        end

        def build_entry(rule)
          policy.resolve_rule_contract(rule)
        end

        def violations_for(entry)
          violation = Contract.violation_for(entry)
          violation ? [violation] : []
        end
      end

      # Class-level API for policy classes including `Contract`.
      module ClassMethods # :nodoc:
        # Marks rules as sensitive. Sensitive rules must resolve to a concrete
        # rule (either directly or through an alias chain).
        def sensitive_rule(*rules)
          contract_config.sensitive(*rules)
          self
        end
        alias sensitive sensitive_rule
        alias register_sensitive_rule sensitive_rule

        # Returns sensitive rules, or marks rules as sensitive when arguments
        # are provided (so both `sensitive_rules` and `sensitive_rules :foo?`
        # work).
        def sensitive_rules(*rules)
          return contract_config.sensitive_rules if rules.empty?

          sensitive_rule(*rules)
        end

        # Returns a contract report. A block is used to configure the contract:
        #
        #   contract do
        #     sensitive :destroy?
        #   end
        def contract(&block)
          if block
            contract_config.instance_eval(&block)
            self
          else
            Contract.check(self)
          end
        end

        def policy_contract(&block) = contract(&block)
        alias contract_report contract
        alias check_contract contract

        def validate_contract!
          Contract.validate!(self)
        end

        # Enables runtime contract enforcement for this policy class (and its
        # subclasses): resolving a sensitive rule that falls back to the default
        # rule raises `ActionPolicy::PolicyContractError`.
        def enforce_contracts!(value = true)
          @contract_enforced = value
          self
        end
        alias enforce_contract! enforce_contracts!
        alias enforce_policy_contracts! enforce_contracts!

        def enforce_contracts?
          return @contract_enforced if instance_variable_defined?(:@contract_enforced)

          superclass.respond_to?(:enforce_contracts?) && superclass.enforce_contracts?
        end
        alias enforce_contract? enforce_contracts?

        def contract_enforced?
          ActionPolicy.enforce_policy_contracts == true || enforce_contracts?
        end

        # Runtime check used by `Aliases#resolve_rule`; only sensitive rules
        # (and broken alias targets) are enforced to keep regular resolution
        # unaffected when enforcement is disabled.
        def validate_rule_contract!(activity, resolution, _target)
          entry = Entry.new(
            policy: self,
            rule: activity,
            chain: resolution.chain,
            status: resolution.status,
            target: resolution.target,
            sensitive: sensitive_rules.include?(activity.to_sym),
            alias_used: resolution.alias_used?,
            default_used: resolution.default_used?
          )

          violation = Contract.violation_for(entry)
          return if violation.nil?

          report = Report.new(
            self,
            [entry],
            [violation],
            default_rule: lookup_default_rule,
            sensitive_rules: sensitive_rules
          )
          raise PolicyContractError, report
        end

        # Returns the resolution report for a single action (useful for
        # ad-hoc audits without building a full report).
        def resolve_rule_contract(activity)
          build_contract_entry(activity)
        end

        private def build_contract_entry(activity)
          resolution = resolve_rule_resolution(activity)

          Entry.new(
            policy: self,
            rule: activity,
            chain: resolution.chain,
            status: resolution.status,
            target: resolution.target,
            sensitive: sensitive_rules.include?(activity.to_sym),
            alias_used: resolution.alias_used?,
            default_used: resolution.default_used?
          )
        end

        def contract_config
          return @contract_config if instance_variable_defined?(:@contract_config)

          @contract_config = if superclass.respond_to?(:contract_config)
            superclass.contract_config.dup
          else
            Config.new
          end
        end
      end

      # Instance-level convenience API (configuration is class-level).
      def contract = self.class.contract
      def policy_contract = self.class.contract
      def check_contract = self.class.contract
      def validate_contract! = self.class.validate_contract!
      def sensitive_rules = self.class.sensitive_rules
      def resolve_rule_contract(activity) = self.class.resolve_rule_contract(activity)
    end

    # A shorter, top-level alias for the contract error.
    ContractError = ActionPolicy::PolicyContractError
    Contract::Error = ActionPolicy::PolicyContractError
    Contract::ViolationError = ActionPolicy::PolicyContractError
  end
end
