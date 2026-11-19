# frozen_string_literal: true

require "test_helper"

class TestPolicyContract < Minitest::Test
  # The first policy models a batched rename: old approval action names stay
  # available as aliases, and aliases are chained to the new implementation.
  class ApprovalPolicy
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Aliases
    include ActionPolicy::Policy::Contract

    default_rule :manage?

    alias_rule :approve?, :publish?, to: :accept?
    alias_rule :accept?, to: :update?

    sensitive_rule :publish?, :destroy?, :revoke?

    def update? = true
    def manage? = true
    def index? = true
  end

  # A second, independent policy verifies cycles and a sensitive action that is
  # not registered anywhere (so it falls through to the default rule).
  class LegacyPolicy
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Aliases
    include ActionPolicy::Policy::Contract

    default_rule :manage?

    alias_rule :archive?, to: :remove?
    alias_rule :remove?, :purge?, to: :archive?

    sensitive_rule :archive?, :transfer?

    def manage? = true
  end

  def test_chained_aliases_resolve_to_the_final_rule
    report = ApprovalPolicy.contract

    assert_equal :update?, report.resolve(:approve?)
    assert_equal :update?, report.resolve(:publish?)
    assert_equal :update?, report.resolve(:accept?)
    assert_equal [:publish?, :accept?, :update?], report.entry(:publish?).chain
    assert report.alias?(:publish?)
    refute report.cycle?(:publish?)
  end

  def test_aliases_map_contains_only_resolved_chains
    report = ApprovalPolicy.contract

    assert_equal :update?, report.aliases[:publish?]
    assert_equal :update?, report.aliases[:approve?]
    assert_equal :update?, report.aliases[:accept?]
  end

  def test_sensitive_rule_falling_back_to_default_is_a_violation
    report = ApprovalPolicy.contract

    refute report.valid?
    violation = report.violations.find { |v| v.rule == :destroy? }

    refute_nil violation
    assert_equal :sensitive_default_fallback, violation.type
    assert_equal ApprovalPolicy, violation.policy
    assert_equal :manage?, report.resolve(:destroy?)
    assert report.fallback?(:destroy?)
    assert_includes violation.message, "ApprovalPolicy"
    assert_includes violation.message, "destroy?"
    assert_includes violation.message, "manage?"
  end

  def test_sensitive_rule_reaching_a_real_rule_is_valid
    report = ApprovalPolicy.contract

    assert report.sensitive?(:publish?)
    assert_equal :update?, report.resolve(:publish?)
    refute report.fallback?(:publish?)
    refute report.violations.any? { |v| v.rule == :publish? }
  end

  def test_missing_sensitive_rule_is_reported_with_policy_context
    policy_class = Class.new do
      include ActionPolicy::Policy::Core
      include ActionPolicy::Policy::Aliases
      include ActionPolicy::Policy::Contract

      default_rule nil
      sensitive_rule :revoke?

      def manage? = true
    end

    report = policy_class.contract
    violation = report.violations.find { |v| v.rule == :revoke? }

    refute_nil violation
    assert_equal :missing_sensitive_target, violation.type
    assert_equal policy_class, violation.policy_class
    assert_nil violation.policy.name
  end

  def test_cycles_do_not_hang_and_are_reported
    report = LegacyPolicy.contract

    assert report.cycle?(:archive?)
    assert report.cycle?(:remove?)
    assert_empty report.aliases.keys & [:archive?, :remove?, :purge?]
    assert_equal 3, report.violations.count { |v| v.type == :cycle }
    assert_equal [:archive?, :remove?, :archive?], report.entry(:archive?).chain
  end

  def test_sensitive_action_falling_to_default_in_second_policy
    report = LegacyPolicy.contract
    violation = report.violations.find { |v| v.rule == :transfer? }

    refute_nil violation
    assert_equal :sensitive_default_fallback, violation.type
    assert_equal LegacyPolicy, violation.policy
    assert_equal :manage?, report.resolve(:transfer?)
  end

  def test_report_serializes_policy_and_rules
    hash = ApprovalPolicy.contract.to_h

    assert_equal ApprovalPolicy, hash[:policy]
    assert_equal :manage?, hash[:default_rule]
    assert_includes hash[:sensitive_rules], :publish?
    refute hash[:valid]
    assert hash[:violations].all? { |violation| violation[:policy] == ApprovalPolicy }
  end

  def test_validate_contract_raises_a_located_error
    error = assert_raises(ActionPolicy::PolicyContractError) do
      ApprovalPolicy.validate_contract!
    end

    assert_equal ApprovalPolicy, error.policy
    assert_equal ApprovalPolicy, error.report.policy
    assert_includes error.message, "ApprovalPolicy#destroy?"
    assert_includes error.message, "ApprovalPolicy#revoke?"
  end

  def test_validate_contract_returns_report_when_valid
    policy = Class.new do
      include ActionPolicy::Policy::Core
      include ActionPolicy::Policy::Aliases
      include ActionPolicy::Policy::Contract

      default_rule :manage?
      sensitive_rule :update?

      def update? = true
      def manage? = true
    end

    report = policy.validate_contract!

    assert report.valid?
    assert_empty report.violations
  end

  def test_contract_check_can_be_used_with_an_instance
    policy = ApprovalPolicy.new

    assert_equal :update?, policy.contract.resolve(:publish?)
    assert policy.check_contract.violations.any? { |v| v.rule == :destroy? }
  end

  def test_resolve_rule_chain_does_not_change_runtime_resolution_when_checks_are_disabled
    assert_equal :manage?, ApprovalPolicy.new.resolve_rule(:destroy?)
    assert_equal :update?, ApprovalPolicy.new.resolve_rule(:publish?)
    assert_equal [:publish?, :accept?, :update?], ApprovalPolicy.new.resolve_rule_chain(:publish?)
  end

  def test_enforcement_rejects_sensitive_default_fallback_at_resolution_time
    policy_class = Class.new do
      include ActionPolicy::Policy::Core
      include ActionPolicy::Policy::Aliases
      include ActionPolicy::Policy::Contract

      default_rule :manage?
      sensitive_rule :destroy?

      def manage? = true
    end

    policy_class.enforce_contracts!

    assert_raises(ActionPolicy::PolicyContractError) do
      policy_class.new.resolve_rule(:destroy?)
    end

    # Non-sensitive actions still fall back to the default rule.
    assert_equal :manage?, policy_class.new.resolve_rule(:archive?)
  end

  def test_global_enforcement_flag
    policy_class = Class.new do
      include ActionPolicy::Policy::Core
      include ActionPolicy::Policy::Aliases
      include ActionPolicy::Policy::Contract

      default_rule :manage?
      sensitive_rule :destroy?

      def manage? = true
    end

    ActionPolicy.enforce_policy_contracts = true

    assert_raises(ActionPolicy::PolicyContractError) do
      policy_class.new.resolve_rule(:destroy?)
    end
  ensure
    ActionPolicy.enforce_policy_contracts = false
  end

  def test_enforce_predicate_rules_naming_still_applies_without_contracts
    policy_class = Class.new do
      include ActionPolicy::Policy::Core
      include ActionPolicy::Policy::Aliases

      default_rule nil
      def manage? = true
    end

    ActionPolicy.enforce_predicate_rules_naming = true

    assert_raises(ActionPolicy::NonPredicateRule) do
      policy_class.new.resolve_rule(:unknown)
    end
  ensure
    ActionPolicy.enforce_predicate_rules_naming = false
  end
end
