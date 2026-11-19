# frozen_string_literal: true

require "test_helper"

# A workflow has an initiator, an approver, and at most one optional
# auto-committer. The initiator and the approver are identities that the policy
# requires from the trusted ingress; a policy rule must never be able to
# supply, replace, or inherit them from a previous authorization.
class TestTrustedWorkflowContext < Minitest::Test
  class Workflow
    attr_reader :name

    def initialize(name:)
      @name = name
    end

    def <=>(other) = name <=> other.name

    def cache_key = "workflow/#{name}"
  end

  class WorkflowBase
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Authorization
    include ActionPolicy::Policy::Reasons
    include ActionPolicy::Policy::CachedApply
    include ActionPolicy::Policy::Cache
  end

  class CommitPolicy < WorkflowBase
    self.identifier = :commit

    authorize :initiator, trusted: true
    authorize :approver, trusted: true
    authorize :committer, trusted: true, optional: true

    def commit?
      # Self-approval is not a valid approval decision.
      initiator != approver
    end
  end

  class WorkflowPolicy < WorkflowBase
    self.identifier = :workflow

    authorize :initiator, trusted: true
    authorize :approver, trusted: true
    authorize :committer, trusted: true, optional: true

    def approve?
      allowed_to?(:commit?, record, with: CommitPolicy, context: {
        initiator: initiator,
        approver: approver,
        committer: committer
      })
    end

    # Derived rules explicitly passing an identity to an inner policy.
    # Forwarding the trusted identity is valid; substituting it is not.
    def approve_as_trusted?
      allowed_to?(:commit?, record, with: CommitPolicy, context: {
        initiator: initiator,
        approver: approver,
        committer: committer
      })
    end

    def approve_as_interloper?
      allowed_to?(:commit?, record, with: CommitPolicy, context: {
        initiator: initiator,
        approver: "mallory",
        committer: committer
      })
    end

    def approve_as_nobody?
      allowed_to?(:commit?, record, with: CommitPolicy, context: {
        initiator: initiator,
        approver: nil,
        committer: committer
      })
    end
  end

  # The trusted ingress: only this object may provide the workflow identities.
  class ApprovalDesk
    include ActionPolicy::Behaviour
    include ActionPolicy::Behaviours::Memoized
    include ActionPolicy::Behaviours::ThreadMemoized

    authorize :initiator, through: :initiator
    authorize :approver, through: :approver
    authorize :committer, through: :committer

    attr_reader :initiator
    attr_accessor :approver, :committer

    def initialize(initiator: nil, approver: nil, committer: nil)
      @initiator = initiator
      @approver = approver
      @committer = committer
    end

    # A long-lived ingress processes different batches: do not memoize the
    # context across calls.
    def authorization_context = build_authorization_context
  end

  # An ingress that knows nothing about an approver: the key is absent
  # rather than explicitly nil.
  class InitiatorOnlyDesk < ApprovalDesk
    class << self
      def authorization_targets
        super.reject { |key, _| key == :approver }
      end
    end

    undef_method :approver
  end

  def setup
    ActionPolicy::PerThreadCache.enabled = true
    ActionPolicy.cache_store = InMemoryCache.new
  end

  def teardown
    ActionPolicy::PerThreadCache.clear_all
    ActionPolicy::PerThreadCache.enabled = false
    ActionPolicy::TrustedContext.clear!
    ActionPolicy.cache_store = nil
    CommitPolicy.cached_rules.clear
  end

  def test_initiator_only_cannot_stand_in_for_an_approver
    desk = InitiatorOnlyDesk.new(initiator: "alice")
    workflow = Workflow.new(name: "release")

    e = assert_raises ActionPolicy::AuthorizationContextMissing do
      desk.authorize! workflow, to: :approve?
    end

    assert_equal "Missing policy authorization context: approver", e.message
  end

  def test_absent_approver_fails_closed
    desk = ApprovalDesk.new(initiator: "alice", approver: nil)
    workflow = Workflow.new(name: "release")

    e = assert_raises ActionPolicy::AuthorizationContextMissing do
      desk.authorize! workflow, to: :approve?
    end

    assert_equal "Missing policy authorization context: approver", e.message
  end

  def test_missing_approver_is_not_reused_from_a_previous_batch
    workflow = Workflow.new(name: "release")
    desk = ApprovalDesk.new(initiator: "alice", approver: "bob")

    assert desk.authorize! workflow, to: :approve?

    # The same ingress (and, thus, the same policy class) later processes
    # another batch whose approver is absent.
    desk.approver = nil

    e = assert_raises ActionPolicy::AuthorizationContextMissing do
      desk.authorize! workflow, to: :approve?
    end

    assert_equal "Missing policy authorization context: approver", e.message
  end

  def test_inner_explicit_authorization_must_match_the_trusted_identity
    workflow = Workflow.new(name: "release")
    desk = ApprovalDesk.new(initiator: "alice", approver: "bob")

    policy = desk.policy_for(record: workflow, with: WorkflowPolicy)
    assert policy.apply(:approve?)

    # Explicitly forwarding the trusted identity is allowed.
    assert policy.apply(:approve_as_trusted?)

    # Explicitly substituting another approver must not be possible.
    e = assert_raises ActionPolicy::UntrustedAuthorizationContext do
      policy.apply(:approve_as_interloper?)
    end

    assert_includes e.message, "approver"
    assert_includes e.message, "trusted ingress"
  end

  def test_inner_rule_cannot_null_out_the_approver
    workflow = Workflow.new(name: "release")
    desk = ApprovalDesk.new(initiator: "alice", approver: "bob")

    policy = desk.policy_for(record: workflow, with: WorkflowPolicy)

    e = assert_raises ActionPolicy::UntrustedAuthorizationContext do
      policy.apply(:approve_as_nobody?)
    end

    assert_includes e.message, "approver"
  end

  def test_optional_committer_may_be_provided_at_most_once
    workflow = Workflow.new(name: "release")

    # No committer: the optional identity is absent and the decision is valid.
    assert ApprovalDesk.new(initiator: "alice", approver: "bob")
      .authorize! workflow, to: :approve?

    # One auto-committer acting for the assigned approver.
    assert ApprovalDesk.new(initiator: "alice", approver: "bob", committer: "carol")
      .authorize! workflow, to: :approve?
  end

  def test_same_policy_class_handles_the_next_batch
    workflow = Workflow.new(name: "release")
    desk = ApprovalDesk.new(initiator: "alice", approver: "bob")

    assert desk.authorize! workflow, to: :approve?

    first_policy = desk.policy_for(record: workflow, with: WorkflowPolicy)
    assert_equal({initiator: "alice", approver: "bob", committer: nil},
      first_policy.authorization_context)

    desk.approver = "dave"
    assert desk.authorize! workflow, to: :approve?

    second_policy = desk.policy_for(record: workflow, with: WorkflowPolicy)
    assert_equal({initiator: "alice", approver: "dave", committer: nil},
      second_policy.authorization_context)

    refute_same first_policy, second_policy

    # The first batch's identity is not reused by a batch without one.
    assert_raises ActionPolicy::AuthorizationContextMissing do
      ApprovalDesk.new(initiator: "alice", approver: nil)
        .authorize! workflow, to: :approve?
    end
  end

  def test_decisions_and_reasons_are_scoped_to_the_batch
    workflow = Workflow.new(name: "release")

    # Self-approval is denied by the inner policy, and the parent reports
    # the failure with the policy/rule that decided it.
    self_approved = ApprovalDesk.new(initiator: "alice", approver: "alice")

    e = assert_raises ActionPolicy::Unauthorized do
      self_approved.authorize! workflow, to: :approve?
    end

    assert_equal WorkflowPolicy, e.policy
    assert_equal :approve?, e.rule
    assert_equal({commit: [:commit?]}, e.result.reasons.details)

    # A later batch is decided independently: no stale reasons are carried over.
    valid = ApprovalDesk.new(initiator: "alice", approver: "bob")
    assert valid.authorize! workflow, to: :approve?

    policy = valid.policy_for(record: workflow, with: WorkflowPolicy)
    assert policy.apply(:approve?)
    assert policy.result.reasons.empty?
  end

  # A derived policy must not launder an identity it added itself and pass it
  # to a deeper policy that requires it to be trusted.
  class LaunderingPolicy < WorkflowBase
    self.identifier = :laundering

    authorize :initiator, trusted: true
    authorize :committer, trusted: true, optional: true

    def approve?
      allowed_to?(:commit?, record, with: CommitPolicy, context: {
        initiator: initiator,
        approver: "mallory",
        committer: committer
      })
    end
  end

  def test_derived_policy_cannot_launder_an_identity_for_a_deeper_policy
    workflow = Workflow.new(name: "release")
    desk = ApprovalDesk.new(initiator: "alice", approver: "bob")

    policy = desk.policy_for(record: workflow, with: LaunderingPolicy)
    assert_equal({initiator: "alice", approver: "bob", committer: nil},
      policy.action_policy_trusted_context)

    e = assert_raises ActionPolicy::UntrustedAuthorizationContext do
      policy.apply(:approve?)
    end

    assert_includes e.message, "approver"
  end

  def test_context_cache_key_distinguishes_absent_and_nil
    key = ->(context) { ActionPolicy::Utils::ContextCacheKey.call(context) }

    refute_equal key.call({initiator: "alice"}), key.call({initiator: "alice", approver: nil})
    refute_equal key.call({initiator: "alice", approver: "bob"}), key.call({initiator: "alice", approver: "dave"})
    assert_equal key.call({initiator: "alice", approver: "bob"}), key.call({approver: "bob", initiator: "alice"})
  end

  def test_rule_cache_is_scoped_to_the_trusted_batch
    CommitPolicy.cache :commit?
    workflow = Workflow.new(name: "release")

    # Two batches with the same initiator, different approvers.
    assert ApprovalDesk.new(initiator: "alice", approver: "bob")
      .authorize! workflow, to: :approve?

    assert ApprovalDesk.new(initiator: "alice", approver: "dave")
      .authorize! workflow, to: :approve?

    # A self-approval in the next batch must be re-evaluated, not served from
    # either cached approval.
    self_approved = ApprovalDesk.new(initiator: "alice", approver: "alice")

    assert_raises ActionPolicy::Unauthorized do
      self_approved.authorize! workflow, to: :approve?
    end
  end
end
