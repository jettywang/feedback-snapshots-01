# frozen_string_literal: true

require "test_helper"

require "stubs/in_memory_cache"

class TestCache < Minitest::Test
  class TestPolicy
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Authorization
    include ActionPolicy::Policy::Reasons
    include ActionPolicy::Policy::Cache

    self.identifier = :test

    class << self
      attr_accessor :managed_count, :shown_count, :saved_count, :custom_count

      def reset
        @managed_count = 0
        @shown_count = 0
        @saved_count = 0
        @custom_count = 0
      end
    end

    reset

    authorize :user

    cache :manage?, :save?

    def manage?
      self.class.managed_count += 1

      user.admin? && !record.admin?
    end

    def show?
      self.class.shown_count += 1

      user.admin? || !record.admin?
    end

    def save?
      self.class.saved_count += 1
      allowed_to?(:manage?)
    end

    def create?
      cache(user, record, :custom) do
        self.class.custom_count += 1
        true
      end
    end
  end

  class MultipleContextPolicy < TestPolicy
    reset

    authorize :account

    cache :show?
  end

  class CacheableUser < User
    def policy_class
      UserPolicy
    end

    def policy_cache_key
      "user/#{name}"
    end

    def admin?
      name.start_with?("admin")
    end
  end

  def setup
    ActionPolicy.cache_store = InMemoryCache.new
    @guest = CacheableUser.new("guest")
  end

  def teardown
    TestPolicy.reset
    MultipleContextPolicy.reset
    ActionPolicy.cache_store = nil
  end

  attr_reader :guest

  def test_cache
    user = CacheableUser.new("admin")

    policy = TestPolicy.new guest, user: user

    assert policy.apply(:manage?)
    assert policy.apply(:manage?)
    assert policy.apply(:show?)
    assert policy.apply(:show?)

    assert_equal 1, TestPolicy.managed_count
    assert_equal 2, TestPolicy.shown_count

    policy_2 = TestPolicy.new guest, user: user

    assert policy_2.apply(:manage?)
    assert policy_2.apply(:show?)

    assert_equal 1, TestPolicy.managed_count
    assert_equal 3, TestPolicy.shown_count
  end

  def test_custom_cache
    user = CacheableUser.new("guest")

    policy = TestPolicy.new nil, user: user

    assert policy.apply(:create?)
    assert policy.apply(:create?)

    assert_equal 1, TestPolicy.custom_count

    policy_2 = TestPolicy.new nil, user: user

    assert policy_2.apply(:create?)

    assert_equal 1, TestPolicy.custom_count
  end

  def test_cache_with_reasons
    user = CacheableUser.new("guest")

    policy = TestPolicy.new guest, user: user

    refute policy.apply(:save?)
    assert_equal({test: [:manage?]}, policy.result.reasons.details)

    policy = TestPolicy.new guest, user: user

    refute policy.apply(:save?)
    assert_equal({test: [:manage?]}, policy.result.reasons.details)

    assert_equal 1, TestPolicy.managed_count
    assert_equal 1, TestPolicy.saved_count
  end

  def test_cache_with_different_records
    user = CacheableUser.new("admin")

    policy = TestPolicy.new guest, user: user

    assert policy.apply(:manage?)

    assert_equal 1, TestPolicy.managed_count

    policy_2 = TestPolicy.new CacheableUser.new("guest_2"), user: user

    assert policy_2.apply(:manage?)
    assert_equal 2, TestPolicy.managed_count
  end

  def test_cache_with_different_contexts
    user = CacheableUser.new("admin")

    policy = TestPolicy.new guest, user: user

    assert policy.apply(:manage?)

    assert_equal 1, TestPolicy.managed_count

    policy_2 = TestPolicy.new guest, user: CacheableUser.new("admin_2")

    assert policy_2.apply(:manage?)
    assert_equal 2, TestPolicy.managed_count
  end

  def test_with_multiple_contexts
    user = CacheableUser.new("admin")

    policy = MultipleContextPolicy.new guest, user: user, account: "test"

    assert policy.apply(:manage?)
    assert policy.apply(:manage?)
    assert policy.apply(:show?)
    assert policy.apply(:show?)

    assert_equal 1, MultipleContextPolicy.managed_count
    assert_equal 1, MultipleContextPolicy.shown_count

    policy_2 = MultipleContextPolicy.new guest, user: CacheableUser.new("admin"), account: :test

    assert policy_2.apply(:manage?)
    assert policy_2.apply(:show?)

    assert_equal 1, MultipleContextPolicy.managed_count
    assert_equal 1, MultipleContextPolicy.shown_count
  end

  def test_with_different_multiple_contexts
    user = CacheableUser.new("admin")

    policy = MultipleContextPolicy.new guest, user: user, account: "test"

    assert policy.apply(:manage?)
    assert policy.apply(:manage?)

    assert_equal 1, MultipleContextPolicy.managed_count

    policy_2 = MultipleContextPolicy.new guest, user: CacheableUser.new("admin"), account: "test_2"

    assert policy_2.apply(:manage?)
    assert_equal 2, MultipleContextPolicy.managed_count
  end
end

class TestCacheContextState < Minitest::Test
  # Operator's temporary approval, passed as a part of the authorization
  # context. Its cache key reflects the approval state, so revoking the
  # approval invalidates cached rules without touching the record.
  class Approval
    attr_reader :state

    def initialize(state)
      @state = state
    end

    def approved?
      state == :approved
    end

    def policy_cache_key
      "approval/#{state}"
    end
  end

  class Operator
    attr_reader :name

    def initialize(name)
      @name = name
    end

    def policy_cache_key
      "operator/#{name}"
    end
  end

  class Document
    def policy_cache_key
      "document/1"
    end
  end

  class DocumentPolicy
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Authorization
    include ActionPolicy::Policy::Reasons
    include ActionPolicy::Policy::Cache

    self.identifier = :document

    class << self
      attr_accessor :managed_count

      def reset
        @managed_count = 0
      end
    end

    reset

    authorize :operator
    authorize :approval

    cache :manage?

    def manage?
      self.class.managed_count += 1
      deny!(:no_active_approval) unless approval.approved?
      true
    end
  end

  def setup
    ActionPolicy.cache_store = InMemoryCache.new
    @record = Document.new
    @operator = Operator.new("root")
  end

  def teardown
    DocumentPolicy.reset
    ActionPolicy.cache_store = nil
  end

  attr_reader :record, :operator

  def store = ActionPolicy.cache_store

  def build_policy(approval)
    DocumentPolicy.new(record, operator: operator, approval: approval)
  end

  def test_rule_cache_follows_authorization_context_state
    policy = build_policy(Approval.new(:approved))
    assert policy.apply(:manage?)
    assert_equal 1, DocumentPolicy.managed_count

    # actual cache calls: a miss followed by a write under the approved-state key
    assert_equal 1, store.reads.size
    assert_equal 1, store.writes.size
    approved_key = store.writes.last
    assert_includes approved_key, "approval/approved"

    # same conditions — the cached result is reused
    policy = build_policy(Approval.new(:approved))
    assert policy.apply(:manage?)
    assert_equal 1, DocumentPolicy.managed_count
    assert policy.result.cached?
    assert_equal approved_key, store.reads.last
    assert_equal 1, store.writes.size

    # revoke the approval; the record is completely unchanged
    policy = build_policy(Approval.new(:revoked))
    refute policy.apply(:manage?)
    assert_equal 2, DocumentPolicy.managed_count
    refute policy.result.cached?

    # a new cache entry is created; the keys only differ in the context state part
    assert_equal 2, store.writes.size
    revoked_key = store.writes.last
    assert_includes revoked_key, "approval/revoked"
    assert_equal approved_key.sub("approval/approved", ""), revoked_key.sub("approval/revoked", "")

    # the denial reason is available from the fresh evaluation
    assert_equal({document: [:no_active_approval]}, policy.result.reasons.details)

    # a new request under the same revoked state hits the cache
    # and still provides the denial reason
    policy = build_policy(Approval.new(:revoked))
    refute policy.apply(:manage?)
    assert_equal 2, DocumentPolicy.managed_count
    assert policy.result.cached?
    assert_equal revoked_key, store.reads.last
    assert_equal({document: [:no_active_approval]}, policy.result.reasons.details)
  end

  def test_non_cacheable_context_raises_clear_error
    policy = build_policy(Object.new)

    error = assert_raises(ArgumentError) { policy.apply(:manage?) }
    assert_includes error.message, ":approval"
    assert_includes error.message, "not cacheable"
  end
end
