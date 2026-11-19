# frozen_string_literal: true

require "test_helper"

# A long-lived worker thread processes approval tasks for different users one
# after another. These tests verify that an authorization context can be
# bounded by an explicit scope: policies built inside the scope are re-used
# within it but cannot leak to subsequent users or other threads, even on
# errors or nested calls.
class TestPerThreadCacheScope < Minitest::Test
  class WorkerUser
    attr_reader :id

    def initialize(id) = (@id = id)

    def policy_cache_key = "worker-user/#{id}"

    def policy_class = ScopedApprovalPolicy
  end

  class ScopedApprovalPolicy < ActionPolicy::Base
    class << self
      def builds
        @builds ||= []
      end

      def reset!
        @builds = []
      end
    end

    def initialize(record = nil, **params)
      super
      self.class.builds << [user.id, record.id]
    end

    def approve? = true
  end

  # A stand-in for a long-lived worker object that serves many users on the
  # same thread. Every task is wrapped in an explicit authorization scope.
  class ApprovalWorker
    include ActionPolicy::Behaviour
    include ActionPolicy::Behaviours::ThreadMemoized

    authorize :user, through: :current_user

    attr_accessor :current_user

    def run(user, record, times: 1)
      ActionPolicy::PerThreadCache.with_cache do
        # A new task means a new authorization context; drop the per-instance
        # memoization so the thread store is keyed by the current user.
        @_authorization_context = nil
        self.current_user = user
        times.times { allowed_to?(:approve?, record) }
      end
    end
  end

  def setup
    ScopedApprovalPolicy.reset!
    ActionPolicy::PerThreadCache.enabled = true
  end

  def teardown
    ActionPolicy::PerThreadCache.clear_all
    ActionPolicy::PerThreadCache.enabled = false
    ScopedApprovalPolicy.reset!
  end

  def test_scope_reuses_policy_within_a_single_task
    worker = ApprovalWorker.new
    alice = WorkerUser.new("alice")
    record = WorkerUser.new("doc-1")

    worker.run(alice, record, times: 3)

    # One build for the record, re-used for every authorization in the task
    assert_equal [["alice", "doc-1"]], ScopedApprovalPolicy.builds
  end

  def test_two_users_on_the_same_thread_do_not_share_a_context
    worker = ApprovalWorker.new
    alice = WorkerUser.new("alice")
    bob = WorkerUser.new("bob")
    record = WorkerUser.new("doc-1")

    worker.run(alice, record)
    worker.run(bob, record)
    # Re-running the first user's task must not revive the discarded context
    worker.run(alice, record)

    assert_equal(
      [
        ["alice", "doc-1"],
        ["bob", "doc-1"],
        ["alice", "doc-1"]
      ],
      ScopedApprovalPolicy.builds
    )
  end

  def test_another_thread_runs_in_parallel_without_reusing_the_context
    alice_worker = ApprovalWorker.new
    bob_worker = ApprovalWorker.new
    alice = WorkerUser.new("alice")
    bob = WorkerUser.new("bob")
    record = WorkerUser.new("doc-1")

    gate = Queue.new
    build_lock = Mutex.new

    threads = [
      Thread.new do
        alice_worker.current_user = alice
        ActionPolicy::PerThreadCache.with_cache do
          gate.pop
          alice_worker.allowed_to?(:approve?, record)
          alice_worker.allowed_to?(:approve?, record)
        end
      end,
      Thread.new do
        bob_worker.current_user = bob
        ActionPolicy::PerThreadCache.with_cache do
          gate.pop
          build_lock.synchronize { bob_worker.allowed_to?(:approve?, record) }
        end
      end
    ]

    # Release both scopes at once so they overlap on different threads.
    2.times { gate.push(:go) }
    threads.map(&:join)

    owners = ScopedApprovalPolicy.builds.map(&:first).sort
    assert_equal %w[alice bob], owners
    # Alice reused her policy inside her own scope; Bob got an independent one.
    assert_equal 2, ScopedApprovalPolicy.builds.size
  end

  def test_context_is_reclaimed_when_the_task_raises
    worker = ApprovalWorker.new
    alice = WorkerUser.new("alice")
    record = WorkerUser.new("doc-1")

    assert_raises(RuntimeError) do
      ActionPolicy::PerThreadCache.with_cache do
        worker.current_user = alice
        worker.allowed_to?(:approve?, record)
        raise "boom"
      end
    end

    # A later task on the same thread starts from an empty store.
    worker.run(alice, record)

    assert_equal(
      [
        ["alice", "doc-1"],
        ["alice", "doc-1"]
      ],
      ScopedApprovalPolicy.builds
    )

    # On a pristine thread the top-level scope restores nil rather than
    # leaving the failed scope's store behind.
    Thread.current[ActionPolicy::PerThreadCache::CACHE_KEY] = nil
    ActionPolicy::PerThreadCache.with_cache { :ok }
    assert_nil Thread.current[ActionPolicy::PerThreadCache::CACHE_KEY]
  end

  def test_nested_scopes_restore_the_outer_context
    outer_record = WorkerUser.new("doc-outer")
    inner_record = WorkerUser.new("doc-inner")
    worker = ApprovalWorker.new
    alice = WorkerUser.new("alice")
    worker.current_user = alice

    ActionPolicy::PerThreadCache.with_cache do
      worker.allowed_to?(:approve?, outer_record)

      ActionPolicy::PerThreadCache.with_cache do
        worker.allowed_to?(:approve?, inner_record)
        worker.allowed_to?(:approve?, inner_record)
      end

      # The inner scope is gone: the outer policy must still be cached,
      # while the inner record has to be built again.
      worker.allowed_to?(:approve?, outer_record)
      worker.allowed_to?(:approve?, inner_record)
    end

    assert_equal(
      [
        ["alice", "doc-outer"],
        ["alice", "doc-inner"],
        ["alice", "doc-inner"]
      ],
      ScopedApprovalPolicy.builds
    )
  end

  def test_scope_returns_the_block_result
    result = ActionPolicy::PerThreadCache.with_cache { :done }

    assert_equal :done, result
  end

  def test_scope_is_a_noop_when_cache_is_disabled
    ActionPolicy::PerThreadCache.enabled = false
    Thread.current[ActionPolicy::PerThreadCache::CACHE_KEY] = nil

    builds = 0
    ActionPolicy::PerThreadCache.with_cache do
      ActionPolicy::PerThreadCache.fetch("k") { builds += 1 }
      ActionPolicy::PerThreadCache.fetch("k") { builds += 1 }
    end

    # Without caching the block runs every time and no store is created.
    assert_equal 2, builds
    assert_nil Thread.current[ActionPolicy::PerThreadCache::CACHE_KEY]
  end
end
