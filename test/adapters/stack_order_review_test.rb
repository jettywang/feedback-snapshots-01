require "test_helper"
require "flipper/adapters/dual_write"
require "flipper/adapters/failover"
require "flipper/adapters/failsafe"
require "flipper/adapters/instrumented"
require "flipper/adapters/read_only"
require_relative "../support/recording_memory"

# These tests pin down the adapter-contract behavior the deployment review
# depends on. They intentionally assert current behavior, including the
# fail-open cases, so the ordering decision is based on observations rather
# than assumptions.
class StackOrderReviewTest < Minitest::Test
  def feature(adapter, key = :pilot)
    Flipper.new(adapter, memoize: false)[key]
  end

  def operations(recording, kind)
    recording.public_send(kind).map(&:operation)
  end

  def stored_actors(recording, key = :pilot)
    adapter = recording.adapter
    adapter.get(Flipper::Feature.new(key, adapter))[:actors]
  end

  def test_failover_reads_the_secondary_but_never_writes_it_without_dual_write
    primary = RecordingMemory.new
    secondary = RecordingMemory.new
    secondary.seed { |flipper| flipper[:pilot].enable }

    stack = Flipper::Adapters::Failover.new(primary, secondary)
    subject = feature(stack)

    primary.down!
    assert_equal true, subject.enabled?
    assert_includes operations(secondary, :reads), :get

    assert_raises(IOError) { subject.enable }
    refute_includes operations(secondary, :writes), :add
    refute_includes operations(secondary, :writes), :enable
  end

  def test_failover_dual_write_updates_the_secondary_only_after_the_primary_succeeds
    primary = RecordingMemory.new
    secondary = RecordingMemory.new
    stack = Flipper::Adapters::Failover.new(primary, secondary, dual_write: true)
    subject = feature(stack)

    subject.enable
    assert_includes operations(primary, :writes), :enable
    assert_includes operations(secondary, :writes), :enable

    primary.reset!
    secondary.reset!
    primary.fail_operation(:add, IOError.new("primary add failed"))

    assert_raises(IOError) { subject.enable }
    assert_equal [], secondary.writes
  end

  def test_failsafe_inside_failover_hides_the_primary_error_from_failover
    primary = RecordingMemory.new
    secondary = RecordingMemory.new
    secondary.seed { |flipper| flipper[:pilot].enable }

    stack = Flipper::Adapters::Failover.new(
      Flipper::Adapters::Failsafe.new(primary),
      secondary
    )
    subject = feature(stack)
    primary.down!

    assert_equal false, subject.enabled?
    assert_equal [], secondary.reads
  end

  def test_failsafe_outside_failover_keeps_the_fallback_and_fails_closed_when_both_are_down
    primary = RecordingMemory.new
    secondary = RecordingMemory.new
    secondary.seed { |flipper| flipper[:pilot].enable }

    stack = Flipper::Adapters::Failsafe.new(
      Flipper::Adapters::Failover.new(primary, secondary)
    )
    subject = feature(stack)

    primary.down!
    assert_equal true, subject.enabled?
    assert_includes operations(secondary, :reads), :get

    secondary.down!
    assert_equal false, subject.enabled?
    assert_equal false, subject.enable
  end

  def test_no_available_source_raises_without_failsafe_and_returns_defaults_with_it
    stack = Flipper::Adapters::Failover.new(UnavailableMemory.new, UnavailableMemory.new)
    subject = feature(stack)

    assert_raises(IOError) { subject.enabled? }
    assert_raises(IOError) { subject.enable }

    guarded = feature(Flipper::Adapters::Failsafe.new(stack))
    assert_equal false, guarded.enabled?
    assert_equal false, guarded.enable
  end

  def test_actor_limit_reads_the_fallback_and_lets_a_new_actor_through_when_primary_reads_fail
    primary = RecordingMemory.new
    primary.seed_actors(:pilot, ["User;0", "User;1"])
    secondary = RecordingMemory.new
    primary.fail_operation(:get, IOError.new("primary get failed"))

    stack = Flipper::Adapters::ActorLimit.new(
      Flipper::Adapters::Failover.new(primary, secondary),
      2
    )
    subject = feature(stack)

    assert_equal true, subject.enable_actor(Flipper::Actor.new("User;2"))
    assert_equal Set["User;0", "User;1", "User;2"], stored_actors(primary)
  end

  def test_actor_limit_enforces_the_cap_when_the_fallback_holds_the_complete_roster
    primary = RecordingMemory.new
    primary.seed_actors(:pilot, ["User;0", "User;1"])
    secondary = RecordingMemory.new
    secondary.seed_actors(:pilot, ["User;0", "User;1"])
    primary.fail_operation(:get, IOError.new("primary get failed"))

    stack = Flipper::Adapters::ActorLimit.new(
      Flipper::Adapters::Failover.new(primary, secondary),
      2
    )
    subject = feature(stack)

    assert_raises(Flipper::Adapters::ActorLimit::LimitExceeded) do
      subject.enable_actor(Flipper::Actor.new("User;2"))
    end
    assert_equal Set["User;0", "User;1"], stored_actors(primary)
  end

  def test_actor_limit_reads_through_the_feature_adapter_not_its_wrapped_adapter
    primary = RecordingMemory.new
    primary.seed_actors(:pilot, ["User;0", "User;1"])
    secondary = RecordingMemory.new
    primary.fail_operation(:get, IOError.new("primary get failed"))

    # Moving the cap inside failover does not make it read the primary. The
    # feature passed to #enable is bound to the outer stack, so the cap reads
    # the same fallback the caller would see.
    stack = Flipper::Adapters::Failover.new(
      Flipper::Adapters::ActorLimit.new(primary, 2),
      secondary
    )
    subject = feature(stack)

    assert_equal true, subject.enable_actor(Flipper::Actor.new("User;2"))
    assert_equal Set["User;0", "User;1", "User;2"], stored_actors(primary)
  end

  def test_actor_limit_checks_the_primary_when_the_feature_is_bound_to_it
    primary = RecordingMemory.new
    primary.seed_actors(:pilot, ["User;0", "User;1"])

    limited = feature(Flipper::Adapters::ActorLimit.new(primary, 2))
    assert_raises(Flipper::Adapters::ActorLimit::LimitExceeded) do
      limited.enable_actor(Flipper::Actor.new("User;2"))
    end
  end

  def test_nil_actor_is_rejected_but_an_actor_with_a_nil_id_becomes_an_empty_slot
    adapter = RecordingMemory.new
    subject = feature(adapter)

    assert_raises(ArgumentError) { subject.enable_actor(nil) }
    assert_equal Set.new, subject.actors_value

    assert_equal true, subject.enable_actor(Flipper::Actor.new(nil))
    assert_equal Set[""], subject.actors_value
  end

  def test_actor_limit_counts_blank_actors_as_slots
    adapter = RecordingMemory.new
    subject = feature(adapter)

    assert_equal true, subject.enable_actor(Flipper::Actor.new(""))
    assert_equal true, subject.enable_actor(Flipper::Actor.new("   "))

    limited = feature(Flipper::Adapters::ActorLimit.new(adapter, 2))
    assert_equal Set["", "   "], limited.actors_value
    assert_raises(Flipper::Adapters::ActorLimit::LimitExceeded) do
      limited.enable_actor(Flipper::Actor.new("User;1"))
    end

    assert_equal true, limited.enable_actor(Flipper::Actor.new("   "))
    assert_equal Set["", "   "], stored_actors(adapter)
  end

  def test_invalid_roster_from_a_snapshot_still_consumes_limit_slots
    adapter = InvalidRosterMemory.new(feature_key: :pilot, actors: [nil, "", "   ", "User;1"])
    limited = feature(Flipper::Adapters::ActorLimit.new(adapter, 4))

    assert_equal 4, limited.actors_value.size
    assert_includes limited.actors_value, nil
    assert_raises(Flipper::Adapters::ActorLimit::LimitExceeded) do
      limited.enable_actor(Flipper::Actor.new("User;2"))
    end
  end

  def test_failsafe_outside_actor_limit_turns_the_cap_rejection_into_false
    storage = RecordingMemory.new
    storage.seed_actors(:pilot, ["User;0"])
    stack = Flipper::Adapters::Failsafe.new(
      Flipper::Adapters::ActorLimit.new(storage, 1)
    )
    subject = feature(stack)

    assert_equal false, subject.enable_actor(Flipper::Actor.new("User;1"))
    assert_equal Set["User;0"], stored_actors(storage)
  end

  def test_failover_default_error_list_masks_strict_not_found
    primary = RecordingMemory.new
    secondary = RecordingMemory.new
    stack = Flipper::Adapters::Failover.new(
      Flipper::Adapters::Strict.new(primary, :raise),
      secondary
    )
    subject = feature(stack)

    assert_equal false, subject.enabled?
    assert_includes operations(secondary, :reads), :get
  end

  def test_failover_narrow_error_list_lets_strict_not_found_raise
    primary = RecordingMemory.new
    secondary = RecordingMemory.new
    stack = Flipper::Adapters::Failover.new(
      Flipper::Adapters::Strict.new(primary, :raise),
      secondary,
      errors: [IOError]
    )
    subject = feature(stack)

    assert_raises(Flipper::Adapters::Strict::NotFound) { subject.enabled? }
    assert_equal [], secondary.reads
  end

  def test_failover_dual_write_with_read_only_secondary_writes_primary_then_raises
    primary = RecordingMemory.new
    secondary = Flipper::Adapters::ReadOnly.new(RecordingMemory.new)
    stack = Flipper::Adapters::Failover.new(primary, secondary, dual_write: true)
    subject = feature(stack)

    assert_equal true, stack.read_only?
    assert_raises(Flipper::Adapters::ReadOnly::WriteAttempted) { subject.enable }
    assert_equal [:add], operations(primary, :writes)
    assert_equal Set["pilot"], primary.adapter.features
  end

  def test_strict_without_a_handler_does_not_raise
    stack = Flipper::Adapters::Strict.new(RecordingMemory.new)
    subject = feature(stack)

    assert_equal false, subject.enabled?
  end

  def test_read_only_outermost_rejects_before_any_composite_write
    inner = RecordingMemory.new
    stack = Flipper::Adapters::ReadOnly.new(
      Flipper::Adapters::Failover.new(inner, RecordingMemory.new, dual_write: true)
    )
    subject = feature(stack)

    assert_raises(Flipper::Adapters::ReadOnly::WriteAttempted) { subject.enable }
    assert_equal [], inner.writes
  end

  def test_read_only_inside_dual_write_allows_the_remote_write_before_rejecting
    local = Flipper::Adapters::ReadOnly.new(RecordingMemory.new)
    remote = RecordingMemory.new
    stack = Flipper::Adapters::DualWrite.new(local, remote)
    subject = feature(stack)

    assert_equal true, stack.read_only?
    assert_raises(Flipper::Adapters::ReadOnly::WriteAttempted) { subject.enable }
    assert_includes operations(remote, :writes), :add
  end

  def test_dual_write_is_remote_first_so_a_local_failure_leaves_a_partial_commit
    local = RecordingMemory.new
    remote = RecordingMemory.new
    local.fail_operation(:enable, IOError.new("local enable failed"))
    stack = Flipper::Adapters::DualWrite.new(local, remote)
    subject = feature(stack)

    assert_raises(IOError) { subject.enable }
    assert_includes operations(remote, :writes), :enable
    assert_includes operations(local, :writes), :enable
  end

  def test_failsafe_outside_read_only_turns_a_rejection_into_false
    inner = RecordingMemory.new
    stack = Flipper::Adapters::Failsafe.new(Flipper::Adapters::ReadOnly.new(inner))
    subject = feature(stack)

    assert_equal true, stack.read_only?
    assert_equal false, subject.enable
    assert_equal [], inner.writes
  end

  def test_instrumented_inside_failsafe_keeps_the_exception_for_audit
    instrumenter = Flipper::Instrumenters::Memory.new
    storage = RecordingMemory.new
    storage.fail_operation(:enable, IOError.new("storage enable failed"))
    stack = Flipper::Adapters::Failsafe.new(
      Flipper::Adapters::Instrumented.new(storage, instrumenter: instrumenter)
    )
    subject = feature(stack)

    assert_equal false, subject.enable
    event = instrumenter.events_by_name("adapter_operation.flipper").last
    assert_equal :enable, event.payload[:operation]
    assert_instance_of IOError, event.payload[:exception_object]
  end

  def test_instrumented_outside_failsafe_sees_false_instead_of_the_exception
    instrumenter = Flipper::Instrumenters::Memory.new
    storage = RecordingMemory.new
    storage.fail_operation(:enable, IOError.new("storage enable failed"))
    stack = Flipper::Adapters::Instrumented.new(
      Flipper::Adapters::Failsafe.new(storage),
      instrumenter: instrumenter
    )
    subject = feature(stack)

    assert_equal false, subject.enable
    event = instrumenter.events_by_name("adapter_operation.flipper").last
    assert_equal false, event.payload[:result]
    assert_nil event.payload[:exception_object]
  end

  def test_sync_version_writes_are_also_refused_by_outer_read_only
    inner = RecordingMemory.new
    stack = Flipper::Adapters::ReadOnly.new(inner)

    assert_raises(Flipper::Adapters::ReadOnly::WriteAttempted) do
      stack.sync_version = Flipper::SyncVersion.new("scope", 10)
    end
    assert_nil inner.sync_version
  end

  def test_composite_read_only_flags_describe_the_write_targets
    writable = RecordingMemory.new
    read_only = Flipper::Adapters::ReadOnly.new(RecordingMemory.new)

    assert_equal true, Flipper::Adapters::Failover.new(read_only, writable).read_only?
    assert_equal false, Flipper::Adapters::Failover.new(writable, read_only).read_only?
    assert_equal true, Flipper::Adapters::Failover.new(writable, read_only, dual_write: true).read_only?
    assert_equal true, Flipper::Adapters::DualWrite.new(read_only, writable).read_only?
    assert_equal true, Flipper::Adapters::DualWrite.new(writable, read_only).read_only?
  end
end
