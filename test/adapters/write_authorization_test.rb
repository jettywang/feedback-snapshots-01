require "test_helper"
require "flipper/instrumenters/memory"
require "flipper/adapters/write_authorization"

class Flipper::Adapters::WriteAuthorizationTest < MiniTest::Test
  Auth = Flipper::Adapters::WriteAuthorization

  def setup
    @memory = Flipper::Adapters::Memory.new
    @instrumenter = Flipper::Instrumenters::Memory.new
    @policy = Auth::Policy.new(
      on_call: { "checkout" => %i[add disable clear] },
      security: :all,
    )
    @adapter = Auth.new(@memory, policy: @policy, instrumenter: @instrumenter)
    @flipper = Flipper.new(@adapter)
    @checkout = @flipper[:checkout]
    @actor = Flipper::Actor.new("user;1")
  end

  def teardown
    Auth.principal = nil
  end

  def as(principal)
    Auth.with_principal(principal) { yield }
  end

  def memory_values
    Flipper::GateValues.new(@memory.get(@checkout))
  end

  def denial_events
    @instrumenter.events_by_name(Auth::DenialInstrumentationName)
  end

  def test_two_on_call_identities_can_narrow_but_only_security_can_expand
    assert_equal :off, @checkout.state

    as(:security) { @checkout.enable_actor(@actor) }
    assert_equal Set["user;1"], memory_values.actors
    assert @checkout.enabled?(@actor)

    as(:on_call) { @checkout.disable_actor(@actor) }
    assert_equal Set.new, memory_values.actors
    refute @checkout.enabled?(@actor)

    as(:security) { @checkout.enable_actor(@actor) }
    assert_equal Set["user;1"], memory_values.actors
    assert @checkout.enabled?(@actor)

    assert_empty denial_events
  end

  def test_on_call_can_clear_all_gates_and_storage_matches_reads
    as(:security) do
      @checkout.enable_actor(@actor)
      @checkout.enable_group(:admins)
      @checkout.enable_percentage_of_actors(25)
    end
    assert_equal :conditional, @checkout.state

    as(:on_call) { assert_equal true, @checkout.clear }

    assert_equal Flipper::Adapters::Memory.default_config, @memory.get(@checkout)
    assert_equal Flipper::GateValues.new(@adapter.default_config), memory_values
    assert_equal :off, @checkout.state
    assert_empty denial_events
  end

  def test_on_call_cannot_expand_and_denial_leaves_storage_and_reads_unchanged
    as(:security) { @checkout.disable_actor(@actor) }
    before = @memory.get(@checkout)

    error = assert_raises(Auth::NotAuthorized) do
      as(:on_call) { @checkout.enable }
    end

    assert_match(/:on_call is not authorized to enable/, error.message)
    assert_equal before, @memory.get(@checkout)
    assert_equal :off, @checkout.state
    refute @adapter.authorized?(:enable, @checkout)

    assert_equal 1, denial_events.size
    payload = denial_events.first.payload
    assert_equal :on_call, payload[:principal]
    assert_equal :enable, payload[:operation]
    assert_equal :checkout, payload[:feature_name]
    assert_equal :boolean, payload[:gate_name]
    assert_equal :policy_denied, payload[:reason]
    assert_kind_of Auth::NotAuthorized, payload[:exception_object]
  end

  def test_allowed_operations_agree_with_authorized
    as(:on_call) do
      assert @adapter.authorized?(:disable, @checkout)
      assert @adapter.authorized?(:clear, @checkout)
      refute @adapter.authorized?(:enable, @checkout)
      refute @adapter.authorized?(:enable, @flipper[:search])
    end

    as(:security) do
      assert @adapter.authorized?(:enable, @checkout)
      assert @adapter.authorized?(:remove, @checkout)
    end
  end

  def test_writes_without_a_principal_are_denied_and_instrumented
    as(:security) { @flipper.add(:checkout) }

    assert_raises(Auth::NotAuthorized) { @checkout.disable }
    assert_equal 1, denial_events.size
    assert_nil denial_events.first.payload[:principal]
    assert_equal :missing_principal, denial_events.first.payload[:reason]
  end

  def test_creating_a_feature_requires_explicit_add_permission
    assert_raises(Auth::NotAuthorized) do
      as(:on_call) { @flipper[:brand_new].add }
    end
    assert_empty @memory.features
  end

  def test_disable_is_authorized_even_when_it_creates_the_feature_first
    as(:on_call) do
      assert_equal true, @checkout.disable_actor(@actor)
    end

    assert_includes @memory.features, "checkout"
    assert_empty denial_events
  end
end
