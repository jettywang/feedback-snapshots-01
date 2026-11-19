# frozen_string_literal: true

require "test_helper"

class FailuresTestPolicy
  include ActionPolicy::Policy::Core
  include ActionPolicy::Policy::Reasons

  def index?
    true
  end

  def manage?
    false
  end
end

class TestFailuresPolicy < Minitest::Test
  def setup
    @policy = FailuresTestPolicy.new
  end

  def test_apply_success
    assert @policy.apply(:index?)
    assert @policy.result.reasons.empty?
  end

  def test_apply_failure
    refute @policy.apply(:manage?)
    assert @policy.result.reasons.empty?
  end
end

class UserFailuresPolicy < ActionPolicy::Base; end

class ComplexFailuresTestPolicy < ActionPolicy::Base
  self.identifier = :complex

  def kill?
    (user.name == "admin") && allowed_to?(:manage?, user, with: UserFailuresPolicy)
  end

  def save?
    allowed_to?(:kill?) || (allowed_to?(:create?, user) && check?(:feed?))
  end

  def feed?
    false
  end

  def sing?
    deny!(:no_singing_today)
  end

  def clone?
    (user.name != "admin") && (
      allowed_to?(:clone?, user, inline_reasons: true) ||
      check?(:copyable?, user, inline_reasons: true)
    )
  end
end

class TestComplexFailuresPolicy < Minitest::Test
  User = Struct.new(:name)

  class UserPolicy < ActionPolicy::Base
    self.identifier = :user

    def create?
      user.name == "admin"
    end

    def clone?
      deny!(:cloning_humans_is_not_allowed)
    end

    def copyable?
      check?(:non_guest)
    end

    def non_guest
      details[:username] = user.name

      user.name != "guest"
    end
  end

  def test_and_condition_first_main_clause_failure
    policy = ComplexFailuresTestPolicy.new user: User.new("guest")

    refute policy.apply(:kill?)
    assert policy.result.reasons.empty?
  end

  def test_and_condition_nested_check_failure
    policy = ComplexFailuresTestPolicy.new user: User.new("admin")

    refute policy.apply(:kill?)

    details = policy.result.reasons.details

    assert_equal({user_failures: [:manage?]}, details)
  end

  def test_or_condition
    policy = ComplexFailuresTestPolicy.new user: User.new("guest")

    refute policy.apply(:save?)

    details = policy.result.reasons.to_h

    assert_equal({
      complex: [:kill?],
      user: [:create?]
    }, details)
  end

  def test_or_condition_2
    policy = ComplexFailuresTestPolicy.new user: User.new("admin")

    refute policy.apply(:save?)

    details = policy.result.reasons.to_h

    assert_equal({
      complex: [:kill?, :feed?]
    }, details)
  end

  def test_no_result
    policy = ComplexFailuresTestPolicy.new user: User.new("admin")

    refute policy.save?
    assert_nil policy.result
  end

  def test_deny
    policy = ComplexFailuresTestPolicy.new user: User.new("guest")

    refute policy.apply(:sing?)

    details = policy.result.reasons.to_h

    assert_equal({
      complex: [:no_singing_today]
    }, details)
  end

  def test_merge_reasons
    policy = ComplexFailuresTestPolicy.new user: User.new("guest")

    refute policy.apply(:clone?)

    details = policy.result.reasons.to_h

    assert_equal({
      user: [
        :cloning_humans_is_not_allowed,
        non_guest: {username: "guest"}
      ]
    }, details)
  end
end

class FailuresWithDetailsPolicy < ActionPolicy::Base
  self.identifier = :detailed

  def kill?
    details[:role] = user.name
    (user.name == "admin") && allowed_to?(:manage?, user, with: UserFailuresPolicy)
  end

  def save?
    allowed_to?(:kill?) || (
      allowed_to?(:create?, user) && check?(:feed?)
    )
  end

  def feed?
    details[:some] = "stuff"
    false
  end
end

class TestFailuresWithDetailsPolicy < Minitest::Test
  User = Struct.new(:name)

  class UserPolicy < ActionPolicy::Base
    self.identifier = :user

    def create?
      check?(:admin?) || check?(:manager?) || check?(:superman?)
    end

    def admin?
      details[:name] = user.name
      user.name == "admin"
    end

    def manager?
      false
    end

    def superman?
      details[:superhero] = "spiderman"
      false
    end
  end

  def test_and_condition_nested_check_details
    policy = FailuresWithDetailsPolicy.new user: User.new("guest")

    refute policy.apply(:save?)

    details = policy.result.reasons.details

    assert_equal({
      detailed: [{kill?: {role: "guest"}}],
      user: [:create?]
    }, details)
  end

  def test_detailed_and_not_detailed_reasons
    policy = UserPolicy.new user: User.new("gusto")

    refute policy.apply(:create?)

    details = policy.result.reasons.details

    assert_equal({
      user: [:manager?, {admin?: {name: "gusto"}, superman?: {superhero: "spiderman"}}]
    }, details)
  end

  def test_multiple_details
    policy = FailuresWithDetailsPolicy.new user: User.new("admin")

    refute policy.apply(:save?)

    details = policy.result.reasons.details

    assert_equal({
      detailed: [{kill?: {role: "admin"}, feed?: {some: "stuff"}}]
    }, details)
  end

  def test_all_details
    policy = UserPolicy.new user: User.new("gusto")

    refute policy.apply(:create?)

    details = policy.result.all_details

    assert_equal({name: "gusto", superhero: "spiderman"}, details)
  end
end

class PublicProjectionChildPolicy < ActionPolicy::Base
  self.identifier = :projection_child

  def show?
    details[:child_business_data] = "child-secret-#{user.name}"
    false
  end
end

class PublicProjectionParentPolicy < ActionPolicy::Base
  self.identifier = :projection_parent

  def show?
    details[:parent_business_data] = "parent-secret-#{user.name}"
    allowed_to?(:local_rule?) ||
      allowed_to?(:show?, record, with: PublicProjectionChildPolicy)
  end

  def local_rule?
    details[:local_business_data] = "local-secret-#{user.name}"
    false
  end

  # Re-evaluates the same checks to make sure duplicate categories are projected once.
  def repeat?
    allowed_to?(:local_rule?) || allowed_to?(:local_rule?)
  end
end

class TestPublicFailureReasonsProjection < Minitest::Test
  User = Struct.new(:name)

  def setup
    @policy = PublicProjectionParentPolicy.new(Object.new, user: User.new("boss"))
    refute @policy.apply(:show?)
    @reasons = @policy.result.reasons
  end

  def test_internal_reasons_keep_the_full_business_details
    assert_equal(
      {
        projection_parent: [{local_rule?: {local_business_data: "local-secret-boss"}}],
        projection_child: [{show?: {child_business_data: "child-secret-boss"}}]
      },
      @reasons.details
    )

    assert_equal(
      {local_business_data: "local-secret-boss", child_business_data: "child-secret-boss"},
      @policy.result.all_details
    )
  end

  def test_public_reasons_expose_only_translatable_categories
    assert_equal(
      {projection_parent: [:local_rule?], projection_child: [:show?]},
      @reasons.public_reasons
    )
  end

  def test_public_reasons_never_contain_business_data
    rendered = @reasons.public_reasons.inspect

    refute_includes rendered, "secret"
    refute_includes rendered, "boss"
  end

  def test_public_reasons_deduplicate_categories
    policy = PublicProjectionParentPolicy.new(Object.new, user: User.new("boss"))
    refute policy.apply(:repeat?)

    assert_equal({projection_parent: [:local_rule?]}, policy.result.reasons.public_reasons)
  end

  def test_public_reasons_do_not_mutate_the_internal_store
    before = Marshal.load(Marshal.dump(@reasons.details))

    @reasons.public_reasons
    @reasons.public_reasons

    assert_equal before, @reasons.details
    assert_includes @reasons.details.inspect, "local-secret-boss"
  end

  def test_query_order_does_not_affect_either_audience
    assert_equal @reasons.public_reasons, @reasons.public_reasons
    assert_equal @reasons.details, @reasons.details

    public_first = @reasons.public_reasons
    internal_after_public = @reasons.details
    public_again = @reasons.public_reasons

    assert_equal public_first, public_again
    assert_includes internal_after_public.inspect, "child-secret-boss"
  end

  def test_public_reasons_for_a_policy_without_failures
    policy = FailuresTestPolicy.new
    assert policy.apply(:index?)

    assert_equal({}, policy.result.reasons.public_reasons)
  end
end
