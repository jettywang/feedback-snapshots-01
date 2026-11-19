# frozen_string_literal: true

require "test_helper"

class TestPreCheck < Minitest::Test
  class BasePolicy
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Authorization
    include ActionPolicy::Policy::PreCheck

    authorize :user

    pre_check :allow_admins

    private

    def allow_admins
      allow! if user.admin?
    end
  end

  class TestPolicy < BasePolicy
    pre_check :deny_when_record_is_nil, except: [:index?]
    pre_check :user_is_nil, only: [:new?, :index?]

    def index?
      true
    end

    def new?
      true
    end

    def manage?
      record != false
    end

    private

    def deny_when_record_is_nil
      deny! if record.nil?
    end

    def user_is_nil
      deny! if user.name == "Neil"
    end
  end

  def setup
    @guest = User.new("guest")
    @admin = User.new("admin")
  end

  attr_reader :guest, :admin

  def test_allow_pre_check
    policy = TestPolicy.new false, user: admin

    assert policy.apply(:manage?)

    policy2 = TestPolicy.new false, user: guest

    refute policy2.apply(:manage?)
  end

  def test_deny_pre_check
    policy = TestPolicy.new false, user: guest

    assert policy.apply(:index?)
    refute policy.apply(:manage?)

    policy2 = TestPolicy.new nil, user: guest

    assert policy2.apply(:index?)
    refute policy2.apply(:manage?)

    policy3 = TestPolicy.new nil, user: admin

    assert policy3.apply(:index?)
    assert policy3.apply(:manage?)
  end

  class AdminTestPolicy < TestPolicy
    skip_pre_check :allow_admins, only: :manage?
    skip_pre_check :deny_when_record_is_nil, only: :manage?
    skip_pre_check :user_is_nil, except: [:new?]

    def show?
      manage?
    end
  end

  def test_skip_except_pre_check_with_only
    policy = AdminTestPolicy.new false, user: admin

    assert policy.apply(:index?)
    refute policy.apply(:manage?)
    assert policy.apply(:show?)

    policy2 = AdminTestPolicy.new nil, user: guest

    assert policy2.apply(:index?)
    assert policy2.apply(:manage?)
    refute policy2.apply(:show?)
  end

  def test_skip_only_pre_check_with_except
    policy = TestPolicy.new true, user: User.new("Neil")

    refute policy.apply(:index?)
    refute policy.apply(:new?)
    assert policy.apply(:manage?)

    policy2 = AdminTestPolicy.new true, user: User.new("Neil")

    assert policy2.apply(:index?)
    refute policy2.apply(:new?)
    assert policy2.apply(:manage?)
    assert policy2.apply(:show?)
  end

  class NoAdminTestPolicy < TestPolicy
    skip_pre_check :allow_admins

    def show?
      manage?
    end
  end

  def test_skip_pre_check_completely
    policy = NoAdminTestPolicy.new false, user: admin

    assert policy.apply(:index?)
    refute policy.apply(:manage?)
    refute policy.apply(:show?)
  end

  class ReasonsTestPolicy < TestPolicy
    include ActionPolicy::Policy::Reasons

    self.identifier = :reasons

    def user_is_nil
      deny!(:no_user) if user.name == "Neil"
    end
  end

  def test_pre_check_with_reasons
    policy = ReasonsTestPolicy.new true, user: User.new("Neil")

    refute policy.apply(:index?)

    assert_equal({reasons: [:no_user]}, policy.result.reasons.details)
  end
end

class TestMandatoryPreCheck < Minitest::Test
  class SecureBasePolicy
    include ActionPolicy::Policy::Core
    include ActionPolicy::Policy::Authorization
    include ActionPolicy::Policy::PreCheck
    include ActionPolicy::Policy::Aliases

    authorize :user

    pre_check :deny_disabled_accounts, mandatory: true, only: [:update?]
    pre_check :allow_admins

    private

    def deny_disabled_accounts
      deny! if user.name == "disabled"
    end

    def allow_admins
      allow! if user.admin?
    end
  end

  class MiddlePolicy < SecureBasePolicy
    alias_rule :publish?, to: :update?

    pre_check :deny_guests, only: [:update?]

    def update?
      record != false
    end

    def index?
      true
    end

    private

    def deny_guests
      deny! if user.name == "guest"
    end
  end

  class PostPolicy < MiddlePolicy
    skip_pre_check :allow_admins
    skip_pre_check :deny_guests, only: :update?
  end

  def test_normal_pre_checks_can_be_skipped
    admin = User.new("admin")
    guest = User.new("guest")

    # allow_admins is still active in MiddlePolicy
    assert MiddlePolicy.new(false, user: admin).apply(:update?)
    # ...but skipped in PostPolicy
    refute PostPolicy.new(false, user: admin).apply(:update?)

    # deny_guests is still active in MiddlePolicy
    refute MiddlePolicy.new(true, user: guest).apply(:update?)
    # ...but skipped for update? in PostPolicy
    assert PostPolicy.new(true, user: guest).apply(:update?)
  end

  def test_mandatory_pre_check_cannot_be_skipped
    user = User.new("disabled")

    refute MiddlePolicy.new(true, user: user).apply(:update?)
    refute PostPolicy.new(true, user: user).apply(:update?)
  end

  def test_mandatory_pre_check_only_applies_to_matched_rules
    user = User.new("disabled")

    # mandatory check is scoped to update? only
    assert PostPolicy.new(true, user: user).apply(:index?)
  end

  def test_mandatory_pre_check_runs_for_aliased_rule
    user = User.new("disabled")

    # publish? is an alias for update?, so the mandatory check applies
    refute PostPolicy.new(true, user: user).apply(:publish?)
    # normal checks skipped for update? are also skipped for the alias
    assert PostPolicy.new(true, user: User.new("guest")).apply(:publish?)
  end

  def test_skip_mandatory_pre_check_raises
    error = assert_raises(ArgumentError) do
      Class.new(MiddlePolicy) { skip_pre_check :deny_disabled_accounts }
    end

    assert_includes error.message, "deny_disabled_accounts"
    assert_includes error.message, "SecureBasePolicy"
  end

  def test_skip_mandatory_pre_check_with_options_raises
    error = assert_raises(ArgumentError) do
      Class.new(MiddlePolicy) { skip_pre_check :deny_disabled_accounts, only: :update? }
    end

    assert_includes error.message, "deny_disabled_accounts"
    assert_includes error.message, "SecureBasePolicy"
  end

  def test_mandatory_pre_check_with_both_only_and_except_raises
    error = assert_raises(ArgumentError) do
      Class.new(SecureBasePolicy) do
        pre_check :another_check, mandatory: true, only: [:update?], except: [:index?]
      end
    end

    assert_includes error.message, "Only one of `except` and `only`"
  end
end
