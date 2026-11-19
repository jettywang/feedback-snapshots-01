# frozen_string_literal: true

require "test_helper"

class I18nDefaultPolicy < ActionPolicy::Base
  def feed?
    allowed_to?(:access_feed?)
  end

  def edit?
    allowed_to?(:admin?)
  end

  def admin?
    user.admin?
  end

  def access_feed?
    false
  end
end

class I18nLocalizedIdentifiedPolicy < I18nDefaultPolicy
  self.identifier = :identified_policy
end

class I18nLocalizedPolicy < I18nDefaultPolicy; end

class I18nInheritedFromLocalizedPolicy < I18nLocalizedPolicy; end

class I18nIncludingCoreLocalizedPolicy
  include ActionPolicy::Policy::Core
  include ActionPolicy::Policy::Reasons

  def edit?
    allowed_to?(:admin?)
  end

  def admin?
    false
  end
end

class TestI18nGlobalDefaults < Minitest::Test
  def setup
    I18n.backend.store_translations(:en, action_policy: {policy: {}})
    @user = User.new("guest")
  end

  def test_result_message_fallbacks_to_global_default
    policy = I18nDefaultPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_equal policy.result.message,
      ActionPolicy::I18n::DEFAULT_UNAUTHORIZED_MESSAGE
  end

  def test_full_messages_fallback_to_global_default
    policy = I18nDefaultPolicy.new(user: @user)
    refute policy.apply(:feed?)
    assert_includes policy.result.reasons.full_messages,
      ActionPolicy::I18n::DEFAULT_UNAUTHORIZED_MESSAGE
  end
end

class TestI18nAppDefaults < Minitest::Test
  def setup
    I18n.backend.store_translations(
      :en,
      action_policy: {
        unauthorized: "This action is not allowed",
        policy: {
          feed?: "You're not authorized to access the feed",
          admin?: "Only admins are authorized to view this data"
        }
      }
    )

    @user = User.new("guest")
  end

  def teardown
    I18n.backend.reload!
  end

  def test_result_message_fallbacks_to_app_default
    policy = I18nDefaultPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_equal policy.result.message, "This action is not allowed"
  end

  def test_full_messages_fallback_to_app_default
    policy = I18nDefaultPolicy.new(user: @user)
    refute policy.apply(:feed?)
    assert_includes policy.result.reasons.full_messages, "This action is not allowed"
  end

  def test_result_message_fallbacks_to_action_default
    policy = I18nDefaultPolicy.new(user: @user)
    refute policy.apply(:feed?)
    assert_equal policy.result.message, "You're not authorized to access the feed"
  end

  def test_full_messages_fallback_to_action_default
    policy = I18nDefaultPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.reasons.full_messages,
      "Only admins are authorized to view this data"
  end
end

class TestI18nPolicies < Minitest::Test
  def setup
    I18n.backend.store_translations(
      :en,
      action_policy: {
        policy: {
          i18n_localized: {
            edit?: "You are not authorized to read this data according to custom policy",
            admin?: "You are not authorized to access feed according to custom policy"
          },
          i18n_inherited_from_localized: {
            edit?: "You are not authorized to read this data according to custom inherited policy",
            admin?: "You are not authorized to access feed according to inherited policy"
          },
          identified_policy: {
            edit?: "You are not authorized to read this data according to identified policy",
            admin?: "You are not authorized to access feed according to identified policy"
          },
          i18n_including_core_localized: {
            edit?: "You are not authorized to read this data according to policy including core",
            admin?: "You are not authorized to access feed according to policy including core"
          }
        }
      }
    )

    @user = User.new("guest")
  end

  def teardown
    I18n.backend.reload!
  end

  def test_result_message_for_localized_policy
    policy = I18nLocalizedPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.message,
      "You are not authorized to read this data according to custom policy"
  end

  def test_full_messages_for_localized_policy
    policy = I18nLocalizedPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.reasons.full_messages,
      "You are not authorized to access feed according to custom policy"
  end

  def test_result_message_for_inherited_localized_policy
    policy = I18nInheritedFromLocalizedPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.message,
      "You are not authorized to read this data according to custom inherited policy"
  end

  def test_full_messages_for_inherited_localized_policy
    policy = I18nInheritedFromLocalizedPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.reasons.full_messages,
      "You are not authorized to access feed according to inherited policy"
  end

  def test_result_message_for_identified_localized_policy
    policy = I18nLocalizedIdentifiedPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.message,
      "You are not authorized to read this data according to identified policy"
  end

  def test_full_messages_message_for_identified_localized_policy
    policy = I18nLocalizedIdentifiedPolicy.new(user: @user)
    refute policy.apply(:edit?)
    assert_includes policy.result.reasons.full_messages,
      "You are not authorized to access feed according to identified policy"
  end

  def test_result_message_for_localized_policy_including_core
    policy = I18nIncludingCoreLocalizedPolicy.new
    refute policy.apply(:edit?)
    assert_includes policy.result.message,
      "You are not authorized to read this data according to policy including core"
  end

  def test_full_messages_message_for_localized_policy_including_core
    policy = I18nIncludingCoreLocalizedPolicy.new
    refute policy.apply(:edit?)
    assert_includes policy.result.reasons.full_messages,
      "You are not authorized to access feed according to policy including core"
  end
end

class I18nNestedPolicy < ActionPolicy::Base
  authorize :account

  def show?
    allowed_to?(:manage?, account) || check?(:admin?)
  end

  def admin?
    details[:role] = user.name
    user.admin?
  end

  def deny?
    details[:role] = user.name
    deny!(:denied) unless user.admin?
    allow!
  end
end

class TestI18nNestedPolicies < Minitest::Test
  def setup
    I18n.backend.store_translations(
      :en,
      action_policy: {
        policy: {
          denied: "I deny you: %{role}",
          i18n_nested: {
            show?: "Stop looking at me!",
            admin?: "Only for admins but you are: %{role}"
          },
          account: {
            manage?: "You're not allowed to manage this account"
          }
        }
      }
    )

    @user = User.new("guest")
    @account = Account.new("admin")
    @policy = I18nNestedPolicy.new(user: @user, account: @account)
  end

  attr_reader :policy

  def teardown
    I18n.backend.reload!
  end

  def test_result_message
    refute policy.apply(:show?)
    assert_includes policy.result.message,
      "Stop looking at me!"
  end

  def test_result_message_with_interpolation
    refute policy.apply(:admin?)
    assert_includes policy.result.message,
      "Only for admins but you are: guest"
  end

  def test_full_messages_for_nested_policy
    refute policy.apply(:show?)
    assert_includes policy.result.reasons.full_messages,
      "You're not allowed to manage this account"
    assert_includes policy.result.reasons.full_messages,
      "Only for admins but you are: guest"
  end

  def test_result_message_with_deny_and_interpolation
    refute policy.apply(:deny?)
    assert_includes policy.result.reasons.full_messages,
      "I deny you: guest"
  end
end

class PublicMessagesChildPolicy < ActionPolicy::Base
  self.identifier = :public_messages_child

  def show?
    details[:secret] = "child-secret-#{user.name}"
    false
  end
end

class PublicMessagesParentPolicy < ActionPolicy::Base
  self.identifier = :public_messages_parent

  def show?
    details[:secret] = "parent-secret-#{user.name}"
    allowed_to?(:local_rule?) ||
      allowed_to?(:show?, record, with: PublicMessagesChildPolicy)
  end

  def local_rule?
    details[:secret] = "local-secret-#{user.name}"
    false
  end
end

class TestPublicMessagesProjection < Minitest::Test
  User = Struct.new(:name)

  def setup
    @previous_available_locales = I18n.available_locales
    I18n.available_locales = [:en, :fr]

    I18n.backend.store_translations(
      :en,
      action_policy: {
        unauthorized: "This action is not allowed",
        policy: {
          public_messages_parent: {local_rule?: "Local rule rejected"},
          # Only an interpolation template exists for the child rule: the secret is
          # required to build the (internal) detailed message.
          public_messages_child: {show?: "Child rule rejected: %{secret}"}
        }
      }
    )
    I18n.backend.store_translations(
      :fr,
      action_policy: {
        unauthorized: "Cette action n'est pas autorisée",
        policy: {
          public_messages_parent: {local_rule?: "Règle locale refusée"},
          public_messages_child: {show?: "Règle enfant refusée : %{secret}"}
        }
      }
    )

    @policy = PublicMessagesParentPolicy.new(Object.new, user: User.new("boss"))
    refute @policy.apply(:show?)
    @reasons = @policy.result.reasons
  end

  def teardown
    I18n.backend.reload!
    I18n.available_locales = @previous_available_locales
  end

  def test_public_messages_use_translatable_categories
    assert_equal(
      ["Local rule rejected", "This action is not allowed"],
      @reasons.public_messages
    )
  end

  def test_public_messages_can_be_localized
    assert_equal(
      ["Règle locale refusée", "Cette action n'est pas autorisée"],
      @reasons.public_messages(locale: :fr)
    )
  end

  def test_public_messages_never_leak_business_data
    rendered = (@reasons.public_messages + @reasons.public_messages(locale: :fr)).join(" ")

    refute_includes rendered, "secret"
    refute_includes rendered, "boss"
    refute_includes rendered, "%{"
  end

  def test_full_messages_still_expose_the_original_detailed_reasons
    assert_includes @reasons.full_messages, "Child rule rejected: child-secret-boss"
  end

  def test_internal_reasons_remain_available_for_the_internal_audience
    assert_equal(
      {
        public_messages_parent: [{local_rule?: {secret: "local-secret-boss"}}],
        public_messages_child: [{show?: {secret: "child-secret-boss"}}]
      },
      @reasons.details
    )
  end

  def test_query_order_does_not_affect_either_audience
    public_en = @reasons.public_messages
    public_fr = @reasons.public_messages(locale: :fr)
    internal = @reasons.details

    assert_equal public_en, @reasons.public_messages
    assert_equal public_fr, @reasons.public_messages(locale: :fr)
    assert_equal internal, @reasons.details
    assert_includes @reasons.details.inspect, "child-secret-boss"
  end

  def test_public_messages_without_failures
    policy = I18nDefaultPolicy.new(user: ::User.new("admin"))
    assert policy.apply(:edit?)
    assert policy.result.reasons.empty?

    assert_equal [], policy.result.reasons.public_messages
  end
end
