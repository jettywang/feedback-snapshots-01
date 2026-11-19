# frozen_string_literal: true

require "test_helper"

class TestScopeContract < Minitest::Test
  Row = Struct.new(:id, :title, :created_at, :secret)

  def rows
    [
      {id: 2, title: "b", created_at: 20, secret: "x"},
      {id: 1, title: "a", created_at: 10, secret: "y"}
    ]
  end

  def contract(data = rows)
    ActionPolicy::ScopeContract.authorize(data, policy: UserPolicy, type: :data, name: :default)
  end

  def test_authorize_records_derivation
    contract = self.contract

    assert_predicate contract, :verified?
    assert_predicate contract, :traceable?

    source = contract.derived_from.first
    assert_predicate source, :authorized?
    assert_equal UserPolicy, source.policy
    assert_equal :data, source.type
    assert_equal :default, source.name
  end

  def test_untracked_is_neither_verified_nor_traceable
    contract = ActionPolicy::ScopeContract.untracked(rows)

    refute_predicate contract, :verified?
    refute_predicate contract, :traceable?
    assert_empty contract.derived_from
  end

  def test_unverified_is_traceable_but_not_verified
    contract = ActionPolicy::ScopeContract.unverified(rows, label: :csv_import)

    refute_predicate contract, :verified?
    assert_predicate contract, :traceable?

    source = contract.derived_from.first
    refute_predicate source, :authorized?
    assert_equal :csv_import, source.label
  end

  def test_sort_by_keeps_verification
    sorted = contract.sort_by(:id)

    assert_predicate sorted, :verified?
    assert_equal [1, 2], sorted.to_a.map { |row| row[:id] }
  end

  def test_sort_by_multiple_keys
    sorted = contract.sort_by(:title, :id)

    assert_equal %w[a b], sorted.to_a.map { |row| row[:title] }
  end

  def test_sort_by_with_allow_list
    sorted = contract.sort_by(:created_at, allow: %i[id created_at])

    assert_equal [10, 20], sorted.to_a.map { |row| row[:created_at] }
  end

  def test_sort_by_rejects_illegal_keys
    e = assert_raises(ArgumentError) do
      contract.sort_by(:secret, allow: %i[id created_at])
    end

    assert_includes e.message, "secret"
  end

  def test_sort_by_objects
    contract = ActionPolicy::ScopeContract.authorize(
      [Row.new(2, "b", 20, "x"), Row.new(1, "a", 10, "y")],
      policy: UserPolicy, type: :data
    )

    sorted = contract.sort_by(:id)

    assert_equal [1, 2], sorted.to_a.map(&:id)
  end

  def test_select_columns_keeps_verification
    selected = contract.select_columns(:id, :title)

    assert_predicate selected, :verified?
    assert_equal [{id: 2, title: "b"}, {id: 1, title: "a"}], selected.to_a
  end

  def test_select_columns_from_objects
    contract = ActionPolicy::ScopeContract.authorize(
      [Row.new(1, "a", 10, "x")],
      policy: UserPolicy, type: :data
    )

    selected = contract.select_columns(:id, :title)

    assert_equal [{id: 1, title: "a"}], selected.to_a
  end

  def test_chained_transformations_keep_provenance
    derived = contract
      .sort_by(:created_at, allow: %i[created_at])
      .select_columns(:id, :created_at)

    assert_predicate derived, :verified?
    assert_equal [{id: 1, created_at: 10}, {id: 2, created_at: 20}], derived.to_a
    assert_equal 1, derived.derived_from.size
  end

  def test_concat_two_verified_contracts_stays_verified
    other = ActionPolicy::ScopeContract.authorize(
      [{id: 3, title: "c", created_at: 30, secret: "z"}],
      policy: UserPolicy, type: :data, name: :own
    )

    merged = contract.concat(other)

    assert_predicate merged, :verified?
    assert_predicate merged, :traceable?
    assert_equal 3, merged.to_a.size
    assert_equal 2, merged.derived_from.size
    assert_equal :own, merged.derived_from.last.name
  end

  def test_concat_with_unverified_source_is_not_verified_but_traceable
    merged = contract.concat(
      ActionPolicy::ScopeContract.unverified([{id: 3}], label: :plugin)
    )

    refute_predicate merged, :verified?
    assert_predicate merged, :traceable?
    assert_equal 2, merged.derived_from.size
  end

  def test_concat_with_raw_collection_is_not_verified
    merged = contract.concat([{id: 3}])

    refute_predicate merged, :verified?
    assert_predicate merged, :traceable?
  end

  def test_two_concatenations_compose
    first = contract.concat(
      ActionPolicy::ScopeContract.authorize([{id: 3}], policy: UserPolicy, type: :data)
    )
    second = first.concat(
      ActionPolicy::ScopeContract.unverified([{id: 4}], label: :plugin)
    )

    assert_predicate first, :verified?
    refute_predicate second, :verified?
    assert_predicate second, :traceable?
    assert_equal 3, second.derived_from.size
    assert_equal 4, second.to_a.size
  end

  def test_two_concatenations_all_verified
    merged = contract
      .concat(ActionPolicy::ScopeContract.authorize([{id: 3}], policy: UserPolicy, type: :data))
      .concat(ActionPolicy::ScopeContract.authorize([{id: 4}], policy: UserPolicy, type: :data))

    assert_predicate merged, :verified?
    assert_equal 4, merged.to_a.size
  end

  def test_transformations_do_not_mutate_original
    original = contract
    original.sort_by(:id)
    original.select_columns(:id)
    original.concat([{id: 3}])

    assert_equal 2, original.to_a.size
    assert_equal 1, original.derived_from.size
  end
end

class TestScopeContractBehaviour < Minitest::Test
  class ChatChannel
    include ActionPolicy::Behaviour

    attr_reader :user

    authorize :user

    def initialize(name)
      @user = User.new(name)
    end

    def export(users)
      authorized_scope(users, type: :data, contract: true)
    end

    def implicit_authorization_target
      User
    end
  end

  def setup
    @users = [User.new("jack"), User.new("admin")]
  end

  attr_reader :users

  def test_authorized_scope_with_contract
    contract = ChatChannel.new("guest").export(users)

    assert_kind_of ActionPolicy::ScopeContract, contract
    assert_predicate contract, :verified?
    assert_equal 1, contract.to_a.size

    source = contract.derived_from.first
    assert_predicate source, :authorized?
    assert_equal UserPolicy, source.policy
    assert_equal :data, source.type
    assert_equal :default, source.name
  end

  def test_authorized_scope_without_contract_is_unchanged
    scoped = ChatChannel.new("guest").authorized_scope(users, type: :data)

    refute_kind_of ActionPolicy::ScopeContract, scoped
    assert_equal 1, scoped.size
  end
end
