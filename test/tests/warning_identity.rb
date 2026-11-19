require_relative '../test'
require 'brakeman/warning'
require 'brakeman/differ'

class WarningIdentityTests < Minitest::Test
  include Brakeman::Util

  def setup
    @file = Brakeman::FilePath.new("/app/app/models/user.rb", "app/models/user.rb")
  end

  def warning line:, source: :a, code: s(:call, s(:call, nil, :params), :[], s(:lit, :a))
    Brakeman::Warning.new(
      warning_code: :sql_injection,
      warning_type: "SQL Injection",
      message: "Possible SQL injection",
      code: code,
      file: @file,
      line: line,
      confidence: :high
    )
  end

  def test_hash_and_eql_use_sink_instance
    one = warning(line: 1)
    same = warning(line: 1)
    moved = warning(line: 2)

    assert_equal one.hash, same.hash
    assert one.eql?(same)
    refute one.eql?(moved)
  end

  def test_fingerprint_unchanged_when_occurrence_is_zero
    legacy = Brakeman::Warning.new(
      warning_code: :sql_injection,
      warning_type: "SQL Injection",
      message: "Possible SQL injection",
      code: s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))),
      file: @file,
      line: 10,
      confidence: :high
    )

    assert_equal legacy.legacy_fingerprint, legacy.fingerprint
  end

  def test_collision_suffix_keeps_first_fingerprint
    first = warning(line: 1)
    second = warning(line: 2)
    second.collision_suffix = 1

    assert_equal first.fingerprint, first.legacy_fingerprint
    refute_equal first.fingerprint, second.fingerprint
  end
end


class DifferIdentityTests < Minitest::Test
  include Brakeman::Util

  def setup
    @file = Brakeman::FilePath.new("/app/app/models/user.rb", "app/models/user.rb")
  end

  def warning code, line
    Brakeman::Warning.new(
      warning_code: :sql_injection,
      warning_type: "SQL Injection",
      message: "Possible SQL injection",
      code: code,
      file: @file,
      line: line,
      confidence: :high
    )
  end

  def test_line_move_only_is_not_reported
    original = warning(s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))), 1)
    moved = warning(s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))), 8)

    diff = Brakeman::Differ.new([moved], [original]).diff

    assert_empty diff[:new]
    assert_empty diff[:fixed]
  end

  def test_changed_sink_structure_is_semantic_change
    original = warning(s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))), 1)
    changed = warning(s(:call, s(:const, :User), :where, s(:str, "role = 'x'")), 1)

    diff = Brakeman::Differ.new([changed], [original]).diff

    assert_equal 1, diff[:new].length
    assert_equal 1, diff[:fixed].length
  end

  def test_changed_source_keeps_sink_identity
    original = warning(s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a))), 1)
    changed = warning(s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :b))), 1)

    diff = Brakeman::Differ.new([changed], [original]).diff

    assert_empty diff[:new]
    assert_empty diff[:fixed]
  end

  def test_one_old_warning_cannot_cancel_two_new_calls
    exp = s(:call, s(:const, :User), :where, s(:call, s(:call, nil, :params), :[], s(:lit, :a)))
    original = warning(exp, 1)
    one = warning(exp, 1)
    two = warning(exp, 1)
    two.collision_suffix = 1

    diff = Brakeman::Differ.new([one, two], [original]).diff

    assert_equal 1, diff[:new].length
    assert_empty diff[:fixed]
  end
end
