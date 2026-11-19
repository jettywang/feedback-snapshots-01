require_relative '../test'

class FileAccessGuardTests < Minitest::Test
  include BrakemanTester::FindWarning
  include BrakemanTester::CheckExpected

  def report
    @@report ||= BrakemanTester.run_scan "file_access_guard", "File Access Guard"
  end

  def expected
    @@expected ||= {
      :controller => 0,
      :model => 0,
      :template => 0,
      :generic => 9
    }
  end

  def test_guarded_directory_boundary_no_warning
    assert_no_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 7,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_guard_clause_no_warning
    assert_no_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 17,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_literal_root_with_boundary_no_warning
    assert_no_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 26,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_guarded_file_read_no_warning
    assert_no_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 34,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_prefix_check_without_directory_boundary
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 43,
      :message => /path\ confinement\ check\ on\ line\ 42\ does\ not\ enforce\ a\ directory\ boundary/,
      :confidence => 2,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_use_not_covered_by_check
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 55,
      :message => /path\ confinement\ check\ on\ line\ 51\ does\ not\ cover\ this\ use/,
      :confidence => 2,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_path_reassigned_after_check
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 64,
      :message => /path\ was\ reassigned\ on\ line\ 63\ after\ the\ confinement\ check/,
      :confidence => 0,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_path_modified_after_check
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 74,
      :message => /path\ was\ modified\ on\ line\ 73\ after\ the\ confinement\ check/,
      :confidence => 0,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_cleanpath_is_not_a_confinement_proof
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 82,
      :message => /^Parameter\ value\ used\ in\ file\ name\ near\ line/,
      :confidence => 2,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_symlink_resolution_remains_unknown
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 91,
      :message => /path\ confinement\ check\ on\ line\ 90\ cannot\ be\ verified\ statically/,
      :confidence => 2,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_runtime_root_remains_unknown
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 101,
      :message => /path\ confinement\ check\ on\ line\ 100\ cannot\ be\ verified\ statically/,
      :confidence => 2,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_unguarded_send_file
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 107,
      :message => /^Parameter\ value\ used\ in\ file\ name\ near\ line/,
      :confidence => 0,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_checked_directory_does_not_match_path_construction
    assert_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 115,
      :message => /path\ confinement\ check\ on\ line\ 114\ does\ not\ match\ the\ directory\ the\ path\ is\ built\ from/,
      :confidence => 2,
      :relative_path => "app/controllers/files_controller.rb"
  end

  def test_raise_guard_clause_no_warning
    assert_no_warning :type => :warning,
      :warning_code => 16,
      :warning_type => "File Access",
      :line => 125,
      :relative_path => "app/controllers/files_controller.rb"
  end
end
