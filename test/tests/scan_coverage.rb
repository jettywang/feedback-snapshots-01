require_relative '../test'
require 'brakeman/commandline'
require 'tmpdir'
require 'fileutils'

class ScanCoverageUnitTests < Minitest::Test
  def setup
    @coverage = Brakeman::ScanCoverage.new({})
  end

  def test_starts_complete_without_limitations
    assert @coverage.complete?
    refute @coverage.incomplete?
    assert_empty @coverage.limitations
  end

  def test_error_makes_scan_incomplete
    @coverage.record_error(:reason => :parse_error, :file => "a.rb", :error => "boom")

    refute @coverage.complete?
    assert_equal [:errors], @coverage.limitations.keys
  end

  def test_excluded_path_makes_scan_incomplete
    @coverage.record_excluded_path("vendor/x.rb", "vendor directory skipped")

    entry = @coverage.excluded_paths.first
    assert_equal "vendor/x.rb", entry[:path]
    assert_equal Brakeman::ScanCoverage::EXCLUDED_PATH, entry[:reason]
    assert_includes entry[:detail], "vendor"
    refute @coverage.complete?
  end

  def test_unsupported_template_makes_scan_incomplete
    @coverage.record_unsupported_template("view.html.liquid", "No template handler available for liquid")

    entry = @coverage.unsupported_templates.first
    assert_equal Brakeman::ScanCoverage::UNSUPPORTED_TEMPLATE, entry[:reason]
    assert_includes entry[:handler], "liquid"
    refute @coverage.complete?
  end

  def test_disabled_check_makes_scan_incomplete
    @coverage.record_disabled_check("CheckSQL", "excluded with --except/-x")

    entry = @coverage.disabled_checks.first
    assert_equal "CheckSQL", entry[:check]
    assert_equal Brakeman::ScanCoverage::DISABLED_CHECK, entry[:reason]
    assert_includes entry[:detail], "--except"
    refute @coverage.complete?
  end

  def test_scan_inputs_are_counted
    @coverage.record_scan_inputs(["a.rb", "b.rb"], ["v.html.erb"])

    hash = @coverage.to_h
    assert_equal 2, hash[:scanned_ruby_files]
    assert_equal 1, hash[:scanned_template_files]
    assert hash[:complete]
  end

  def test_file_path_objects_are_relative
    app_tree = Brakeman::AppTree.new(File.expand_path("#{TEST_PATH}/apps/rails6"))
    file_path = app_tree.file_path("app/controllers/users_controller.rb")

    @coverage.record_excluded_path(file_path, "test")

    assert_equal "app/controllers/users_controller.rb",
      @coverage.excluded_paths.first[:path]
  end
end

# Tests for the scan coverage contract: callers must be able to tell a fully
# checked, warning-free scan apart from one where some input was never
# analyzed. The coverage_demo fixture contains:
#
#   * one dangerous call (a real warning that must never be swallowed),
#   * one Ruby file that cannot be parsed,
#   * one template with an unsupported handler (.liquid).
class ScanCoverageTests < Minitest::Test
  DEMO_APP = File.expand_path("#{TEST_PATH}/apps/coverage_demo")

  def run_demo(overrides = {})
    options = {
      :app_path => DEMO_APP,
      :quiet => true,
      :parallel_checks => false
    }.merge(overrides)

    Brakeman.run(options)
  end

  def copy_demo
    dir = Dir.mktmpdir('brakeman-coverage')
    FileUtils.cp_r("#{DEMO_APP}/.", dir)
    dir
  end

  def test_incomplete_scan_reports_all_three_gaps
    tracker = run_demo
    coverage = tracker.coverage

    refute coverage.complete?, "scan with failures must not be reported as complete"
    assert coverage.incomplete?

    reasons = coverage.limitations
    assert_includes reasons.keys, :errors
    assert_includes reasons.keys, :unsupported_templates

    parse_error = tracker.errors.find { |e| e[:reason] == :parse_error }
    refute_nil parse_error, "unparseable file must be classified as a parse error"
    assert_equal "app/controllers/broken_controller.rb", parse_error[:file]

    unsupported = coverage.unsupported_templates.first
    assert_equal "app/views/dashboard/report.html.liquid", unsupported[:path]
    assert_includes unsupported[:handler], "liquid"
  end

  def test_errors_are_never_emitted_as_warnings
    tracker = run_demo

    warning_types = tracker.filtered_warnings.map(&:warning_type)
    refute_includes warning_types, "Parse Error"
    refute_includes warning_types, "Processing Error"

    # Every recorded warning still carries the normal confidence field, proving
    # an analysis error is not downgraded into a low confidence finding.
    tracker.filtered_warnings.each do |warning|
      assert_includes [0, 1, 2], warning.confidence
    end
  end

  def test_existing_findings_survive_partial_failure
    tracker = run_demo

    command_injection = tracker.filtered_warnings.find do |w|
      w.warning_type == "Command Injection"
    end

    refute_nil command_injection,
      "the dangerous call must still be reported even though another file failed to parse"
    assert_equal "app/controllers/dashboard_controller.rb", command_injection.file.relative
  end

  def test_json_report_exposes_the_completeness_contract
    require 'json'

    tracker = run_demo
    report = JSON.parse(tracker.report.to_json)

    assert_equal false, report["coverage"]["complete"]
    assert_equal false, report["scan_info"]["coverage"]["complete"]
    assert_equal report["coverage"], report["scan_info"]["coverage"]

    json_error = report["errors"].first
    assert_equal "parse_error", json_error["reason"]
    assert_equal "app/controllers/broken_controller.rb", json_error["file"]

    assert_kind_of Integer, report["coverage"]["scanned_ruby_files"]
    assert_kind_of Integer, report["coverage"]["scanned_template_files"]
  end

  def test_hash_report_exposes_coverage
    tracker = run_demo
    report = tracker.report.to_hash

    assert_equal false, report[:coverage][:complete]
    assert_includes report[:coverage][:limitations].keys, :unsupported_templates
  end

  def test_excluded_paths_are_recorded_with_reason
    tracker = run_demo(:skip_files => ["app/controllers/broken_controller.rb"])
    excluded = tracker.coverage.excluded_paths.map(&:to_h)

    entry = excluded.find { |e| e[:path] == "app/controllers/broken_controller.rb" }
    refute_nil entry
    assert_equal Brakeman::ScanCoverage::EXCLUDED_PATH, entry[:reason]
    assert_includes entry[:detail], "skip-files"
    assert tracker.coverage.incomplete?
  end

  def test_only_files_limits_are_recorded
    tracker = run_demo(:only_files => ["app/views/"])
    paths = tracker.coverage.excluded_paths.map { |e| e[:path] }

    assert(paths.any? { |p| p.include?("controllers") },
      "files outside --only-files must be reported as excluded")
    assert tracker.coverage.incomplete?
  end

  def test_disabled_checks_are_recorded
    tracker = run_demo(:skip_checks => Set["CheckSanitizeMethods"])
    disabled = tracker.coverage.disabled_checks.map(&:to_h)

    entry = disabled.find { |e| e[:check] == "CheckSanitizeMethods" }
    refute_nil entry
    assert_equal Brakeman::ScanCoverage::DISABLED_CHECK, entry[:reason]
    assert_includes entry[:detail], "--except"
  end

  def test_run_checks_limits_are_recorded
    tracker = run_demo(:run_checks => Set["CheckSanitizeMethods"])
    disabled = tracker.coverage.disabled_checks.map { |e| e[:check] }

    assert_includes disabled, "CheckCrossSiteScripting"
    assert tracker.coverage.incomplete?
  end

  def test_repairing_parse_error_changes_coverage
    Dir.mktmpdir('brakeman-coverage') do |dir|
      FileUtils.cp_r("#{DEMO_APP}/.", dir)

      broken = File.join(dir, "app/controllers/broken_controller.rb")
      File.write(broken, <<~RUBY)
        class BrokenController < ApplicationController
          def broken
            x = 1
          end
        end
      RUBY

      tracker = Brakeman.run(:app_path => dir, :quiet => true, :parallel_checks => false)

      refute tracker.coverage.complete?
      assert_empty tracker.coverage.errors
      assert_equal [:unsupported_templates], tracker.coverage.limitations.keys
      assert_equal 1, tracker.filtered_warnings.length
    end
  end

  def test_repairing_template_changes_coverage
    Dir.mktmpdir('brakeman-coverage') do |dir|
      FileUtils.cp_r("#{DEMO_APP}/.", dir)

      liquid = File.join(dir, "app/views/dashboard/report.html.liquid")
      File.delete(liquid)
      File.write(File.join(dir, "app/views/dashboard/report.html.erb"),
        "<h1>Repaired</h1>\n")

      tracker = Brakeman.run(:app_path => dir, :quiet => true, :parallel_checks => false)

      refute tracker.coverage.complete?
      assert_empty tracker.coverage.unsupported_templates
      assert_equal [:errors], tracker.coverage.limitations.keys
    end
  end

  def test_fully_repaired_scan_is_complete
    Dir.mktmpdir('brakeman-coverage') do |dir|
      FileUtils.cp_r("#{DEMO_APP}/.", dir)

      File.write(File.join(dir, "app/controllers/broken_controller.rb"), <<~RUBY)
        class BrokenController < ApplicationController
          def broken
            x = 1
          end
        end
      RUBY

      File.delete(File.join(dir, "app/views/dashboard/report.html.liquid"))
      File.write(File.join(dir, "app/views/dashboard/report.html.erb"),
        "<h1>Repaired</h1>\n")

      tracker = Brakeman.run(:app_path => dir, :quiet => true, :parallel_checks => false)

      assert tracker.coverage.complete?,
        "once every in-scope file is analyzable there must be no limitation"
      assert_empty tracker.coverage.limitations
      assert_equal 1, tracker.filtered_warnings.length,
        "the dangerous call remains a finding on a complete scan"
    end
  end

  def test_clean_complete_app_has_no_limitation
    tracker = Brakeman.run(
      :app_path => File.expand_path("#{TEST_PATH}/apps/rails6"),
      :quiet => true,
      :parallel_checks => false
    )

    assert tracker.coverage.complete?
    assert_empty tracker.coverage.limitations
  end

  def test_scan_inputs_are_bound_to_actual_files
    tracker = run_demo
    coverage = tracker.coverage

    ruby_files = coverage.scanned_ruby_paths
    template_files = coverage.scanned_template_paths

    assert_includes ruby_files, "app/controllers/dashboard_controller.rb"
    assert_includes template_files, "app/views/dashboard/report.html.liquid"
    assert(ruby_files.length.positive? && template_files.length.positive?)
  end

  def test_incomplete_exit_code_when_zero_warnings
    Dir.mktmpdir('brakeman-coverage') do |dir|
      FileUtils.cp_r("#{DEMO_APP}/.", dir)

      # Remove the dangerous call: no warnings, but a skipped path remains.
      File.write(File.join(dir, "app/controllers/dashboard_controller.rb"), <<~RUBY)
        class DashboardController < ApplicationController
          def run
            x = 1
          end
        end
      RUBY
      File.write(File.join(dir, "app/controllers/broken_controller.rb"), <<~RUBY)
        class BrokenController < ApplicationController
          def broken
            x = 1
          end
        end
      RUBY
      File.delete(File.join(dir, "app/views/dashboard/report.html.liquid"))

      exit_code = run_commandline(dir, "--skip-files", "app/controllers/application_controller.rb")
      assert_equal Brakeman::Incomplete_Scan_Exit_Code, exit_code

      opt_out = run_commandline(dir, "--no-exit-on-incomplete",
        "--skip-files", "app/controllers/application_controller.rb")
      assert_equal 0, opt_out
    end
  end

  def test_warning_exit_code_takes_precedence_over_incomplete
    exit_code = run_commandline(DEMO_APP)
    assert_equal Brakeman::Warnings_Found_Exit_Code, exit_code
  end

  def test_error_exit_code_takes_precedence_over_incomplete
    # The demo has both an error and zero-warning potential after removing the
    # dangerous call; errors (exit 7) must still outrank incompleteness (10).
    Dir.mktmpdir('brakeman-coverage') do |dir|
      FileUtils.cp_r("#{DEMO_APP}/.", dir)
      File.write(File.join(dir, "app/controllers/dashboard_controller.rb"), <<~RUBY)
        class DashboardController < ApplicationController
          def run
            x = 1
          end
        end
      RUBY

      exit_code = run_commandline(dir)
      assert_equal Brakeman::Errors_Found_Exit_Code, exit_code
    end
  end

  def test_report_base_exposes_coverage_rows
    tracker = run_demo
    reporter = Brakeman::Report::Base.new(tracker)
    rows = reporter.coverage_limit_rows

    refute reporter.coverage_complete?

    reasons = rows.map(&:first)
    assert_includes reasons, "parse_error"
    assert_includes reasons, "unsupported_template"

    parse_row = rows.find { |reason, _, _| reason == "parse_error" }
    assert_equal "app/controllers/broken_controller.rb", parse_row[1]
  end

  def test_report_base_has_no_rows_when_complete
    tracker = Brakeman.run(
      :app_path => File.expand_path("#{TEST_PATH}/apps/rails6"),
      :quiet => true,
      :parallel_checks => false
    )
    reporter = Brakeman::Report::Base.new(tracker)

    assert reporter.coverage_complete?
    assert_empty reporter.coverage_limit_rows
  end

  def test_coverage_tracks_repairs_through_rescan
    require 'brakeman/rescanner'

    Dir.mktmpdir('brakeman-coverage') do |dir|
      FileUtils.cp_r("#{DEMO_APP}/.", dir)

      options = {
        :app_path => dir,
        :quiet => true,
        :parallel_checks => false,
        :support_rescanning => true
      }
      original = Brakeman.run(options)
      assert_equal [:errors, :unsupported_templates], original.coverage.limitations.keys

      File.write(File.join(dir, "app/controllers/broken_controller.rb"), <<~RUBY)
        class BrokenController < ApplicationController
          def broken
            x = 1
          end
        end
      RUBY

      rescanner = Brakeman::Rescanner.new(original.options, original.processor,
        ["app/controllers/broken_controller.rb"])
      rescanner.recheck
      rescanned = rescanner.tracker

      assert_empty rescanned.errors
      assert_equal [:unsupported_templates], rescanned.coverage.limitations.keys
      assert_equal 1, rescanned.filtered_warnings.length,
        "the dangerous call must remain a finding after the rescan"
    end
  end

  private

  # Drive the real command line flow but capture the exit code instead of
  # killing the test process.
  def run_commandline(app_path, *extra)
    options, parsed_path = Brakeman::Commandline.parse_options(
      ["-q", "--no-progress", "-n", *extra, app_path]
    )

    catch(:quit_code) do
      Brakeman::Commandline.stub(:quit, ->(code = 0, _msg = nil) { throw :quit_code, code }) do
        Brakeman::Commandline.run(options, parsed_path)
      end
      0
    end
  end
end
