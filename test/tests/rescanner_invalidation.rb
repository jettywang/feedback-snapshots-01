require_relative '../test'
require 'tmpdir'
require 'fileutils'
require 'brakeman/rescanner'

# Tests for incremental scanning (rescanning) correctness.
#
# These tests build a small Rails app in a temporary directory,
# then repeatedly modify/delete/restore files and verify that
# each incremental rescan produces exactly the same warnings,
# locations, call index entries, and parse errors as a fresh
# full scan of the same directory.
#
# They also verify the rescan remains incremental: only changed
# files are re-parsed.
class RescannerInvalidationTests < Minitest::Test
  ROUTES = <<~'RUBY'
    Rails.application.routes.draw do
      resources :users
    end
  RUBY

  APPLICATION_RECORD = <<~'RUBY'
    class ApplicationRecord < ActiveRecord::Base
    end
  RUBY

  APPLICATION_CONTROLLER = <<~'RUBY'
    class ApplicationController < ActionController::Base
    end
  RUBY

  USERS_CONTROLLER = <<~'RUBY'
    class UsersController < ApplicationController
      include Dangerable

      def show
        do_danger
        User.search(params[:q])
      end
    end
  RUBY

  # Dangerous: SQL injection via string interpolation
  USER_MODEL_V1 = <<~'RUBY'
    class User < ApplicationRecord
      def self.search(term)
        User.where("name = #{term}")
      end
    end
  RUBY

  # Safe version of the upstream method
  USER_MODEL_SAFE = <<~'RUBY'
    class User < ApplicationRecord
      def self.search(term)
        User.where(name: term)
      end
    end
  RUBY

  # A different dangerous implementation
  USER_MODEL_V2 = <<~'RUBY'
    class User < ApplicationRecord
      def self.search(term)
        User.find_by_sql("select * from users where name = '#{term}'")
      end
    end
  RUBY

  # Unrelated model with its own warning that should
  # remain stable across all rescans
  COMMENT_MODEL = <<~'RUBY'
    class Comment < ApplicationRecord
      def self.search(q)
        Comment.where("body = #{q}")
      end
    end
  RUBY

  COMMENT_MODEL_V2 = <<~'RUBY'
    class Comment < ApplicationRecord
      def self.search(q)
        Comment.where(body: q)
      end
    end
  RUBY

  CONCERN_V1 = <<~'RUBY'
    module Dangerable
      def do_danger
        system(params[:cmd])
      end
    end
  RUBY

  CONCERN_SAFE = <<~'RUBY'
    module Dangerable
      def do_danger
        system("ls")
      end
    end
  RUBY

  HELPER_V1 = <<~'RUBY'
    module UsersHelper
      def run_it
        system(params[:util])
      end
    end
  RUBY

  HELPER_SAFE = <<~'RUBY'
    module UsersHelper
      def run_it
        system("true")
      end
    end
  RUBY

  HELPER_V2 = <<~'RUBY'
    module UsersHelper
      def run_it
        `#{params[:util]}`
      end
    end
  RUBY

  TEMPLATE_V1 = <<~'ERB'
    <%= raw params[:bio] %>
  ERB

  TEMPLATE_SAFE = <<~'ERB'
    <%= params[:bio] %>
  ERB

  TEMPLATE_V2 = <<~'ERB'
    <%= raw cookies[:bio] %>
  ERB

  BROKEN_MODEL = "def broken(\n"
  FIXED_MODEL = "class Broken; end\n"

  APP_FILES = {
    "config/routes.rb" => ROUTES,
    "app/models/application_record.rb" => APPLICATION_RECORD,
    "app/models/user.rb" => USER_MODEL_V1,
    "app/models/comment.rb" => COMMENT_MODEL,
    "app/controllers/application_controller.rb" => APPLICATION_CONTROLLER,
    "app/controllers/users_controller.rb" => USERS_CONTROLLER,
    "app/controllers/concerns/dangerable.rb" => CONCERN_V1,
    "app/helpers/users_helper.rb" => HELPER_V1,
    "app/views/users/show.html.erb" => TEMPLATE_V1,
  }

  USER_RB = "app/models/user.rb"
  COMMENT_RB = "app/models/comment.rb"
  CONCERN_RB = "app/controllers/concerns/dangerable.rb"
  HELPER_RB = "app/helpers/users_helper.rb"
  TEMPLATE = "app/views/users/show.html.erb"
  BROKEN_RB = "app/models/broken.rb"

  # Counts files parsed through Brakeman::FileParser
  # to prove rescans stay incremental
  module ParseCounter
    class << self
      attr_accessor :count
    end

    self.count = 0

    def parse_files list
      ParseCounter.count += list.count
      super
    end

    def read_files list, &block
      ParseCounter.count += list.count
      super
    end
  end

  Brakeman::FileParser.prepend ParseCounter

  def setup
    @dir = Dir.mktmpdir("brakeman-rescan-invalidation")
    write_files APP_FILES
  end

  def teardown
    FileUtils.remove_dir @dir, true
  end

  def write_files files
    files.each do |relative, contents|
      path = File.join(@dir, relative)
      FileUtils.mkdir_p File.dirname(path)
      File.write path, contents
    end
  end

  def remove_file relative
    FileUtils.rm File.join(@dir, relative)
  end

  def scan_options
    {
      app_path: @dir,
      quiet: true,
      pager: false,
      support_rescanning: true,
    }
  end

  # Full scan of the current state of the app directory
  def full_scan
    Brakeman.run scan_options
  end

  # Incremental rescan. Returns [rescanner, report]
  def rescan tracker, changed_files
    rescanner = Brakeman::Rescanner.new(tracker.options, tracker.processor, changed_files)
    report = rescanner.recheck
    [rescanner, report]
  end

  def warning_sigs tracker
    tracker.filtered_warnings.map { |w|
      [w.warning_code, w.file&.relative, w.line, w.message.to_s]
    }.sort
  end

  def error_sigs tracker
    tracker.errors.map { |e| e[:error] }.sort
  end

  # Signature of relevant call index entries,
  # to verify the call index is correctly invalidated
  def call_sigs tracker
    [:where, :find_by_sql, :system, :raw].flat_map { |method|
      tracker.find_call(methods: [method]).map { |call|
        location = call[:location]

        location_name = if location[:type] == :template
          location[:template].name.inspect
        else
          "#{location[:class].inspect}##{location[:method]}"
        end

        [
          call[:target].inspect,
          call[:method].to_s,
          location[:type],
          location_name,
          location[:file]&.relative,
        ]
      }
    }.sort
  end

  # The incremental result must be identical to a fresh
  # full scan of the same directory
  def assert_matches_fresh_scan tracker, step
    fresh = full_scan

    assert_equal warning_sigs(fresh), warning_sigs(tracker),
      "Warnings differ from fresh scan after: #{step}"

    assert_equal error_sigs(fresh), error_sigs(tracker),
      "Errors differ from fresh scan after: #{step}"

    assert_equal call_sigs(fresh), call_sigs(tracker),
      "Call index differs from fresh scan after: #{step}"
  end

  def assert_warning tracker, warning_code, file
    matches = tracker.filtered_warnings.select { |w|
      w.warning_code == warning_code && w.file&.relative == file
    }

    refute_empty matches, "Expected warning #{warning_code} in #{file}"
  end

  def refute_warning tracker, warning_code, file
    matches = tracker.filtered_warnings.select { |w|
      w.warning_code == warning_code && w.file&.relative == file
    }

    assert_empty matches, "Expected no warning #{warning_code} in #{file}"
  end

  # The main scenario: change the upstream method of a dangerous
  # call, delete its definition, then restore a different
  # implementation. Each step is compared against a fresh scan.
  def test_modify_delete_restore_upstream_method
    sql_injection = 0 # CheckSQL warning code

    original = full_scan
    assert_warning original, sql_injection, USER_RB
    assert_matches_fresh_scan original, "initial scan"

    # 1. Make the upstream method safe
    write_files USER_RB => USER_MODEL_SAFE
    rescanner, report = rescan original, [USER_RB]
    assert_equal 1, report.fixed_warnings.length
    assert_equal 0, report.new_warnings.length
    refute_warning rescanner.tracker, sql_injection, USER_RB
    assert_matches_fresh_scan rescanner.tracker, "safe upstream method"

    # 2. Delete the method definition entirely (chained rescan)
    remove_file USER_RB
    rescanner2, _report2 = rescan rescanner.tracker, [USER_RB]
    refute_warning rescanner2.tracker, sql_injection, USER_RB
    assert_matches_fresh_scan rescanner2.tracker, "deleted model"

    # 3. Restore with a different dangerous implementation
    write_files USER_RB => USER_MODEL_V2
    rescanner3, report3 = rescan rescanner2.tracker, [USER_RB]
    assert_equal 1, report3.new_warnings.length
    assert_equal 0, report3.fixed_warnings.length
    assert_warning rescanner3.tracker, sql_injection, USER_RB
    assert_matches_fresh_scan rescanner3.tracker, "restored model with new implementation"
  end

  # Multiple rescans from the same original tracker must not
  # corrupt the original tracker's cached state
  def test_repeated_rescans_from_same_tracker
    sql_injection = 0

    original = full_scan
    original_warnings = warning_sigs(original)
    original_cached_models = original.pristine_file_cache.models.keys.sort

    # First rescan: make the model safe
    write_files USER_RB => USER_MODEL_SAFE
    rescanner1, _ = rescan original, [USER_RB]
    refute_warning rescanner1.tracker, sql_injection, USER_RB
    assert_matches_fresh_scan rescanner1.tracker, "first rescan"

    # The original tracker must be untouched by the rescan
    assert_equal original_warnings, warning_sigs(original)
    assert_equal original_cached_models, original.pristine_file_cache.models.keys.sort

    # Revert the file on disk to the dangerous version,
    # then rescan an unrelated change from the SAME original tracker
    write_files USER_RB => USER_MODEL_V1, COMMENT_RB => COMMENT_MODEL_V2
    rescanner2, _ = rescan original, [COMMENT_RB]

    # The dangerous model must be picked up from the intact cache
    assert_warning rescanner2.tracker, sql_injection, USER_RB
    assert_matches_fresh_scan rescanner2.tracker, "second rescan from same tracker"
  end

  def test_modify_and_delete_concern
    command_injection = 14 # CheckExecute warning code

    original = full_scan
    assert_warning original, command_injection, CONCERN_RB

    # Modify the concern to be safe
    write_files CONCERN_RB => CONCERN_SAFE
    rescanner, report = rescan original, [CONCERN_RB]
    assert_equal 1, report.fixed_warnings.length
    assert_equal 0, report.new_warnings.length
    refute_warning rescanner.tracker, command_injection, CONCERN_RB
    assert_matches_fresh_scan rescanner.tracker, "safe concern"

    # Delete the concern
    remove_file CONCERN_RB
    rescanner2, _ = rescan rescanner.tracker, [CONCERN_RB]
    refute_warning rescanner2.tracker, command_injection, CONCERN_RB
    assert_matches_fresh_scan rescanner2.tracker, "deleted concern"

    # Restore the dangerous concern
    write_files CONCERN_RB => CONCERN_V1
    rescanner3, report3 = rescan rescanner2.tracker, [CONCERN_RB]
    assert_equal 1, report3.new_warnings.length
    assert_warning rescanner3.tracker, command_injection, CONCERN_RB
    assert_matches_fresh_scan rescanner3.tracker, "restored concern"
  end

  def test_modify_and_delete_helper
    command_injection = 14

    original = full_scan
    assert_warning original, command_injection, HELPER_RB

    # Modify the helper to be safe
    write_files HELPER_RB => HELPER_SAFE
    rescanner, report = rescan original, [HELPER_RB]
    assert_equal 1, report.fixed_warnings.length
    assert_equal 0, report.new_warnings.length
    refute_warning rescanner.tracker, command_injection, HELPER_RB
    assert_matches_fresh_scan rescanner.tracker, "safe helper"

    # Delete the helper
    remove_file HELPER_RB
    rescanner2, _ = rescan rescanner.tracker, [HELPER_RB]
    refute_warning rescanner2.tracker, command_injection, HELPER_RB
    assert_matches_fresh_scan rescanner2.tracker, "deleted helper"

    # Restore with a different dangerous implementation
    write_files HELPER_RB => HELPER_V2
    rescanner3, report3 = rescan rescanner2.tracker, [HELPER_RB]
    assert_equal 1, report3.new_warnings.length
    assert_warning rescanner3.tracker, command_injection, HELPER_RB
    assert_matches_fresh_scan rescanner3.tracker, "restored helper"
  end

  def test_modify_and_delete_template
    xss = 2 # CheckCrossSiteScripting warning code

    original = full_scan
    assert_warning original, xss, TEMPLATE

    # Modify the template to be safe
    write_files TEMPLATE => TEMPLATE_SAFE
    rescanner, report = rescan original, [TEMPLATE]
    assert_equal 1, report.fixed_warnings.length
    assert_equal 0, report.new_warnings.length
    refute_warning rescanner.tracker, xss, TEMPLATE
    assert_matches_fresh_scan rescanner.tracker, "safe template"

    # Delete the template
    remove_file TEMPLATE
    rescanner2, _ = rescan rescanner.tracker, [TEMPLATE]
    refute_warning rescanner2.tracker, xss, TEMPLATE
    assert_matches_fresh_scan rescanner2.tracker, "deleted template"

    # Restore with a different dangerous implementation
    write_files TEMPLATE => TEMPLATE_V2
    rescanner3, report3 = rescan rescanner2.tracker, [TEMPLATE]
    assert_equal 1, report3.new_warnings.length
    assert_warning rescanner3.tracker, xss, TEMPLATE
    assert_matches_fresh_scan rescanner3.tracker, "restored template"
  end

  # Parse errors in files that are not re-parsed must be
  # preserved, and must disappear when the file is fixed
  def test_parse_errors_survive_rescan_of_other_files
    write_files BROKEN_RB => BROKEN_MODEL

    original = full_scan
    assert_equal 1, original.errors.length
    assert_match BROKEN_RB, original.errors.first[:error]

    # Rescan an unrelated change: broken.rb is not re-parsed,
    # but its parse error must be preserved
    write_files COMMENT_RB => COMMENT_MODEL_V2
    rescanner, _ = rescan original, [COMMENT_RB]
    assert_matches_fresh_scan rescanner.tracker, "rescan with broken file"
    assert_equal 1, rescanner.tracker.errors.length

    # Fix the broken file: the error must disappear
    write_files BROKEN_RB => FIXED_MODEL
    rescanner2, _ = rescan rescanner.tracker, [BROKEN_RB]
    assert_equal 0, rescanner2.tracker.errors.length
    assert_matches_fresh_scan rescanner2.tracker, "fixed broken file"

    # Break it again: the error must reappear
    write_files BROKEN_RB => BROKEN_MODEL
    rescanner3, _ = rescan rescanner2.tracker, [BROKEN_RB]
    assert_equal 1, rescanner3.tracker.errors.length
    assert_matches_fresh_scan rescanner3.tracker, "re-broken file"
  end

  # The order of changed files given to the rescanner
  # must not affect the results
  def test_changed_file_order_does_not_matter
    original = full_scan

    write_files USER_RB => USER_MODEL_SAFE,
      HELPER_RB => HELPER_SAFE,
      TEMPLATE => TEMPLATE_SAFE,
      COMMENT_RB => COMMENT_MODEL_V2
    remove_file CONCERN_RB

    changed = [USER_RB, HELPER_RB, TEMPLATE, COMMENT_RB, CONCERN_RB]

    rescanner1, _ = rescan original, changed
    # Reversed and with duplicates: results must be identical
    rescanner2, _ = rescan original, changed.reverse + changed

    assert_equal warning_sigs(rescanner1.tracker), warning_sigs(rescanner2.tracker)
    assert_equal error_sigs(rescanner1.tracker), error_sigs(rescanner2.tracker)
    assert_equal call_sigs(rescanner1.tracker), call_sigs(rescanner2.tracker)

    assert_matches_fresh_scan rescanner1.tracker, "ordered changes"
    assert_matches_fresh_scan rescanner2.tracker, "reversed changes"
  end

  # Rescanning must stay incremental: only changed files
  # are parsed again
  def test_rescan_only_parses_changed_files
    ParseCounter.count = 0
    original = full_scan
    full_scan_count = ParseCounter.count

    assert full_scan_count >= APP_FILES.length - 1,
      "Expected full scan to parse at least #{APP_FILES.length - 1} files, got #{full_scan_count}"

    # Rescan a single changed file
    write_files USER_RB => USER_MODEL_SAFE
    ParseCounter.count = 0
    rescanner, _ = rescan original, [USER_RB]
    assert_equal 1, ParseCounter.count
    assert_matches_fresh_scan rescanner.tracker, "single file rescan"

    # Rescan two changed files
    write_files HELPER_RB => HELPER_SAFE, TEMPLATE => TEMPLATE_SAFE
    ParseCounter.count = 0
    rescanner2, _ = rescan rescanner.tracker, [HELPER_RB, TEMPLATE]
    assert_equal 2, ParseCounter.count
    assert_matches_fresh_scan rescanner2.tracker, "two file rescan"

    # A change that cannot affect results parses nothing
    write_files "README.md" => "hello\n"
    ParseCounter.count = 0
    rescanner3, report3 = rescan rescanner2.tracker, ["README.md"]
    assert_equal 0, ParseCounter.count
    assert_equal false, report3.warnings_changed?
  end
end
