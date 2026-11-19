require_relative '../test'
require 'tmpdir'
require 'fileutils'
require 'brakeman/scanner'
require 'brakeman/rescanner'

class SinkIdentityRescanTests < Minitest::Test
  def setup
    @dir = Dir.mktmpdir("brakeman-sink-rescan")
    %w[app/controllers app/models config].each { |d| FileUtils.mkdir_p(File.join(@dir, d)) }

    File.write(File.join(@dir, "app/models/user.rb"), "class User < ActiveRecord::Base\nend\n")
    File.write(File.join(@dir, "config/routes.rb"), "Rails.application.routes.draw do\n  resources :users\nend\n")
    File.write(File.join(@dir, "config/application.rb"), "module SinkApp; class Application < Rails::Application; end; end\n")
    write_controller(SITEMAP)
    scan # establish the baseline before any test edits the file
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  SITEMAP = <<~'RUBY'
    class UsersController < ApplicationController
      def sitemap
        User.where(params[:a] + params[:b])
      end

      def feeds
        User.where(params[:a] + params[:b])
      end
    end
  RUBY

  CHANGED_FEEDS = <<~'RUBY'
    class UsersController < ApplicationController
      def sitemap
        User.where(params[:a] + params[:b])
      end

      def feeds
        User.where("role = '#{params[:a]}'")
      end
    end
  RUBY

  CHANGED_SOURCE = <<~'RUBY'
    class UsersController < ApplicationController
      def sitemap
        User.where(params[:a] + params[:b])
      end

      def feeds
        User.where(params[:a] + params[:c])
      end
    end
  RUBY

  ADDED_CALL = <<~'RUBY'
    class UsersController < ApplicationController
      def sitemap
        User.where(params[:a] + params[:b])
      end

      def feeds
        User.where(params[:a] + params[:b])
      end

      def legacy
        User.where(params[:a] + params[:b])
      end
    end
  RUBY

  def write_controller(src)
    @controller_path = "app/controllers/users_controller.rb"
    File.write(File.join(@dir, @controller_path), src)
  end

  def scan
    @scan ||= Brakeman.run(app_path: @dir, rails4: true, force_scan: true,
                           parallel_checks: false, support_rescanning: true)
  end

  def rescan
    tracker = Marshal.load(Marshal.dump(scan.marshallable))
    Brakeman::Rescanner.new(tracker.options, tracker.processor, [@controller_path]).recheck
  end

  def test_formatting_only_change_has_no_diff
    write_controller(SITEMAP.sub("    User.where(params[:a] + params[:b])\n  end\n\n  def feeds",
                                 "\n    User.where( params[:a] + params[:b] )\n  end\n\n  def feeds"))
    report = rescan

    assert_empty report.new_warnings
    assert_empty report.fixed_warnings
  end

  def test_semantic_change_reports_one_new_and_one_fixed
    write_controller(CHANGED_FEEDS)
    report = rescan

    assert_equal 1, report.new_warnings.length
    assert_equal 1, report.fixed_warnings.length
    assert_equal :feeds, report.fixed_warnings.first.method
    assert_equal :feeds, report.new_warnings.first.method
  end

  def test_source_change_keeps_sink_identity_but_updates_evidence
    write_controller(CHANGED_SOURCE)
    report = rescan

    assert_empty report.fixed_warnings
    feeds = report.all_warnings.find { |w| w.method == :feeds }
    assert_equal ["params[:a]", "params[:c]"], feeds.evidence.map(&:code).sort
  end

  def test_added_real_call_is_only_new
    write_controller(ADDED_CALL)
    report = rescan

    assert_equal 1, report.new_warnings.length
    assert_empty report.fixed_warnings
    assert_equal :legacy, report.new_warnings.first.method
  end
end
