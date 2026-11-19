require_relative '../test'
require 'tmpdir'
require 'fileutils'
require 'brakeman/report/ignore/config'

# Small end-to-end app exercising the identity/evidence rules described in the
# task: one sink with two sources, another similar sink, duplicate calls, and
# templates rendered from two controllers.
class SinkIdentityIntegrationTests < Minitest::Test
  def setup
    @dir = Dir.mktmpdir("brakeman-sink-identity")
    write_app
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  def write_app
    %w[app/controllers app/models app/views/users config/initializers].each do |d|
      FileUtils.mkdir_p(File.join(@dir, d))
    end

    File.write(File.join(@dir, "app/controllers/users_controller.rb"), <<~RUBY)
      class UsersController < ApplicationController
        def show
          @user = User.find(params[:id])
          render "users/show"
        end

        def sitemap
          User.where(params[:a] + params[:b])
        end

        def feeds
          User.where(params[:a] + params[:b])
        end
      end

      class AdminController < ApplicationController
        def show
          @user = User.find(params[:admin_id])
          render "users/show"
        end
      end
    RUBY

    File.write(File.join(@dir, "app/models/user.rb"), "class User < ActiveRecord::Base\nend\n")
    File.write(File.join(@dir, "app/views/users/show.html.erb"), "<%= raw @user.name %>\n")
    File.write(File.join(@dir, "config/routes.rb"), <<~RUBY)
      Rails.application.routes.draw do
        get "users/show" => "users#show"
        get "admin/show" => "admin#show"
      end
    RUBY
    File.write(File.join(@dir, "config/application.rb"), "module SinkApp; class Application < Rails::Application; end; end\n")
  end

  def scan
    @scan ||= Brakeman.run(app_path: @dir, rails4: true, force_scan: true,
                           parallel_checks: false, assume_all_routes: false)
  end

  def sql_warnings
    scan.warnings.select { |w| w.warning_type == "SQL Injection" }.sort_by(&:line)
  end

  def xss_warnings
    scan.warnings.select { |w| w.warning_type == "Cross-Site Scripting" }
  end

  def test_same_sink_with_two_sources_reports_once_with_both_sources
    warning = sql_warnings.find { |w| w.method == :sitemap }

    assert_equal ["params[:a]", "params[:b]"], warning.evidence.map(&:code).sort
  end

  def test_similar_sink_in_other_action_is_distinct
    assert_equal 2, sql_warnings.length
    refute_equal sql_warnings[0].sink_id, sql_warnings[1].sink_id
  end

  def test_template_sink_reached_from_two_controllers_reports_once_with_both_paths
    assert_equal 1, xss_warnings.length
    warning = xss_warnings.first

    paths = warning.render_paths.map { |p| p.respond_to?(:to_a) ? p.to_a : p }
    assert_equal [["AdminController#show"], ["UsersController#show"]], paths.sort
    assert_equal ["params[:admin_id]", "params[:id]"], warning.evidence.map(&:code).sort
  end

  def test_identical_outputs_on_one_template_line_are_distinct
    File.write(File.join(@dir, "app/views/users/show.html.erb"),
               "<%= raw params[:a] %> <%= raw params[:a] %>\n")

    warnings = Brakeman.run(app_path: @dir, rails4: true, force_scan: true,
                            parallel_checks: false, assume_all_routes: false)
      .warnings.select { |w| w.warning_type == "Cross-Site Scripting" }

    assert_equal 2, warnings.length
    refute_equal warnings[0].sink_id, warnings[1].sink_id
    refute_equal warnings[0].fingerprint, warnings[1].fingerprint
  end

  def test_identical_outputs_on_different_template_lines_are_distinct
    File.write(File.join(@dir, "app/views/users/show.html.erb"),
               "<%= raw params[:a] %>\n<%= raw params[:a] %>\n")

    warnings = Brakeman.run(app_path: @dir, rails4: true, force_scan: true,
                            parallel_checks: false, assume_all_routes: false)
      .warnings.select { |w| w.warning_type == "Cross-Site Scripting" }

    assert_equal 2, warnings.length
    refute_equal warnings[0].fingerprint, warnings[1].fingerprint
  end

  def test_same_finding_survives_pure_formatting_move
    first = scan.warnings.find { |w| w.method == :sitemap }

    src = File.read(File.join(@dir, "app/controllers/users_controller.rb"))
    moved = src.sub("  def sitemap\n    User.where(params[:a] + params[:b])",
                    "  def sitemap\n\n    User.where( params[:a] + params[:b] )")
    File.write(File.join(@dir, "app/controllers/users_controller.rb"), moved)

    after = Brakeman.run(app_path: @dir, rails4: true, force_scan: true,
                         parallel_checks: false, assume_all_routes: false)
      .warnings.find { |w| w.method == :sitemap }

    assert_equal first.sink_id, after.sink_id
    assert_equal first.fingerprint, after.fingerprint
  end

  def test_warning_to_hash_exposes_identity_and_evidence
    hash = xss_warnings.first.to_hash

    assert hash[:sink_id]
    assert_equal ["params[:admin_id]", "params[:id]"], hash[:evidence].map { |e| e[:code] }.sort
    assert_equal 2, hash[:render_paths].length
  end
end
