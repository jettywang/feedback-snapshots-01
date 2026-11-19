require_relative '../test'
require 'tmpdir'
require 'fileutils'
require 'json'
require 'brakeman/report/ignore/config'

class SinkIdentityIgnoreTests < Minitest::Test
  def setup
    @dir = Dir.mktmpdir("brakeman-sink-ignore")
    %w[app/controllers app/models config].each { |d| FileUtils.mkdir_p(File.join(@dir, d)) }
    File.write(File.join(@dir, "app/models/user.rb"), "class User < ActiveRecord::Base\nend\n")
    File.write(File.join(@dir, "config/routes.rb"), "Rails.application.routes.draw do\n  resources :users\nend\n")
    File.write(File.join(@dir, "config/application.rb"), "module SinkApp; class Application < Rails::Application; end; end\n")
    @controller = File.join(@dir, "app/controllers/users_controller.rb")
    write_controller(two_sinks)
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.exist?(@dir)
  end

  def two_sinks
    <<~RUBY
      class UsersController < ApplicationController
        def one
          User.where(params[:a] + params[:b])
        end
        def two
          User.where(params[:a] + params[:b])
        end
      end
    RUBY
  end

  def one_sink
    <<~RUBY
      class UsersController < ApplicationController
        def one
          User.where(params[:a] + params[:b])
        end
        def two
          User.where(id: 1)
        end
      end
    RUBY
  end

  def write_controller(src)
    File.write(@controller, src)
  end

  def scan
    Brakeman.run(app_path: @dir, rails4: true, force_scan: true, parallel_checks: false)
  end

  def ignore_file(entries)
    path = File.join(@dir, "config/brakeman.ignore")
    File.write(path, JSON.pretty_generate(ignored_warnings: entries, brakeman_version: "8.1.0"))
    path
  end

  def config_for(warnings, entries)
    config = Brakeman::IgnoreConfig.new(ignore_file(entries), warnings)
    config.read_from_file
    config.filter_ignored
    config
  end

  def test_ambiguous_legacy_entry_is_not_widened
    original = scan
    first = original.warnings.find { |w| w.method == :one }

    config = config_for(original.warnings, [{
      fingerprint: first.legacy_fingerprint,
      file: "app/controllers/users_controller.rb",
      line: first.line,
      note: "legacy"
    }])

    assert_equal 1, config.ignored_warnings.length
    assert_equal 1, config.shown_warnings.length
    assert_equal :one, config.ignored_warnings.first.method
    assert_equal :two, config.shown_warnings.first.method
  end

  def test_legacy_entry_migrates_when_candidate_is_unique
    original = scan
    first = original.warnings.find { |w| w.method == :one }

    write_controller(one_sink)
    after = scan

    config = config_for(after.warnings, [{
      fingerprint: first.legacy_fingerprint,
      file: "app/controllers/users_controller.rb",
      line: first.line,
      note: "keep me"
    }])

    assert_equal 1, config.ignored_warnings.length
    assert_empty config.shown_warnings
    assert_equal "keep me", config.note_for(config.ignored_warnings.first)
    assert_empty config.obsolete_fingerprints

    config.save_with_old
    saved = JSON.parse(File.read(config.file), symbolize_names: true)[:ignored_warnings]
    assert_equal 1, saved.length
    assert_equal config.ignored_warnings.first.fingerprint, saved.first[:fingerprint]
    assert_equal "keep me", saved.first[:note]
  end

  def test_legacy_entry_for_removed_sink_does_not_ignore_similar_sink
    original = scan
    first = original.warnings.find { |w| w.method == :one }

    # Remove the original sink and leave only a different one that shares its
    # structure but has a different legacy fingerprint (different method).
    write_controller(<<~RUBY)
      class UsersController < ApplicationController
        def two
          User.where(params[:a] + params[:b])
        end
      end
    RUBY
    after = scan

    config = config_for(after.warnings, [{
      fingerprint: first.legacy_fingerprint,
      file: "app/controllers/users_controller.rb",
      line: first.line,
      note: "stale"
    }])

    assert_empty config.ignored_warnings
    assert_equal 1, config.shown_warnings.length
    refute_empty config.obsolete_fingerprints
  end
end
