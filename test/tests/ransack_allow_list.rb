require_relative '../test'
require 'tmpdir'
require 'fileutils'

class RansackAllowListTests < Minitest::Test
  def setup
    @tmpdir = Dir.mktmpdir('brakeman-ransack')
    write_app
    @tracker = scan
    @check = Brakeman::CheckRansack.new(@tracker)
  end

  def teardown
    FileUtils.remove_entry @tmpdir if @tmpdir
  end

  def write_app
    FileUtils.mkdir_p File.join(@tmpdir, 'app', 'models')
    FileUtils.mkdir_p File.join(@tmpdir, 'app', 'controllers')
    FileUtils.mkdir_p File.join(@tmpdir, 'config')

    File.write File.join(@tmpdir, 'config', 'routes.rb'), "Rails.application.routes.draw do\nend\n"
    File.write File.join(@tmpdir, 'config', 'application.rb'), <<~RUBY
      require 'rails'
      module RansackFixture
        class Application < Rails::Application
        end
      end
    RUBY
    File.write File.join(@tmpdir, 'app', 'controllers', 'application_controller.rb'), "class ApplicationController < ActionController::Base\nend\n"
    File.write File.join(@tmpdir, 'app', 'models', 'application_record.rb'), "class ApplicationRecord < ActiveRecord::Base\n  primary_abstract_class\nend\n"
    File.write File.join(@tmpdir, 'Gemfile'), "source 'https://rubygems.org'\ngem 'rails', '= 7.0.4'\ngem 'ransack', '= 3.0.1'\n"
    File.write File.join(@tmpdir, 'Gemfile.lock'), <<~LOCK
      GEM
        remote: https://rubygems.org/
        specs:
          rails (7.0.4)
          ransack (3.0.1)

      PLATFORMS
        ruby

      DEPENDENCIES
        rails (= 7.0.4)
        ransack (= 3.0.1)

      BUNDLED WITH
         2.4.0
    LOCK
  end

  def add_model name, source
    File.write File.join(@tmpdir, 'app', 'models', "#{name.to_s.downcase}.rb"), source
    @tracker = scan
    @check = Brakeman::CheckRansack.new(@tracker)
  end

  def scan
    opts = Brakeman.set_options(
      app_path: @tmpdir,
      parallel_checks: false,
      quiet: true
    )
    Brakeman.run(opts)
  end

  def analyze class_name, method = :ransackable_attributes, kind = :attributes
    @check.analyze_allow_list(class_name, method, kind)
  end

  def test_finite_literal_list
    add_model :Finite, <<~RUBY
      class Finite < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          [:title, :body]
        end

        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    assert analyze(:Finite).finite?
    assert analyze(:Finite, :ransackable_associations, :associations).finite?
  end

  def test_finite_constant_list
    add_model :ConstFinite, <<~RUBY
      class ConstFinite < ApplicationRecord
        ATTRIBUTES = %w[title body].freeze

        def self.ransackable_attributes(auth_object = nil)
          ATTRIBUTES
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    assert analyze(:ConstFinite).finite?
  end

  def test_finite_conditional_branches
    add_model :ConditionalFinite, <<~RUBY
      class ConditionalFinite < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          if auth_object&.admin?
            %w[title]
          else
            %w[title body]
          end
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    assert analyze(:ConditionalFinite).finite?
  end

  def test_unrestricted_column_names_branch
    add_model :ConditionalFallback, <<~RUBY
      class ConditionalFallback < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          if auth_object&.admin?
            [:title]
          else
            column_names
          end
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    result = analyze(:ConditionalFallback)

    assert result.unrestricted?
    assert_match(/column_names/, result.reason)
    assert_match(/conditional branch/, result.reason)
  end

  def test_unrestricted_reflect_on_all_associations
    add_model :SelectedAssociations, <<~RUBY
      class SelectedAssociations < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          [:title]
        end
        def self.ransackable_associations(auth_object = nil)
          reflect_on_all_associations.map(&:name)
        end
      end
    RUBY

    result = analyze(:SelectedAssociations, :ransackable_associations, :associations)

    assert result.unrestricted?
    assert_match(/reflect_on_all_associations/, result.reason)
  end

  def test_inherited_association_permission_is_checked
    add_model :BaseSearch, <<~RUBY
      class BaseSearch < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          [:title]
        end
        def self.ransackable_associations(auth_object = nil)
          reflect_on_all_associations.map(&:name)
        end
      end

      class NarrowChild < BaseSearch
        def self.ransackable_attributes(auth_object = nil)
          [:title]
        end
      end
    RUBY

    assert analyze(:NarrowChild).finite?
    assert analyze(:NarrowChild, :ransackable_associations, :associations).unrestricted?
  end

  def test_parent_default_via_super
    add_model :SuperChild, <<~RUBY
      class SuperParent < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          [:title]
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end

      class SuperChild < SuperParent
        def self.ransackable_attributes(auth_object = nil)
          super
        end
      end
    RUBY

    assert analyze(:SuperChild).finite?
    assert analyze(:SuperChild, :ransackable_associations, :associations).finite?
  end

  def test_missing_method_is_unrestricted
    add_model :Bare, <<~RUBY
      class Bare < ApplicationRecord
      end
    RUBY

    assert analyze(:Bare).unrestricted?
    assert analyze(:Bare, :ransackable_associations, :associations).unrestricted?
  end

  def test_dynamic_unknown_return_is_not_trusted
    add_model :Dynamic, <<~RUBY
      class Dynamic < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          allowed_attributes_for(auth_object)
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    result = analyze(:Dynamic)

    assert result.unknown?
    refute result.finite?
    assert_match(/cannot be proven finite/, result.reason)
  end

  def test_recombined_request_input_is_unrestricted
    add_model :Recombined, <<~RUBY
      class Recombined < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          [:title] + [params[:column]]
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    result = analyze(:Recombined)

    assert result.unrestricted?
    assert_match(/request input/, result.reason)
  end

  def test_early_return_all_paths_are_considered
    add_model :Early, <<~RUBY
      class Early < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          return [:admin] if auth_object&.admin?
          column_names
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    assert analyze(:Early).unrestricted?
  end

  def test_constant_from_included_module
    File.write File.join(@tmpdir, 'app', 'models', 'shared_allow_list.rb'), <<~RUBY
      module SharedAllowList
        ATTRIBUTES = %w[shared_a shared_b]
      end
    RUBY
    add_model :ModuleUser, <<~RUBY
      class ModuleUser < ApplicationRecord
        include SharedAllowList

        def self.ransackable_attributes(auth_object = nil)
          ATTRIBUTES
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    result = analyze(:ModuleUser)

    assert result.finite?
    assert_equal Set['shared_a', 'shared_b'], result.names
  end

  def test_association_to_unrestricted_model_is_not_safe
    add_model :RelatedAuthor, <<~RUBY
      class RelatedAuthor < ApplicationRecord
        has_many :related_books

        def self.ransackable_attributes(auth_object = nil)
          [:name]
        end
        def self.ransackable_associations(auth_object = nil)
          [:related_books]
        end
      end

      class RelatedBook < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          column_names
        end
        def self.ransackable_associations(auth_object = nil)
          []
        end
      end
    RUBY

    capability = @check.search_capability(:RelatedAuthor)

    refute capability[:available]
    assert capability[:definite]
    assert_match(/related model with unrestricted search/, capability[:reasons].join)
  end

  def test_unresolved_association_is_not_proven_finite
    add_model :UnknownAssociation, <<~RUBY
      class UnknownAssociation < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          []
        end
        def self.ransackable_associations(auth_object = nil)
          [:widgets]
        end
      end
    RUBY

    capability = @check.search_capability(:UnknownAssociation)

    refute capability[:available]
    refute capability[:definite]
    assert_match(/could not be resolved/, capability[:reasons].join)
  end

  def test_associations_are_checked_separately
    add_model :AttributeOnly, <<~RUBY
      class AttributeOnly < ApplicationRecord
        def self.ransackable_attributes(auth_object = nil)
          []
        end
        def self.ransackable_associations(auth_object = nil)
          allowed_associations
        end
      end
    RUBY

    assert analyze(:AttributeOnly).finite?
    assert analyze(:AttributeOnly, :ransackable_associations, :associations).unknown?
  end
end
