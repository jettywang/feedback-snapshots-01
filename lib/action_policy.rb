# frozen_string_literal: true

require "ruby-next"

require "ruby-next/language/setup"
RubyNext::Language.setup_gem_load_path(transpile: true)

# ActionPolicy is an authorization framework for Ruby/Rails applications.
#
# It provides a way to write access policies and helpers to check these policies
# in your application.
module ActionPolicy
  class Error < StandardError; end

  # Raised when Action Policy fails to find a policy class for a record.
  class NotFound < Error
    attr_reader :target, :message, :namespace, :strict_namespace, :policy_name

    def initialize(
      target,
      message = nil,
      namespace: nil,
      strict_namespace: false,
      policy_name: nil
    )
      @target = target
      @namespace = namespace
      @strict_namespace = strict_namespace
      @policy_name = policy_name
      @message =
        message ||
        default_message
    end

    private

    def default_message
      base =
        "Couldn't find policy class for #{target.inspect}" \
        "#{" (#{target.class})" unless target.is_a?(Module)}"

      return base unless strict_namespace

      "#{base} within the strict namespace #{namespace_name}" \
        "#{" (expected #{policy_name})" if policy_name}. " \
        "Define the policy inside this namespace or perform the lookup " \
        "without `strict_namespace: true`."
    end

    def namespace_name
      namespace.respond_to?(:name) ? namespace.name : namespace.inspect
    end
  end

  require "action_policy/version"
  require "action_policy/base"
  require "action_policy/lookup_chain"
  require "action_policy/behaviour"
  require "action_policy/i18n" if defined?(::I18n)

  class << self
    attr_accessor :cache_store

    attr_accessor :enforce_predicate_rules_naming

    # Find a policy class for a target
    def lookup(target, allow_nil: false, default: nil, **options)
      LookupChain.call(target, **options) ||
        default ||
        if allow_nil
          nil
        else
          raise NotFound.new(
            target,
            nil,
            namespace: options[:namespace],
            strict_namespace: options[:strict_namespace] == true,
            policy_name: LookupChain.policy_name_for(target)
          )
        end
    end
  end

  require "action_policy/railtie" if defined?(::Rails)
end
