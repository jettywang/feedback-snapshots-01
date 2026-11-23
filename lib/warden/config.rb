# encoding: utf-8
# frozen_string_literal: true

module Warden
  # This class is yielded inside Warden::Manager. If you have a plugin and want to
  # add more configuration to warden, you just need to extend this class.
  class Config < Hash
    # The manager this configuration belongs to. Used to route callbacks
    # declared inside the configuration block to the application's own
    # registry instead of the global one.
    attr_accessor :manager

    # Creates an accessor that simply sets and reads a key in the hash:
    #
    #   class Config < Hash
    #     hash_accessor :failure_app
    #   end
    #
    #   config = Config.new
    #   config.failure_app = Foo
    #   config[:failure_app] #=> Foo
    #
    #   config[:failure_app] = Bar
    #   config.failure_app #=> Bar
    #
    def self.hash_accessor(*names) #:nodoc:
      names.each do |name|
        class_eval <<-METHOD, __FILE__, __LINE__ + 1
          def #{name}
            self[:#{name}]
          end

          def #{name}=(value)
            self[:#{name}] = value
          end
        METHOD
      end
    end

    hash_accessor :failure_app, :default_scope, :intercept_401

    def initialize(other={})
      merge!(other)
      self[:default_scope]      ||= :default
      self[:scope_defaults]     ||= {}
      self[:default_strategies] ||= {}
      self[:intercept_401] = true unless key?(:intercept_401)
    end

    def initialize_copy(other)
      super
      deep_dup(:scope_defaults, other)
      deep_dup(:default_strategies, other)
    end

    # Do not raise an error if a missing strategy is given.
    # :api: plugin
    def silence_missing_strategies!
      self[:silence_missing_strategies] = true
    end

    def silence_missing_strategies? #:nodoc:
      !!self[:silence_missing_strategies]
    end

    # Set the default strategies to use.
    # :api: public
    def default_strategies(*strategies)
      opts  = Hash === strategies.last ? strategies.pop : {}
      hash  = self[:default_strategies]
      scope = opts[:scope] || :_all

      hash[scope] = strategies.flatten unless strategies.empty?
      hash[scope] || hash[:_all] || []
    end

    # A short hand way to set up a particular scope
    # :api: public
    def scope_defaults(scope, opts = {})
      if strategies = opts.delete(:strategies)
        default_strategies(strategies, :scope => scope)
      end

      if opts.empty?
        self[:scope_defaults][scope] || {}
      else
        self[:scope_defaults][scope] ||= {}
        self[:scope_defaults][scope].merge!(opts)
      end
    end

    # Quick accessor to strategies from manager
    # :api: public
    def strategies
      Warden::Strategies
    end

    # Hook from configuration to serialize_into_session.
    # :api: public
    def serialize_into_session(*args, &block)
      Warden::Manager.serialize_into_session(*args, &block)
    end

    # Hook from configuration to serialize_from_session.
    # :api: public
    def serialize_from_session(*args, &block)
      Warden::Manager.serialize_from_session(*args, &block)
    end

    # Authentication callbacks that belong only to this application. They are
    # stored on the manager's own registry and run after the globally
    # registered (operations approved and shared) callbacks.
    #
    # The method names and options mirror the hooks on Warden::Manager.
    #
    # Example:
    #   use Warden::Manager do |config|
    #     config.on_request do |proxy|
    #       # runs only for requests handled by this manager
    #     end
    #   end
    %w(after_set_user after_authentication after_fetch on_request
       before_failure before_logout after_failed_fetch).each do |hook|
      define_method(hook) do |options = {}, method = :push, &block|
        manager.callbacks.public_send(hook, options, method, &block)
      end
    end

    # Prepend variants for every hook that supports them on Warden::Manager.
    %w(after_set_user after_authentication after_fetch on_request
       before_failure before_logout).each do |hook|
      define_method("prepend_#{hook}") do |options = {}, &block|
        manager.callbacks.public_send("prepend_#{hook}", options, &block)
      end
    end

  protected

    def deep_dup(key, other)
      self[key] = hash = other[key].dup
      hash.each { |k, v| hash[k] = v.dup }
    end
  end
end
