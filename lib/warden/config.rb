# encoding: utf-8
# frozen_string_literal: true

module Warden
  # This class is yielded inside Warden::Manager. If you have a plugin and want to
  # add more configuration to warden, you just need to extend this class.
  class Config < Hash
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
      self[:default_scope]       ||= :default
      self[:scope_defaults]      ||= {}
      self[:default_strategies]  ||= {}
      self[:scope_inheritance]   ||= {}
      self[:intercept_401] = true unless key?(:intercept_401)
    end

    def initialize_copy(other)
      super
      deep_dup(:scope_defaults, other)
      deep_dup(:default_strategies, other)
      deep_dup(:scope_inheritance, other)
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

    # Declares that an authenticated identity for one scope may be reused to
    # satisfy another scope. Inheritance is opt-in and directional: it only
    # applies to the scopes explicitly named here, and the identity flows from
    # the source scope toward the scope being configured.
    #
    # A scope always consults its own session first. The inherited identity is
    # only used as a read-only fallback, so declaring inheritance never writes
    # to, renews, or otherwise touches the source scope's session.
    #
    # Parameters:
    #   target - the scope that may reuse an identity (pass a Hash to declare
    #            several rules at once, mapping target scopes to source scopes)
    #   source - the scope whose authenticated identity may be reused. When
    #            omitted the source is taken from the :from option.
    #
    # Examples:
    #   # the :support scope may reuse the :default identity
    #   config.inherit_scope :support, :default
    #   config.inherit_scope :support, :from => :default
    #
    #   # declare several directional rules at once
    #   config.inherit_scope :support => :default, :auditor => :admin
    #
    # :api: public
    def inherit_scope(*args)
      options = args.last.is_a?(Hash) && args.last.key?(:from) ? args.pop : {}

      if args.first.is_a?(Hash)
        rules = args.first
      else
        target = args.first
        source = args[1] || options[:from]
        rules  = { target => source }
      end

      rules.each do |child, parent|
        child  = validate_inheritance_scope!(child,  "inheriting scope")
        parent = validate_inheritance_scope!(parent, "scope inherited from")
        raise InvalidScopeInheritance,
          "scope #{child.inspect} cannot inherit its own identity; remove the self-inheritance rule" if child == parent
        self[:scope_inheritance][child] = parent
      end

      validate_scope_inheritance!
      self[:scope_inheritance]
    end

    # Returns the source scope that +scope+ reuses an identity from, or nil when
    # the scope has not declared any inheritance.
    # :api: public
    def inherited_scope_for(scope)
      self[:scope_inheritance][scope]
    end

    # Walks the declared inheritance chain for +scope+, returning the scopes
    # consulted as read-only identity sources, nearest first. Returns an empty
    # array when the scope does not inherit from anything.
    # :api: plugin
    def scope_inheritance_chain(scope)
      chain = []
      visited = {}
      while (parent = self[:scope_inheritance][scope])
        raise InvalidScopeInheritance,
          "scope inheritance cycle detected at #{parent.inspect}; break the cycle in your Warden configuration" if visited[parent]
        visited[parent] = true
        chain << parent
        scope = parent
      end
      chain
    end

    # Verifies the whole inheritance graph is acyclic. Called while Warden is
    # configured so an invalid rule fails fast with an actionable message
    # instead of causing infinite recursion during a request.
    # :api: plugin
    def validate_scope_inheritance!
      self[:scope_inheritance].each_key { |scope| scope_inheritance_chain(scope) }
      true
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

  protected

    def deep_dup(key, other)
      self[key] = hash = other[key].dup
      hash.each { |k, v| hash[k] = v.dup }
    end

    def validate_inheritance_scope!(scope, role)
      unless scope.is_a?(Symbol) || scope.is_a?(String)
        raise InvalidScopeInheritance,
          "unknown scope inheritance rule: the #{role} must be a Symbol or String, got #{scope.inspect}"
      end

      scope = scope.to_sym
      if scope.to_s.empty?
        raise InvalidScopeInheritance,
          "unknown scope inheritance rule: the #{role} cannot be blank"
      end
      scope
    end
  end
end
