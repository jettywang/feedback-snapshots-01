# frozen_string_literal: true

module Grape
  class Entity
    module Disclosure
      # Immutable per-representation state shared by every entity rendered by a
      # single +Entity.represent+ call. Keeping it in the options chain (instead
      # of in global state) is what keeps sibling records and later requests
      # from inheriting each other's scope.
      class Context
        attr_reader :policy, :receipt

        def initialize(policy:, receipt: nil)
          @policy = policy
          @receipt = receipt
          freeze
        end

        def self.build(config, receipt: nil)
          return config if config.is_a?(Context)

          policy = build_policy(config)
          configured_receipt = config.is_a?(Hash) ? config[:receipt] : nil
          # A caller-supplied receipt object is authoritative; a +receipt: true+
          # flag in the configuration only asks for a fresh one.
          receipt = receipt_from(receipt) || receipt_from(configured_receipt)
          new(policy: policy, receipt: receipt)
        end

        def self.build_policy(config)
          if config.is_a?(Policy)
            config
          elsif config.respond_to?(:resolve) && !config.is_a?(Hash)
            config
          elsif config.is_a?(Hash)
            build_policy_from_hash(config)
          elsif config.respond_to?(:call)
            Policy.new(&config)
          elsif config.nil? || config == true || config == false
            Policy.new
          else
            raise ArgumentError, 'disclosure must be a policy, a callable, or a configuration Hash'
          end
        end

        def self.build_policy_from_hash(config)
          resolver = config[:resolver] || config[:scope_for] || path_resolver(config[:paths])
          Policy.new(
            default: config[:default],
            identifier: config[:identifier],
            levels: config[:levels],
            &resolver
          )
        end

        # A plain server-supplied map of occurrence path to scope, e.g.
        # +{ [:groups, 0, :orders] => :summary }+. It is a convenience over a
        # resolver and follows the same per-occurrence semantics.
        def self.path_resolver(paths)
          return unless paths

          normalized = paths.each_with_object({}) { |(path, scope), memo| memo[Array(path)] = scope }
          ->(_object, occurrence, _options) { normalized[occurrence.path] }
        end

        def self.receipt_from(value)
          return value if value.is_a?(Receipt)
          return Receipt.new if value == true

          nil
        end

        def levels
          policy.respond_to?(:levels) ? policy.levels : []
        end

        def default_scope
          policy.respond_to?(:default_scope) ? policy.default_scope : nil
        end

        def resolve(object, occurrence, options)
          policy.resolve(object, occurrence, options)
        end

        def identifier_for(object)
          policy.identifier_for(object)
        end

      end
    end
  end
end
