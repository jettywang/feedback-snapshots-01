# frozen_string_literal: true

module ActionPolicy
  # Raised when aliases point to each other and never reach a concrete rule.
  class CircularRule < (defined?(ActionPolicy::Error) ? ActionPolicy::Error : StandardError)
    attr_reader :policy, :rule, :chain, :message

    def initialize(policy, rule, chain)
      @policy = policy.class
      @rule = rule
      @chain = chain.freeze
      @message = "Circular rule reference for #{@policy}##{rule}: " \
        "#{chain.map(&:inspect).join(" -> ")}"
    end
  end

  module Policy
    # Internal, side-effect-free policy rule resolution.
    #
    # It is shared by `Aliases#resolve_rule` (the runtime entry point) and
    # `Policy::Contract` (the inspection entry point), so contract reports
    # always describe what would actually be applied.
    class RuleResolution
      MAX_CHAIN_LENGTH = 64

      attr_reader :policy, :rule, :chain, :status, :target

      def self.call(policy, rule) = new(policy, rule)

      def initialize(policy, rule)
        @policy = policy
        @rule = rule
        @chain = []
        @status = nil
        @target = nil

        resolve
        @chain.freeze
      end

      def direct? = status == :rule
      def alias? = status == :alias
      def default? = status == :default
      def missing? = status == :missing
      def cycle? = status == :cycle
      def too_long? = status == :too_long
      def resolved? = !target.nil?
      def fallback? = default?
      def alias_used? = @alias_used
      def default_used? = @default_used

      def inspect
        "#<#{self.class} policy=#{policy} rule=#{rule.inspect} " \
          "chain=#{chain.inspect} status=#{status.inspect} target=#{target.inspect}>"
      end

      private

      def resolve
        @alias_used = false
        @default_used = false
        seen = {rule => true}
        current = rule

        loop do
          if chain.length >= MAX_CHAIN_LENGTH
            @status = :too_long
            return
          end

          chain << current

          if (alias_target = lookup_alias(current))
            @alias_used = true

            if seen.key?(alias_target)
              chain << alias_target
              @status = :cycle
              return
            end

            seen[alias_target] = true
            current = alias_target
            next
          end

          if policy.public_method_defined?(current)
            @status = @default_used ? :default : (@alias_used ? :alias : :rule)
            @target = current
            return
          end

          # An alias always wins over the default rule (even when its target is
          # missing); do not silently fall back to the default after an alias.
          if @alias_used
            @status = :missing
            return
          end

          default_rule = lookup_default_rule

          if default_rule.nil?
            @status = :missing
            return
          end

          # The default rule is applied as-is (it is not resolved through
          # aliases), matching the original resolution order.
          chain << default_rule
          @default_used = true
          @status = :default
          @target = default_rule
          return
        end
      end

      def lookup_alias(rule) = policy.lookup_alias(rule)

      def lookup_default_rule = policy.lookup_default_rule
    end
  end
end
