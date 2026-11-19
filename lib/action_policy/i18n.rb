# frozen_string_literal: true

module ActionPolicy
  module I18n # :nodoc:
    DEFAULT_UNAUTHORIZED_MESSAGE = "You are not authorized to perform this action"

    class << self
      def full_message(policy_class, rule, details = nil, locale: nil)
        candidates = candidates_for(policy_class, rule)

        options = {scope: :action_policy}
        options[:locale] = locale unless locale.nil?
        options.merge!(details) unless details.nil?

        ::I18n.t(
          candidates.shift,
          default: candidates,
          **options
        )
      end

      # Resolves a public-safe, localized message for a failure reason category.
      #
      # The detailed business data is intentionally never passed to the translations,
      # so it cannot leak through interpolation. If the only matching translation
      # requires interpolation (i.e. contains `%{...}` placeholders but no values are
      # available), we fall back to the generic `unauthorized` message instead of
      # exposing the raw template.
      def public_full_message(policy_class, rule, locale: nil)
        candidates = candidates_for(policy_class, rule)

        options = {scope: :action_policy}
        options[:locale] = locale unless locale.nil?

        message = ::I18n.t(candidates.first, default: candidates.drop(1), **options)

        return message unless message.to_s.match?(/%\{/)

        ::I18n.t(
          :unauthorized,
          default: [DEFAULT_UNAUTHORIZED_MESSAGE],
          **options
        )
      end

      private

      def candidates_for(policy_class, rule)
        policy_hierarchy = policy_class.ancestors.select { it.respond_to?(:identifier) }
        [
          *policy_hierarchy.map { |klass| :"policy.#{klass.identifier}.#{rule}" },
          :"policy.#{rule}",
          :unauthorized,
          DEFAULT_UNAUTHORIZED_MESSAGE
        ]
      end
    end

    ActionPolicy::Policy::FailureReasons.prepend(Module.new do
      def full_messages
        reasons.flat_map do |policy_klass, rules|
          rules.flat_map do |rule|
            if rule.is_a?(::Hash)
              rule.map do |key, details|
                ActionPolicy::I18n.full_message(policy_klass, key, details)
              end
            else
              ActionPolicy::I18n.full_message(policy_klass, rule)
            end
          end
        end
      end

      # Returns localized, public-safe messages for the failure reasons.
      #
      # Unlike `full_messages`, the detailed business data is never passed to the
      # translations (so it cannot leak through interpolation). Only the translatable
      # error categories are used, and the desired `locale` can be specified to serve
      # public errors in any available language.
      #
      # The messages are derived from the internal store without mutating it, so the
      # query order does not affect the result and internal reasons stay intact.
      def public_messages(locale: nil)
        reasons.flat_map do |policy_klass, rules|
          public_rules(rules).map do |rule|
            ActionPolicy::I18n.public_full_message(policy_klass, rule, locale: locale)
          end
        end
      end
    end)

    ActionPolicy::Policy::ExecutionResult.prepend(Module.new do
      def message
        ActionPolicy::I18n.full_message(policy, rule, details)
      end
    end)
  end
end
