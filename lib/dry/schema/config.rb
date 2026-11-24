# frozen_string_literal: true

require "dry/core/equalizer"
require "dry/configurable"
require "dry/schema/constants"

module Dry
  module Schema
    # Schema definition configuration class
    #
    # @see DSL#configure
    #
    # @api public
    class Config
      include ::Dry::Configurable
      include ::Dry::Equalizer(:to_h, inspect: false)

      # @!method predicates
      #
      # Return configured predicate registry
      #
      # @return [Schema::PredicateRegistry]
      #
      # @api public
      setting :predicates, default: PredicateRegistry.new, constructor: -> predicates {
        predicates.is_a?(PredicateRegistry) ? predicates : PredicateRegistry.new(predicates)
      }

      # @!method types
      #
      # Return configured container with extra types
      #
      # @return [Hash]
      #
      # @api public
      setting :types, default: ::Dry::Types

      # @!method messages
      #
      # Return configuration for message backend
      #
      # `backend` is `:yaml` (the default), `:i18n`, or an object that responds to
      # `build(options)`, such as a subclass of {Messages::Abstract}. A custom backend's `build`
      # receives only the options for settings defined on {Messages::Abstract}, so settings that a
      # subclass adds keep their defaults unless the subclass sets them.
      #
      # @return [Dry::Configurable::Config]
      #
      # @api public
      setting :messages do
        setting :backend, default: :yaml
        setting :namespace
        setting :load_paths, default: ::Set[DEFAULT_MESSAGES_PATH], constructor: :dup.to_proc
        setting :top_namespace, default: DEFAULT_MESSAGES_ROOT, constructor: :to_s.to_proc
        setting :default_locale
      end

      # @!method validate_keys
      #
      # On/off switch for key validator
      #
      # @return [Boolean]
      #
      # @api public
      setting :validate_keys, default: false

      # @!method key_attribution
      #
      # Key attribution policy. Set to true or a policy hash to record which
      # approved/registered source key supplied each canonical value.
      #
      # @return [Boolean, Hash, KeyAttribution::Policy]
      #
      # @api public
      setting :key_attribution, default: false

      # @!method key_aliases
      #
      # Registered aliases grouped by their canonical key path.
      #
      # @return [Hash]
      #
      # @api public
      setting :key_aliases, default: EMPTY_HASH.dup

      # @!method key_conflict_policy
      #
      # Policy used when multiple registered spellings supply one canonical key.
      #
      # @return [Symbol, #call]
      #
      # @api public
      setting :key_conflict_policy, default: :reject

      # @!method permit_key_aliases
      #
      # Global switch for registered alias sources.
      #
      # @return [Boolean]
      #
      # @api public
      setting :permit_key_aliases, default: true

      # @!method verify_key_ownership
      #
      # Descriptive alias for enabling key attribution checks.
      #
      # @return [Boolean]
      #
      # @api public
      setting :verify_key_ownership, default: false

      # @!method approved_fields
      #
      # Optional explicit list of approved canonical field paths.
      #
      # @return [Array]
      #
      # @api public
      setting :approved_fields, default: EMPTY_ARRAY.dup

      # @api private
      def key_attribution_policy
        return key_attribution if key_attribution.is_a?(KeyAttribution::Policy)

        options = {
          aliases: key_aliases,
          approved_fields: approved_fields,
          conflict: key_conflict_policy,
          permit_aliases: permit_key_aliases
        }

        explicit_enabled = key_attribution

        if key_attribution.is_a?(::Hash)
          attribution_options = key_attribution.transform_keys(&:to_sym)
          options.merge!(attribution_options)
          explicit_enabled = options.delete(:enabled) { true }

          configured_aliases =
            attribution_options[:aliases] ||
            attribution_options[:registered_aliases] ||
            attribution_options[:key_aliases] ||
            EMPTY_HASH

          options[:aliases] = key_aliases.merge(configured_aliases)
        elsif key_attribution.is_a?(::Symbol)
          options[:conflict] = :merge if key_attribution == :permissive
        end

        enabled = explicit_enabled &&
                  key_attribution != :disabled &&
                  key_attribution != "disabled"
        enabled ||= verify_key_ownership
        enabled ||= !key_aliases.empty?

        return KeyAttribution::NullPolicy.new unless enabled

        KeyAttribution::Policy.normalize(options)
      end

      # @api private
      def respond_to_missing?(meth, include_private = false)
        super || config.respond_to?(meth, include_private)
      end

      # @api private
      def inspect
        "#<#{self.class} #{to_h.map { |k, v| ["#{k}=", v.inspect] }.map(&:join).join(" ")}>"
      end

      private

      # Forward to the underlying config object
      #
      # @api private
      def method_missing(meth, ...)
        super unless config.respond_to?(meth)
        config.public_send(meth, ...)
      end
    end
  end
end
