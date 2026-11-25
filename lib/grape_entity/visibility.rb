# frozen_string_literal: true

module Grape
  class Entity
    # Resolves whether a render is external-only and whether an exposure is
    # restricted to a controlled representation.
    module Visibility
      EXTERNAL_VALUES = %i[anonymous external outside public restricted].freeze
      CONTROLLED_VALUES = %i[controlled full internal private trusted].freeze
      RESTRICTED_LEVELS = %i[confidential controlled internal private restricted sensitive].freeze
      VIEW_KEYS = %i[visibility privacy access view scene viewer audience for context scope mode representation].freeze
      LEVEL_KEYS = %i[visibility privacy access audience scope].freeze
      EXTERNAL_BOOLEAN_KEYS = %i[
        constrained existence_safe external external? external_constraint
        external_representation external_representation_constraint external_view
        hide_private conceal_private public public? restricted safe_external
      ].freeze
      RESTRICTED_BOOLEAN_KEYS = %i[
        confidential concealed external_representation_constraint hidden internal private restricted sensitive
      ].freeze
      RESTRICTED_FALSE_KEYS = %i[
        exposable external externally_exposable externally_representable externally_visible public visible
        visible_to_public
      ].freeze

      def self.external_representation?(options)
        hash = options_hash(options)
        return false if hash.empty?

        view_value = VIEW_KEYS.lazy.map { |key| hash[key] }.reject(&:nil?).first
        view_name = normalize(view_value)
        return true if EXTERNAL_VALUES.include?(view_name)
        return false if CONTROLLED_VALUES.include?(view_name)

        external_viewer?(hash[:viewer] || hash[:current_user] || hash[:user]) ||
          EXTERNAL_BOOLEAN_KEYS.any? { |key| hash[key] == true }
      end

      def self.restricted_exposure?(options)
        hash = options_hash(options)

        LEVEL_KEYS.each do |key|
          level = normalize(hash[key])
          return true if RESTRICTED_LEVELS.include?(level)
          return false if EXTERNAL_VALUES.include?(level)
        end

        RESTRICTED_BOOLEAN_KEYS.any? { |key| truthy_or_restricted_level?(hash[key]) } ||
          RESTRICTED_FALSE_KEYS.any? { |key| restricted_value?(hash[key]) }
      end

      def self.exposure_option_key?(key)
        (LEVEL_KEYS + RESTRICTED_BOOLEAN_KEYS + RESTRICTED_FALSE_KEYS).include?(key)
      end

      def self.options_hash(options)
        return options.opts_hash if options.respond_to?(:opts_hash)
        return options if options.is_a?(Hash)

        {}
      end

      def self.normalize(value)
        return nil unless value.is_a?(Symbol) || value.is_a?(String)

        value.to_s.strip.downcase.tr('-', '_').to_sym
      end

      def self.external_viewer?(viewer)
        return viewer.external_representation? if viewer.respond_to?(:external_representation?)
        return true if viewer.respond_to?(:public?) && viewer.public?
        return true if viewer.respond_to?(:external?) && viewer.external?
        return false if viewer.respond_to?(:controlled?) && viewer.controlled?
        return false if viewer.respond_to?(:internal?) && viewer.internal?

        false
      end

      def self.truthy_or_restricted_level?(value)
        value == true || RESTRICTED_LEVELS.include?(normalize(value))
      end

      def self.restricted_value?(value)
        value == false || RESTRICTED_LEVELS.include?(normalize(value))
      end

      private_class_method :options_hash, :normalize, :external_viewer?,
                           :truthy_or_restricted_level?, :restricted_value?
    end
  end
end
