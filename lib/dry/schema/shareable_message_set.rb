# frozen_string_literal: true

require "dry/schema/constants"
require_relative "shareable_message"

module Dry
  module Schema
    # Collection of redacted, partner-shareable messages
    #
    # @api public
    class ShareableMessageSet
      include ::Enumerable

      # @return [Array<ShareableMessage>]
      attr_reader :entries

      # @return [ShareableMessage::Policy]
      attr_reader :policy

      # @return [Symbol, nil]
      attr_reader :locale

      # Build from a {Result}, calling the existing `errors` and `hints` APIs
      #
      # @api private
      def self.from_result(result, **options)
        locale = options[:locale]
        policy = options[:policy] || ShareableMessage::Policy.new(**policy_options(options))
        lookup_options = locale ? {locale: locale} : EMPTY_HASH

        sources = []

        if errors_enabled?(options)
          error_set = result.errors(lookup_options)
          sources.concat(Array(error_set.messages))
        end

        if hints_enabled?(options) && result.respond_to?(:hints)
          hint_set = result.hints(lookup_options)
          hint_sources = hint_set.respond_to?(:hints) ? hint_set.hints : hint_set.messages
          sources.concat(Array(hint_sources))
        end

        new(sources, policy: policy, locale: locale)
      end

      # Build from existing message objects
      #
      # @api public
      def self.from_messages(messages, **options)
        new(messages, **options)
      end

      # @api private
      def self.policy_options(options)
        options.reject do |key, _|
          %i[locale policy errors include_errors hints include_hints].include?(key)
        end
      end

      def self.errors_enabled?(options)
        options.fetch(:include_errors) { options.fetch(:errors, true) }
      end

      def self.hints_enabled?(options)
        options.fetch(:include_hints) { options.fetch(:hints, true) }
      end

      # @param sources [Array<Message, Message::Or, ShareableMessage>]
      # @api public
      def initialize(sources = EMPTY_ARRAY, policy: nil, locale: nil, **policy_options)
        @policy = policy || ShareableMessage::Policy.new(**policy_options)
        @locale = locale&.to_sym
        @entries = flatten_sources(Array(sources)).filter_map do |source|
          entry = ShareableMessage.new(source, locale: locale)
          next unless @policy.allow?(entry)

          @policy.apply(entry)
        end.uniq.freeze
      end

      # @api public
      def each(&block)
        return to_enum unless block_given?

        entries.each(&block)
      end

      # Plain record hashes
      #
      # @return [Array<Hash>]
      # @api public
      def records
        map(&:to_h)
      end

      # @return [Array<ShareableMessage>]
      # @api public
      def errors
        select(&:error?)
      end

      # @return [Array<ShareableMessage>]
      # @api public
      def hints
        select(&:hint?)
      end

      # @return [Array<Hash>]
      # @api public
      def error_records
        errors.map(&:to_h)
      end

      # @return [Array<Hash>]
      # @api public
      def hint_records
        hints.map(&:to_h)
      end

      # Shareable envelope
      #
      # @return [Hash]
      # @api public
      def to_h
        {
          locale: locale,
          messages: records,
          errors: error_records,
          hints: hint_records
        }.compact
      end
      alias_method :to_hash, :to_h

      # @return [Array<Hash>]
      # @api public
      def as_json(*)
        map(&:as_json)
      end

      # @api public
      def to_json(options = nil)
        require "json" unless defined?(::JSON)
        as_json.to_json(options)
      end

      # Hash keyed by JSON Pointer for convenient field matching
      #
      # @return [Hash<String, Array<Hash>>]
      # @api public
      def by_pointer
        each_with_object({}) do |entry, result|
          (result[entry.pointer] ||= []) << entry.to_h
        end
      end

      # @api public
      def inspect
        "#<#{self.class} entries=#{entries.map(&:to_h).inspect}>"
      end

      private

      def flatten_sources(sources)
        sources.flat_map do |source|
          if source.is_a?(::Array)
            flatten_sources(source)
          elsif or_message?(source)
            flatten_sources([source.left, source.right])
          else
            source
          end
        end
      end

      def or_message?(source)
        source.respond_to?(:left) && source.respond_to?(:right) &&
          source.class.name&.include?("Or")
      end
    end
  end
end
